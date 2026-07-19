#include <fmt/core.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <session/export.h>
#include <session/pro_backend.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include <chrono>
#include <concepts>
#include <nlohmann/json.hpp>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/sodium_array.hpp>
#include <session/types.hpp>

namespace {
const nlohmann::json json_parse(std::string_view json, std::vector<std::string>& errors) {
    nlohmann::json result;
    try {
        result = nlohmann::json::parse(json);
    } catch (const std::exception& e) {
        errors.push_back(fmt::format("Invalid JSON received, parse failed: {}", e.what()));
    }
    return result;
}

template <typename T>
const T json_require(
        const nlohmann::json& j, std::string_view key, std::vector<std::string>& errors) {
    T result = {};
    auto it = j.find(key);
    if (it == j.end()) {
        errors.push_back(fmt::format("Key '{}' is missing", key));
    } else {
        bool success = false;
        std::string_view type;
        if constexpr (std::floating_point<T>) {
            type = "a float";
            success = it->is_number_float();
        } else if constexpr (std::same_as<T, bool>) {
            type = "a boolean";
            success = it->is_boolean();
        } else if constexpr (std::integral<T>) {
            type = "a number";
            success = it->is_number();
        } else if constexpr (session::is_one_of<T, std::string, std::string_view>) {
            type = "a string";
            success = it->is_string();
        } else if constexpr (std::same_as<T, nlohmann::json::array_t>) {
            type = "an array";
            success = it->is_array();
        } else {
            static_assert(std::same_as<T, nlohmann::json::object_t>);
            type = "an object";
            success = it->is_object();
        }

        if (success)
            it->get_to<T>(result);
        else
            errors.push_back(fmt::format("Key value ({}, {}) was not {}", key, it->dump(1), type));
    }
    return result;
}

// Reads a JSON number that may be an integer *or* a float, as a double. Used for the two
// upstream-provider event instants (`purchased_ts`, `revoked_ts`) which the backend emits as floats
// carrying the provider's sub-second precision (pro-wire-protocol.md §1).
double json_require_number(
        const nlohmann::json& j, std::string_view key, std::vector<std::string>& errors) {
    auto it = j.find(key);
    if (it == j.end())
        errors.push_back(fmt::format("Key '{}' is missing", key));
    else if (it->is_number())
        return it->get<double>();
    else
        errors.push_back(fmt::format("Key value ({}, {}) was not a number", key, it->dump(1)));
    return 0;
}

// Fractional UNIX seconds (double) -> millisecond-precision system time, preserving the provider's
// sub-second precision (rounded to the nearest millisecond).
session::sys_ms sys_ms_from_seconds(double seconds) {
    return session::sys_ms(
            std::chrono::round<std::chrono::milliseconds>(std::chrono::duration<double>(seconds)));
}

// Millisecond-precision system time -> fractional UNIX seconds (double); the C API carries these
// two instants as double seconds (millisecond-precise, having passed through sys_ms).
double epoch_seconds_double(session::sys_ms t) {
    return std::chrono::duration<double>(t.time_since_epoch()).count();
}

void parse_json_response_errors(const nlohmann::json& j, std::vector<std::string>& errors) {
    const auto& array = json_require<nlohmann::json::array_t>(j, "errors", errors);
    errors.reserve(errors.size() + array.size());
    for (size_t index = 0; index < array.size(); index++) {
        const auto& it = array[index];
        if (it.is_string()) {
            errors.push_back(it.get<std::string>());
        } else {
            errors.push_back(fmt::format(
                    "Aborting parse, 'result.errors[{}]' was not a string "
                    "error: '{}'",
                    index,
                    it.dump(1)));
            break;
        }
    }
}

bool json_require_fixed_bytes_from_hex(
        const nlohmann::json& j,
        std::string_view key,
        std::vector<std::string>& errors,
        std::span<uint8_t> dest) {
    auto hex = json_require<std::string_view>(j, key, errors);
    if (hex.starts_with("0X") || hex.starts_with("0x"))
        hex = hex.substr(2);

    size_t hex_avail = dest.size() * 2;
    if (hex.size() != hex_avail) {
        errors.push_back(fmt::format(
                "Hex -> bytes failed ({}, {}). {} hex chars capacity (requires {})",
                key,
                hex,
                hex_avail,
                hex.size()));
        return false;
    }

    bool result = oxenc::is_hex(hex);
    if (result)
        oxenc::from_hex(hex.begin(), hex.end(), dest.begin());
    else
        errors.push_back(fmt::format("Key value string was not hex: '{}': '{}'", key, hex));
    return result;
}
};  // namespace

namespace session::pro_backend {

namespace {

    // Endpoint paths (single master storage). Both the C `SESSION_PRO_BACKEND_*_ENDPOINT` symbols
    // and the C++ `*_request()` return values point at these — the path is defined exactly once.
    constexpr char add_payment_endpoint[] = "add_pro_payment";
    constexpr char generate_proof_endpoint[] = "generate_pro_proof";
    constexpr char get_pro_details_endpoint[] = "get_pro_details";
    constexpr char get_pro_revocations_endpoint[] = "get_pro_revocations";
    constexpr char set_refund_endpoint[] = "set_payment_refund_requested";

    // Normalise an Ed25519 private key to libsodium's 64-byte form (seed(32) || pubkey(32)): a
    // 32-byte seed is expanded, a 64-byte key copied, anything else throws. The public key is then
    // available at bytes [32, 64) so callers never need a second derivation.
    cleared_uc64 normalize_privkey(std::span<const uint8_t> privkey, const char* name) {
        cleared_uc64 out;
        if (privkey.size() == crypto_sign_ed25519_SEEDBYTES) {
            array_uc32 pubkey;
            crypto_sign_ed25519_seed_keypair(pubkey.data(), out.data(), privkey.data());
        } else if (privkey.size() == crypto_sign_ed25519_SECRETKEYBYTES) {
            std::memcpy(out.data(), privkey.data(), crypto_sign_ed25519_SECRETKEYBYTES);
        } else {
            throw std::invalid_argument{fmt::format("Invalid {}: expected 32 or 64 bytes", name)};
        }
        return out;
    }

    // Public-key view (bytes [32, 64)) of a normalised 64-byte private key.
    std::span<const uint8_t> pubkey_of(const cleared_uc64& priv64) {
        return {priv64.data() + crypto_sign_ed25519_SEEDBYTES, crypto_sign_ed25519_PUBLICKEYBYTES};
    }

    std::string_view payment_id_view(std::span<const uint8_t> payment_id) {
        return {reinterpret_cast<const char*>(payment_id.data()), payment_id.size()};
    }

    // --- add-payment (endpoint add_pro_payment) ---

    array_uc32 add_payment_hash(
            std::span<const uint8_t> master_pubkey,
            std::span<const uint8_t> rotating_pubkey,
            std::string_view provider_code,
            std::span<const uint8_t> payment_id) {
        // Must match the add-payment signed-request hash in pro-wire-protocol.md §3.2 (+ §3.5).
        array_uc32 hash = {};
        crypto_generichash_blake2b_state state = {};
        make_blake2b32_hasher(
                &state,
                {SESSION_PROTOCOL_ADD_PRO_PAYMENT_HASH_PERSONALISATION,
                 sizeof(SESSION_PROTOCOL_ADD_PRO_PAYMENT_HASH_PERSONALISATION) - 1});
        crypto_generichash_blake2b_update(&state, master_pubkey.data(), master_pubkey.size());
        crypto_generichash_blake2b_update(&state, rotating_pubkey.data(), rotating_pubkey.size());
        crypto_generichash_blake2b_update(
                &state,
                reinterpret_cast<const uint8_t*>(provider_code.data()),
                provider_code.size());
        crypto_generichash_blake2b_update(&state, payment_id.data(), payment_id.size());
        crypto_generichash_blake2b_final(&state, hash.data(), hash.size());
        return hash;
    }

    MasterRotatingSignatures add_payment_sign(
            const cleared_uc64& master,
            const cleared_uc64& rotating,
            std::string_view provider_code,
            std::span<const uint8_t> payment_id) {
        auto hash =
                add_payment_hash(pubkey_of(master), pubkey_of(rotating), provider_code, payment_id);
        MasterRotatingSignatures result = {};
        crypto_sign_ed25519_detached(
                result.master_sig.data(), nullptr, hash.data(), hash.size(), master.data());
        crypto_sign_ed25519_detached(
                result.rotating_sig.data(), nullptr, hash.data(), hash.size(), rotating.data());
        return result;
    }

    // Serialise an add-payment request body from already-computed fields (shared by the C++
    // add_payment_request and the C ..._request_to_json wrapper).
    std::string add_payment_body(
            std::span<const uint8_t> master_pubkey,
            std::span<const uint8_t> rotating_pubkey,
            std::string_view provider_code,
            std::string_view payment_id,
            std::span<const uint8_t> master_sig,
            std::span<const uint8_t> rotating_sig) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"rotating_pkey", oxenc::to_hex(rotating_pubkey)},
                {"payment_tx", {{"provider", provider_code}, {"payment_id", payment_id}}},
                {"master_sig", oxenc::to_hex(master_sig)},
                {"rotating_sig", oxenc::to_hex(rotating_sig)}}
                .dump();
    }

}  // namespace

// C endpoint symbols: each points at the single master endpoint string defined above, so the C API
// and the C++ `ProRequest::endpoint` values are backed by one definition.
extern "C" {
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_ENDPOINT =
        add_payment_endpoint;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GENERATE_PRO_PROOF_ENDPOINT =
        generate_proof_endpoint;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PRO_DETAILS_ENDPOINT =
        get_pro_details_endpoint;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PRO_REVOCATIONS_ENDPOINT =
        get_pro_revocations_endpoint;
LIBSESSION_EXPORT extern const char* const
        SESSION_PRO_BACKEND_SET_PAYMENT_REFUND_REQUESTED_ENDPOINT = set_refund_endpoint;
}

std::optional<ProviderUrls> provider_urls(std::string_view provider_code) {
    if (provider_code == SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY)
        return ProviderUrls{
                "https://support.google.com/googleplay/workflow/9813244?",
                "https://getsession.org/android-refund",
                "https://getsession.org/android-refund",
                "https://play.google.com/store/account/"
                "subscriptions?package=network.loki.messenger",
                "https://play.google.com/store/account/"
                "subscriptions?package=network.loki.messenger"};
    if (provider_code == SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_APP_STORE)
        return ProviderUrls{
                "https://support.apple.com/118223",
                "https://support.apple.com/118223",
                "https://support.apple.com/118224",
                "https://apps.apple.com/account/subscriptions",
                "https://account.apple.com/account/manage/section/subscriptions"};
    // rangeproof and unknown providers have no applicable URLs
    return std::nullopt;
}

LIBSESSION_C_API session_pro_backend_provider_urls
session_pro_backend_get_provider_urls(const char* provider_code) {
    // No URLs → all-NULL fields; otherwise each view is a static, null-terminated literal.
    if (auto u = provider_urls(provider_code))
        return {u->refund_platform_url.data(),
                u->refund_support_url.data(),
                u->refund_status_url.data(),
                u->update_subscription_url.data(),
                u->cancel_subscription_url.data()};
    return {nullptr, nullptr, nullptr, nullptr, nullptr};
}

MasterRotatingSignatures add_payment_sigs(
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        std::string_view provider_code,
        std::span<const uint8_t> payment_id) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    auto rotating = normalize_privkey(rotating_privkey, "rotating_privkey");
    return add_payment_sign(master, rotating, provider_code, payment_id);
}

ProRequest add_payment_request(
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        std::string_view provider_code,
        std::span<const uint8_t> payment_id) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    auto rotating = normalize_privkey(rotating_privkey, "rotating_privkey");
    auto sigs = add_payment_sign(master, rotating, provider_code, payment_id);
    return {add_payment_endpoint,
            add_payment_body(
                    pubkey_of(master),
                    pubkey_of(rotating),
                    provider_code,
                    payment_id_view(payment_id),
                    sigs.master_sig,
                    sigs.rotating_sig)};
}

namespace {
    // Shared parse for the proof-carrying responses (add-payment and generate-proof both reply with
    // exactly a proof); fills the common ProProofResponse base of whichever derived response is
    // passed.
    void fill_proof_response(std::string_view json, ProProofResponse& result) {
        // Parse basics
        nlohmann::json j = json_parse(json, result.errors);
        result.status = json_require<uint8_t>(j, "status", result.errors);
        if (result.errors.size()) {
            result.status = SESSION_PRO_BACKEND_STATUS_GENERIC_ERROR;
            return;
        }

        // Parse errors
        if (result.status != SESSION_PRO_BACKEND_STATUS_SUCCESS) {
            parse_json_response_errors(j, result.errors);
            return;
        }

        auto result_obj = json_require<nlohmann::json::object_t>(j, "result", result.errors);
        if (result.errors.size())
            return;

        // Parse payload
        result.proof.version = json_require<uint8_t>(result_obj, "version", result.errors);
        auto expiry_ts = json_require<int64_t>(result_obj, "expiry_ts", result.errors);
        result.proof.expiry_unix_ts = std::chrono::sys_seconds(std::chrono::seconds(expiry_ts));
        json_require_fixed_bytes_from_hex(
                result_obj, "revocation_tag", result.errors, result.proof.revocation_tag);
        json_require_fixed_bytes_from_hex(
                result_obj, "rotating_pkey", result.errors, result.proof.rotating_pubkey);
        json_require_fixed_bytes_from_hex(result_obj, "sig", result.errors, result.proof.sig);
    }
}  // namespace

AddProPaymentResponse parse_add_payment(std::string_view json) {
    AddProPaymentResponse result = {};
    fill_proof_response(json, result);
    return result;
}

GenerateProProofResponse parse_pro_proof(std::string_view json) {
    GenerateProProofResponse result = {};
    fill_proof_response(json, result);
    return result;
}

namespace {

    // --- generate-proof (endpoint generate_pro_proof) ---

    array_uc32 generate_proof_hash(
            std::span<const uint8_t> master_pubkey,
            std::span<const uint8_t> rotating_pubkey,
            std::chrono::sys_seconds unix_ts) {
        // Must match the generate-proof signed-request hash in pro-wire-protocol.md §3.1.
        int64_t ts = epoch_seconds(unix_ts);
        array_uc32 hash = {};
        crypto_generichash_blake2b_state state = {};
        make_blake2b32_hasher(
                &state,
                {SESSION_PROTOCOL_GENERATE_PROOF_HASH_PERSONALISATION,
                 sizeof(SESSION_PROTOCOL_GENERATE_PROOF_HASH_PERSONALISATION) - 1});
        crypto_generichash_blake2b_update(&state, master_pubkey.data(), master_pubkey.size());
        crypto_generichash_blake2b_update(&state, rotating_pubkey.data(), rotating_pubkey.size());
        oxenc::host_to_little_inplace(ts);
        crypto_generichash_blake2b_update(&state, reinterpret_cast<uint8_t*>(&ts), sizeof(ts));
        crypto_generichash_blake2b_final(&state, hash.data(), hash.size());
        return hash;
    }

    MasterRotatingSignatures generate_proof_sign(
            const cleared_uc64& master,
            const cleared_uc64& rotating,
            std::chrono::sys_seconds unix_ts) {
        auto hash = generate_proof_hash(pubkey_of(master), pubkey_of(rotating), unix_ts);
        MasterRotatingSignatures result = {};
        crypto_sign_ed25519_detached(
                result.master_sig.data(), nullptr, hash.data(), hash.size(), master.data());
        crypto_sign_ed25519_detached(
                result.rotating_sig.data(), nullptr, hash.data(), hash.size(), rotating.data());
        return result;
    }

    std::string generate_proof_body(
            std::span<const uint8_t> master_pubkey,
            std::span<const uint8_t> rotating_pubkey,
            std::chrono::sys_seconds unix_ts,
            std::span<const uint8_t> master_sig,
            std::span<const uint8_t> rotating_sig) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"rotating_pkey", oxenc::to_hex(rotating_pubkey)},
                {"ts", epoch_seconds(unix_ts)},
                {"master_sig", oxenc::to_hex(master_sig)},
                {"rotating_sig", oxenc::to_hex(rotating_sig)}}
                .dump();
    }

}  // namespace

MasterRotatingSignatures pro_proof_sigs(
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        std::chrono::sys_seconds unix_ts) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    auto rotating = normalize_privkey(rotating_privkey, "rotating_privkey");
    return generate_proof_sign(master, rotating, unix_ts);
}

ProRequest pro_proof_request(
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        std::chrono::sys_seconds unix_ts) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    auto rotating = normalize_privkey(rotating_privkey, "rotating_privkey");
    auto sigs = generate_proof_sign(master, rotating, unix_ts);
    return {generate_proof_endpoint,
            generate_proof_body(
                    pubkey_of(master),
                    pubkey_of(rotating),
                    unix_ts,
                    sigs.master_sig,
                    sigs.rotating_sig)};
}

ProRequest revocations_request(std::int64_t ticket) {
    nlohmann::json j;
    j["ticket"] = ticket;
    return {get_pro_revocations_endpoint, j.dump()};
}

GetProRevocationsResponse parse_revocations(std::string_view json) {
    // Parse basics
    GetProRevocationsResponse result = {};
    nlohmann::json j = json_parse(json, result.errors);
    result.status = json_require<uint8_t>(j, "status", result.errors);
    if (result.errors.size()) {
        result.status = SESSION_PRO_BACKEND_STATUS_GENERIC_ERROR;
        return result;
    }

    // Parse errors
    if (result.status != SESSION_PRO_BACKEND_STATUS_SUCCESS) {
        parse_json_response_errors(j, result.errors);
        return result;
    }

    auto result_obj = json_require<nlohmann::json::object_t>(j, "result", result.errors);
    if (result.errors.size())
        return result;

    // Parse payload
    result.ticket = json_require<int64_t>(result_obj, "ticket", result.errors);
    result.retry_in =
            std::chrono::seconds(json_require<int64_t>(result_obj, "retry_in", result.errors));
    result.retain_for =
            std::chrono::seconds(json_require<int64_t>(result_obj, "retain_for", result.errors));

    auto array = json_require<nlohmann::json::array_t>(result_obj, "items", result.errors);
    result.items.reserve(array.size());
    for (size_t index = 0; index < array.size(); index++) {
        const auto& it = array[index];
        if (!it.is_object()) {
            result.errors.push_back(fmt::format(
                    "Aborting parse, 'items[{}]' was not an object: {}", index, it.dump(1)));
            break;
        }

        // Parse revocation item
        auto obj = it.get<nlohmann::json::object_t>();
        auto effective_ts = json_require<int64_t>(obj, "effective_ts", result.errors);

        ProRevocationItem item = {};
        item.effective_unix_ts = as_sys_seconds(effective_ts);
        json_require_fixed_bytes_from_hex(
                obj, "revocation_tag", result.errors, item.revocation_tag);

        // Handle parsing result
        if (result.errors.size())
            break;
        result.items.emplace_back(std::move(item));
    }

    return result;
}

namespace {

    // --- payment-details / get-pro-details (endpoint get_pro_details) ---

    array_uc32 payment_details_hash(
            std::span<const uint8_t> master_pubkey,
            std::chrono::sys_seconds unix_ts,
            uint32_t count) {
        // Must match the get-pro-details signed-request hash in pro-wire-protocol.md §3.4.
        int64_t ts = epoch_seconds(unix_ts);
        array_uc32 hash = {};
        crypto_generichash_blake2b_state state = {};
        make_blake2b32_hasher(
                &state,
                {SESSION_PROTOCOL_GET_PRO_DETAILS_HASH_PERSONALISATION,
                 sizeof(SESSION_PROTOCOL_GET_PRO_DETAILS_HASH_PERSONALISATION) - 1});
        crypto_generichash_blake2b_update(&state, master_pubkey.data(), master_pubkey.size());
        oxenc::host_to_little_inplace(ts);
        oxenc::host_to_little_inplace(count);
        crypto_generichash_blake2b_update(
                &state, reinterpret_cast<unsigned char*>(&ts), sizeof(ts));
        crypto_generichash_blake2b_update(
                &state, reinterpret_cast<unsigned char*>(&count), sizeof(count));
        crypto_generichash_blake2b_final(&state, hash.data(), hash.size());
        return hash;
    }

    array_uc64 payment_details_sign(
            const cleared_uc64& master, std::chrono::sys_seconds unix_ts, uint32_t count) {
        auto hash = payment_details_hash(pubkey_of(master), unix_ts, count);
        array_uc64 sig = {};
        crypto_sign_ed25519_detached(sig.data(), nullptr, hash.data(), hash.size(), master.data());
        return sig;
    }

    std::string payment_details_body(
            std::span<const uint8_t> master_pubkey,
            std::span<const uint8_t> master_sig,
            std::chrono::sys_seconds unix_ts,
            uint32_t count) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"master_sig", oxenc::to_hex(master_sig)},
                {"ts", epoch_seconds(unix_ts)},
                {"count", count}}
                .dump();
    }

}  // namespace

array_uc64 payment_details_sig(
        std::span<const uint8_t> master_privkey, std::chrono::sys_seconds unix_ts, uint32_t count) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    return payment_details_sign(master, unix_ts, count);
}

ProRequest payment_details_request(
        std::span<const uint8_t> master_privkey, std::chrono::sys_seconds unix_ts, uint32_t count) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    auto sig = payment_details_sign(master, unix_ts, count);
    return {get_pro_details_endpoint, payment_details_body(pubkey_of(master), sig, unix_ts, count)};
}

GetProDetailsResponse parse_payment_details(std::string_view json) {
    // Parse basics
    GetProDetailsResponse result = {};
    nlohmann::json j = json_parse(json, result.errors);
    result.status = json_require<uint8_t>(j, "status", result.errors);
    if (result.errors.size()) {
        result.status = SESSION_PRO_BACKEND_STATUS_GENERIC_ERROR;
        return result;
    }

    // Parse errors
    if (result.status != SESSION_PRO_BACKEND_STATUS_SUCCESS) {
        parse_json_response_errors(j, result.errors);
        return result;
    }

    auto result_obj = json_require<nlohmann::json::object_t>(j, "result", result.errors);
    if (result.errors.size())
        return result;

    // Parse payload
    uint32_t user_status = json_require<uint32_t>(result_obj, "status", result.errors);
    if (user_status >= SESSION_PRO_BACKEND_USER_PRO_STATUS_COUNT) {
        result.errors.push_back(
                fmt::format("User pro status value was out-of-bounds: {}", user_status));
        return result;
    }
    result.user_status = static_cast<SESSION_PRO_BACKEND_USER_PRO_STATUS>(user_status);

    uint32_t error_report = json_require<uint32_t>(result_obj, "error_report", result.errors);
    if (error_report >= SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_COUNT) {
        result.errors.push_back(
                fmt::format("Error report value was out-of-bounds: {}", user_status));
        return result;
    }
    result.error_report =
            static_cast<SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT>(error_report);

    result.auto_renewing = json_require<bool>(result_obj, "auto_renewing", result.errors);

    result.payments_total = json_require<uint32_t>(result_obj, "payments_total", result.errors);

    result.expiry_unix_ts = std::chrono::sys_seconds(
            std::chrono::seconds(json_require<int64_t>(result_obj, "expiry_ts", result.errors)));
    result.grace_period_duration = std::chrono::seconds(
            json_require<int64_t>(result_obj, "grace_period_duration", result.errors));
    result.refund_requested_unix_ts = std::chrono::sys_seconds(std::chrono::seconds(
            json_require<int64_t>(result_obj, "refund_requested_ts", result.errors)));

    auto array = json_require<nlohmann::json::array_t>(result_obj, "items", result.errors);
    result.items.reserve(array.size());
    for (size_t index = 0; index < array.size(); index++) {
        const auto& it = array[index];
        if (!it.is_object()) {
            result.errors.push_back(fmt::format(
                    "Aborting parse, 'items[{}]' was not an object: {}", index, it.dump(1)));
            break;
        }

        // Parse payment item
        auto obj = it.get<nlohmann::json::object_t>();
        auto status = json_require<uint64_t>(obj, "status", result.errors);
        auto plan = json_require<std::string>(obj, "plan", result.errors);
        auto payment_provider = json_require<std::string>(obj, "payment_provider", result.errors);
        auto payment_id = json_require<std::string>(obj, "payment_id", result.errors);
        auto auto_renewing = json_require<bool>(obj, "auto_renewing", result.errors);
        // purchased_ts and revoked_ts are upstream-provider event instants: floats on the wire
        // carrying sub-second precision (kept as millisecond-precision sys_ms). All other
        // timestamps are whole-second integers.
        auto purchased_ts = json_require_number(obj, "purchased_ts", result.errors);
        auto redeemed_ts = json_require<int64_t>(obj, "redeemed_ts", result.errors);
        auto expiry_ts = json_require<int64_t>(obj, "expiry_ts", result.errors);
        auto grace_period_duration =
                json_require<int64_t>(obj, "grace_period_duration", result.errors);
        auto platform_refund_expiry_ts =
                json_require<int64_t>(obj, "platform_refund_expiry_ts", result.errors);
        auto revoked_ts = json_require_number(obj, "revoked_ts", result.errors);
        auto refund_requested_ts = json_require<int64_t>(obj, "refund_requested_ts", result.errors);

        ProPaymentItem item = {};
        if (status > SESSION_PRO_BACKEND_PAYMENT_STATUS_NIL &&
            status < SESSION_PRO_BACKEND_PAYMENT_STATUS_COUNT) {
            item.status = static_cast<SESSION_PRO_BACKEND_PAYMENT_STATUS>(status);
        } else {
            result.errors.push_back(fmt::format("Status value was out-of-bounds: {}", status));
        }

        item.plan = std::move(plan);
        item.payment_provider = std::move(payment_provider);
        item.payment_id = std::move(payment_id);

        item.auto_renewing = auto_renewing;
        item.purchased_unix_ts = sys_ms_from_seconds(purchased_ts);
        item.redeemed_unix_ts = std::chrono::sys_seconds(std::chrono::seconds(redeemed_ts));
        item.expiry_unix_ts = std::chrono::sys_seconds(std::chrono::seconds(expiry_ts));
        item.grace_period_duration = std::chrono::seconds(grace_period_duration);
        item.platform_refund_expiry_unix_ts =
                std::chrono::sys_seconds(std::chrono::seconds(platform_refund_expiry_ts));
        item.revoked_unix_ts = sys_ms_from_seconds(revoked_ts);
        item.refund_requested_unix_ts =
                std::chrono::sys_seconds(std::chrono::seconds(refund_requested_ts));

        // Handle parsing result
        if (result.errors.size())
            break;

        result.items.emplace_back(std::move(item));
    }
    return result;
}

namespace {

    // --- refund / set-payment-refund-requested (endpoint set_payment_refund_requested) ---

    array_uc32 refund_hash(
            std::span<const uint8_t> master_pubkey,
            std::chrono::sys_seconds unix_ts,
            std::chrono::sys_seconds refund_requested_unix_ts,
            std::string_view provider_code,
            std::span<const uint8_t> payment_id) {
        // Must match the set-payment-refund-requested signed-request hash in pro-wire-protocol.md
        // §3.3 (+ §3.5 for payment_id).
        int64_t ts = epoch_seconds(unix_ts);
        int64_t refund_requested_ts = epoch_seconds(refund_requested_unix_ts);
        array_uc32 hash = {};
        crypto_generichash_blake2b_state state = {};
        make_blake2b32_hasher(
                &state,
                {SESSION_PROTOCOL_SET_PAYMENT_REFUND_REQUESTED_HASH_PERSONALISATION,
                 sizeof(SESSION_PROTOCOL_SET_PAYMENT_REFUND_REQUESTED_HASH_PERSONALISATION) - 1});
        crypto_generichash_blake2b_update(&state, master_pubkey.data(), master_pubkey.size());
        oxenc::host_to_little_inplace(ts);
        oxenc::host_to_little_inplace(refund_requested_ts);
        crypto_generichash_blake2b_update(
                &state, reinterpret_cast<const uint8_t*>(&ts), sizeof(ts));
        crypto_generichash_blake2b_update(
                &state,
                reinterpret_cast<const uint8_t*>(&refund_requested_ts),
                sizeof(refund_requested_ts));
        crypto_generichash_blake2b_update(
                &state,
                reinterpret_cast<const uint8_t*>(provider_code.data()),
                provider_code.size());
        crypto_generichash_blake2b_update(&state, payment_id.data(), payment_id.size());
        crypto_generichash_blake2b_final(&state, hash.data(), hash.size());
        return hash;
    }

    array_uc64 refund_sign(
            const cleared_uc64& master,
            std::chrono::sys_seconds unix_ts,
            std::chrono::sys_seconds refund_requested_unix_ts,
            std::string_view provider_code,
            std::span<const uint8_t> payment_id) {
        auto hash = refund_hash(
                pubkey_of(master), unix_ts, refund_requested_unix_ts, provider_code, payment_id);
        array_uc64 sig = {};
        crypto_sign_ed25519_detached(sig.data(), nullptr, hash.data(), hash.size(), master.data());
        return sig;
    }

    std::string refund_body(
            std::span<const uint8_t> master_pubkey,
            std::chrono::sys_seconds unix_ts,
            std::chrono::sys_seconds refund_requested_unix_ts,
            std::string_view provider_code,
            std::string_view payment_id,
            std::span<const uint8_t> master_sig) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"ts", epoch_seconds(unix_ts)},
                {"refund_requested_ts", epoch_seconds(refund_requested_unix_ts)},
                {"payment_tx", {{"provider", provider_code}, {"payment_id", payment_id}}},
                {"master_sig", oxenc::to_hex(master_sig)}}
                .dump();
    }

}  // namespace

array_uc64 refund_sig(
        std::span<const uint8_t> master_privkey,
        std::chrono::sys_seconds unix_ts,
        std::chrono::sys_seconds refund_requested_unix_ts,
        std::string_view provider_code,
        std::span<const uint8_t> payment_id) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    return refund_sign(master, unix_ts, refund_requested_unix_ts, provider_code, payment_id);
}

ProRequest refund_request(
        std::span<const uint8_t> master_privkey,
        std::chrono::sys_seconds unix_ts,
        std::chrono::sys_seconds refund_requested_unix_ts,
        std::string_view provider_code,
        std::span<const uint8_t> payment_id) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    auto sig = refund_sign(master, unix_ts, refund_requested_unix_ts, provider_code, payment_id);
    return {set_refund_endpoint,
            refund_body(
                    pubkey_of(master),
                    unix_ts,
                    refund_requested_unix_ts,
                    provider_code,
                    payment_id_view(payment_id),
                    sig)};
}

SetPaymentRefundRequestedResponse parse_refund(std::string_view json) {
    // Parse basics
    SetPaymentRefundRequestedResponse result = {};
    nlohmann::json j = json_parse(json, result.errors);
    result.status = json_require<uint8_t>(j, "status", result.errors);
    if (result.errors.size()) {
        result.status = SESSION_PRO_BACKEND_STATUS_GENERIC_ERROR;
        return result;
    }

    // Parse errors
    if (result.status != SESSION_PRO_BACKEND_STATUS_SUCCESS) {
        parse_json_response_errors(j, result.errors);
        return result;
    }

    auto result_obj = json_require<nlohmann::json::object_t>(j, "result", result.errors);
    if (result.errors.size())
        return result;

    // Parse payload
    result.updated = json_require<bool>(result_obj, "updated", result.errors);
    return result;
}
}  // namespace session::pro_backend

using namespace session::pro_backend;

/// Define a string8 from a c-string literal. The string should not be modified as it'll live in the
/// data-section of the binary (or be interned, e.t.c)
#define STRING8_LIT(val) {(char*)val, sizeof(val) - 1}

static string8 C_PARSE_ERROR_OUT_OF_MEMORY = STRING8_LIT("Ran out-of-memory creating C response");
static string8 C_PARSE_ERROR_INVALID_ARGS = STRING8_LIT("One or more C arguments were NULL");

LIBSESSION_C_API session_pro_backend_master_rotating_signatures
session_pro_backend_add_pro_payment_request_build_sigs(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        const char* payment_tx_provider_code,
        const uint8_t* payment_tx_payment_id,
        size_t payment_tx_payment_id_len) {

    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span(master_privkey, master_privkey_len);
    std::span<const uint8_t> rotating_span(rotating_privkey, rotating_privkey_len);
    std::span<const uint8_t> payment_tx_payment_id_span(
            payment_tx_payment_id, payment_tx_payment_id_len);

    session_pro_backend_master_rotating_signatures result = {};
    try {
        auto sigs = add_payment_sigs(
                master_span, rotating_span, payment_tx_provider_code, payment_tx_payment_id_span);
        std::memcpy(result.master_sig.data, sigs.master_sig.data(), sigs.master_sig.size());
        std::memcpy(result.rotating_sig.data, sigs.rotating_sig.data(), sigs.rotating_sig.size());
        result.success = true;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error_count),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_master_rotating_signatures
session_pro_backend_generate_pro_proof_request_build_sigs(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        int64_t ts) {

    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span(master_privkey, master_privkey_len);
    std::span<const uint8_t> rotating_span(rotating_privkey, rotating_privkey_len);
    session_pro_backend_master_rotating_signatures result = {};
    try {
        auto sigs = pro_proof_sigs(master_span, rotating_span, session::as_sys_seconds(ts));
        std::memcpy(result.master_sig.data, sigs.master_sig.data(), sigs.master_sig.size());
        std::memcpy(result.rotating_sig.data, sigs.rotating_sig.data(), sigs.rotating_sig.size());
        result.success = true;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error_count),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_signature
session_pro_backend_get_pro_details_request_build_sig(
        const uint8_t* master_privkey, size_t master_privkey_len, int64_t ts, uint32_t count) {
    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span{master_privkey, master_privkey_len};
    session_pro_backend_signature result = {};
    try {
        auto sig = payment_details_sig(master_span, session::as_sys_seconds(ts), count);
        std::memcpy(result.sig.data, sig.data(), sig.size());
        result.success = true;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error_count),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_to_json session_pro_backend_add_pro_payment_request_to_json(
        const session_pro_backend_add_pro_payment_request* request) {
    session_pro_backend_to_json result = {};
    if (!request)
        return result;

    try {
        std::string json = add_payment_body(
                {request->master_pkey.data, sizeof(request->master_pkey.data)},
                {request->rotating_pkey.data, sizeof(request->rotating_pkey.data)},
                {request->payment_tx.provider_code, request->payment_tx.provider_code_count},
                {request->payment_tx.payment_id, request->payment_tx.payment_id_count},
                {request->master_sig.data, sizeof(request->master_sig.data)},
                {request->rotating_sig.data, sizeof(request->rotating_sig.data)});
        result.json = session::string8_copy_or_throw(json.data(), json.size());
        result.success = true;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error_count),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }

    return result;
}

LIBSESSION_C_API session_pro_backend_to_json session_pro_backend_generate_pro_proof_request_to_json(
        const session_pro_backend_generate_pro_proof_request* request) {
    session_pro_backend_to_json result = {};
    if (!request)
        return result;

    try {
        std::string json = generate_proof_body(
                {request->master_pkey.data, sizeof(request->master_pkey.data)},
                {request->rotating_pkey.data, sizeof(request->rotating_pkey.data)},
                session::as_sys_seconds(request->ts),
                {request->master_sig.data, sizeof(request->master_sig.data)},
                {request->rotating_sig.data, sizeof(request->rotating_sig.data)});
        result.json = session::string8_copy_or_throw(json.data(), json.size());
        result.success = true;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error_count),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }

    return result;
}

LIBSESSION_C_API session_pro_backend_to_json
session_pro_backend_get_pro_revocations_request_to_json(
        const session_pro_backend_get_pro_revocations_request* request) {
    session_pro_backend_to_json result = {};
    if (!request)
        return result;

    try {
        std::string json = revocations_request(request->ticket).body;
        result.json = session::string8_copy_or_throw(json.data(), json.size());
        result.success = true;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error_count),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }

    return result;
}

LIBSESSION_C_API session_pro_backend_to_json session_pro_backend_get_pro_details_request_to_json(
        const session_pro_backend_get_pro_details_request* request) {
    session_pro_backend_to_json result = {};
    if (!request)
        return result;

    try {
        std::string json = payment_details_body(
                {request->master_pkey.data, sizeof(request->master_pkey.data)},
                {request->master_sig.data, sizeof(request->master_sig.data)},
                session::as_sys_seconds(request->ts),
                request->count);
        result.json = session::string8_copy_or_throw(json.data(), json.size());
        result.success = true;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error_count),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }

    return result;
}

LIBSESSION_C_API session_pro_backend_pro_proof_response
session_pro_backend_pro_proof_response_parse(const char* json, size_t json_len) {

    session_pro_backend_pro_proof_response result = {};
    if (!json) {
        result.header.status = 1;
        result.header.errors = &C_PARSE_ERROR_INVALID_ARGS;
        result.header.errors_count = 1;
        return result;
    }

    // Note, parse is written to not throw so we can safely read without try-catch crap
    // add-payment and generate-proof share the proof-response shape; the C response struct is
    // generic, so either derived parser works here.
    auto cpp = parse_add_payment({json, json_len});

    // Calculate how much memory we need and create an arena
    arena_t arena = {};
    {
        for (const auto& it : cpp.errors)
            arena.max += sizeof(*result.header.errors) + (it.size() + 1 /*null-terminator*/);

        if (arena.max)
            arena.data = static_cast<uint8_t*>(calloc(1, arena.max));

        if (arena.max && !arena.data) {
            result.header.status = 1;
            result.header.errors = &C_PARSE_ERROR_OUT_OF_MEMORY;
            result.header.errors_count = 1;
            return result;
        }

        // Store the pointer to the backing memory. Upon freeing, we release this one pointer
        result.header.internal_arena_buf_ = arena.data;
    }

    // Copy to C struct, this is guaranteed not to fail because we pre-allocated memory upfront.
    // Note that a response error and success case folds into the same code path. A success and
    // error response returns the same struct just with different fields populated.
    result.header.status = cpp.status;
    result.proof.version = cpp.proof.version;
    result.proof.expiry_ts = session::epoch_seconds(cpp.proof.expiry_unix_ts);
    std::memcpy(
            result.proof.revocation_tag.data,
            cpp.proof.revocation_tag.data(),
            cpp.proof.revocation_tag.size());
    std::memcpy(
            result.proof.rotating_pubkey.data,
            cpp.proof.rotating_pubkey.data(),
            cpp.proof.rotating_pubkey.size());
    std::memcpy(result.proof.sig.data, cpp.proof.sig.data(), cpp.proof.sig.size());

    // Copy errors
    result.header.errors_count = cpp.errors.size();
    result.header.errors = static_cast<string8*>(
            arena_alloc(&arena, result.header.errors_count * sizeof(*result.header.errors)));
    for (size_t index = 0; index < cpp.errors.size(); index++) {
        const std::string& it = cpp.errors[index];
        result.header.errors[index] = arena_alloc_to_string8(&arena, it.data(), it.size());
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_get_pro_revocations_response
session_pro_backend_get_pro_revocations_response_parse(const char* json, size_t json_len) {
    session_pro_backend_get_pro_revocations_response result = {};
    if (!json) {
        result.header.status = 1;
        result.header.errors = &C_PARSE_ERROR_INVALID_ARGS;
        result.header.errors_count = 1;
        return result;
    }

    // Note, parse is written to not throw so we can safely read without try-catch crap
    GetProRevocationsResponse cpp = parse_revocations({json, json_len});

    // Calculate how much memory we need and create an arena
    arena_t arena = {};
    {
        arena.max += cpp.items.size() * sizeof(*result.items);
        static_assert(
                sizeof(cpp.items[0]) >= sizeof(*result.items),
                "Ensure we allocate enough memory. We might slightly over-allocate but that's not "
                "a big deal");
        for (auto it : cpp.errors)
            arena.max += sizeof(*result.header.errors) + (it.size() + 1 /*null-terminator*/);

        if (arena.max)
            arena.data = static_cast<uint8_t*>(calloc(1, arena.max));

        if (arena.max && !arena.data) {
            result.header.status = 1;
            result.header.errors = &C_PARSE_ERROR_OUT_OF_MEMORY;
            result.header.errors_count = 1;
            return result;
        }

        // Store the pointer to the backing memory. Upon freeing, we release this one pointer
        result.header.internal_arena_buf_ = arena.data;
    }

    // Copy to C struct, this is guaranteed not to fail because we pre-allocated memory upfront.
    result.header.status = cpp.status;
    result.ticket = cpp.ticket;
    result.retry_in = cpp.retry_in.count();
    result.retain_for = cpp.retain_for.count();

    // Copy errors
    result.header.errors_count = cpp.errors.size();
    result.header.errors = (string8*)arena_alloc(
            &arena, result.header.errors_count * sizeof(*result.header.errors));
    for (size_t index = 0; index < cpp.errors.size(); index++) {
        const std::string& it = cpp.errors[index];
        result.header.errors[index] = arena_alloc_to_string8(&arena, it.data(), it.size());
    }

    // Copy items
    result.items_count = cpp.items.size();
    result.items = static_cast<session_pro_backend_pro_revocation_item*>(
            arena_alloc(&arena, result.items_count * sizeof(*result.items)));

    for (size_t index = 0; index < result.items_count; ++index) {
        const ProRevocationItem& src = cpp.items[index];
        session_pro_backend_pro_revocation_item& dest = result.items[index];
        std::memcpy(dest.revocation_tag.data, src.revocation_tag.data(), src.revocation_tag.size());
        dest.effective_ts = session::epoch_seconds(src.effective_unix_ts);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_get_pro_details_response
session_pro_backend_get_pro_details_response_parse(const char* json, size_t json_len) {
    session_pro_backend_get_pro_details_response result = {};
    if (!json) {
        result.header.status = 1;
        result.header.errors = &C_PARSE_ERROR_INVALID_ARGS;
        result.header.errors_count = 1;
        return result;
    }

    // Note, parse is written to not throw so we can safely read without try-catch crap
    auto cpp = parse_payment_details({json, json_len});

    // Calculate how much memory we need and create an arena
    arena_t arena = {};
    {
        arena.max += cpp.items.size() * sizeof(*result.items);
        for (auto it : cpp.errors)
            arena.max += sizeof(*result.header.errors) + (it.size() + 1 /*null-terminator*/);

        if (arena.max)
            arena.data = static_cast<uint8_t*>(calloc(1, arena.max));

        if (arena.max && !arena.data) {
            result.header.status = 1;
            result.header.errors = &C_PARSE_ERROR_OUT_OF_MEMORY;
            result.header.errors_count = 1;
            return result;
        }

        // Store the pointer to the backing memory. Upon freeing, we release this one pointer
        result.header.internal_arena_buf_ = arena.data;
    }

    using session::epoch_seconds;

    // Copy to C struct, this is guaranteed not to fail because we pre-allocated memory upfront.
    result.header.status = cpp.status;
    result.status = cpp.user_status;
    result.error_report = cpp.error_report;
    result.items_count = cpp.items.size();
    result.items = (session_pro_backend_pro_payment_item*)arena_alloc(
            &arena, result.items_count * sizeof(*result.items));
    result.auto_renewing = cpp.auto_renewing;
    result.expiry_ts = epoch_seconds(cpp.expiry_unix_ts);
    result.grace_period_duration = cpp.grace_period_duration.count();
    result.refund_requested_ts = epoch_seconds(cpp.refund_requested_unix_ts);
    result.payments_total = cpp.payments_total;

    for (size_t index = 0; index < result.items_count; ++index) {
        const ProPaymentItem& src = cpp.items[index];
        session_pro_backend_pro_payment_item& dest = result.items[index];
        dest.status = src.status;
        dest.plan_count = snprintf_clamped(dest.plan, sizeof(dest.plan), "%s", src.plan.c_str());
        dest.payment_provider_count = snprintf_clamped(
                dest.payment_provider,
                sizeof(dest.payment_provider),
                "%s",
                src.payment_provider.c_str());
        dest.purchased_ts = epoch_seconds_double(src.purchased_unix_ts);
        dest.redeemed_ts = epoch_seconds(src.redeemed_unix_ts);
        dest.expiry_ts = epoch_seconds(src.expiry_unix_ts);
        dest.grace_period_duration = src.grace_period_duration.count();
        dest.platform_refund_expiry_ts = epoch_seconds(src.platform_refund_expiry_unix_ts);
        dest.revoked_ts = epoch_seconds_double(src.revoked_unix_ts);
        dest.refund_requested_ts = epoch_seconds(src.refund_requested_unix_ts);

        dest.payment_id_count = snprintf_clamped(
                dest.payment_id, sizeof(dest.payment_id), "%s", src.payment_id.c_str());
    }

    // Copy errors
    result.header.errors_count = cpp.errors.size();
    result.header.errors = (string8*)arena_alloc(
            &arena, result.header.errors_count * sizeof(*result.header.errors));
    for (size_t index = 0; index < cpp.errors.size(); index++) {
        const std::string& it = cpp.errors[index];
        result.header.errors[index] = arena_alloc_to_string8(&arena, it.data(), it.size());
    }

    return result;
}

LIBSESSION_C_API
session_pro_backend_signature session_pro_backend_set_payment_refund_requested_request_build_sigs(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        int64_t refund_requested_ts,
        const char* payment_tx_provider_code,
        const uint8_t* payment_tx_payment_id,
        size_t payment_tx_payment_id_len) {
    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span{master_privkey, master_privkey_len};
    std::chrono::sys_seconds unix_ts = session::as_sys_seconds(ts);
    std::chrono::sys_seconds refund_requested_unix_ts =
            session::as_sys_seconds(refund_requested_ts);
    std::span<const uint8_t> payment_tx_payment_id_span(
            payment_tx_payment_id, payment_tx_payment_id_len);

    session_pro_backend_signature result = {};
    try {
        auto sig = refund_sig(
                master_span,
                unix_ts,
                refund_requested_unix_ts,
                payment_tx_provider_code,
                payment_tx_payment_id_span);
        std::memcpy(result.sig.data, sig.data(), sig.size());
        result.success = true;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error_count),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_to_json
session_pro_backend_set_payment_refund_requested_request_to_json(
        const session_pro_backend_set_payment_refund_requested_request* request) {
    session_pro_backend_to_json result = {};
    if (!request)
        return result;

    try {
        std::string json = refund_body(
                {request->master_pkey.data, sizeof(request->master_pkey.data)},
                session::as_sys_seconds(request->ts),
                session::as_sys_seconds(request->refund_requested_ts),
                {request->payment_tx.provider_code, request->payment_tx.provider_code_count},
                {request->payment_tx.payment_id, request->payment_tx.payment_id_count},
                {request->master_sig.data, sizeof(request->master_sig.data)});
        result.json = session::string8_copy_or_throw(json.data(), json.size());
        result.success = true;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error_count),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }

    return result;
}

LIBSESSION_C_API session_pro_backend_set_payment_refund_requested_response
session_pro_backend_set_payment_refund_requested_response_parse(const char* json, size_t json_len) {
    session_pro_backend_set_payment_refund_requested_response result = {};
    if (!json) {
        result.header.status = 1;
        result.header.errors = &C_PARSE_ERROR_INVALID_ARGS;
        result.header.errors_count = 1;
        return result;
    }

    // Note, parse is written to not throw so we can safely read without try-catch crap
    auto cpp = parse_refund({json, json_len});

    // Calculate how much memory we need and create an arena
    arena_t arena = {};
    {
        for (auto it : cpp.errors)
            arena.max += sizeof(*result.header.errors) + (it.size() + 1 /*null-terminator*/);

        if (arena.max)
            arena.data = static_cast<uint8_t*>(calloc(1, arena.max));

        if (arena.max && !arena.data) {
            result.header.status = 1;
            result.header.errors = &C_PARSE_ERROR_OUT_OF_MEMORY;
            result.header.errors_count = 1;
            return result;
        }

        // Store the pointer to the backing memory. Upon freeing, we release this one pointer
        result.header.internal_arena_buf_ = arena.data;
    }

    // Copy to C struct
    result.header.status = cpp.status;
    result.updated = cpp.updated;

    // Copy errors
    result.header.errors_count = cpp.errors.size();
    result.header.errors = (string8*)arena_alloc(
            &arena, result.header.errors_count * sizeof(*result.header.errors));
    for (size_t index = 0; index < cpp.errors.size(); index++) {
        const std::string& it = cpp.errors[index];
        result.header.errors[index] = arena_alloc_to_string8(&arena, it.data(), it.size());
    }

    return result;
}

LIBSESSION_C_API void session_pro_backend_to_json_free(session_pro_backend_to_json* to_json) {
    if (to_json) {
        free(to_json->json.data);
        *to_json = {};
    }
}

LIBSESSION_C_API void session_pro_backend_pro_proof_response_free(
        session_pro_backend_pro_proof_response* response) {
    if (response) {
        free(response->header.internal_arena_buf_);
        *response = {};
    }
}

LIBSESSION_C_API void session_pro_backend_get_pro_revocations_response_free(
        session_pro_backend_get_pro_revocations_response* response) {
    if (response) {
        free(response->header.internal_arena_buf_);
        *response = {};
    }
}

LIBSESSION_C_API void session_pro_backend_get_pro_details_response_free(
        session_pro_backend_get_pro_details_response* response) {
    if (response) {
        free(response->header.internal_arena_buf_);
        *response = {};
    }
}

LIBSESSION_C_API void session_pro_backend_set_payment_refund_requested_response_free(
        session_pro_backend_set_payment_refund_requested_response* response) {
    if (response) {
        free(response->header.internal_arena_buf_);
        *response = {};
    }
}
