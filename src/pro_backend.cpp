#include <fmt/core.h>
#include <oxenc/hex.h>
#include <session/export.h>
#include <session/pro_backend.h>
#include <sodium/crypto_sign_ed25519.h>

#include <chrono>
#include <concepts>
#include <nlohmann/json.hpp>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/sodium_array.hpp>
#include <session/types.hpp>
#include <session/util.hpp>

#include "pro_message.hpp"

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

    // Content type for the request payload (single master storage, shared with the C API's
    // session_pro_backend_request.content_type). The wire encoding is libsession's to change; the
    // content type travels alongside the payload so clients never hardcode a format.
    constexpr char application_json[] = "application/json";

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
    std::span<const uint8_t, 32> pubkey_of(const cleared_uc64& priv64) {
        return std::span<const uint8_t, 32>(
                priv64.data() + crypto_sign_ed25519_SEEDBYTES, crypto_sign_ed25519_PUBLICKEYBYTES);
    }

    // --- add-payment (endpoint add_pro_payment) ---

    std::vector<unsigned char> add_payment_message(
            std::span<const uint8_t, 32> master_pubkey,
            std::span<const uint8_t, 32> rotating_pubkey,
            std::string_view provider_code,
            std::span<const uint8_t> payment_id) {
        // Must match the add-payment signed-request message in pro-wire-protocol.md §3.2
        // (+ §3.5), built per §1.1.
        return session::pro::signed_message(
                session::ADD_PRO_PAYMENT_DOMAIN,
                master_pubkey,
                rotating_pubkey,
                provider_code,
                to_string_view(payment_id));
    }

    MasterRotatingSignatures add_payment_sign(
            const cleared_uc64& master,
            const cleared_uc64& rotating,
            std::string_view provider_code,
            std::span<const uint8_t> payment_id) {
        auto msg = add_payment_message(
                pubkey_of(master), pubkey_of(rotating), provider_code, payment_id);
        MasterRotatingSignatures result = {};
        crypto_sign_ed25519_detached(
                result.master_sig.data(), nullptr, msg.data(), msg.size(), master.data());
        crypto_sign_ed25519_detached(
                result.rotating_sig.data(), nullptr, msg.data(), msg.size(), rotating.data());
        return result;
    }

    // Serialise an add-payment request body from already-computed fields (shared by the C++
    // add_payment_request and the C ..._request_build wrapper).
    std::string add_payment_body(
            std::span<const uint8_t, 32> master_pubkey,
            std::span<const uint8_t, 32> rotating_pubkey,
            std::string_view provider_code,
            std::string_view payment_id,
            std::span<const uint8_t, 64> master_sig,
            std::span<const uint8_t, 64> rotating_sig) {
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

// Backend base URL + Ed25519 pubkey: C symbols pointing at the single C++ definitions above.
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_URL = URL.data();
LIBSESSION_EXPORT extern const unsigned char* const SESSION_PRO_BACKEND_PUBKEY = PUBKEY.data();
LIBSESSION_EXPORT extern const unsigned char* const SESSION_PRO_BACKEND_PUBKEY_X25519 =
        PUBKEY_X25519.data();
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
            application_json,
            add_payment_body(
                    pubkey_of(master),
                    pubkey_of(rotating),
                    provider_code,
                    to_string_view(payment_id),
                    sigs.master_sig,
                    sigs.rotating_sig)};
}

namespace {
    // libsession-side slug when the backend's reply can't be parsed at all (malformed envelope,
    // missing/unrecognized status). Distinct from any backend error_code slug.
    constexpr std::string_view invalid_response_code = "invalid_response";

    // Put a ResponseBase into a protocol-error state (a libsession-side parse failure, distinct
    // from a backend-reported fail/error).
    void set_protocol_error(ResponseBase& result, std::string message) {
        result.status = ResponseStatus::Error;
        result.error_code = std::string(invalid_response_code);
        result.error = std::move(message);
    }

    // Read the response envelope (spec §5) into `result`: string `status` -> ResponseStatus (a
    // CLOSED set -- an unrecognized value is a protocol error, never passed through) and, on
    // non-ok, `error_code` + `error`. Returns the `result` object to read the payload from when
    // status is "ok" (an empty object otherwise; the caller returns early). libsession-side parse
    // problems accumulate in `errs` for the caller to fold into a protocol error.
    nlohmann::json::object_t read_envelope(
            std::string_view json, ResponseBase& result, std::vector<std::string>& errs) {
        nlohmann::json j = json_parse(json, errs);
        auto status = json_require<std::string>(j, "status", errs);
        if (!errs.empty())
            return {};
        if (status == "ok") {
            result.status = ResponseStatus::Ok;
            return json_require<nlohmann::json::object_t>(j, "result", errs);
        }
        if (status == "fail" || status == "error") {
            result.status = status == "fail" ? ResponseStatus::Fail : ResponseStatus::Error;
            result.error_code = json_require<std::string>(j, "error_code", errs);
            result.error = json_require<std::string>(j, "error", errs);
            return {};
        }
        errs.push_back(fmt::format("Unrecognized response status: '{}'", status));
        return {};
    }

    // Fills the common proof payload (add-payment and generate-proof both reply with exactly a
    // proof) from the already-extracted `result` object.
    void fill_proof(
            const nlohmann::json::object_t& result_obj,
            ProProofResponse& result,
            std::vector<std::string>& errs) {
        result.proof.version = json_require<uint8_t>(result_obj, "version", errs);
        auto expiry_ts = json_require<int64_t>(result_obj, "expiry_ts", errs);
        result.proof.expiry_at = std::chrono::sys_seconds(std::chrono::seconds(expiry_ts));
        json_require_fixed_bytes_from_hex(
                result_obj, "revocation_tag", errs, result.proof.revocation_tag);
        json_require_fixed_bytes_from_hex(
                result_obj, "rotating_pkey", errs, result.proof.rotating_pubkey);
        json_require_fixed_bytes_from_hex(result_obj, "sig", errs, result.proof.sig);
    }
}  // namespace

AddProPaymentResponse parse_add_payment(std::string_view json) {
    AddProPaymentResponse result = {};
    std::vector<std::string> errs;
    auto result_obj = read_envelope(json, result, errs);
    if (!result || !errs.empty()) {
        if (!errs.empty())
            set_protocol_error(result, errs.front());
        return result;
    }
    fill_proof(result_obj, result, errs);
    if (!errs.empty())
        set_protocol_error(result, errs.front());
    return result;
}

GenerateProProofResponse parse_pro_proof(std::string_view json) {
    GenerateProProofResponse result = {};
    std::vector<std::string> errs;
    auto result_obj = read_envelope(json, result, errs);
    if (!result || !errs.empty()) {
        if (!errs.empty())
            set_protocol_error(result, errs.front());
        return result;
    }
    fill_proof(result_obj, result, errs);
    if (!errs.empty())
        set_protocol_error(result, errs.front());
    return result;
}

namespace {

    // --- generate-proof (endpoint generate_pro_proof) ---

    std::vector<unsigned char> generate_proof_message(
            std::span<const uint8_t, 32> master_pubkey,
            std::span<const uint8_t, 32> rotating_pubkey,
            std::chrono::sys_seconds unix_ts) {
        // Must match the generate-proof signed-request message in pro-wire-protocol.md §3.1,
        // built per §1.1.
        return session::pro::signed_message(
                session::GENERATE_PROOF_DOMAIN,
                master_pubkey,
                rotating_pubkey,
                epoch_seconds(unix_ts));
    }

    MasterRotatingSignatures generate_proof_sign(
            const cleared_uc64& master,
            const cleared_uc64& rotating,
            std::chrono::sys_seconds unix_ts) {
        auto msg = generate_proof_message(pubkey_of(master), pubkey_of(rotating), unix_ts);
        MasterRotatingSignatures result = {};
        crypto_sign_ed25519_detached(
                result.master_sig.data(), nullptr, msg.data(), msg.size(), master.data());
        crypto_sign_ed25519_detached(
                result.rotating_sig.data(), nullptr, msg.data(), msg.size(), rotating.data());
        return result;
    }

    std::string generate_proof_body(
            std::span<const uint8_t, 32> master_pubkey,
            std::span<const uint8_t, 32> rotating_pubkey,
            std::chrono::sys_seconds unix_ts,
            std::span<const uint8_t, 64> master_sig,
            std::span<const uint8_t, 64> rotating_sig) {
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
            application_json,
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
    return {get_pro_revocations_endpoint, application_json, j.dump()};
}

GetProRevocationsResponse parse_revocations(std::string_view json) {
    GetProRevocationsResponse result = {};
    std::vector<std::string> errs;
    auto result_obj = read_envelope(json, result, errs);
    if (!result || !errs.empty()) {
        if (!errs.empty())
            set_protocol_error(result, errs.front());
        return result;
    }

    // Parse payload
    result.ticket = json_require<int64_t>(result_obj, "ticket", errs);
    result.retry_in = std::chrono::seconds(json_require<int64_t>(result_obj, "retry_in", errs));
    result.retain_for = std::chrono::seconds(json_require<int64_t>(result_obj, "retain_for", errs));

    auto array = json_require<nlohmann::json::array_t>(result_obj, "items", errs);
    result.items.reserve(array.size());
    for (size_t index = 0; index < array.size(); index++) {
        const auto& it = array[index];
        if (!it.is_object()) {
            errs.push_back(fmt::format(
                    "Aborting parse, 'items[{}]' was not an object: {}", index, it.dump(1)));
            break;
        }

        // Parse revocation item
        auto obj = it.get<nlohmann::json::object_t>();
        auto effective_ts = json_require<int64_t>(obj, "effective_ts", errs);

        ProRevocationItem item = {};
        item.effective_at = as_sys_seconds(effective_ts);
        json_require_fixed_bytes_from_hex(obj, "revocation_tag", errs, item.revocation_tag);

        // Handle parsing result
        if (errs.size())
            break;
        result.items.emplace_back(std::move(item));
    }

    if (!errs.empty())
        set_protocol_error(result, errs.front());
    return result;
}

namespace {

    // --- payment-details / get-pro-details (endpoint get_pro_details) ---

    std::vector<unsigned char> payment_details_message(
            std::span<const uint8_t, 32> master_pubkey,
            std::chrono::sys_seconds unix_ts,
            int64_t count) {
        // Must match the get-pro-details signed-request message in pro-wire-protocol.md §3.4,
        // built per §1.1. `count` is a signed integer (a decimal-ASCII -1 requests "all").
        return session::pro::signed_message(
                session::GET_PRO_DETAILS_DOMAIN, master_pubkey, epoch_seconds(unix_ts), count);
    }

    array_uc64 payment_details_sign(
            const cleared_uc64& master, std::chrono::sys_seconds unix_ts, uint32_t count) {
        auto msg = payment_details_message(pubkey_of(master), unix_ts, count);
        array_uc64 sig = {};
        crypto_sign_ed25519_detached(sig.data(), nullptr, msg.data(), msg.size(), master.data());
        return sig;
    }

    std::string payment_details_body(
            std::span<const uint8_t, 32> master_pubkey,
            std::span<const uint8_t, 64> master_sig,
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
    return {get_pro_details_endpoint,
            application_json,
            payment_details_body(pubkey_of(master), sig, unix_ts, count)};
}

GetProDetailsResponse parse_payment_details(std::string_view json) {
    GetProDetailsResponse result = {};
    std::vector<std::string> errs;
    auto result_obj = read_envelope(json, result, errs);
    if (!result || !errs.empty()) {
        if (!errs.empty())
            set_protocol_error(result, errs.front());
        return result;
    }

    // Parse payload. The account Pro status is an opaque string code ("never"/"active"/"expired");
    // an unknown value passes through unchanged (§1: enums are codes) rather than failing the
    // parse. (Wire key `user_status`, disambiguated from the envelope `status` -- spec §5.2.)
    result.user_status = json_require<std::string>(result_obj, "user_status", errs);

    uint32_t error_report = json_require<uint32_t>(result_obj, "error_report", errs);
    if (error_report >= SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_COUNT) {
        errs.push_back(fmt::format("Error report value was out-of-bounds: {}", error_report));
        set_protocol_error(result, errs.front());
        return result;
    }
    result.error_report =
            static_cast<SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT>(error_report);

    result.auto_renewing = json_require<bool>(result_obj, "auto_renewing", errs);

    result.payments_total = json_require<uint32_t>(result_obj, "payments_total", errs);

    result.expiry_at = std::chrono::sys_seconds(
            std::chrono::seconds(json_require<int64_t>(result_obj, "expiry_ts", errs)));
    result.grace_period_duration =
            std::chrono::seconds(json_require<int64_t>(result_obj, "grace_period_duration", errs));
    result.refund_requested_at = std::chrono::sys_seconds(
            std::chrono::seconds(json_require<int64_t>(result_obj, "refund_requested_ts", errs)));

    auto array = json_require<nlohmann::json::array_t>(result_obj, "items", errs);
    result.items.reserve(array.size());
    for (size_t index = 0; index < array.size(); index++) {
        const auto& it = array[index];
        if (!it.is_object()) {
            errs.push_back(fmt::format(
                    "Aborting parse, 'items[{}]' was not an object: {}", index, it.dump(1)));
            break;
        }

        // Parse payment item
        auto obj = it.get<nlohmann::json::object_t>();
        auto status = json_require<std::string>(obj, "status", errs);
        auto plan = json_require<std::string>(obj, "plan", errs);
        auto payment_provider = json_require<std::string>(obj, "payment_provider", errs);
        auto payment_id = json_require<std::string>(obj, "payment_id", errs);
        auto auto_renewing = json_require<bool>(obj, "auto_renewing", errs);
        // purchased_ts and revoked_ts are upstream-provider event instants: floats on the wire
        // carrying sub-second precision (kept as millisecond-precision sys_ms). All other
        // timestamps are whole-second integers.
        auto purchased_ts = json_require_number(obj, "purchased_ts", errs);
        auto redeemed_ts = json_require<int64_t>(obj, "redeemed_ts", errs);
        auto expiry_ts = json_require<int64_t>(obj, "expiry_ts", errs);
        auto grace_period_duration = json_require<int64_t>(obj, "grace_period_duration", errs);
        auto platform_refund_expiry_ts =
                json_require<int64_t>(obj, "platform_refund_expiry_ts", errs);
        auto revoked_ts = json_require_number(obj, "revoked_ts", errs);
        auto refund_requested_ts = json_require<int64_t>(obj, "refund_requested_ts", errs);

        ProPaymentItem item = {};
        item.status = std::move(status);
        item.plan = std::move(plan);
        item.payment_provider = std::move(payment_provider);
        item.payment_id = std::move(payment_id);

        item.auto_renewing = auto_renewing;
        item.purchased_at = sys_ms_from_seconds(purchased_ts);
        item.redeemed_at = std::chrono::sys_seconds(std::chrono::seconds(redeemed_ts));
        item.expiry_at = std::chrono::sys_seconds(std::chrono::seconds(expiry_ts));
        item.grace_period_duration = std::chrono::seconds(grace_period_duration);
        item.platform_refund_expiry_at =
                std::chrono::sys_seconds(std::chrono::seconds(platform_refund_expiry_ts));
        item.revoked_at = sys_ms_from_seconds(revoked_ts);
        item.refund_requested_at =
                std::chrono::sys_seconds(std::chrono::seconds(refund_requested_ts));

        // Handle parsing result
        if (errs.size())
            break;

        result.items.emplace_back(std::move(item));
    }

    if (!errs.empty())
        set_protocol_error(result, errs.front());
    return result;
}

namespace {

    // --- refund / set-payment-refund-requested (endpoint set_payment_refund_requested) ---

    std::vector<unsigned char> refund_message(
            std::span<const uint8_t, 32> master_pubkey,
            std::chrono::sys_seconds unix_ts,
            std::chrono::sys_seconds refund_requested_at,
            std::string_view provider_code,
            std::span<const uint8_t> payment_id) {
        // Must match the set-payment-refund-requested signed-request message in
        // pro-wire-protocol.md §3.3 (+ §3.5 for payment_id), built per §1.1.
        return session::pro::signed_message(
                session::SET_PAYMENT_REFUND_REQUESTED_DOMAIN,
                master_pubkey,
                epoch_seconds(unix_ts),
                epoch_seconds(refund_requested_at),
                provider_code,
                to_string_view(payment_id));
    }

    array_uc64 refund_sign(
            const cleared_uc64& master,
            std::chrono::sys_seconds unix_ts,
            std::chrono::sys_seconds refund_requested_at,
            std::string_view provider_code,
            std::span<const uint8_t> payment_id) {
        auto msg = refund_message(
                pubkey_of(master), unix_ts, refund_requested_at, provider_code, payment_id);
        array_uc64 sig = {};
        crypto_sign_ed25519_detached(sig.data(), nullptr, msg.data(), msg.size(), master.data());
        return sig;
    }

    std::string refund_body(
            std::span<const uint8_t, 32> master_pubkey,
            std::chrono::sys_seconds unix_ts,
            std::chrono::sys_seconds refund_requested_at,
            std::string_view provider_code,
            std::string_view payment_id,
            std::span<const uint8_t, 64> master_sig) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"ts", epoch_seconds(unix_ts)},
                {"refund_requested_ts", epoch_seconds(refund_requested_at)},
                {"payment_tx", {{"provider", provider_code}, {"payment_id", payment_id}}},
                {"master_sig", oxenc::to_hex(master_sig)}}
                .dump();
    }

}  // namespace

array_uc64 refund_sig(
        std::span<const uint8_t> master_privkey,
        std::chrono::sys_seconds unix_ts,
        std::chrono::sys_seconds refund_requested_at,
        std::string_view provider_code,
        std::span<const uint8_t> payment_id) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    return refund_sign(master, unix_ts, refund_requested_at, provider_code, payment_id);
}

ProRequest refund_request(
        std::span<const uint8_t> master_privkey,
        std::chrono::sys_seconds unix_ts,
        std::chrono::sys_seconds refund_requested_at,
        std::string_view provider_code,
        std::span<const uint8_t> payment_id) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    auto sig = refund_sign(master, unix_ts, refund_requested_at, provider_code, payment_id);
    return {set_refund_endpoint,
            application_json,
            refund_body(
                    pubkey_of(master),
                    unix_ts,
                    refund_requested_at,
                    provider_code,
                    to_string_view(payment_id),
                    sig)};
}

SetPaymentRefundRequestedResponse parse_refund(std::string_view json) {
    SetPaymentRefundRequestedResponse result = {};
    std::vector<std::string> errs;
    auto result_obj = read_envelope(json, result, errs);
    if (!result || !errs.empty()) {
        if (!errs.empty())
            set_protocol_error(result, errs.front());
        return result;
    }

    result.updated = json_require<bool>(result_obj, "updated", errs);
    if (!errs.empty())
        set_protocol_error(result, errs.front());
    return result;
}
}  // namespace session::pro_backend

using namespace session::pro_backend;

/// Define a string8 from a c-string literal. The string should not be modified as it'll live in the
/// data-section of the binary (or be interned, e.t.c)
#define STRING8_LIT(val) {(char*)val, sizeof(val) - 1}

static string8 C_PARSE_ERROR_OUT_OF_MEMORY = STRING8_LIT("Ran out-of-memory creating C response");
static string8 C_PARSE_ERROR_INVALID_ARGS = STRING8_LIT("One or more C arguments were NULL");
// error_code slug libsession reports when it can't parse/build the C response at all.
static string8 C_INVALID_RESPONSE_CODE = STRING8_LIT("invalid_response");

// Map the C++ ResponseStatus to the C enum.
static SESSION_PRO_BACKEND_RESPONSE_STATUS c_response_status(ResponseStatus status) {
    switch (status) {
        case ResponseStatus::Ok: return SESSION_PRO_BACKEND_RESPONSE_STATUS_OK;
        case ResponseStatus::Fail: return SESSION_PRO_BACKEND_RESPONSE_STATUS_FAIL;
        case ResponseStatus::Error: break;
    }
    return SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
}

// Arena bytes needed for a header's error_code + error strings.
static size_t c_header_arena_bytes(const ResponseBase& cpp) {
    size_t n = 0;
    if (cpp.error_code)
        n += cpp.error_code->size() + 1;
    if (cpp.error)
        n += cpp.error->size() + 1;
    return n;
}

// Fill a C response header's status + error_code/error from a C++ ResponseBase, copying the two
// optional strings into the arena (which must already have room; see c_header_arena_bytes).
static void fill_c_header(
        session_pro_backend_response_header& header, const ResponseBase& cpp, arena_t& arena) {
    header.status = c_response_status(cpp.status);
    header.error_code =
            cpp.error_code
                    ? arena_alloc_to_string8(&arena, cpp.error_code->data(), cpp.error_code->size())
                    : string8{};
    header.error = cpp.error ? arena_alloc_to_string8(&arena, cpp.error->data(), cpp.error->size())
                             : string8{};
}

// Wrap a freshly-built C++ ProRequest as an owning C session_pro_backend_request: heap-own the
// ProRequest and point endpoint/content_type/data into it (zero copy). Released by
// session_pro_backend_request_free.
static session_pro_backend_request c_own_request(ProRequest&& req) {
    auto* owned = new ProRequest(std::move(req));
    session_pro_backend_request result = {};
    result.internal_ = owned;
    result.endpoint = owned->endpoint.data();
    result.content_type = owned->content_type.data();
    result.data = string8{owned->data.data(), owned->data.size()};
    result.success = true;
    return result;
}

// Fill a session_pro_backend_request's error buffer from a caught exception.
static void c_request_error(session_pro_backend_request& result, const std::exception& e) {
    const std::string& error = e.what();
    result.error_count = snprintf_clamped(
            result.error,
            sizeof(result.error),
            "%.*s",
            static_cast<int>(error.size()),
            error.data());
}

LIBSESSION_C_API session_pro_backend_request session_pro_backend_add_pro_payment_request_build(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        const char* provider_code,
        const uint8_t* payment_id,
        size_t payment_id_len) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(add_payment_request(
                {master_privkey, master_privkey_len},
                {rotating_privkey, rotating_privkey_len},
                provider_code,
                {payment_id, payment_id_len}));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_request session_pro_backend_generate_pro_proof_request_build(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        int64_t ts) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(pro_proof_request(
                {master_privkey, master_privkey_len},
                {rotating_privkey, rotating_privkey_len},
                session::as_sys_seconds(ts)));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_request
session_pro_backend_get_pro_revocations_request_build(int64_t ticket) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(revocations_request(ticket));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_request session_pro_backend_get_pro_details_request_build(
        const uint8_t* master_privkey, size_t master_privkey_len, int64_t ts, uint32_t count) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(payment_details_request(
                {master_privkey, master_privkey_len}, session::as_sys_seconds(ts), count));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_pro_proof_response
session_pro_backend_pro_proof_response_parse(const char* json, size_t json_len) {

    session_pro_backend_pro_proof_response result = {};
    if (!json) {
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_INVALID_ARGS;
        return result;
    }

    // Note, parse is written to not throw so we can safely read without try-catch crap
    // add-payment and generate-proof share the proof-response shape; the C response struct is
    // generic, so either derived parser works here.
    auto cpp = parse_add_payment({json, json_len});

    // Calculate how much memory we need and create an arena
    arena_t arena = {};
    {
        arena.max += c_header_arena_bytes(cpp);

        if (arena.max)
            arena.data = static_cast<uint8_t*>(calloc(1, arena.max));

        if (arena.max && !arena.data) {
            result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
            result.header.error_code = C_INVALID_RESPONSE_CODE;
            result.header.error = C_PARSE_ERROR_OUT_OF_MEMORY;
            return result;
        }

        // Store the pointer to the backing memory. Upon freeing, we release this one pointer
        result.header.internal_arena_buf_ = arena.data;
    }

    // Copy to C struct, this is guaranteed not to fail because we pre-allocated memory upfront.
    // Note that a response error and success case folds into the same code path. A success and
    // error response returns the same struct just with different fields populated.
    result.proof.version = cpp.proof.version;
    result.proof.expiry_ts = session::epoch_seconds(cpp.proof.expiry_at);
    std::memcpy(
            result.proof.revocation_tag.data,
            cpp.proof.revocation_tag.data(),
            cpp.proof.revocation_tag.size());
    std::memcpy(
            result.proof.rotating_pubkey.data,
            cpp.proof.rotating_pubkey.data(),
            cpp.proof.rotating_pubkey.size());
    std::memcpy(result.proof.sig.data, cpp.proof.sig.data(), cpp.proof.sig.size());

    // Copy status + error code/message
    fill_c_header(result.header, cpp, arena);
    return result;
}

LIBSESSION_C_API session_pro_backend_get_pro_revocations_response
session_pro_backend_get_pro_revocations_response_parse(const char* json, size_t json_len) {
    session_pro_backend_get_pro_revocations_response result = {};
    if (!json) {
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_INVALID_ARGS;
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
        arena.max += c_header_arena_bytes(cpp);

        if (arena.max)
            arena.data = static_cast<uint8_t*>(calloc(1, arena.max));

        if (arena.max && !arena.data) {
            result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
            result.header.error_code = C_INVALID_RESPONSE_CODE;
            result.header.error = C_PARSE_ERROR_OUT_OF_MEMORY;
            return result;
        }

        // Store the pointer to the backing memory. Upon freeing, we release this one pointer
        result.header.internal_arena_buf_ = arena.data;
    }

    // Copy to C struct, this is guaranteed not to fail because we pre-allocated memory upfront.
    result.ticket = cpp.ticket;
    result.retry_in = cpp.retry_in.count();
    result.retain_for = cpp.retain_for.count();

    // Copy status + error code/message
    fill_c_header(result.header, cpp, arena);

    // Copy items
    result.items_count = cpp.items.size();
    result.items = static_cast<session_pro_backend_pro_revocation_item*>(
            arena_alloc(&arena, result.items_count * sizeof(*result.items)));

    for (size_t index = 0; index < result.items_count; ++index) {
        const ProRevocationItem& src = cpp.items[index];
        session_pro_backend_pro_revocation_item& dest = result.items[index];
        std::memcpy(dest.revocation_tag.data, src.revocation_tag.data(), src.revocation_tag.size());
        dest.effective_ts = session::epoch_seconds(src.effective_at);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_get_pro_details_response
session_pro_backend_get_pro_details_response_parse(const char* json, size_t json_len) {
    session_pro_backend_get_pro_details_response result = {};
    if (!json) {
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_INVALID_ARGS;
        return result;
    }

    // Note, parse is written to not throw so we can safely read without try-catch crap
    auto cpp = parse_payment_details({json, json_len});

    // Calculate how much memory we need and create an arena
    arena_t arena = {};
    {
        arena.max += cpp.items.size() * sizeof(*result.items);
        arena.max += c_header_arena_bytes(cpp);

        if (arena.max)
            arena.data = static_cast<uint8_t*>(calloc(1, arena.max));

        if (arena.max && !arena.data) {
            result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
            result.header.error_code = C_INVALID_RESPONSE_CODE;
            result.header.error = C_PARSE_ERROR_OUT_OF_MEMORY;
            return result;
        }

        // Store the pointer to the backing memory. Upon freeing, we release this one pointer
        result.header.internal_arena_buf_ = arena.data;
    }

    using session::epoch_seconds;

    // Copy to C struct, this is guaranteed not to fail because we pre-allocated memory upfront.
    result.status_count =
            snprintf_clamped(result.status, sizeof(result.status), "%s", cpp.user_status.c_str());
    result.error_report = cpp.error_report;
    result.items_count = cpp.items.size();
    result.items = (session_pro_backend_pro_payment_item*)arena_alloc(
            &arena, result.items_count * sizeof(*result.items));
    result.auto_renewing = cpp.auto_renewing;
    result.expiry_ts = epoch_seconds(cpp.expiry_at);
    result.grace_period_duration = cpp.grace_period_duration.count();
    result.refund_requested_ts = epoch_seconds(cpp.refund_requested_at);
    result.payments_total = cpp.payments_total;

    for (size_t index = 0; index < result.items_count; ++index) {
        const ProPaymentItem& src = cpp.items[index];
        session_pro_backend_pro_payment_item& dest = result.items[index];
        dest.status_count =
                snprintf_clamped(dest.status, sizeof(dest.status), "%s", src.status.c_str());
        dest.plan_count = snprintf_clamped(dest.plan, sizeof(dest.plan), "%s", src.plan.c_str());
        dest.payment_provider_count = snprintf_clamped(
                dest.payment_provider,
                sizeof(dest.payment_provider),
                "%s",
                src.payment_provider.c_str());
        dest.purchased_ts = epoch_seconds_double(src.purchased_at);
        dest.redeemed_ts = epoch_seconds(src.redeemed_at);
        dest.expiry_ts = epoch_seconds(src.expiry_at);
        dest.grace_period_duration = src.grace_period_duration.count();
        dest.platform_refund_expiry_ts = epoch_seconds(src.platform_refund_expiry_at);
        dest.revoked_ts = epoch_seconds_double(src.revoked_at);
        dest.refund_requested_ts = epoch_seconds(src.refund_requested_at);

        dest.payment_id_count = snprintf_clamped(
                dest.payment_id, sizeof(dest.payment_id), "%s", src.payment_id.c_str());
    }

    // Copy status + error code/message
    fill_c_header(result.header, cpp, arena);

    return result;
}

LIBSESSION_C_API session_pro_backend_request
session_pro_backend_set_payment_refund_requested_request_build(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        int64_t refund_requested_ts,
        const char* provider_code,
        const uint8_t* payment_id,
        size_t payment_id_len) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(refund_request(
                {master_privkey, master_privkey_len},
                session::as_sys_seconds(ts),
                session::as_sys_seconds(refund_requested_ts),
                provider_code,
                {payment_id, payment_id_len}));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_set_payment_refund_requested_response
session_pro_backend_set_payment_refund_requested_response_parse(const char* json, size_t json_len) {
    session_pro_backend_set_payment_refund_requested_response result = {};
    if (!json) {
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_INVALID_ARGS;
        return result;
    }

    // Note, parse is written to not throw so we can safely read without try-catch crap
    auto cpp = parse_refund({json, json_len});

    // Calculate how much memory we need and create an arena
    arena_t arena = {};
    {
        arena.max += c_header_arena_bytes(cpp);

        if (arena.max)
            arena.data = static_cast<uint8_t*>(calloc(1, arena.max));

        if (arena.max && !arena.data) {
            result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
            result.header.error_code = C_INVALID_RESPONSE_CODE;
            result.header.error = C_PARSE_ERROR_OUT_OF_MEMORY;
            return result;
        }

        // Store the pointer to the backing memory. Upon freeing, we release this one pointer
        result.header.internal_arena_buf_ = arena.data;
    }

    // Copy to C struct
    result.updated = cpp.updated;

    // Copy status + error code/message
    fill_c_header(result.header, cpp, arena);

    return result;
}

LIBSESSION_C_API void session_pro_backend_request_free(session_pro_backend_request* request) {
    if (request) {
        if (request->internal_)
            delete static_cast<ProRequest*>(request->internal_);
        *request = {};
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
