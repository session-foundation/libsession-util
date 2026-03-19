#include <fmt/core.h>
#include <oxenc/hex.h>
#include <session/export.h>
#include <session/pro_backend.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include <chrono>
#include <nlohmann/json.hpp>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/sodium_array.hpp>
#include <session/types.hpp>

// clang-format off
const session_pro_backend_payment_provider_metadata SESSION_PRO_BACKEND_PAYMENT_PROVIDER_METADATA[SESSION_PRO_BACKEND_PAYMENT_PROVIDER_COUNT] = {
    /*SESSION_PRO_PAYMENT_PROVIDER_NIL*/ {
        .device                             = string8_literal(""),
        .store                              = string8_literal(""),
        .platform                           = string8_literal(""),
        .platform_account                   = string8_literal(""),
        .refund_platform_url                = string8_literal(""),
        .refund_support_url                 = string8_literal(""),
        .refund_status_url                  = string8_literal(""),
        .update_subscription_url            = string8_literal(""),
        .cancel_subscription_url            = string8_literal(""),
    },
    /*SESSION_PRO_PAYMENT_PROVIDER_GOOGLE_PLAY_STORE*/ {
        .device                             = string8_literal("Android"),
        .store                              = string8_literal("Google Play Store"),
        .platform                           = string8_literal("Google"),
        .platform_account                   = string8_literal("Google account"),
        .refund_platform_url                = string8_literal("https://support.google.com/googleplay/workflow/9813244?"),
        .refund_support_url                 = string8_literal("https://getsession.org/android-refund"),
        .refund_status_url                  = string8_literal("https://getsession.org/android-refund"),
        .update_subscription_url            = string8_literal("https://play.google.com/store/account/subscriptions?package=network.loki.messenger"),
        .cancel_subscription_url            = string8_literal("https://play.google.com/store/account/subscriptions?package=network.loki.messenger"),
    },
    /*SESSION_PRO_PAYMENT_PROVIDER_IOS_APP_STORE*/ {
        .device                             = string8_literal("iOS"),
        .store                              = string8_literal("Apple App Store"),
        .platform                           = string8_literal("Apple"),
        .platform_account                   = string8_literal("Apple account"),
        .refund_platform_url                = string8_literal("https://support.apple.com/118223"),
        .refund_support_url                 = string8_literal("https://support.apple.com/118223"),
        .refund_status_url                  = string8_literal("https://support.apple.com/118224"),
        .update_subscription_url            = string8_literal("https://apps.apple.com/account/subscriptions"),
        .cancel_subscription_url            = string8_literal("https://account.apple.com/account/manage/section/subscriptions"),
    },
    /*SESSION_PRO_PAYMENT_PROVIDER_RANGEPROOF*/ {
        .device                             = string8_literal(""),
        .store                              = string8_literal(""),
        .platform                           = string8_literal(""),
        .platform_account                   = string8_literal(""),
        .refund_platform_url                = string8_literal(""),
        .refund_support_url                 = string8_literal(""),
        .refund_status_url                  = string8_literal(""),
        .update_subscription_url            = string8_literal(""),
        .cancel_subscription_url            = string8_literal(""),
    }
};

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
        std::string_view type = {};
        if constexpr (session::is_one_of<T, double, float>) {
            type = "a float";
            success = it->is_number_float();
        } else if constexpr (session::is_one_of<T, uint64_t, uint32_t, uint16_t, uint8_t>) {
            type = "a number";
            success = it->is_number();
        } else if constexpr (session::is_one_of<T, std::string, std::string_view>) {
            type = "a string";
            success = it->is_string();
        } else if constexpr (session::is_one_of<T, nlohmann::json::array_t>) {
            type = "an array";
            success = it->is_array();
        } else if constexpr (session::is_one_of<T, bool>) {
            type = "a boolean";
            success = it->is_boolean();
        } else {
            static_assert(session::is_one_of<T, nlohmann::json::object_t>);
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
std::string AddProPaymentRequest::to_json() const {
    nlohmann::json j;
    j["version"] = version;
    j["master_pkey"] = oxenc::to_hex(master_pkey);
    j["rotating_pkey"] = oxenc::to_hex(rotating_pkey);
    j["payment_tx"]["provider"] = payment_tx.provider;
    switch (payment_tx.provider) {
        case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_NIL: [[fallthrough]];
        case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_COUNT: break;
        case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_RANGEPROOF: {assert(false && "Unimplemented");} break;
        case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_GOOGLE_PLAY_STORE: {
            j["payment_tx"]["google_payment_token"] = payment_tx.payment_id;
            j["payment_tx"]["google_order_id"] = payment_tx.order_id;
        } break;
        case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_IOS_APP_STORE: {
            j["payment_tx"]["apple_tx_id"] = payment_tx.payment_id;
        } break;
    }
    j["master_sig"] = oxenc::to_hex(master_sig);
    j["rotating_sig"] = oxenc::to_hex(rotating_sig);
    std::string result = j.dump();
    return result;
}

MasterRotatingSignatures AddProPaymentRequest::build_sigs(
        std::uint8_t version,
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        std::span<const uint8_t> payment_tx_payment_id,
        std::span<const uint8_t> payment_tx_order_id) {
    cleared_uc64 master_from_seed;
    if (master_privkey.size() == crypto_sign_ed25519_SEEDBYTES) {
        array_uc32 master_pubkey;
        crypto_sign_ed25519_seed_keypair(
                master_pubkey.data(), master_from_seed.data(), master_privkey.data());
        master_privkey = master_from_seed;
    } else if (master_privkey.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        throw std::invalid_argument{"Invalid master_privkey: expected 32 or 64 bytes"};
    }

    cleared_uc64 rotating_from_seed;
    if (rotating_privkey.size() == crypto_sign_ed25519_SEEDBYTES) {
        array_uc32 rotating_pubkey;
        crypto_sign_ed25519_seed_keypair(
                rotating_pubkey.data(), rotating_from_seed.data(), rotating_privkey.data());
        rotating_privkey = rotating_from_seed;
    } else if (rotating_privkey.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        throw std::invalid_argument{"Invalid rotating_privkey: expected 32 or 64 bytes"};
    }

    if (payment_tx_provider == SESSION_PRO_BACKEND_PAYMENT_PROVIDER_GOOGLE_PLAY_STORE) {
        if (payment_tx_order_id.empty())
            throw std::invalid_argument{
                    "Invalid payment_tx_order_id: order ID must be set for a Google Play store "
                    "payment"};
    } else {
        if (payment_tx_order_id.size())
            throw std::invalid_argument{
                    "Invalid payment_tx_order_id: order ID must not be set for an iOS App store "
                    "payment"};
    }

    // Hash components to 32 bytes, must match:
    //   https://github.com/Doy-lee/session-pro-backend/blob/5b66b1a4a64dc8da0225507019cbe21d7642fa78/backend.py#L171
    array_uc32 hash_to_sign = {};
    crypto_generichash_blake2b_state state = {};
    make_blake2b32_hasher(
            &state,
            {SESSION_PROTOCOL_ADD_PRO_PAYMENT_HASH_PERSONALISATION,
             sizeof(SESSION_PROTOCOL_ADD_PRO_PAYMENT_HASH_PERSONALISATION) - 1});
    crypto_generichash_blake2b_update(&state, &version, sizeof(version));
    crypto_generichash_blake2b_update(
            &state,
            master_privkey.data() + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);
    crypto_generichash_blake2b_update(
            &state,
            rotating_privkey.data() + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);

    uint8_t provider_u8 = payment_tx_provider;
    crypto_generichash_blake2b_update(&state, &provider_u8, sizeof(provider_u8));
    crypto_generichash_blake2b_update(
            &state,
            reinterpret_cast<const uint8_t*>(payment_tx_payment_id.data()),
            payment_tx_payment_id.size());
    if (payment_tx_order_id.size()) {
        crypto_generichash_blake2b_update(
                &state,
                reinterpret_cast<const uint8_t*>(payment_tx_order_id.data()),
                payment_tx_order_id.size());
    }
    crypto_generichash_blake2b_final(&state, hash_to_sign.data(), hash_to_sign.size());

    // Sign the hash with both keys
    MasterRotatingSignatures result = {};
    crypto_sign_ed25519_detached(
            result.master_sig.data(),
            nullptr,
            hash_to_sign.data(),
            hash_to_sign.size(),
            master_privkey.data());
    crypto_sign_ed25519_detached(
            result.rotating_sig.data(),
            nullptr,
            hash_to_sign.data(),
            hash_to_sign.size(),
            rotating_privkey.data());
    return result;
}

std::string AddProPaymentRequest::build_to_json(
        std::uint8_t version,
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        std::span<const uint8_t> payment_tx_payment_id,
        std::span<const uint8_t> payment_tx_order_id) {
    cleared_uc64 master_from_seed;
    if (master_privkey.size() == crypto_sign_ed25519_SEEDBYTES) {
        array_uc32 master_pubkey;
        crypto_sign_ed25519_seed_keypair(
                master_pubkey.data(), master_from_seed.data(), master_privkey.data());
        master_privkey = master_from_seed;
    } else if (master_privkey.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        throw std::invalid_argument{"Invalid master_privkey: expected 32 or 64 bytes"};
    }

    cleared_uc64 rotating_from_seed;
    if (rotating_privkey.size() == crypto_sign_ed25519_SEEDBYTES) {
        array_uc32 rotating_pubkey;
        crypto_sign_ed25519_seed_keypair(
                rotating_pubkey.data(), rotating_from_seed.data(), rotating_privkey.data());
        rotating_privkey = rotating_from_seed;
    } else if (rotating_privkey.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        throw std::invalid_argument{"Invalid rotating_privkey: expected 32 or 64 bytes"};
    }

    MasterRotatingSignatures sigs = AddProPaymentRequest::build_sigs(
            version,
            master_privkey,
            rotating_privkey,
            payment_tx_provider,
            payment_tx_payment_id,
            payment_tx_order_id);

    AddProPaymentRequest request = {};
    request.version = version;
    std::memcpy(
            request.master_pkey.data(),
            master_privkey.data() + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);
    std::memcpy(
            request.rotating_pkey.data(),
            rotating_privkey.data() + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);
    request.payment_tx.provider = payment_tx_provider;
    request.payment_tx.payment_id = std::string(
            reinterpret_cast<const char*>(payment_tx_payment_id.data()),
            payment_tx_payment_id.size());
    request.payment_tx.order_id = std::string(
            reinterpret_cast<const char*>(payment_tx_order_id.data()), payment_tx_order_id.size());
    request.master_sig = sigs.master_sig;
    request.rotating_sig = sigs.rotating_sig;

    std::string result = request.to_json();
    return result;
}

AddProPaymentOrGenerateProProofResponse AddProPaymentOrGenerateProProofResponse::parse(
        std::string_view json) {
    // Parse basics
    AddProPaymentOrGenerateProProofResponse result = {};
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
    result.proof.version = json_require<uint8_t>(result_obj, "version", result.errors);
    auto expiry_unix_ts_ms = json_require<uint64_t>(result_obj, "expiry_unix_ts_ms", result.errors);
    result.proof.expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
            std::chrono::milliseconds(expiry_unix_ts_ms));
    json_require_fixed_bytes_from_hex(
            result_obj, "gen_index_hash", result.errors, result.proof.gen_index_hash);
    json_require_fixed_bytes_from_hex(
            result_obj, "rotating_pkey", result.errors, result.proof.rotating_pubkey);
    json_require_fixed_bytes_from_hex(result_obj, "sig", result.errors, result.proof.sig);
    return result;
}

std::string GenerateProProofRequest::to_json() const {
    nlohmann::json j;
    j["version"] = version;
    j["master_pkey"] = oxenc::to_hex(master_pkey);
    j["rotating_pkey"] = oxenc::to_hex(rotating_pkey);
    j["unix_ts_ms"] = epoch_ms(unix_ts);
    j["master_sig"] = oxenc::to_hex(master_sig);
    j["rotating_sig"] = oxenc::to_hex(rotating_sig);
    std::string result = j.dump();
    return result;
}

MasterRotatingSignatures GenerateProProofRequest::build_sigs(
        std::uint8_t request_version,
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        std::chrono::sys_time<std::chrono::milliseconds> unix_ts) {

    cleared_uc64 master_from_seed;
    if (master_privkey.size() == 32) {
        array_uc32 master_pubkey;
        crypto_sign_ed25519_seed_keypair(
                master_pubkey.data(), master_from_seed.data(), master_privkey.data());
        master_privkey = master_from_seed;
    } else if (master_privkey.size() != 64) {
        throw std::invalid_argument{"Invalid master_privkey: expected 32 or 64 bytes"};
    }

    cleared_uc64 rotating_from_seed;
    if (rotating_privkey.size() == 32) {
        array_uc32 rotating_pubkey;
        crypto_sign_ed25519_seed_keypair(
                rotating_pubkey.data(), rotating_from_seed.data(), rotating_privkey.data());
        rotating_privkey = rotating_from_seed;
    } else if (rotating_privkey.size() != 64) {
        throw std::invalid_argument{"Invalid rotating_privkey: expected 32 or 64 bytes"};
    }

    // Hash components to 32 bytes, must match:
    //   https://github.com/Doy-lee/session-pro-backend/blob/5b66b1a4a64dc8da0225507019cbe21d7642fa78/backend.py#L631
    uint8_t version = 0;
    uint64_t unix_ts_ms = epoch_ms(unix_ts);
    array_uc32 hash_to_sign = {};
    crypto_generichash_blake2b_state state = {};
    make_blake2b32_hasher(
            &state,
            {SESSION_PROTOCOL_GENERATE_PROOF_HASH_PERSONALISATION,
             sizeof(SESSION_PROTOCOL_GENERATE_PROOF_HASH_PERSONALISATION) - 1});
    crypto_generichash_blake2b_update(&state, &version, sizeof(version));
    crypto_generichash_blake2b_update(
            &state, master_privkey.data() + 32, crypto_sign_ed25519_PUBLICKEYBYTES);
    crypto_generichash_blake2b_update(
            &state, rotating_privkey.data() + 32, crypto_sign_ed25519_PUBLICKEYBYTES);
    crypto_generichash_blake2b_update(
            &state, reinterpret_cast<uint8_t*>(&unix_ts_ms), sizeof(unix_ts_ms));
    crypto_generichash_blake2b_final(&state, hash_to_sign.data(), hash_to_sign.size());

    // Sign the hash with both keys
    MasterRotatingSignatures result = {};
    crypto_sign_ed25519_detached(
            result.master_sig.data(),
            nullptr,
            hash_to_sign.data(),
            hash_to_sign.size(),
            master_privkey.data());
    crypto_sign_ed25519_detached(
            result.rotating_sig.data(),
            nullptr,
            hash_to_sign.data(),
            hash_to_sign.size(),
            rotating_privkey.data());
    return result;
}

std::string GenerateProProofRequest::build_to_json(
        std::uint8_t request_version,
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        std::chrono::sys_time<std::chrono::milliseconds> unix_ts) {
    // Rederive keys from 32 byte seed if given
    cleared_uc64 master_from_seed;
    if (master_privkey.size() == 32) {
        array_uc32 master_pubkey;
        crypto_sign_ed25519_seed_keypair(
                master_pubkey.data(), master_from_seed.data(), master_privkey.data());
        master_privkey = master_from_seed;
    } else if (master_privkey.size() != 64) {
        throw std::invalid_argument{"Invalid master_privkey: expected 32 or 64 bytes"};
    }

    cleared_uc64 rotating_from_seed;
    if (rotating_privkey.size() == 32) {
        array_uc32 rotating_pubkey;
        crypto_sign_ed25519_seed_keypair(
                rotating_pubkey.data(), rotating_from_seed.data(), rotating_privkey.data());
        rotating_privkey = rotating_from_seed;
    } else if (rotating_privkey.size() != 64) {
        throw std::invalid_argument{"Invalid rotating_privkey: expected 32 or 64 bytes"};
    }

    MasterRotatingSignatures sigs = GenerateProProofRequest::build_sigs(
            request_version, master_privkey, rotating_privkey, unix_ts);

    GenerateProProofRequest request = {};
    request.version = request_version;
    std::memcpy(
            request.master_pkey.data(),
            master_privkey.data() + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);
    std::memcpy(
            request.rotating_pkey.data(),
            rotating_privkey.data() + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);
    request.unix_ts = unix_ts;
    request.master_sig = sigs.master_sig;
    request.rotating_sig = sigs.rotating_sig;

    std::string result = request.to_json();
    return result;
}

std::string GetProRevocationsRequest::to_json() const {
    nlohmann::json j;
    j["version"] = version;
    j["ticket"] = ticket;
    std::string result = j.dump();
    return result;
}

GetProRevocationsResponse GetProRevocationsResponse::parse(std::string_view json) {
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
    result.ticket = json_require<uint32_t>(result_obj, "ticket", result.errors);

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
        auto expiry_unix_ts = json_require<uint64_t>(obj, "expiry_unix_ts_ms", result.errors);

        ProRevocationItem item = {};
        item.expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                std::chrono::milliseconds(expiry_unix_ts));
        json_require_fixed_bytes_from_hex(
                obj, "gen_index_hash", result.errors, item.gen_index_hash);

        // Handle parsing result
        if (result.errors.size())
            break;
        result.items.emplace_back(std::move(item));
    }

    return result;
}

std::string GetProDetailsRequest::to_json() const {
    nlohmann::json j;
    j["version"] = version;
    j["master_pkey"] = oxenc::to_hex(master_pkey);
    j["master_sig"] = oxenc::to_hex(master_sig);
    j["unix_ts_ms"] = epoch_ms(unix_ts);
    j["count"] = count;
    std::string result = j.dump();
    return result;
}

array_uc64 GetProDetailsRequest::build_sig(
        uint8_t version,
        std::span<const uint8_t> master_privkey,
        std::chrono::sys_time<std::chrono::milliseconds> unix_ts,
        uint32_t count) {
    cleared_uc64 master_from_seed;
    if (master_privkey.size() == crypto_sign_ed25519_SEEDBYTES) {
        array_uc32 master_pubkey;
        crypto_sign_ed25519_seed_keypair(
                master_pubkey.data(), master_from_seed.data(), master_privkey.data());
        master_privkey = master_from_seed;
    } else if (master_privkey.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        throw std::invalid_argument{"Invalid master_privkey: expected 32 or 64 bytes"};
    }

    // Hash components to 32 bytes, must match:
    //   https://github.com/Doy-lee/session-pro-backend/blob/635b14fc93302658de6c07c017f705673fc7c57f/server.py#L395
    array_uc32 hash_to_sign = {};
    crypto_generichash_blake2b_state state = {};
    uint64_t unix_ts_ms = epoch_ms(unix_ts);
    make_blake2b32_hasher(
            &state,
            {SESSION_PROTOCOL_GET_PRO_DETAILS_HASH_PERSONALISATION,
             sizeof(SESSION_PROTOCOL_GET_PRO_DETAILS_HASH_PERSONALISATION) - 1});
    crypto_generichash_blake2b_update(&state, &version, sizeof(version));
    crypto_generichash_blake2b_update(
            &state,
            master_privkey.data() + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);
    crypto_generichash_blake2b_update(
            &state, reinterpret_cast<unsigned char*>(&unix_ts_ms), sizeof(unix_ts_ms));
    crypto_generichash_blake2b_update(
            &state, reinterpret_cast<unsigned char*>(&count), sizeof(count));
    crypto_generichash_blake2b_final(&state, hash_to_sign.data(), hash_to_sign.size());

    // Sign the hash
    array_uc64 result = {};
    crypto_sign_ed25519_detached(
            result.data(),
            nullptr,
            hash_to_sign.data(),
            hash_to_sign.size(),
            master_privkey.data());
    return result;
}

std::string GetProDetailsRequest::build_to_json(
        uint8_t version,
        std::span<const uint8_t> master_privkey,
        std::chrono::sys_time<std::chrono::milliseconds> unix_ts,
        uint32_t count) {
    cleared_uc64 master_from_seed;
    if (master_privkey.size() == crypto_sign_ed25519_SEEDBYTES) {
        array_uc32 master_pubkey;
        crypto_sign_ed25519_seed_keypair(
                master_pubkey.data(), master_from_seed.data(), master_privkey.data());
        master_privkey = master_from_seed;
    } else if (master_privkey.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        throw std::invalid_argument{"Invalid master_privkey: expected 32 or 64 bytes"};
    }

    GetProDetailsRequest request = {};
    request.version = version;
    memcpy(request.master_pkey.data(),
           master_privkey.data() + crypto_sign_ed25519_SEEDBYTES,
           crypto_sign_ed25519_PUBLICKEYBYTES);
    request.master_sig = GetProDetailsRequest::build_sig(version, master_privkey, unix_ts, count);
    request.unix_ts = unix_ts;
    request.count = count;

    std::string result = request.to_json();
    return result;
}

GetProDetailsResponse GetProDetailsResponse::parse(std::string_view json) {
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

    uint64_t expiry_unix_ts_ms =
            json_require<uint64_t>(result_obj, "expiry_unix_ts_ms", result.errors);
    uint64_t grace_period_duration_ms =
            json_require<uint64_t>(result_obj, "grace_period_duration_ms", result.errors);
    uint64_t refund_requested_unix_ts_ms =
            json_require<uint64_t>(result_obj, "refund_requested_unix_ts_ms", result.errors);
    result.expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
            std::chrono::milliseconds(expiry_unix_ts_ms));
    result.grace_period_duration = std::chrono::milliseconds(grace_period_duration_ms);
    result.refund_requested_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
            std::chrono::milliseconds(refund_requested_unix_ts_ms));

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
        auto plan = json_require<uint64_t>(obj, "plan", result.errors);
        auto payment_provider = json_require<uint32_t>(obj, "payment_provider", result.errors);
        auto auto_renewing = json_require<bool>(obj, "auto_renewing", result.errors);
        auto unredeemed_ts = json_require<uint64_t>(obj, "unredeemed_unix_ts_ms", result.errors);
        auto redeemed_ts = json_require<uint64_t>(obj, "redeemed_unix_ts_ms", result.errors);
        auto expiry_ts = json_require<uint64_t>(obj, "expiry_unix_ts_ms", result.errors);
        auto grace_period_duration_ms =
                json_require<uint64_t>(obj, "grace_period_duration_ms", result.errors);
        auto platform_refund_expiry_ts =
                json_require<uint64_t>(obj, "platform_refund_expiry_unix_ts_ms", result.errors);
        auto revoked_ts = json_require<uint64_t>(obj, "revoked_unix_ts_ms", result.errors);
        auto refund_requested_ts =
                json_require<uint64_t>(obj, "refund_requested_unix_ts_ms", result.errors);

        ProPaymentItem item = {};
        if (status > SESSION_PRO_BACKEND_PAYMENT_STATUS_NIL &&
            status < SESSION_PRO_BACKEND_PAYMENT_STATUS_COUNT) {
            item.status = static_cast<SESSION_PRO_BACKEND_PAYMENT_STATUS>(status);
        } else {
            result.errors.push_back(fmt::format("Status value was out-of-bounds: {}", status));
        }

        if (plan > SESSION_PRO_BACKEND_PLAN_NIL && plan < SESSION_PRO_BACKEND_PLAN_COUNT) {
            item.plan = static_cast<SESSION_PRO_BACKEND_PLAN>(plan);
        } else {
            result.errors.push_back(fmt::format("Plan value was out-of-bounds: {}", plan));
        }

        if (payment_provider > SESSION_PRO_BACKEND_PAYMENT_PROVIDER_NIL &&
            payment_provider < SESSION_PRO_BACKEND_PAYMENT_PROVIDER_COUNT) {
            item.payment_provider =
                    static_cast<SESSION_PRO_BACKEND_PAYMENT_PROVIDER>(payment_provider);
            item.payment_provider_metadata =
                    SESSION_PRO_BACKEND_PAYMENT_PROVIDER_METADATA + payment_provider;
        } else {
            result.errors.push_back(
                    fmt::format("Payment provider value was out-of-bounds: {}", payment_provider));
        }

        item.auto_renewing = auto_renewing;
        item.unredeemed_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                std::chrono::milliseconds(unredeemed_ts));
        item.redeemed_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                std::chrono::milliseconds(redeemed_ts));
        item.expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                std::chrono::milliseconds(expiry_ts));
        item.grace_period_duration_ms = std::chrono::milliseconds(grace_period_duration_ms);
        item.platform_refund_expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                std::chrono::milliseconds(platform_refund_expiry_ts));
        item.revoked_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                std::chrono::milliseconds(revoked_ts));
        item.refund_requested_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                std::chrono::milliseconds(refund_requested_ts));
        switch (item.payment_provider) {
            case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_COUNT: [[fallthrough]];
            case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_NIL: {
            } break;
            case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_GOOGLE_PLAY_STORE: {
                item.google_payment_token =
                        json_require<std::string>(obj, "google_payment_token", result.errors);
                assert(item.google_payment_token.size() <
                       sizeof(((session_pro_backend_pro_payment_item*)0)->google_payment_token));
                item.google_order_id =
                        json_require<std::string>(obj, "google_order_id", result.errors);
                assert(item.google_order_id.size() <
                       sizeof(((session_pro_backend_pro_payment_item*)0)->google_order_id));
            } break;

            case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_IOS_APP_STORE: {
                item.apple_original_tx_id =
                        json_require<std::string>(obj, "apple_original_tx_id", result.errors);
                item.apple_tx_id = json_require<std::string>(obj, "apple_tx_id", result.errors);
                item.apple_web_line_order_id =
                        json_require<std::string>(obj, "apple_web_line_order_id", result.errors);
                assert(item.apple_original_tx_id.size() <
                       sizeof(((session_pro_backend_pro_payment_item*)0)->apple_original_tx_id));
                assert(item.apple_tx_id.size() <
                       sizeof(((session_pro_backend_pro_payment_item*)0)->apple_tx_id));
                assert(item.apple_web_line_order_id.size() <
                       sizeof(((session_pro_backend_pro_payment_item*)0)->apple_web_line_order_id));
            } break;
            case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_RANGEPROOF: {
                item.rangeproof_order_id =
                          json_require<std::string>(obj, "rangeproof_order_id", result.errors);
                assert(item.rangeproof_order_id.size() <
                        sizeof(((session_pro_backend_pro_payment_item*)0)->rangeproof_order_id));
            } break;
        }

        // Handle parsing result
        if (result.errors.size())
            break;

        result.items.emplace_back(std::move(item));
    }
    return result;
}

array_uc64 SetPaymentRefundRequestedRequest::build_sig(
        uint8_t version,
        std::span<const uint8_t> master_privkey,
        std::chrono::sys_time<std::chrono::milliseconds> unix_ts,
        std::chrono::sys_time<std::chrono::milliseconds> refund_requested_unix_ts,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        std::span<const uint8_t> payment_tx_payment_id,
        std::span<const uint8_t> payment_tx_order_id) {
    cleared_uc64 master_from_seed;
    if (master_privkey.size() == crypto_sign_ed25519_SEEDBYTES) {
        array_uc32 master_pubkey;
        crypto_sign_ed25519_seed_keypair(
                master_pubkey.data(), master_from_seed.data(), master_privkey.data());
        master_privkey = master_from_seed;
    } else if (master_privkey.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        throw std::invalid_argument{"Invalid master_privkey: expected 32 or 64 bytes"};
    }

    // Hash components to 32 bytes, must match:
    //   https://github.com/Doy-lee/session-pro-backend/blob/5962925d7f18f83a3ff5774885495e5dd55ecb0a/server.py#L634
    array_uc32 hash_to_sign = {};
    crypto_generichash_blake2b_state state = {};
    make_blake2b32_hasher(
            &state,
            {SESSION_PROTOCOL_SET_PAYMENT_REFUND_REQUESTED_HASH_PERSONALISATION,
             sizeof(SESSION_PROTOCOL_SET_PAYMENT_REFUND_REQUESTED_HASH_PERSONALISATION) - 1});
    crypto_generichash_blake2b_update(&state, &version, sizeof(version));
    crypto_generichash_blake2b_update(
            &state,
            master_privkey.data() + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);

    // Timestamps
    uint64_t unix_ts_ms = epoch_ms(unix_ts);
    uint64_t refund_requested_unix_ts_ms = epoch_ms(refund_requested_unix_ts);
    crypto_generichash_blake2b_update(
            &state, reinterpret_cast<const uint8_t*>(&unix_ts_ms), sizeof(unix_ts_ms));
    crypto_generichash_blake2b_update(
            &state,
            reinterpret_cast<const uint8_t*>(&refund_requested_unix_ts_ms),
            sizeof(refund_requested_unix_ts_ms));

    // Payment provider
    uint8_t provider_u8 = payment_tx_provider;
    crypto_generichash_blake2b_update(&state, &provider_u8, sizeof(provider_u8));
    crypto_generichash_blake2b_update(
            &state,
            reinterpret_cast<const uint8_t*>(payment_tx_payment_id.data()),
            payment_tx_payment_id.size());
    if (payment_tx_order_id.size()) {
        crypto_generichash_blake2b_update(
                &state,
                reinterpret_cast<const uint8_t*>(payment_tx_order_id.data()),
                payment_tx_order_id.size());
    }
    crypto_generichash_blake2b_final(&state, hash_to_sign.data(), hash_to_sign.size());

    // Sign the hash
    array_uc64 result = {};
    crypto_sign_ed25519_detached(
            result.data(),
            nullptr,
            hash_to_sign.data(),
            hash_to_sign.size(),
            master_privkey.data());
    return result;
}

std::string SetPaymentRefundRequestedRequest::build_to_json(
        uint8_t version,
        std::span<const uint8_t> master_privkey,
        std::chrono::sys_time<std::chrono::milliseconds> unix_ts,
        std::chrono::sys_time<std::chrono::milliseconds> refund_requested_unix_ts,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        std::span<const uint8_t> payment_tx_payment_id,
        std::span<const uint8_t> payment_tx_order_id) {
    array_uc64 sig = SetPaymentRefundRequestedRequest::build_sig(
            version,
            master_privkey,
            unix_ts,
            refund_requested_unix_ts,
            payment_tx_provider,
            payment_tx_payment_id,
            payment_tx_order_id);

    SetPaymentRefundRequestedRequest request = {};
    request.version = version;
    std::memcpy(
            request.master_pkey.data(),
            master_privkey.data() + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);
    request.payment_tx.provider = payment_tx_provider;
    request.payment_tx.payment_id = std::string(
            reinterpret_cast<const char*>(payment_tx_payment_id.data()),
            payment_tx_payment_id.size());
    request.payment_tx.order_id = std::string(
            reinterpret_cast<const char*>(payment_tx_order_id.data()), payment_tx_order_id.size());
    request.master_sig = sig;
    request.unix_ts = unix_ts;
    request.refund_requested_unix_ts = refund_requested_unix_ts;

    std::string result = request.to_json();
    return result;
}

std::string SetPaymentRefundRequestedRequest::to_json() const {
    nlohmann::json j;
    j["version"] = version;
    j["master_pkey"] = oxenc::to_hex(master_pkey);
    j["unix_ts_ms"] = epoch_ms(unix_ts);
    j["refund_requested_unix_ts_ms"] = epoch_ms(refund_requested_unix_ts);
    j["payment_tx"]["provider"] = payment_tx.provider;
    switch (payment_tx.provider) {
        case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_NIL: [[fallthrough]];
        case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_COUNT: break;
        case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_RANGEPROOF: {assert(false && "Unimplemented");} break;
        case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_GOOGLE_PLAY_STORE: {
            j["payment_tx"]["google_payment_token"] = payment_tx.payment_id;
            j["payment_tx"]["google_order_id"] = payment_tx.order_id;
        } break;
        case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_IOS_APP_STORE: {
            j["payment_tx"]["apple_tx_id"] = payment_tx.payment_id;
        } break;
    }
    j["master_sig"] = oxenc::to_hex(master_sig);
    std::string result = j.dump();
    return result;
}

SetPaymentRefundRequestedResponse SetPaymentRefundRequestedResponse::parse(std::string_view json) {
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
    result.version = json_require<uint8_t>(result_obj, "version", result.errors);
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
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        const uint8_t* payment_tx_payment_id,
        size_t payment_tx_payment_id_len,
        const uint8_t* payment_tx_order_id,
        size_t payment_tx_order_id_len) {

    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span(master_privkey, master_privkey_len);
    std::span<const uint8_t> rotating_span(rotating_privkey, rotating_privkey_len);
    std::span<const uint8_t> payment_tx_payment_id_span(
            payment_tx_payment_id, payment_tx_payment_id_len);
    std::span<const uint8_t> payment_tx_order_id_span(payment_tx_order_id, payment_tx_order_id_len);

    session_pro_backend_master_rotating_signatures result = {};
    try {
        auto sigs = AddProPaymentRequest::build_sigs(
                request_version,
                master_span,
                rotating_span,
                payment_tx_provider,
                payment_tx_payment_id_span,
                payment_tx_order_id_span);
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

LIBSESSION_C_API session_pro_backend_to_json
session_pro_backend_add_pro_payment_request_build_to_json(
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        const uint8_t* payment_tx_payment_id,
        size_t payment_tx_payment_id_len,
        const uint8_t* payment_tx_order_id,
        size_t payment_tx_order_id_len) {
    session_pro_backend_to_json result = {};

    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span(master_privkey, master_privkey_len);
    std::span<const uint8_t> rotating_span(rotating_privkey, rotating_privkey_len);
    std::span<const uint8_t> payment_tx_payment_id_span(
            payment_tx_payment_id, payment_tx_payment_id_len);
    std::span<const uint8_t> payment_tx_order_id_span(payment_tx_order_id, payment_tx_order_id_len);

    try {
        std::string json = AddProPaymentRequest::build_to_json(
                request_version,
                master_span,
                rotating_span,
                payment_tx_provider,
                payment_tx_payment_id_span,
                payment_tx_order_id_span);
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

LIBSESSION_C_API session_pro_backend_master_rotating_signatures
session_pro_backend_generate_pro_proof_request_build_sigs(
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        uint64_t unix_ts_ms) {

    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span(master_privkey, master_privkey_len);
    std::span<const uint8_t> rotating_span(rotating_privkey, rotating_privkey_len);
    std::chrono::milliseconds ts{unix_ts_ms};

    session_pro_backend_master_rotating_signatures result = {};
    try {
        auto sigs = GenerateProProofRequest::build_sigs(
                request_version,
                master_span,
                rotating_span,
                std::chrono::sys_time<std::chrono::milliseconds>(ts));
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

LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_generate_pro_proof_request_build_to_json(
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        uint64_t unix_ts_ms) {
    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span(master_privkey, master_privkey_len);
    std::span<const uint8_t> rotating_span(rotating_privkey, rotating_privkey_len);
    std::chrono::milliseconds ts{unix_ts_ms};

    session_pro_backend_to_json result = {};
    try {
        auto json = GenerateProProofRequest::build_to_json(
                request_version,
                master_span,
                rotating_span,
                std::chrono::sys_time<std::chrono::milliseconds>(ts));
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

LIBSESSION_C_API session_pro_backend_signature
session_pro_backend_get_pro_details_request_build_sig(
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        uint64_t unix_ts_ms,
        uint32_t count) {
    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span{master_privkey, master_privkey_len};
    std::chrono::sys_time<std::chrono::milliseconds> ts{std::chrono::milliseconds(unix_ts_ms)};

    session_pro_backend_signature result = {};
    try {
        auto sig = GetProDetailsRequest::build_sig(request_version, master_span, ts, count);
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
session_pro_backend_get_pro_details_request_build_to_json(
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        uint64_t unix_ts_ms,
        uint32_t count) {
    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span{master_privkey, master_privkey_len};
    std::chrono::sys_time<std::chrono::milliseconds> ts{std::chrono::milliseconds(unix_ts_ms)};

    session_pro_backend_to_json result = {};
    try {
        auto json = GetProDetailsRequest::build_to_json(request_version, master_span, ts, count);
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

LIBSESSION_C_API session_pro_backend_to_json session_pro_backend_add_pro_payment_request_to_json(
        const session_pro_backend_add_pro_payment_request* request) {
    session_pro_backend_to_json result = {};
    if (!request)
        return result;

    // Construct C++ struct
    AddProPaymentRequest cpp = {};
    cpp.version = request->version;
    std::memcpy(cpp.master_pkey.data(), request->master_pkey.data, cpp.master_pkey.size());
    std::memcpy(cpp.rotating_pkey.data(), request->rotating_pkey.data, cpp.rotating_pkey.size());
    cpp.payment_tx.provider = request->payment_tx.provider;
    cpp.payment_tx.payment_id =
            std::string(request->payment_tx.payment_id, request->payment_tx.payment_id_count);
    cpp.payment_tx.order_id =
            std::string(request->payment_tx.order_id, request->payment_tx.order_id_count);
    std::memcpy(cpp.master_sig.data(), request->master_sig.data, cpp.master_sig.size());
    std::memcpy(cpp.rotating_sig.data(), request->rotating_sig.data, cpp.rotating_sig.size());

    try {
        std::string json = cpp.to_json();
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

    // Construct C++ struct
    GenerateProProofRequest cpp;
    cpp.version = request->version;
    std::memcpy(cpp.master_pkey.data(), request->master_pkey.data, cpp.master_pkey.size());
    std::memcpy(cpp.rotating_pkey.data(), request->rotating_pkey.data, cpp.rotating_pkey.size());
    cpp.unix_ts = std::chrono::sys_time<std::chrono::milliseconds>{
            std::chrono::milliseconds(request->unix_ts_ms)};
    std::memcpy(cpp.master_sig.data(), request->master_sig.data, cpp.master_sig.size());
    std::memcpy(cpp.rotating_sig.data(), request->rotating_sig.data, cpp.rotating_sig.size());

    try {
        std::string json = cpp.to_json();
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

    // Construct C++ struct
    GetProRevocationsRequest cpp = {};
    cpp.version = request->version;
    cpp.ticket = request->ticket;

    try {
        std::string json = cpp.to_json();
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

    // Construct C++ struct
    GetProDetailsRequest cpp = {};
    cpp.version = request->version;
    std::memcpy(
            cpp.master_pkey.data(), request->master_pkey.data, sizeof(request->master_pkey.data));
    std::memcpy(cpp.master_sig.data(), request->master_sig.data, sizeof(request->master_sig.data));
    cpp.unix_ts = std::chrono::sys_time<std::chrono::milliseconds>{
            std::chrono::milliseconds{request->unix_ts_ms}};
    cpp.count = request->count;

    try {
        std::string json = cpp.to_json();
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

LIBSESSION_C_API session_pro_backend_add_pro_payment_or_generate_pro_proof_response
session_pro_backend_add_pro_payment_or_generate_pro_proof_response_parse(
        const char* json, size_t json_len) {

    session_pro_backend_add_pro_payment_or_generate_pro_proof_response result = {};
    if (!json) {
        result.header.status = 1;
        result.header.errors = &C_PARSE_ERROR_INVALID_ARGS;
        result.header.errors_count = 1;
        return result;
    }

    // Note, parse is written to not throw so we can safely read without try-catch crap
    auto cpp = AddProPaymentOrGenerateProProofResponse::parse({json, json_len});

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
    result.proof.expiry_unix_ts_ms = session::epoch_ms(cpp.proof.expiry_unix_ts);
    std::memcpy(
            result.proof.gen_index_hash.data,
            cpp.proof.gen_index_hash.data(),
            cpp.proof.gen_index_hash.size());
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
    GetProRevocationsResponse cpp = GetProRevocationsResponse::parse({json, json_len});

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
        std::memcpy(dest.gen_index_hash.data, src.gen_index_hash.data(), src.gen_index_hash.size());
        dest.expiry_unix_ts_ms = session::epoch_ms(src.expiry_unix_ts);
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
    auto cpp = GetProDetailsResponse::parse({json, json_len});

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

    using session::epoch_ms;

    // Copy to C struct, this is guaranteed not to fail because we pre-allocated memory upfront.
    result.header.status = cpp.status;
    result.status = cpp.user_status;
    result.error_report = cpp.error_report;
    result.items_count = cpp.items.size();
    result.items = (session_pro_backend_pro_payment_item*)arena_alloc(
            &arena, result.items_count * sizeof(*result.items));
    result.auto_renewing = cpp.auto_renewing;
    result.expiry_unix_ts_ms = epoch_ms(cpp.expiry_unix_ts);
    result.grace_period_duration_ms = cpp.grace_period_duration.count();
    result.refund_requested_unix_ts_ms = epoch_ms(cpp.refund_requested_unix_ts);
    result.payments_total = cpp.payments_total;

    for (size_t index = 0; index < result.items_count; ++index) {
        const ProPaymentItem& src = cpp.items[index];
        session_pro_backend_pro_payment_item& dest = result.items[index];
        dest.status = src.status;
        dest.plan = src.plan;
        dest.payment_provider = src.payment_provider;
        dest.payment_provider_metadata = src.payment_provider_metadata;
        dest.unredeemed_unix_ts_ms = epoch_ms(src.unredeemed_unix_ts);
        dest.redeemed_unix_ts_ms = epoch_ms(src.redeemed_unix_ts);
        dest.expiry_unix_ts_ms = epoch_ms(src.expiry_unix_ts);
        dest.grace_period_duration_ms = session::duration_ms(src.grace_period_duration_ms);
        dest.platform_refund_expiry_unix_ts_ms = epoch_ms(src.platform_refund_expiry_unix_ts);
        dest.revoked_unix_ts_ms = epoch_ms(src.revoked_unix_ts);
        dest.refund_requested_unix_ts_ms = epoch_ms(src.refund_requested_unix_ts);

        switch (dest.payment_provider) {
            case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_NIL: [[fallthrough]];
            case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_COUNT: break;
            case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_GOOGLE_PLAY_STORE: {
                dest.google_payment_token_count = snprintf_clamped(
                        dest.google_payment_token,
                        sizeof(dest.google_payment_token),
                        src.google_payment_token.data());
                dest.google_order_id_count = snprintf_clamped(
                        dest.google_order_id,
                        sizeof(dest.google_order_id),
                        src.google_order_id.data());
            } break;

            case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_IOS_APP_STORE: {
                dest.apple_original_tx_id_count = snprintf_clamped(
                        dest.apple_original_tx_id,
                        sizeof(dest.apple_original_tx_id),
                        src.apple_original_tx_id.data());
                dest.apple_tx_id_count = snprintf_clamped(
                        dest.apple_tx_id, sizeof(dest.apple_tx_id), src.apple_tx_id.data());
                dest.apple_web_line_order_id_count = snprintf_clamped(
                        dest.apple_web_line_order_id,
                        sizeof(dest.apple_web_line_order_id),
                        src.apple_web_line_order_id.data());
            } break;
            case SESSION_PRO_BACKEND_PAYMENT_PROVIDER_RANGEPROOF: {
                dest.rangeproof_order_id_count = snprintf_clamped(
                        dest.rangeproof_order_id,
                        sizeof(dest.rangeproof_order_id),
                        src.rangeproof_order_id.data());

            } break;

        }
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
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        uint64_t unix_ts_ms,
        uint64_t refund_requested_unix_ts_ms,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        const uint8_t* payment_tx_payment_id,
        size_t payment_tx_payment_id_len,
        const uint8_t* payment_tx_order_id,
        size_t payment_tx_order_id_len) {
    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span{master_privkey, master_privkey_len};
    std::chrono::sys_time<std::chrono::milliseconds> unix_ts{std::chrono::milliseconds(unix_ts_ms)};
    std::chrono::sys_time<std::chrono::milliseconds> refund_requested_unix_ts{
            std::chrono::milliseconds(refund_requested_unix_ts_ms)};
    std::span<const uint8_t> payment_tx_payment_id_span(
            payment_tx_payment_id, payment_tx_payment_id_len);
    std::span<const uint8_t> payment_tx_order_id_span(payment_tx_order_id, payment_tx_order_id_len);

    session_pro_backend_signature result = {};
    try {
        auto sig = SetPaymentRefundRequestedRequest::build_sig(
                request_version,
                master_span,
                unix_ts,
                refund_requested_unix_ts,
                payment_tx_provider,
                payment_tx_payment_id_span,
                payment_tx_order_id_span);
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
session_pro_backend_set_payment_refund_requested_request_build_to_json(
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        uint64_t unix_ts_ms,
        uint64_t refund_requested_unix_ts_ms,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        const uint8_t* payment_tx_payment_id,
        size_t payment_tx_payment_id_len,
        const uint8_t* payment_tx_order_id,
        size_t payment_tx_order_id_len) {

    // Convert C inputs to C++ types
    std::span<const uint8_t> master_span{master_privkey, master_privkey_len};
    std::chrono::sys_time<std::chrono::milliseconds> unix_ts{std::chrono::milliseconds(unix_ts_ms)};
    std::chrono::sys_time<std::chrono::milliseconds> refund_requested_unix_ts{
            std::chrono::milliseconds(refund_requested_unix_ts_ms)};
    std::span<const uint8_t> payment_tx_payment_id_span(
            payment_tx_payment_id, payment_tx_payment_id_len);
    std::span<const uint8_t> payment_tx_order_id_span(payment_tx_order_id, payment_tx_order_id_len);

    session_pro_backend_to_json result = {};
    try {
        auto json = SetPaymentRefundRequestedRequest::build_to_json(
                request_version,
                master_span,
                unix_ts,
                refund_requested_unix_ts,
                payment_tx_provider,
                payment_tx_payment_id_span,
                payment_tx_order_id_span);
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
session_pro_backend_set_payment_refund_requested_request_to_json(
        const session_pro_backend_set_payment_refund_requested_request* request) {
    session_pro_backend_to_json result = {};
    if (!request)
        return result;

    // Construct C++ struct
    SetPaymentRefundRequestedRequest cpp = {};
    cpp.version = request->version;
    std::memcpy(
            cpp.master_pkey.data(), request->master_pkey.data, sizeof(request->master_pkey.data));
    std::memcpy(cpp.master_sig.data(), request->master_sig.data, sizeof(request->master_sig.data));
    cpp.unix_ts = std::chrono::sys_time<std::chrono::milliseconds>{
            std::chrono::milliseconds{request->unix_ts_ms}};
    cpp.refund_requested_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
            std::chrono::milliseconds{request->refund_requested_unix_ts_ms});
    cpp.payment_tx.provider = request->payment_tx.provider;
    cpp.payment_tx.payment_id =
            std::string(request->payment_tx.payment_id, request->payment_tx.payment_id_count);
    cpp.payment_tx.order_id =
            std::string(request->payment_tx.order_id, request->payment_tx.order_id_count);

    try {
        std::string json = cpp.to_json();
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
    auto cpp = SetPaymentRefundRequestedResponse::parse({json, json_len});

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
    result.version = cpp.version;
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

LIBSESSION_C_API void session_pro_backend_add_pro_payment_or_generate_pro_proof_response_free(
        session_pro_backend_add_pro_payment_or_generate_pro_proof_response* response) {
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
