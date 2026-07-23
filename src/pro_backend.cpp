#include <fmt/core.h>
#include <oxenc/hex.h>
#include <session/export.h>
#include <session/pro_backend.h>
#include <sodium/crypto_sign_ed25519.h>

#include <charconv>
#include <chrono>
#include <concepts>
#include <nlohmann/json.hpp>
#include <optional>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/sodium_array.hpp>
#include <session/types.hpp>
#include <session/util.hpp>

#include "internal-util.hpp"
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
        std::span<std::byte> dest) {
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
    constexpr char get_pro_status_endpoint[] = "get_pro_status";
    constexpr char get_payment_details_endpoint[] = "get_payment_details";
    constexpr char get_pro_revocations_endpoint[] = "get_pro_revocations";
    constexpr char set_refund_endpoint[] = "set_payment_refund_requested";

    // Content type for the request payload (single master storage, shared with the C API's
    // session_pro_backend_request.content_type). The wire encoding is libsession's to change; the
    // content type travels alongside the payload so clients never hardcode a format.
    constexpr char application_json[] = "application/json";

    // --- add-payment (endpoint add_pro_payment) ---

    std::vector<std::byte> add_payment_message(
            std::span<const std::byte, 32> master_pubkey,
            std::span<const std::byte, 32> rotating_pubkey,
            std::string_view provider_code,
            std::span<const std::byte> payment_id) {
        // Must match the add-payment signed-request message in pro-wire-protocol.md §3.2
        // (+ §3.5), built per §1.1.
        return pro::signed_message(
                ADD_PRO_PAYMENT_DOMAIN,
                master_pubkey,
                rotating_pubkey,
                provider_code,
                to_string_view(payment_id));
    }

    // Serialise an add-payment request body from already-computed fields (shared by the C++
    // add_payment_request and the C ..._request_build wrapper).
    std::string add_payment_body(
            std::span<const std::byte, 32> master_pubkey,
            std::span<const std::byte, 32> rotating_pubkey,
            std::string_view provider_code,
            std::string_view payment_id,
            std::span<const std::byte, 64> master_sig,
            std::span<const std::byte, 64> rotating_sig) {
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
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PRO_STATUS_ENDPOINT =
        get_pro_status_endpoint;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PAYMENT_DETAILS_ENDPOINT =
        get_payment_details_endpoint;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PRO_REVOCATIONS_ENDPOINT =
        get_pro_revocations_endpoint;
LIBSESSION_EXPORT extern const char* const
        SESSION_PRO_BACKEND_SET_PAYMENT_REFUND_REQUESTED_ENDPOINT = set_refund_endpoint;

// Backend base URL + Ed25519 pubkey: C symbols pointing at the single C++ definitions above.
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_URL = URL.data();
LIBSESSION_EXPORT extern const unsigned char* const SESSION_PRO_BACKEND_PUBKEY =
        reinterpret_cast<const unsigned char*>(PUBKEY.data());
LIBSESSION_EXPORT extern const unsigned char* const SESSION_PRO_BACKEND_PUBKEY_X25519 =
        reinterpret_cast<const unsigned char*>(PUBKEY_X25519.data());

// Payment-provider code strings: C symbols pointing at the single C++ definitions above.
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY =
        PAYMENT_PROVIDER_GOOGLE_PLAY.data();
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_APP_STORE =
        PAYMENT_PROVIDER_APP_STORE.data();
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_RANGEPROOF =
        PAYMENT_PROVIDER_RANGEPROOF.data();
}

using namespace std::literals;

// Fixed per-provider URL sets; provider_urls() just maps a provider code to one of these. The
// values are `""sv` literals so clang-format keeps each URL on one line (it won't split a string
// literal).
constexpr ProviderURLs google_play_urls{
        .refund_platform_url = "https://support.google.com/googleplay/workflow/9813244?"sv,
        .refund_support_url = "https://getsession.org/android-refund"sv,
        .refund_status_url = "https://getsession.org/android-refund"sv,
        .update_subscription_url =
                "https://play.google.com/store/account/subscriptions?package=network.loki.messenger"sv,
        .cancel_subscription_url =
                "https://play.google.com/store/account/subscriptions?package=network.loki.messenger"sv,
};
constexpr ProviderURLs app_store_urls{
        .refund_platform_url = "https://support.apple.com/118223"sv,
        .refund_support_url = "https://support.apple.com/118223"sv,
        .refund_status_url = "https://support.apple.com/118224"sv,
        .update_subscription_url = "https://apps.apple.com/account/subscriptions"sv,
        .cancel_subscription_url =
                "https://account.apple.com/account/manage/section/subscriptions"sv,
};

const ProviderURLs* provider_urls(std::string_view provider_code) {
    if (provider_code == PAYMENT_PROVIDER_GOOGLE_PLAY)
        return &google_play_urls;
    if (provider_code == PAYMENT_PROVIDER_APP_STORE)
        return &app_store_urls;
    // rangeproof and unknown providers have no applicable URLs
    return nullptr;
}

LIBSESSION_C_API session_pro_backend_provider_urls
session_pro_backend_get_provider_urls(const char* provider_code) {
    // Each present field is a static, null-terminated literal; an absent one is NULL. `found`
    // distinguishes an unknown provider ({} -> found == false) from a recognised provider that
    // simply has some/all URLs absent.
    auto c = [](const std::optional<std::string_view>& u) -> const char* {
        return u ? u->data() : nullptr;
    };
    if (auto u = provider_urls(provider_code))
        return {.found = true,
                .refund_platform_url = c(u->refund_platform_url),
                .refund_support_url = c(u->refund_support_url),
                .refund_status_url = c(u->refund_status_url),
                .update_subscription_url = c(u->update_subscription_url),
                .cancel_subscription_url = c(u->cancel_subscription_url)};
    return {};
}

std::span<const std::string_view> visible_platforms() {
    static const std::array<std::string_view, 2> platforms = {
            PAYMENT_PROVIDER_GOOGLE_PLAY, PAYMENT_PROVIDER_APP_STORE};
    return platforms;
}

std::optional<ProPlanPeriod> parse_plan_period(std::string_view code) {
    // pro-wire-protocol.md §1: closed grammar. "lifetime", or "<N><unit>" with N a
    // positive integer (no leading zeros) and unit one of s/d/w/m/y. Single-unit only.
    if (code == "lifetime")
        return ProPlanPeriod{0, ProPlanUnit::lifetime};

    if (code.size() < 2)
        return std::nullopt;
    ProPlanUnit unit;
    switch (code.back()) {
        case 's': unit = ProPlanUnit::second; break;
        case 'd': unit = ProPlanUnit::day; break;
        case 'w': unit = ProPlanUnit::week; break;
        case 'm': unit = ProPlanUnit::month; break;
        case 'y': unit = ProPlanUnit::year; break;
        default: return std::nullopt;
    }

    // N = [1-9][0-9]*: reject a leading zero (or sign) up front, then require from_chars to consume
    // every remaining digit into a positive int (this also rejects overflow).
    std::string_view digits = code.substr(0, code.size() - 1);
    if (digits.empty() || digits.front() < '1' || digits.front() > '9')
        return std::nullopt;
    int count = 0;
    auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), count);
    if (ec != std::errc{} || ptr != digits.data() + digits.size())
        return std::nullopt;
    return ProPlanPeriod{count, unit};
}

LIBSESSION_C_API const char* const* session_pro_backend_visible_platforms(size_t* count) {
    // Derived from the C++ list (single source); each slug's data() is a static, null-terminated
    // literal, so the pointer array is safe to hand out as static storage.
    static const std::vector<const char*> codes = [] {
        std::vector<const char*> v;
        for (auto slug : visible_platforms())
            v.push_back(slug.data());
        return v;
    }();
    if (count)
        *count = codes.size();
    return codes.data();
}

MasterRotatingSignatures add_payment_sigs(
        const ed25519::PrivKeySpan& master_privkey,
        const ed25519::PrivKeySpan& rotating_privkey,
        std::string_view provider_code,
        std::span<const std::byte> payment_id) {
    auto msg = add_payment_message(
            master_privkey.pubkey(), rotating_privkey.pubkey(), provider_code, payment_id);
    MasterRotatingSignatures result = {};
    result.master_sig = ed25519::sign(master_privkey, msg);
    result.rotating_sig = ed25519::sign(rotating_privkey, msg);
    return result;
}

ProRequest add_payment_request(
        const ed25519::PrivKeySpan& master_privkey,
        const ed25519::PrivKeySpan& rotating_privkey,
        std::string_view provider_code,
        std::span<const std::byte> payment_id) {
    auto sigs = add_payment_sigs(master_privkey, rotating_privkey, provider_code, payment_id);
    return {add_payment_endpoint,
            application_json,
            add_payment_body(
                    master_privkey.pubkey(),
                    rotating_privkey.pubkey(),
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
        result.proof.expiry_at = as_sys_seconds(expiry_ts);
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

    std::vector<std::byte> generate_proof_message(
            std::span<const std::byte, 32> master_pubkey,
            std::span<const std::byte, 32> rotating_pubkey,
            std::chrono::sys_seconds unix_ts) {
        // Must match the generate-proof signed-request message in pro-wire-protocol.md §3.1,
        // built per §1.1.
        return pro::signed_message(
                GENERATE_PROOF_DOMAIN, master_pubkey, rotating_pubkey, epoch_seconds(unix_ts));
    }

    std::string generate_proof_body(
            std::span<const std::byte, 32> master_pubkey,
            std::span<const std::byte, 32> rotating_pubkey,
            std::chrono::sys_seconds unix_ts,
            std::span<const std::byte, 64> master_sig,
            std::span<const std::byte, 64> rotating_sig) {
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
        const ed25519::PrivKeySpan& master_privkey,
        const ed25519::PrivKeySpan& rotating_privkey,
        std::chrono::sys_seconds unix_ts) {
    auto msg = generate_proof_message(master_privkey.pubkey(), rotating_privkey.pubkey(), unix_ts);
    MasterRotatingSignatures result = {};
    result.master_sig = ed25519::sign(master_privkey, msg);
    result.rotating_sig = ed25519::sign(rotating_privkey, msg);
    return result;
}

ProRequest pro_proof_request(
        const ed25519::PrivKeySpan& master_privkey,
        const ed25519::PrivKeySpan& rotating_privkey,
        std::chrono::sys_seconds unix_ts) {
    auto sigs = pro_proof_sigs(master_privkey, rotating_privkey, unix_ts);
    return {generate_proof_endpoint,
            application_json,
            generate_proof_body(
                    master_privkey.pubkey(),
                    rotating_privkey.pubkey(),
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
    // Parse basics
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

    // --- get-pro-status (endpoint get_pro_status) ---

    std::vector<std::byte> pro_status_message(
            std::span<const std::byte, 32> master_pubkey, std::chrono::sys_seconds unix_ts) {
        // Must match the get-pro-status signed-request message in pro-wire-protocol.md §3.4, built
        // per §1.1.
        return pro::signed_message(GET_PRO_STATUS_DOMAIN, master_pubkey, epoch_seconds(unix_ts));
    }

    std::string pro_status_body(
            std::span<const std::byte, 32> master_pubkey,
            std::span<const std::byte, 64> master_sig,
            std::chrono::sys_seconds unix_ts) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"master_sig", oxenc::to_hex(master_sig)},
                {"ts", epoch_seconds(unix_ts)}}
                .dump();
    }

    // --- get-payment-details (endpoint get_payment_details) ---

    std::vector<std::byte> payment_details_message(
            std::span<const std::byte, 32> master_pubkey,
            std::chrono::sys_seconds unix_ts,
            uint32_t limit,
            std::string_view before) {
        // Must match the get-payment-details signed-request message in pro-wire-protocol.md §3.4,
        // built per §1.1. `before` is the opaque pagination cursor (§5.3), empty for the newest
        // page.
        return pro::signed_message(
                GET_PAYMENT_DETAILS_DOMAIN, master_pubkey, epoch_seconds(unix_ts), limit, before);
    }

    std::string payment_details_body(
            std::span<const std::byte, 32> master_pubkey,
            std::span<const std::byte, 64> master_sig,
            std::chrono::sys_seconds unix_ts,
            uint32_t limit,
            std::string_view before) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"master_sig", oxenc::to_hex(master_sig)},
                {"ts", epoch_seconds(unix_ts)},
                {"limit", limit},
                {"before", before}}
                .dump();
    }

    // Parse one payment item object (shared by get-pro-status's `latest_payment` and
    // get-payment-details's `items`). Appends to `errs` and returns a best-effort item on any
    // field error; the caller checks `errs`.
    ProPaymentItem parse_payment_item(
            const nlohmann::json::object_t& obj, std::vector<std::string>& errs) {
        auto status = json_require<std::string>(obj, "status", errs);
        auto plan_code = json_require<std::string>(obj, "plan", errs);
        auto plan = parse_plan_period(plan_code);
        if (!plan)
            errs.push_back(
                    fmt::format("'plan' is not a recognized billing-period code: '{}'", plan_code));
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
        // `plan` is parsed (closed grammar, §1); an unrecognized code is a protocol
        // error (handled above). payment_provider / payment_id are opaque strings that pass through
        // as-is.
        if (plan)
            item.plan = *plan;
        item.payment_provider = std::move(payment_provider);
        item.payment_id = std::move(payment_id);
        item.auto_renewing = auto_renewing;
        item.purchased_at = sys_ms_from_seconds(purchased_ts);
        item.redeemed_at = as_sys_seconds(redeemed_ts);
        item.expiry_at = as_sys_seconds(expiry_ts);
        item.grace_period_duration = std::chrono::seconds(grace_period_duration);
        item.platform_refund_expiry_at = as_sys_seconds(platform_refund_expiry_ts);
        item.revoked_at = sys_ms_from_seconds(revoked_ts);
        item.refund_requested_at = as_sys_seconds(refund_requested_ts);
        return item;
    }

}  // namespace

b64 pro_status_sig(const ed25519::PrivKeySpan& master_privkey, std::chrono::sys_seconds unix_ts) {
    auto msg = pro_status_message(master_privkey.pubkey(), unix_ts);
    return ed25519::sign(master_privkey, msg);
}

ProRequest pro_status_request(
        const ed25519::PrivKeySpan& master_privkey, std::chrono::sys_seconds unix_ts) {
    auto sig = pro_status_sig(master_privkey, unix_ts);
    return {get_pro_status_endpoint,
            application_json,
            pro_status_body(master_privkey.pubkey(), sig, unix_ts)};
}

b64 payment_details_sig(
        const ed25519::PrivKeySpan& master_privkey,
        std::chrono::sys_seconds unix_ts,
        uint32_t limit,
        std::string_view before) {
    auto msg = payment_details_message(master_privkey.pubkey(), unix_ts, limit, before);
    return ed25519::sign(master_privkey, msg);
}

ProRequest payment_details_request(
        const ed25519::PrivKeySpan& master_privkey,
        std::chrono::sys_seconds unix_ts,
        uint32_t limit,
        std::string_view before) {
    auto sig = payment_details_sig(master_privkey, unix_ts, limit, before);
    return {get_payment_details_endpoint,
            application_json,
            payment_details_body(master_privkey.pubkey(), sig, unix_ts, limit, before)};
}

ProStatusResponse parse_pro_status(std::string_view json) {
    // Parse basics
    ProStatusResponse result = {};
    std::vector<std::string> errs;
    auto result_obj = read_envelope(json, result, errs);
    if (!result || !errs.empty()) {
        if (!errs.empty())
            set_protocol_error(result, errs.front());
        return result;
    }

    // Parse payload. The account Pro status is an opaque string code ("never"/"active"/"expired");
    // an unknown value passes through unchanged (§1: enums are codes) rather than failing the
    // parse.
    result.user_status = json_require<std::string>(result_obj, "user_status", errs);

    uint32_t error_report = json_require<uint32_t>(result_obj, "error_report", errs);
    if (error_report >= SESSION_PRO_BACKEND_GET_PRO_STATUS_ERROR_REPORT_COUNT) {
        errs.push_back(fmt::format("Error report value was out-of-bounds: {}", error_report));
        set_protocol_error(result, errs.front());
        return result;
    }
    result.error_report =
            static_cast<SESSION_PRO_BACKEND_GET_PRO_STATUS_ERROR_REPORT>(error_report);

    result.auto_renewing = json_require<bool>(result_obj, "auto_renewing", errs);

    int64_t expiry_ts = json_require<int64_t>(result_obj, "expiry_ts", errs);
    int64_t grace_period_duration =
            json_require<int64_t>(result_obj, "grace_period_duration", errs);
    int64_t refund_requested_ts = json_require<int64_t>(result_obj, "refund_requested_ts", errs);
    result.expiry_at = as_sys_seconds(expiry_ts);
    result.grace_period_duration = std::chrono::seconds(grace_period_duration);
    result.refund_requested_at = as_sys_seconds(refund_requested_ts);

    // `latest_payment` is a single payment item, or null when the account has no payments.
    if (auto it = result_obj.find("latest_payment"); it == result_obj.end()) {
        errs.push_back("Key 'latest_payment' is missing");
    } else if (it->second.is_null()) {
        // No payments: latest_payment stays std::nullopt.
    } else if (it->second.is_object()) {
        auto obj = it->second.get<nlohmann::json::object_t>();
        auto item = parse_payment_item(obj, errs);
        if (errs.empty())
            result.latest_payment = std::move(item);
    } else {
        errs.push_back(fmt::format(
                "Key value (latest_payment, {}) was not an object or null", it->second.dump(1)));
    }

    if (!errs.empty())
        set_protocol_error(result, errs.front());
    return result;
}

PaymentDetailsResponse parse_payment_details(std::string_view json) {
    // Parse basics
    PaymentDetailsResponse result = {};
    std::vector<std::string> errs;
    auto result_obj = read_envelope(json, result, errs);
    if (!result || !errs.empty()) {
        if (!errs.empty())
            set_protocol_error(result, errs.front());
        return result;
    }

    result.payments_total = json_require<uint32_t>(result_obj, "payments_total", errs);

    auto array = json_require<nlohmann::json::array_t>(result_obj, "items", errs);
    result.items.reserve(array.size());
    for (size_t index = 0; index < array.size(); index++) {
        const auto& it = array[index];
        if (!it.is_object()) {
            errs.push_back(fmt::format(
                    "Aborting parse, 'items[{}]' was not an object: {}", index, it.dump(1)));
            break;
        }

        auto obj = it.get<nlohmann::json::object_t>();
        auto item = parse_payment_item(obj, errs);
        if (!errs.empty())
            break;
        result.items.emplace_back(std::move(item));
    }

    // `next_cursor` is the opaque keyset cursor (§5.3), or null at end-of-data.
    if (auto it = result_obj.find("next_cursor"); it == result_obj.end()) {
        errs.push_back("Key 'next_cursor' is missing");
    } else if (it->second.is_null()) {
        // End of data: next_cursor stays std::nullopt.
    } else if (it->second.is_string()) {
        result.next_cursor = it->second.get<std::string>();
    } else {
        errs.push_back(fmt::format(
                "Key value (next_cursor, {}) was not a string or null", it->second.dump(1)));
    }

    if (!errs.empty())
        set_protocol_error(result, errs.front());
    return result;
}

namespace {

    // --- refund / set-payment-refund-requested (endpoint set_payment_refund_requested) ---

    std::vector<std::byte> refund_message(
            std::span<const std::byte, 32> master_pubkey,
            std::chrono::sys_seconds unix_ts,
            std::chrono::sys_seconds refund_requested_at,
            std::string_view provider_code,
            std::span<const std::byte> payment_id) {
        // Must match the set-payment-refund-requested signed-request message in
        // pro-wire-protocol.md §3.3 (+ §3.5 for payment_id), built per §1.1.
        return pro::signed_message(
                SET_PAYMENT_REFUND_REQUESTED_DOMAIN,
                master_pubkey,
                epoch_seconds(unix_ts),
                epoch_seconds(refund_requested_at),
                provider_code,
                to_string_view(payment_id));
    }

    std::string refund_body(
            std::span<const std::byte, 32> master_pubkey,
            std::chrono::sys_seconds unix_ts,
            std::chrono::sys_seconds refund_requested_at,
            std::string_view provider_code,
            std::string_view payment_id,
            std::span<const std::byte, 64> master_sig) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"ts", epoch_seconds(unix_ts)},
                {"refund_requested_ts", epoch_seconds(refund_requested_at)},
                {"payment_tx", {{"provider", provider_code}, {"payment_id", payment_id}}},
                {"master_sig", oxenc::to_hex(master_sig)}}
                .dump();
    }

}  // namespace

b64 refund_sig(
        const ed25519::PrivKeySpan& master_privkey,
        std::chrono::sys_seconds unix_ts,
        std::chrono::sys_seconds refund_requested_at,
        std::string_view provider_code,
        std::span<const std::byte> payment_id) {
    auto msg = refund_message(
            master_privkey.pubkey(), unix_ts, refund_requested_at, provider_code, payment_id);
    return ed25519::sign(master_privkey, msg);
}

ProRequest refund_request(
        const ed25519::PrivKeySpan& master_privkey,
        std::chrono::sys_seconds unix_ts,
        std::chrono::sys_seconds refund_requested_at,
        std::string_view provider_code,
        std::span<const std::byte> payment_id) {
    auto sig = refund_sig(master_privkey, unix_ts, refund_requested_at, provider_code, payment_id);
    return {set_refund_endpoint,
            application_json,
            refund_body(
                    master_privkey.pubkey(),
                    unix_ts,
                    refund_requested_at,
                    provider_code,
                    to_string_view(payment_id),
                    sig)};
}

SetPaymentRefundRequestedResponse parse_refund(std::string_view json) {
    // Parse basics
    SetPaymentRefundRequestedResponse result = {};
    std::vector<std::string> errs;
    auto result_obj = read_envelope(json, result, errs);
    if (!result || !errs.empty()) {
        if (!errs.empty())
            set_protocol_error(result, errs.front());
        return result;
    }

    // Parse payload
    result.updated = json_require<bool>(result_obj, "updated", errs);
    if (!errs.empty())
        set_protocol_error(result, errs.front());
    return result;
}
}  // namespace session::pro_backend

using namespace session;
using namespace session::pro_backend;

// error / error_code strings libsession synthesizes when it cannot parse or build the C response.
static constexpr const char* C_PARSE_ERROR_OUT_OF_MEMORY = "Ran out-of-memory creating C response";
static constexpr const char* C_PARSE_ERROR_INVALID_ARGS = "One or more C arguments were NULL";
static constexpr const char* C_INVALID_RESPONSE_CODE = "invalid_response";

// Map the C++ ResponseStatus to the C enum.
static SESSION_PRO_BACKEND_RESPONSE_STATUS c_response_status(ResponseStatus status) {
    switch (status) {
        case ResponseStatus::Ok: return SESSION_PRO_BACKEND_RESPONSE_STATUS_OK;
        case ResponseStatus::Fail: return SESSION_PRO_BACKEND_RESPONSE_STATUS_FAIL;
        case ResponseStatus::Error: break;
    }
    return SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
}

// Fill a C response header from a C++ ResponseBase. error_code/error point into `cpp`
// (NUL-terminated via c_str(), NULL when absent); `cpp` is owned by the response's
// header.internal_.
static void fill_c_header(session_pro_backend_response_header& header, const ResponseBase& cpp) {
    header.status = c_response_status(cpp.status);
    header.error_code = cpp.error_code ? cpp.error_code->c_str() : nullptr;
    header.error = cpp.error ? cpp.error->c_str() : nullptr;
}

// Project a parsed C++ item to its C view. The string members are pointers into `src` (valid while
// the owning response lives) -- kept file-local rather than a public conversion operator, and
// taking a non-const lvalue ref so a temporary (whose aliased strings would immediately dangle)
// can't bind.
static session_pro_backend_pro_revocation_item to_c(ProRevocationItem& src) {
    return {
            .revocation_tag = reinterpret_cast<const unsigned char*>(src.revocation_tag.data()),
            .effective_ts = session::epoch_seconds(src.effective_at),
    };
}

static session_pro_backend_pro_payment_item to_c(ProPaymentItem& src) {
    return {
            .status = src.status.c_str(),
            .plan_count = src.plan.count,
            .plan_unit = static_cast<SESSION_PRO_BACKEND_PLAN_UNIT>(src.plan.unit),
            .payment_provider = src.payment_provider.c_str(),
            .auto_renewing = src.auto_renewing,
            .purchased_ts = epoch_seconds_double(src.purchased_at),
            .redeemed_ts = session::epoch_seconds(src.redeemed_at),
            .expiry_ts = session::epoch_seconds(src.expiry_at),
            .grace_period_duration = src.grace_period_duration.count(),
            .platform_refund_expiry_ts = session::epoch_seconds(src.platform_refund_expiry_at),
            .revoked_ts = epoch_seconds_double(src.revoked_at),
            .refund_requested_ts = session::epoch_seconds(src.refund_requested_at),
            .payment_id = src.payment_id.c_str(),
    };
}

// Owns the parsed C++ response object that a C response's fields point into, plus the C item-view
// array. `header.internal_` points here; the response's *_free deletes it. (Item-less responses own
// the bare C++ object directly.)
struct GetProRevocationsCResponse : GetProRevocationsResponse {
    std::vector<session_pro_backend_pro_revocation_item> item_views;
};
struct GetPaymentDetailsCResponse : PaymentDetailsResponse {
    std::vector<session_pro_backend_pro_payment_item> item_views;
};

// Free any C response: delete the owned object (of concrete type `Owned`, as stored by the matching
// *_parse) behind header.internal_, then zero the struct. `Owned` is a proof/refund response or a
// *CResponse holder -- all deriving from ResponseBase.
template <std::derived_from<ResponseBase> Owned, typename Response>
static void c_free_response(Response* response) {
    if (response) {
        delete static_cast<Owned*>(response->header.internal_);
        *response = {};
    }
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
    result.data = span_u8{reinterpret_cast<unsigned char*>(owned->data.data()), owned->data.size()};
    result.success = true;
    return result;
}

// Fill a session_pro_backend_request's error buffer from a caught exception.
static void c_request_error(session_pro_backend_request& result, const std::exception& e) {
    result.error_count = session::copy_c_str(result.error, sizeof(result.error), e.what()) - 1;
}

LIBSESSION_C_API session_pro_backend_request session_pro_backend_add_pro_payment_request_build(
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        const unsigned char* rotating_privkey,
        size_t rotating_privkey_len,
        const char* provider_code,
        const unsigned char* payment_id,
        size_t payment_id_len) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(add_payment_request(
                ed25519::PrivKeySpan{master_privkey, master_privkey_len},
                ed25519::PrivKeySpan{rotating_privkey, rotating_privkey_len},
                provider_code,
                to_byte_span(payment_id, payment_id_len)));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_request session_pro_backend_generate_pro_proof_request_build(
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        const unsigned char* rotating_privkey,
        size_t rotating_privkey_len,
        int64_t ts) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(pro_proof_request(
                ed25519::PrivKeySpan{master_privkey, master_privkey_len},
                ed25519::PrivKeySpan{rotating_privkey, rotating_privkey_len},
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

LIBSESSION_C_API session_pro_backend_request session_pro_backend_get_pro_status_request_build(
        const unsigned char* master_privkey, size_t master_privkey_len, int64_t ts) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(pro_status_request(
                ed25519::PrivKeySpan{master_privkey, master_privkey_len},
                session::as_sys_seconds(ts)));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_request session_pro_backend_get_payment_details_request_build(
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        uint32_t limit,
        const char* before) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(payment_details_request(
                ed25519::PrivKeySpan{master_privkey, master_privkey_len},
                session::as_sys_seconds(ts),
                limit,
                before ? std::string_view{before} : std::string_view{}));
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

    try {
        // add-payment and generate-proof share the proof-response shape; either parser works.
        auto* owned = new AddProPaymentResponse(parse_add_payment({json, json_len}));
        result.header.internal_ = owned;
        fill_c_header(result.header, *owned);

        // Success and error responses fold into one path -- different fields populated.
        const auto& p = owned->proof;
        result.proof.version = p.version;
        result.proof.expiry_ts = session::epoch_seconds(p.expiry_at);
        std::memcpy(
                result.proof.revocation_tag.data, p.revocation_tag.data(), p.revocation_tag.size());
        std::memcpy(
                result.proof.rotating_pubkey.data,
                p.rotating_pubkey.data(),
                p.rotating_pubkey.size());
        std::memcpy(result.proof.sig.data, p.sig.data(), p.sig.size());
    } catch (const std::exception&) {
        delete static_cast<AddProPaymentResponse*>(result.header.internal_);
        result = {};
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_OUT_OF_MEMORY;
    }
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

    try {
        auto* owned = new GetProRevocationsCResponse{parse_revocations({json, json_len}), {}};
        result.header.internal_ = owned;
        fill_c_header(result.header, *owned);
        result.ticket = owned->ticket;
        result.retry_in = owned->retry_in.count();
        result.retain_for = owned->retain_for.count();

        owned->item_views.reserve(owned->items.size());
        for (auto& src : owned->items)
            owned->item_views.push_back(to_c(src));
        result.items = owned->item_views.data();
        result.items_count = owned->item_views.size();
    } catch (const std::exception&) {
        delete static_cast<GetProRevocationsCResponse*>(result.header.internal_);
        result = {};
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_OUT_OF_MEMORY;
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_get_pro_status_response
session_pro_backend_get_pro_status_response_parse(const char* json, size_t json_len) {
    session_pro_backend_get_pro_status_response result = {};
    if (!json) {
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_INVALID_ARGS;
        return result;
    }

    try {
        using session::epoch_seconds;
        auto* owned = new ProStatusResponse(parse_pro_status({json, json_len}));
        result.header.internal_ = owned;
        fill_c_header(result.header, *owned);

        result.status = owned->user_status.c_str();
        result.error_report = owned->error_report;
        result.auto_renewing = owned->auto_renewing;
        result.expiry_ts = epoch_seconds(owned->expiry_at);
        result.grace_period_duration = owned->grace_period_duration.count();
        result.refund_requested_ts = epoch_seconds(owned->refund_requested_at);
        result.has_latest_payment = owned->latest_payment.has_value();
        if (owned->latest_payment)
            result.latest_payment = to_c(*owned->latest_payment);
    } catch (const std::exception&) {
        delete static_cast<ProStatusResponse*>(result.header.internal_);
        result = {};
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_OUT_OF_MEMORY;
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_get_payment_details_response
session_pro_backend_get_payment_details_response_parse(const char* json, size_t json_len) {
    session_pro_backend_get_payment_details_response result = {};
    if (!json) {
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_INVALID_ARGS;
        return result;
    }

    try {
        auto* owned = new GetPaymentDetailsCResponse{parse_payment_details({json, json_len}), {}};
        result.header.internal_ = owned;
        fill_c_header(result.header, *owned);

        result.payments_total = owned->payments_total;
        result.next_cursor = owned->next_cursor ? owned->next_cursor->c_str() : nullptr;

        owned->item_views.reserve(owned->items.size());
        for (auto& src : owned->items)
            owned->item_views.push_back(to_c(src));
        result.items = owned->item_views.data();
        result.items_count = owned->item_views.size();
    } catch (const std::exception&) {
        delete static_cast<GetPaymentDetailsCResponse*>(result.header.internal_);
        result = {};
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_OUT_OF_MEMORY;
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_request
session_pro_backend_set_payment_refund_requested_request_build(
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        int64_t refund_requested_ts,
        const char* provider_code,
        const unsigned char* payment_id,
        size_t payment_id_len) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(refund_request(
                ed25519::PrivKeySpan{master_privkey, master_privkey_len},
                session::as_sys_seconds(ts),
                session::as_sys_seconds(refund_requested_ts),
                provider_code,
                to_byte_span(payment_id, payment_id_len)));
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

    try {
        auto* owned = new SetPaymentRefundRequestedResponse(parse_refund({json, json_len}));
        result.header.internal_ = owned;
        fill_c_header(result.header, *owned);
        result.updated = owned->updated;
    } catch (const std::exception&) {
        delete static_cast<SetPaymentRefundRequestedResponse*>(result.header.internal_);
        result = {};
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_OUT_OF_MEMORY;
    }
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
    c_free_response<AddProPaymentResponse>(response);
}

LIBSESSION_C_API void session_pro_backend_get_pro_revocations_response_free(
        session_pro_backend_get_pro_revocations_response* response) {
    c_free_response<GetProRevocationsCResponse>(response);
}

LIBSESSION_C_API void session_pro_backend_get_pro_status_response_free(
        session_pro_backend_get_pro_status_response* response) {
    c_free_response<ProStatusResponse>(response);
}

LIBSESSION_C_API void session_pro_backend_get_payment_details_response_free(
        session_pro_backend_get_payment_details_response* response) {
    c_free_response<GetPaymentDetailsCResponse>(response);
}

LIBSESSION_C_API void session_pro_backend_set_payment_refund_requested_response_free(
        session_pro_backend_set_payment_refund_requested_response* response) {
    c_free_response<SetPaymentRefundRequestedResponse>(response);
}
