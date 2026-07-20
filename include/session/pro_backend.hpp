#pragma once

#include <oxenc/hex.h>
#include <session/pro_backend.h>

#include <chrono>
#include <optional>
#include <session/session_protocol.hpp>
#include <session/types.hpp>
#include <span>
#include <string>

/// Helper functions to construct payloads to communicate with the Session Pro Backend. The data
/// structures here are largely bindings to the endpoints exposed on the Session Pro Backend; the
/// wire format they produce and parse is byte-pinned in pro-wire-protocol.md (the authoritative
/// spec).
///
/// The high level summary of the functionality in this file. Clients can:
///
/// 1. Build a request with `add_payment_request(...)` from a Session Pro payment and submit its
///    `{endpoint, content_type, data}` to the backend to register the specified Ed25519 keys.
///
///    Parse the server's reply with `parse_add_payment(...)`. Clients should validate the response
///    and update their `UserProfile` by constructing a `ProConfig` with the `proof` from the
///    response and filling in the relevant rotating private key that the proof was authorised for.
///
///    The server will only respond successfully if it can also independently verify the purchase
///    otherwise an error is returned and can be read from the `ResponseBase` after parsing the
///    raw response.
///
/// 2. Attach the `ProProof` constructed from (1) into their messages. Libsession has helper
///    functions to embed the proof into their messages via the helper functions in the Session
///    Protocol header file. This is done by assigning the `ProProof` into the
///    `Content.proMessage.proof` protobuf structure. Additionally the caller will use
///    `pro_features_for_utf8/16` to determine the correct flags to assign the `features` to
///    `Content.proMessage.flags` in the protobuf structure.
///
///    Lastly the high-level libsession encoding functions accept the rotating private key to which
///    the protobuf encoded plaintext content will be signed and the payload augmented as necessary
///    to enable pro features for that message.
///
/// 3. Periodically poll the global revocation list which overrides the validity of current
///    circulating proofs. This is done by building the request via `revocations_request(...)` and
///    sending it to the backend.
///
///    Parse the reply with `parse_revocations(...)`, which contains the list that clients should
///    cache. Any incoming messages with a Pro proof that is in the list of revoked proofs will not
///    be entitled to Pro features.
///
/// 4. Query the status (and optionally payment history) of a user's Session Pro Master Ed25519 key
///    by building a `payment_details_request(...)` query and submitting it.
///
///    Parse the reply with `parse_payment_details(...)`, which they can use to populate their
///    client's payment history.
///
/// See the unit tests for examples of using the APIs mentioned.

namespace session::pro_backend {

using namespace oxenc::literals;

/// The Session Pro Backend's Ed25519 public key: verify that a proof was issued by the backend by
/// checking its signature against this key (see ProProof::verify_signature). This is the current
/// backend signing key (test deployment, expected to carry through to production).
constexpr auto PUBKEY = "479ffca8bcec7b4a0f0f7afe48b8a6d15635a8c7ff15ad16add05752c19414d4"_hex_u;
static_assert(PUBKEY.size() == 32);

/// The X25519 form of `PUBKEY` (the same key converted via crypto_sign_ed25519_pk_to_curve25519),
/// provided as a constant for clients that need the X25519 pubkey (e.g. to establish an encrypted
/// channel to the backend) without doing the conversion themselves. A unit test asserts these bytes
/// match the runtime conversion of `PUBKEY`, so the two cannot drift.
constexpr auto PUBKEY_X25519 =
        "ce5a75f64b6c43db6c1374d362c3ea9d85951c4f42a3d04cf94f87822d4f803b"_hex_u;
static_assert(PUBKEY_X25519.size() == 32);

/// The Session Pro Backend's production base URL: POST a request body to `<URL>/<endpoint>` (see
/// the SESSION_PRO_BACKEND_*_ENDPOINT paths). This is the canonical production value; a client may
/// point at a different dev/test server if it chooses.
constexpr std::string_view URL = "https://pro.session.codes";

/// Response outcome category (the wire `status`, spec §5). CLOSED/exhaustive by design: the backend
/// will never add a fourth value, so libsession treats any unrecognized wire status as a protocol
/// error (fail-closed) rather than passing it through. New categories/detail arrive via
/// `error_code`, which IS open/extensible.
enum class ResponseStatus {
    Ok,    ///< Success; the response's payload fields are populated.
    Fail,  ///< Request rejected on client input / a precondition; retrying the identical request
           ///< won't help (except the `stale_request` error_code). See `error_code`.
    Error,  ///< Backend fault; the client did nothing wrong and the same request may succeed later.
};

struct ResponseBase {
    /// Outcome category; `success()` is the usual check. See ResponseStatus.
    ResponseStatus status = ResponseStatus::Ok;

    /// On non-Ok, a stable machine-readable slug identifying the outcome (spec §5.1), e.g.
    /// "unknown_payment", "expired", "stale_request". std::nullopt on success. Opaque and
    /// forward-compatible: map known slugs to localized text; for an unrecognized one fall back to
    /// `error` / the `status` category. (libsession synthesizes "invalid_response" if it cannot
    /// parse the backend's reply at all.)
    std::optional<std::string> error_code;

    /// On non-Ok, an English diagnostic string. NOT user-facing text (that comes from mapping
    /// `error_code` to a localized string); show it only when the slug is unrecognized, and it is
    /// always safe to log. std::nullopt on success.
    std::optional<std::string> error;

    /// Contextually convertible to bool: `if (response) { ... }` is true iff the request succeeded
    /// (status == Ok). Explicit, so it can't silently leak into arithmetic or comparisons.
    explicit operator bool() const { return status == ResponseStatus::Ok; }
};

struct MasterRotatingSignatures {
    array_uc64 master_sig;
    array_uc64 rotating_sig;
};

/// Per-provider support/management URLs. These are identical for every user (not translation data),
/// so libsession owns them as the single source of truth rather than each client duplicating them;
/// the human-readable provider/store *names* are translation data and remain the client's job.
/// Returned by `provider_urls()`. The views point at static, null-terminated storage.
struct ProviderUrls {
    std::string_view refund_platform_url;      ///< Native store refund flow
    std::string_view refund_support_url;       ///< Session support page for requesting a refund
    std::string_view refund_status_url;        ///< Where a user checks refund status
    std::string_view update_subscription_url;  ///< Manage/update the subscription
    std::string_view cancel_subscription_url;  ///< Cancel the subscription
};

/// Look up the support/management URLs for a provider code (see
/// SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*). Returns std::nullopt for a provider with no
/// applicable URLs (an unknown code, or e.g. rangeproof) — so callers test the optional rather than
/// hunting for empty members.
std::optional<ProviderUrls> provider_urls(std::string_view provider_code);

/// Endpoint + content-type + opaque payload for a request to be POSTed to the Session Pro backend,
/// returned by the `*_request()` helpers below. Callers relay `data` verbatim under `content_type`
/// and never inspect or assume its format -- libsession owns the wire encoding.
struct ProRequest {
    /// Endpoint path relative to the backend base URL, e.g. "add_pro_payment". As returned from a
    /// `*_request()` function this points at a static, null-terminated string, so using
    /// `endpoint.data()` as a C string is valid.
    std::string_view endpoint;

    /// Content type to send as the request's `Content-Type` header. Points at a static,
    /// null-terminated string. Clients MUST relay this verbatim and MUST NOT assume a particular
    /// format: `data` is libsession's opaque payload for the backend and libsession owns the wire
    /// encoding, which may change without client involvement.
    std::string_view content_type;

    /// The opaque request payload to POST to `endpoint`. This is libsession's data for the backend;
    /// clients relay it untouched and must not parse, inspect, or modify it.
    std::string data;
};

/// Register a new Session Pro payment with the backend (endpoint `add_pro_payment`). The payment is
/// registered under the master key and authorises the rotating key to use the resulting proof, so
/// that proof can be attached to messages signed by the rotating key to entitle them to Pro.
///
/// `add_payment_sigs` computes just the master+rotating signatures over the request;
/// `add_payment_request` builds the whole request (computing the signatures internally) and returns
/// the endpoint + JSON body. Both throw if a key is not a 32-byte Ed25519 seed or 64-byte libsodium
/// key.
///
/// Inputs:
/// - `master_privkey` / `rotating_privkey` -- 32-byte Ed25519 seed or 64-byte libsodium private key
/// - `provider_code` -- provider code string the payment is coming from (see
///   SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*)
/// - `payment_id` -- opaque payment identifier from the provider (multi-part providers fold their
///   parts into this one value per a backend-defined composite; hashed verbatim)
MasterRotatingSignatures add_payment_sigs(
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        std::string_view provider_code,
        std::span<const uint8_t> payment_id);

ProRequest add_payment_request(
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        std::string_view provider_code,
        std::span<const uint8_t> payment_id);

/// Common base for the responses that carry a freshly-issued Session Pro proof: both add-payment
/// and generate-proof reply with exactly a proof. `AddProPaymentResponse` and
/// `GenerateProProofResponse` are distinct types (each parsed by its own free function below) that
/// share `proof` today but can diverge independently. `proof` is the raw parse result, convertible
/// to a config::ProProof.
struct ProProofResponse : ResponseBase {
    ProProof proof;
};

/// Response to `add_payment_request` (endpoint `add_pro_payment`). On failure the reason(s) are in
/// `errors` (the backend sends a human-readable message, including for already-redeemed /
/// unknown-payment); check `success()`.
struct AddProPaymentResponse : ProProofResponse {};

/// Response to `pro_proof_request` (endpoint `generate_pro_proof`).
struct GenerateProProofResponse : ProProofResponse {};

/// Parse the reply to an add-payment / generate-proof request. On failure `status` is set to an
/// error state and `errors` is populated; on success `proof` holds the issued proof.
AddProPaymentResponse parse_add_payment(std::string_view json);
GenerateProProofResponse parse_pro_proof(std::string_view json);

/// Request a new Session Pro proof from the backend (endpoint `generate_pro_proof`). The master key
/// must already have a prior, still-active payment registered; this pairs a (new) rotating key to a
/// freshly-issued proof.
///
/// `pro_proof_sigs` computes the master+rotating signatures; `pro_proof_request` builds the whole
/// request (signing internally) and returns the endpoint + JSON body. Both throw on an
/// incorrectly-sized key.
///
/// Inputs:
/// - `master_privkey` / `rotating_privkey` -- 32-byte Ed25519 seed or 64-byte libsodium private key
/// - `unix_ts` -- Unix timestamp for the request
MasterRotatingSignatures pro_proof_sigs(
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        sys_seconds unix_ts);

ProRequest pro_proof_request(
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        sys_seconds unix_ts);

/// Build a request for the current Session Pro revocation list (endpoint `get_pro_revocations`).
/// This request is unsigned. The caller retains each returned item for the response's `retain_for`
/// window after first seeing it (memory-only aging) and polls again after `retry_in`.
///
/// Inputs:
/// - `ticket` -- 64-bit monotonic revocation-list iteration. Pass 0 if unknown; otherwise the
/// latest
///   known `ticket` from a prior `GetProRevocationsResponse`, so the backend may omit an unchanged
///   list.
ProRequest revocations_request(std::int64_t ticket);

struct ProRevocationItem {
    /// 32-byte opaque revocation tag identifying a proof
    array_uc32 revocation_tag;

    /// A matching proof is revoked once the client's clock reaches this unix timestamp (not before)
    sys_seconds effective_at;
};

struct GetProRevocationsResponse : ResponseBase {
    /// 64-bit monotonic integer for the latest revocation list iteration.
    /// Update the caller's ticket to this value for subsequent requests.
    std::int64_t ticket;

    /// Recommended interval to wait before polling the revocation list again.
    std::chrono::seconds retry_in;

    /// How long a client should retain each item after first seeing it, for memory-only local
    /// aging (roughly the maximum proof-validity window). Applied as `seen + retain_for`; holding
    /// an entry longer is harmless.
    std::chrono::seconds retain_for;

    /// List of revoked Session Pro proofs
    std::vector<ProRevocationItem> items;
};

/// Parse the reply to a `revocations_request`. On failure `status` is set to an error state and
/// `errors` is populated.
GetProRevocationsResponse parse_revocations(std::string_view json);

/// Query a master key's Session Pro payment/subscription details and history (endpoint
/// `get_pro_details`). `payment_details_sig` computes the master signature;
/// `payment_details_request` builds the whole request (signing internally) and returns the endpoint
/// + JSON body. Both throw on an incorrectly-sized key.
///
/// Inputs:
/// - `master_privkey` -- 32-byte Ed25519 seed or 64-byte libsodium master private key
/// - `unix_ts` -- Unix timestamp for the request
/// - `count` -- maximum number of historical payments to request
array_uc64 payment_details_sig(
        std::span<const uint8_t> master_privkey, sys_seconds unix_ts, uint32_t count);

ProRequest payment_details_request(
        std::span<const uint8_t> master_privkey, sys_seconds unix_ts, uint32_t count);

struct ProPaymentItem {
    /// Describes the current status of the consumption of the payment for Session Pro entitlement
    /// The status should be used to determine which timestamps should be used.
    ///
    /// For example, a payment can be in a redeemed state whilst also have a refunded timestamp set
    /// if the payment was refunded and then the refund was reversed. We preserve all timestamps for
    /// book-keeping purposes.
    std::string status;

    /// Billing-period code that was purchased (e.g. "1m"/"3m"/"1y"); opaque, may be free-form for
    /// non-period plans. The client maps/parses it for display.
    std::string plan;

    /// Provider code this payment came from (e.g. "google_play"); opaque -- an unknown value passes
    /// through as-is for the client to handle.
    std::string payment_provider;

    /// Flag indicating whether or not this payment will automatically bill itself at the end of the
    /// billing cycle.
    bool auto_renewing;

    /// Provider purchase time (when the upstream provider recorded the purchase). Always set.
    /// Carries the provider's sub-second precision as a millisecond-resolution `sys_ms`; the wire
    /// sends it as a float of seconds.
    sys_ms purchased_at;

    /// Unix timestamp of when the payment was redeemed. 0 if not activated
    sys_seconds redeemed_at;

    /// Unix timestamp of when the payment was expiry. 0 if not activated
    sys_seconds expiry_at;

    /// Duration of the grace period, e.g. when the payment provider will start to attempt to renew
    /// the Session Pro subscription. During the period between
    /// [expiry_at, expiry_at + grace_period_duration] the user continues to have
    /// entitlement to Session Pro. This value is only applicable if `auto_renewing` is `true`.
    std::chrono::seconds grace_period_duration;

    /// Unix deadline timestamp of when the user is able to refund the subscription via the payment
    /// provider. Thereafter the user must initiate a refund manually via Session support.
    sys_seconds platform_refund_expiry_at;

    /// Provider revocation instant (when the payment was revoked). Epoch (0) if not applicable.
    /// Carries the provider's sub-second precision as a millisecond-resolution `sys_ms`; the wire
    /// sends it as a float of seconds.
    sys_ms revoked_at;

    /// UNIX timestamp at which a refund request was requested for this payment. This is set to 0
    /// if no refund has been requested for this payment yet.
    sys_seconds refund_requested_at;

    /// Opaque payment identifier (the value passed at add-payment; multi-part providers fold their
    /// parts in per the backend-defined composite -- libsession does not interpret it).
    /// Confidential; store appropriately.
    std::string payment_id;
};

struct GetProDetailsResponse : ResponseBase {
    /// List of payment items for the master public key
    std::vector<ProPaymentItem> items;

    /// Current Session Pro entitlement status for the master public key
    std::string user_status;

    /// Error code that indicates that the Session Pro Backend encountered an error book-keeping
    /// Session Pro entitlement for the user. If this value is not `SUCCESS` implementing clients
    /// can optionally prompt the user that they should contact support for investigation.
    SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT error_report;

    /// Flag to indicate if the user will automatically renew their subscription.
    bool auto_renewing;

    /// Deadline UNIX timestamp that a user is entitled to Session Pro Proofs. The user is allowed
    /// to request a Session Pro Proof from the Pro Backend up until this timestamp. Thereafter
    /// the user is no longer entitled to Session Pro. This deadline includes the grace period if
    /// applicable.
    ///
    /// The grace period is enabled when `auto_renewing` is `true` and is the extra period after a
    /// user's subscription has elapsed that the payment provider allocates to continue entitlement
    /// to Session Pro whilst attempting to execute the billing of a Session Pro subscription.
    ///
    /// This allows a user to maintain entitlement to Session Pro across billing cycles by giving
    /// some leeway as to the time required for the payment provider to successfully bill the user.
    /// This expiry timestamp is hence calculated as:
    ///
    ///   expiry_at = subscription_expiry + grace_period_duration
    ///
    /// E.g. The subscription expiry timestamp can be calculated by subtracting
    /// `grace_period_duration` to determine if the user is currently in a grace period. Some
    /// platforms do not support a grace period so this value can be 0.
    ///
    /// Finally, a reminder that the grace period is not activated or included in this deadline
    /// timestamp if they have configured subscription `auto_renewing` to be off.
    ///
    /// This timestamp may be in the past if the user no longer has active payments. Overtime the
    /// Pro Backend may prune user history and so after long lapses of activity, a user's
    /// subscription history may be deleted.
    sys_seconds expiry_at;

    /// Duration that a user is entitled to for their grace period. This value is to be ignored if
    /// `auto_renewing` is false. It can be used to calculate the subscription expiry timestamp by
    /// subtracting it from `expiry_at`.
    std::chrono::seconds grace_period_duration;

    /// UNIX timestamp at which a refund request was requested by this user. This timestamp comes
    /// from the latest payment that the backend has deemed to be active for the user (e.g. the
    /// payment associated with the `expiry_at`). This value is 0 if no refund has been
    /// requested on the active payment.
    sys_seconds refund_requested_at;

    /// Total number of payments known by the backend for the user. This may be greater than the
    /// length of items if the request, requested less than the number of payments the user has.
    uint32_t payments_total;
};

/// Parse the reply to a `payment_details_request`. On failure `status` is set to an error state and
/// `errors` is populated.
GetProDetailsResponse parse_payment_details(std::string_view json);

/// Record a refund request against an existing Session Pro payment (endpoint
/// `set_payment_refund_requested`). `refund_sig` computes the master signature; `refund_request`
/// builds the whole request (signing internally) and returns the endpoint + JSON body. Both throw
/// on an incorrectly-sized key.
///
/// Inputs:
/// - `master_privkey` -- 32-byte Ed25519 seed or 64-byte libsodium master private key
/// - `unix_ts` -- Unix timestamp for the request
/// - `refund_requested_at` -- timestamp to record as when the refund was requested
/// - `provider_code` -- provider code string the payment is from (see
///   SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*)
/// - `payment_id` -- opaque payment identifier from the provider (hashed verbatim)
array_uc64 refund_sig(
        std::span<const uint8_t> master_privkey,
        sys_seconds unix_ts,
        sys_seconds refund_requested_at,
        std::string_view provider_code,
        std::span<const uint8_t> payment_id);

ProRequest refund_request(
        std::span<const uint8_t> master_privkey,
        sys_seconds unix_ts,
        sys_seconds refund_requested_at,
        std::string_view provider_code,
        std::span<const uint8_t> payment_id);

struct SetPaymentRefundRequestedResponse : ResponseBase {
    /// True if a payment was found matching the given payment information and that the refund
    /// request unix timestamp was set
    bool updated;
};

/// Parse the reply to a `refund_request`. On failure `status` is set to an error state and `errors`
/// is populated.
SetPaymentRefundRequestedResponse parse_refund(std::string_view json);
}  // namespace session::pro_backend
