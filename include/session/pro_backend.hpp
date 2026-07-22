#pragma once

#include <oxenc/hex.h>
#include <session/pro_backend.h>

#include <chrono>
#include <optional>
#include <session/clock.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/session_protocol.hpp>
#include <session/types.hpp>
#include <span>
#include <string>

/// Helper functions to construct payloads to communicate with the Session Pro Backend. The data
/// structures here are largely bindings to the endpoints exposed on the Session Pro Backend:
///
///   https://github.com/Doy-lee/session-pro-backend/blob/06e82c9d5b5a0a881d12d0182358219a4081acf5/server.py#L2
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
/// 4. Query a user's Session Pro entitlement status for their Master Ed25519 key by building a
///    `pro_status_request(...)` query (the hot "am I Pro?" path) and submitting it. Parse the reply
///    with `parse_pro_status(...)`, which yields the account status plus its single latest payment.
///
///    For the full payment history (e.g. a receipts view), page through it with
///    `payment_details_request(...)` / `parse_payment_details(...)` using the opaque keyset cursor.
///
/// See the unit tests for examples of using the APIs mentioned.

namespace session::pro_backend {

/// The Session Pro Backend's Ed25519 public key: verify that a proof was issued by the backend by
/// checking its signature against this key (see ProProof::verify_signature). This is the current
/// backend signing key (test deployment, expected to carry through to production).
constexpr auto PUBKEY = "479ffca8bcec7b4a0f0f7afe48b8a6d15635a8c7ff15ad16add05752c19414d4"_hex_b;
static_assert(PUBKEY.size() == 32);

/// The X25519 form of `PUBKEY` (the same key converted via crypto_sign_ed25519_pk_to_curve25519),
/// provided as a constant for clients that need the X25519 pubkey (e.g. to establish an encrypted
/// channel to the backend) without doing the conversion themselves. A unit test asserts these bytes
/// match the runtime conversion of `PUBKEY`, so the two cannot drift.
constexpr auto PUBKEY_X25519 =
        "ce5a75f64b6c43db6c1374d362c3ea9d85951c4f42a3d04cf94f87822d4f803b"_hex_b;
static_assert(PUBKEY_X25519.size() == 32);

/// The Session Pro Backend's production base URL: POST a request body to `<URL>/<endpoint>` (see
/// the SESSION_PRO_BACKEND_*_ENDPOINT paths). This is the canonical production value; a client may
/// point at a different dev/test server if it chooses.
constexpr std::string_view URL = "https://pro.session.codes";

/// Canonical payment-provider code strings — the value transmitted on the wire and folded into the
/// add-payment / set-refund signed messages (§3). Reference these rather than hardcoding the slug
/// so a sent code cannot drift from what libsession signs/parses. The C
/// `SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*` symbols point at these. An unknown code is still
/// valid on the wire and passes through as an opaque string.
constexpr std::string_view PAYMENT_PROVIDER_GOOGLE_PLAY = "google_play";
constexpr std::string_view PAYMENT_PROVIDER_APP_STORE = "app_store";
constexpr std::string_view PAYMENT_PROVIDER_RANGEPROOF = "rangeproof";

/// Domain used with ed25519::derive_subkey to derive the Session Pro signing keypair from the
/// account's root Ed25519 seed.
constexpr auto pro_subkey_domain = "SessionProRandom"_bytes;

/// Response outcome category (the wire `status`, spec §5). CLOSED/exhaustive by design: the backend
/// will never add a fourth value, so libsession treats any unrecognized wire status as a protocol
/// error (fail-closed) rather than passing it through. New categories/detail arrive via
/// `error_code`, which IS open/extensible.
enum class ResponseStatus {
    Ok,     ///< Success; the response's payload fields are populated.
    Fail,   ///< Request rejected on client input / a precondition; retrying the identical request
            ///< won't help (except the `stale_request` error_code). See `error_code`.
    Error,  ///< Backend fault; the client did nothing wrong and the same request may succeed later.
};

struct ResponseBase {
    /// Outcome category; the `explicit operator bool()` is the usual check. See ResponseStatus.
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
    b64 master_sig;
    b64 rotating_sig;
};

/// Per-provider support/management URLs (from provider_urls()). These are identical for every user
/// (not translation data), so libsession owns them as the single source of truth rather than each
/// client duplicating them; the human-readable provider/store *names* are translation data and
/// remain the client's job. Each field is std::nullopt when that provider has no such URL -- clients
/// test the optional rather than an empty-string sentinel. Present views point at static,
/// null-terminated string literals.
struct ProviderURLs {
    std::optional<std::string_view> refund_platform_url;  ///< Native store refund flow
    std::optional<std::string_view> refund_support_url;   ///< Session page for requesting a refund
    std::optional<std::string_view> refund_status_url;    ///< Where a user checks refund status
    std::optional<std::string_view> update_subscription_url;  ///< Manage/update the subscription
    std::optional<std::string_view> cancel_subscription_url;  ///< Cancel the subscription
};

/// Look up the support/management URLs for a provider code (see
/// SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*). Returns a pointer to a static per-provider
/// constant, or nullptr for a provider with no applicable URLs at all (an unknown code, or e.g.
/// rangeproof); within a returned set each field is present or std::nullopt per that provider.
const ProviderURLs* provider_urls(std::string_view provider_code);

/// The user-visible purchasable platforms, as provider-code slugs (a subset of the
/// SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_* values — currently "google_play" and "app_store").
/// Order is not significant; clients pick their own. Hidden mechanisms (e.g. rangeproof) are
/// excluded — they surface only for users who already hold them — so this is the set that drives a
/// "purchase via …" store list.
std::span<const std::string_view> visible_platforms();

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
        const ed25519::PrivKeySpan& master_privkey,
        const ed25519::PrivKeySpan& rotating_privkey,
        std::string_view provider_code,
        std::span<const std::byte> payment_id);

ProRequest add_payment_request(
        const ed25519::PrivKeySpan& master_privkey,
        const ed25519::PrivKeySpan& rotating_privkey,
        std::string_view provider_code,
        std::span<const std::byte> payment_id);

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
        const ed25519::PrivKeySpan& master_privkey,
        const ed25519::PrivKeySpan& rotating_privkey,
        std::chrono::sys_seconds unix_ts);

ProRequest pro_proof_request(
        const ed25519::PrivKeySpan& master_privkey,
        const ed25519::PrivKeySpan& rotating_privkey,
        std::chrono::sys_seconds unix_ts);

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
    b32 revocation_tag;

    /// A matching proof is revoked once the client's clock reaches this unix timestamp (not before)
    std::chrono::sys_seconds effective_at;
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

/// Query a master key's Session Pro status (endpoint `get_pro_status`): the account entitlement
/// state plus its single latest payment -- the hot "am I Pro?" path. `pro_status_sig` computes the
/// master signature; `pro_status_request` builds the whole request (signing internally) and returns
/// the endpoint + JSON body. Both throw on an incorrectly-sized key.
///
/// Inputs:
/// - `master_privkey` -- 32-byte Ed25519 seed or 64-byte libsodium master private key
/// - `unix_ts` -- Unix timestamp for the request
b64 pro_status_sig(const ed25519::PrivKeySpan& master_privkey, std::chrono::sys_seconds unix_ts);

ProRequest pro_status_request(
        const ed25519::PrivKeySpan& master_privkey, std::chrono::sys_seconds unix_ts);

/// Query a master key's Session Pro payment history (endpoint `get_payment_details`), one keyset
/// page at a time. `payment_details_sig` computes the master signature; `payment_details_request`
/// builds the whole request (signing internally) and returns the endpoint + JSON body. Both throw
/// on an incorrectly-sized key.
///
/// Inputs:
/// - `master_privkey` -- 32-byte Ed25519 seed or 64-byte libsodium master private key
/// - `unix_ts` -- Unix timestamp for the request
/// - `limit` -- maximum payments to return on this page (the backend may clamp it)
/// - `before` -- opaque pagination cursor from a previous page's `next_cursor` (see
///   PaymentDetailsResponse); the empty string requests the newest page. Pass it through verbatim;
///   it must not be parsed or synthesized.
b64 payment_details_sig(
        const ed25519::PrivKeySpan& master_privkey,
        std::chrono::sys_seconds unix_ts,
        uint32_t limit,
        std::string_view before);

ProRequest payment_details_request(
        const ed25519::PrivKeySpan& master_privkey,
        std::chrono::sys_seconds unix_ts,
        uint32_t limit,
        std::string_view before);

/// Unit of a billing period (the `unit` of a parsed `plan` code, pro-wire-protocol.md §1 / Delta
/// #14). A closed set: the backend emits only these, so an unrecognized code is a protocol error.
enum class ProPlanUnit { second, day, week, month, year, lifetime };

/// A parsed `plan` billing-period code. The `unit` is preserved exactly as transmitted and never
/// canonicalized ("12m" and "1y" are the same duration but distinct values). `count` is meaningful
/// only for the periodic units and is >= 1; for `lifetime` it is 0 (invariant: count == 0 iff unit
/// == lifetime), so consumers switch on `unit` and never render "<count> <unit>" for lifetime.
struct ProPlanPeriod {
    int count;
    ProPlanUnit unit;
};

/// Parse a `plan` billing-period code (pro-wire-protocol.md §1, Delta #14): "<N><unit>" with N a
/// positive integer (no leading zeros) and unit one of s/d/w/m/y (second/day/week/month/year), or
/// the literal "lifetime". Single-unit only ("1y6m" is invalid). Returns std::nullopt for any
/// non-conforming code (the caller treats that as a protocol error).
std::optional<ProPlanPeriod> parse_plan_period(std::string_view plan_code);

struct ProPaymentItem {
    /// Describes the current status of the consumption of the payment for Session Pro entitlement
    /// The status should be used to determine which timestamps should be used.
    ///
    /// For example, a payment can be in a redeemed state whilst also have a refunded timestamp set
    /// if the payment was refunded and then the refund was reversed. We preserve all timestamps for
    /// book-keeping purposes.
    std::string status;

    /// The parsed billing period that was purchased (e.g. "1m" -> {1, month}, "lifetime" -> {0,
    /// lifetime}). libsession parses the closed `plan` grammar (§1 / Delta #14); the client just
    /// localizes the display. The unit is preserved as transmitted, never canonicalized.
    ProPlanPeriod plan;

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
    std::chrono::sys_seconds redeemed_at;

    /// Unix timestamp of when the payment was expiry. 0 if not activated
    std::chrono::sys_seconds expiry_at;

    /// Duration of the grace period, e.g. when the payment provider will start to attempt to renew
    /// the Session Pro subscription. During the period between
    /// [expiry_at, expiry_at + grace_period_duration] the user continues to have
    /// entitlement to Session Pro. This value is only applicable if `auto_renewing` is `true`.
    std::chrono::seconds grace_period_duration;

    /// Unix deadline timestamp of when the user is able to refund the subscription via the payment
    /// provider. Thereafter the user must initiate a refund manually via Session support.
    std::chrono::sys_seconds platform_refund_expiry_at;

    /// Provider revocation instant (when the payment was revoked). Epoch (0) if not applicable.
    /// Carries the provider's sub-second precision as a millisecond-resolution `sys_ms`; the wire
    /// sends it as a float of seconds.
    sys_ms revoked_at;

    /// UNIX timestamp at which a refund request was requested for this payment. This is set to 0
    /// if no refund has been requested for this payment yet.
    std::chrono::sys_seconds refund_requested_at;

    /// Opaque payment identifier (the value passed at add-payment; multi-part providers fold their
    /// parts in per the backend-defined composite -- libsession does not interpret it).
    /// Confidential; store appropriately.
    std::string payment_id;
};

struct ProStatusResponse : ResponseBase {
    /// Current Session Pro entitlement status for the master public key
    /// ("never"/"active"/"expired"; opaque -- an unknown value passes through as-is).
    std::string user_status;

    /// The single most-recent payment for the master public key, or std::nullopt when the account
    /// has no payments. (The full payment history is a separate query -- parse_payment_details.)
    std::optional<ProPaymentItem> latest_payment;

    /// Error code that indicates that the Session Pro Backend encountered an error book-keeping
    /// Session Pro entitlement for the user. If this value is not `SUCCESS` implementing clients
    /// can optionally prompt the user that they should contact support for investigation.
    SESSION_PRO_BACKEND_GET_PRO_STATUS_ERROR_REPORT error_report;

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
    std::chrono::sys_seconds expiry_at;

    /// Duration that a user is entitled to for their grace period. This value is to be ignored if
    /// `auto_renewing` is false. It can be used to calculate the subscription expiry timestamp by
    /// subtracting it from `expiry_at`.
    std::chrono::seconds grace_period_duration;

    /// UNIX timestamp at which a refund request was requested by this user. This timestamp comes
    /// from the latest payment that the backend has deemed to be active for the user (e.g. the
    /// payment associated with the `expiry_at`). This value is 0 if no refund has been
    /// requested on the active payment.
    std::chrono::sys_seconds refund_requested_at;
};

struct PaymentDetailsResponse : ResponseBase {
    /// One keyset page of the master public key's payment history, newest-first (at most the
    /// `limit` passed to payment_details_request).
    std::vector<ProPaymentItem> items;

    /// Total number of payments known by the backend for the user. This may be greater than the
    /// length of `items` when the requested page did not cover the full history.
    uint32_t payments_total;

    /// Opaque keyset-pagination cursor for the next (older) page: re-request with this value as
    /// `before` to continue, and stop when it is std::nullopt (end-of-data). Store and echo it
    /// verbatim -- it is an encrypted token and MUST NOT be parsed or synthesized (a tampered or
    /// foreign cursor is rejected). (pro-wire-protocol.md §5.3.)
    std::optional<std::string> next_cursor;
};

/// Parse the reply to a `pro_status_request`. On failure `status` is set to an error state and
/// `errors` is populated.
ProStatusResponse parse_pro_status(std::string_view json);

/// Parse the reply to a `payment_details_request`. On failure `status` is set to an error state and
/// `errors` is populated.
PaymentDetailsResponse parse_payment_details(std::string_view json);

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
b64 refund_sig(
        const ed25519::PrivKeySpan& master_privkey,
        std::chrono::sys_seconds unix_ts,
        std::chrono::sys_seconds refund_requested_at,
        std::string_view provider_code,
        std::span<const std::byte> payment_id);

ProRequest refund_request(
        const ed25519::PrivKeySpan& master_privkey,
        std::chrono::sys_seconds unix_ts,
        std::chrono::sys_seconds refund_requested_at,
        std::string_view provider_code,
        std::span<const std::byte> payment_id);

struct SetPaymentRefundRequestedResponse : ResponseBase {
    /// True if a payment was found matching the given payment information and that the refund
    /// request unix timestamp was set
    bool updated;
};

/// Parse the reply to a `refund_request`. On failure `status` is set to an error state and `errors`
/// is populated.
SetPaymentRefundRequestedResponse parse_refund(std::string_view json);
}  // namespace session::pro_backend
