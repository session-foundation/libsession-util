#pragma once

#include <session/session_protocol.h>
#include <session/types.h>
#include <stddef.h>
#include <stdint.h>

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Response status codes; must match the backend's status enum (session-pro-backend server.py).
enum {
    SESSION_PRO_BACKEND_STATUS_SUCCESS = 0,
    SESSION_PRO_BACKEND_STATUS_GENERIC_ERROR = 1,
    SESSION_PRO_BACKEND_STATUS_PARSE_ERROR = 2,
};

/// Canonical payment-provider `code` strings — the value transmitted on the wire and folded into
/// the add-payment / set-refund signed hashes (spec §1). Reference these constants rather than
/// hardcoding the slug so a sent code cannot drift from what libsession hashes/parses. Unknown
/// codes (e.g. a future provider) are still valid on the wire and pass through as opaque strings.
static const char SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY[] = "google_play";
static const char SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_APP_STORE[] = "app_store";
static const char SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_RANGEPROOF[] = "rangeproof";

/// Endpoint path (relative to the backend base URL) that each request type is POSTed to. libsession
/// owns the body<->route pairing, so reference these rather than hardcoding the path client-side.
/// The C++ `*_request()` helpers return the matching endpoint alongside the body; C callers read
/// the constant beside each request's build function. Each is a pointer to the single master string
/// owned in the C++ implementation (defined once, shared by the C and C++ sides).
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_ENDPOINT;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GENERATE_PRO_PROOF_ENDPOINT;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PRO_DETAILS_ENDPOINT;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PRO_REVOCATIONS_ENDPOINT;
LIBSESSION_EXPORT extern const char* const
        SESSION_PRO_BACKEND_SET_PAYMENT_REFUND_REQUESTED_ENDPOINT;

/// The Session Pro Backend's production base URL (POST a request body to `<URL>/<endpoint>`).
/// Canonical production value; clients may override with a dev/test server. Points at the single
/// master string owned in the C++ implementation.
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_URL;

/// The Session Pro Backend's Ed25519 public signing key, 32 bytes, for verifying a proof was issued
/// by the backend. Points at the same value as the C++ `session::pro_backend::PUBKEY`.
LIBSESSION_EXPORT extern const unsigned char* const SESSION_PRO_BACKEND_PUBKEY;

/// The X25519 form of SESSION_PRO_BACKEND_PUBKEY, 32 bytes (the Ed25519 key converted via
/// crypto_sign_ed25519_pk_to_curve25519). Points at the same value as the C++
/// `session::pro_backend::PUBKEY_X25519`.
LIBSESSION_EXPORT extern const unsigned char* const SESSION_PRO_BACKEND_PUBKEY_X25519;

/// Per-provider support/management URLs, keyed by provider code. These are identical for every user
/// (not translation data), so libsession owns them as the single source of truth rather than each
/// client duplicating them; the human-readable provider/store names are translation data and remain
/// the client's job. An unknown provider code (or one with no applicable URLs, e.g. rangeproof)
/// yields all-NULL fields. Otherwise each is a static, null-terminated C string.
typedef struct session_pro_backend_provider_urls session_pro_backend_provider_urls;
struct session_pro_backend_provider_urls {
    const char* refund_platform_url;      /// Native store refund flow
    const char* refund_support_url;       /// Session support page for requesting a refund
    const char* refund_status_url;        /// Where a user checks refund status
    const char* update_subscription_url;  /// Manage/update the subscription
    const char* cancel_subscription_url;  /// Cancel the subscription
};

/// API: session_pro_backend/get_provider_urls
///
/// Returns the support/management URLs for `provider_code` (a
/// SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_* value). A provider with no applicable URLs (unknown
/// code, or e.g. rangeproof) returns a struct with all fields NULL.
LIBSESSION_EXPORT session_pro_backend_provider_urls
session_pro_backend_get_provider_urls(const char* provider_code) NON_NULL_ARG(1);

typedef enum SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT {
    SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_SUCCESS,
    SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_GENERIC_ERROR,
    SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_COUNT,
} SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT;

/// Must match the backend's add-pro-payment response status enum (session-pro-backend server.py).
typedef enum SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS {
    SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS_SUCCESS =
            SESSION_PRO_BACKEND_STATUS_SUCCESS,
    SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS_PARSE_ERROR =
            SESSION_PRO_BACKEND_STATUS_PARSE_ERROR,
    SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS_ERROR =
            SESSION_PRO_BACKEND_STATUS_GENERIC_ERROR,

    SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS_ALREADY_REDEEMED = 100,
    SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS_UNKNOWN_PAYMENT = 101,
} SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS;

typedef struct session_pro_backend_response_header session_pro_backend_response_header;
struct session_pro_backend_response_header {
    uint32_t status;
    /// Array of error messages (NULL if no errors), with errors_count elements
    string8* errors;
    size_t errors_count;
    uint8_t* internal_arena_buf_;  /// Internal buffer for all the memory allocations, do not touch
};

/// A built request to POST to the Session Pro backend. Mirrors the C++
/// `session::pro_backend::ProRequest`: an `endpoint`, the `content_type` to send as the request's
/// Content-Type header, and the opaque `data` payload. `data` is libsession's data for the backend
/// -- relay it verbatim with the given `content_type` and do NOT parse, inspect, or assume a format
/// for it. libsession owns the wire encoding and may change it without client involvement.
typedef struct session_pro_backend_request session_pro_backend_request;
struct session_pro_backend_request {
    char error[256];
    size_t error_count;
    bool success;  /// True if the request was built successfully, false if out-of-memory
    /// Endpoint path (relative to the backend base URL) to POST to; static, null-terminated string.
    const char* endpoint;
    /// Value for the request's Content-Type header; static, null-terminated string. Relay verbatim.
    const char* content_type;
    /// The opaque request payload. Relay untouched; do not parse or modify.
    string8 data;
    /// Owned C++ object backing endpoint/content_type/data; do not touch (freed by request_free).
    void* internal_;
};

typedef struct session_pro_backend_pro_proof_response session_pro_backend_pro_proof_response;
struct session_pro_backend_pro_proof_response {
    session_pro_backend_response_header header;
    session_protocol_pro_proof proof;
};

typedef struct session_pro_backend_pro_revocation_item session_pro_backend_pro_revocation_item;
struct session_pro_backend_pro_revocation_item {
    bytes32 revocation_tag;
    /// Unix timestamp (seconds); a matching proof is revoked once the client clock reaches this
    int64_t effective_ts;
};

typedef struct session_pro_backend_get_pro_revocations_response
        session_pro_backend_get_pro_revocations_response;
struct session_pro_backend_get_pro_revocations_response {
    session_pro_backend_response_header header;
    int64_t ticket;
    int64_t retry_in;    /// Recommended seconds to wait before polling the list again
    int64_t retain_for;  /// Seconds to retain each item after first seeing it (memory-only aging)
    /// Array of items, with items_count elements
    session_pro_backend_pro_revocation_item* items;
    size_t items_count;
};

typedef struct session_pro_backend_pro_payment_item session_pro_backend_pro_payment_item;
struct session_pro_backend_pro_payment_item {
    /// Opaque payment lifecycle status code (e.g. "unredeemed"/"redeemed"/"expired"/"revoked");
    /// unknown values pass through as-is
    char status[64];
    size_t status_count;
    /// Billing-period code (e.g. "1m"/"3m"/"1y"); opaque, may be free-form for non-period plans
    char plan[64];
    size_t plan_count;
    /// Provider code (e.g. "google_play"); opaque -- an unknown value passes through as-is
    char payment_provider[64];
    size_t payment_provider_count;

    bool auto_renewing;
    /// Provider purchase time, fractional UNIX seconds. Millisecond-precise: the value passes
    /// through a millisecond-resolution representation, so sub-millisecond digits are not retained.
    double purchased_ts;
    int64_t redeemed_ts;
    int64_t expiry_ts;
    int64_t grace_period_duration;
    int64_t platform_refund_expiry_ts;
    /// Provider revocation instant, fractional UNIX seconds (millisecond-precise; 0 if not revoked)
    double revoked_ts;
    int64_t refund_requested_ts;

    /// Opaque payment identifier (the value passed at add-payment; multi-part providers fold their
    /// parts in per the backend-defined composite -- libsession does not interpret it)
    char payment_id[128];
    size_t payment_id_count;
};

typedef struct session_pro_backend_get_pro_details_response
        session_pro_backend_get_pro_details_response;
struct session_pro_backend_get_pro_details_response {
    session_pro_backend_response_header header;
    /// Array of payment items, with items_count elements
    session_pro_backend_pro_payment_item* items;
    size_t items_count;
    /// Opaque account Pro status code ("never"/"active"/"expired"); unknown values pass through
    char status[64];
    size_t status_count;
    SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT error_report;
    bool auto_renewing;
    int64_t expiry_ts;
    int64_t grace_period_duration;
    int64_t refund_requested_ts;
    uint32_t payments_total;
};

typedef struct session_pro_backend_set_payment_refund_requested_response
        session_pro_backend_set_payment_refund_requested_response;
struct session_pro_backend_set_payment_refund_requested_response {
    session_pro_backend_response_header header;
    bool updated;
};

/// API: session_pro_backend/add_pro_payment_request_build
///
/// Builds the add-payment request to POST, as a session_pro_backend_request (endpoint +
/// content_type + opaque data). Free it with `session_pro_backend_request_free`. On a key-size
/// error `success` is false and `error`/`error_count` describe it.
///
/// Inputs:
/// - `master_privkey` / `master_privkey_len` -- Ed25519 master private key (32 or 64-byte
/// libsodium).
/// - `rotating_privkey` / `rotating_privkey_len` -- Ed25519 rotating private key (32 or 64-byte).
/// - `provider_code` -- null-terminated provider code
/// (SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*).
/// - `payment_id` / `payment_id_len` -- opaque provider payment identifier.
LIBSESSION_EXPORT
session_pro_backend_request session_pro_backend_add_pro_payment_request_build(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        const char* provider_code,
        const uint8_t* payment_id,
        size_t payment_id_len) NON_NULL_ARG(1, 3, 5, 6);

/// API: session_pro_backend/generate_pro_proof_request_build
///
/// Builds the generate-proof request to POST, as a session_pro_backend_request (endpoint +
/// content_type + opaque data). Free it with `session_pro_backend_request_free`. On a key-size
/// error `success` is false and `error`/`error_count` describe it.
///
/// Inputs:
/// - `master_privkey` / `master_privkey_len` -- Ed25519 master private key (32 or 64-byte
/// libsodium).
/// - `rotating_privkey` / `rotating_privkey_len` -- Ed25519 rotating private key (32 or 64-byte).
/// - `ts` -- Unix timestamp (seconds) for the request.
LIBSESSION_EXPORT
session_pro_backend_request session_pro_backend_generate_pro_proof_request_build(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        int64_t ts) NON_NULL_ARG(1, 3);

/// API: session_pro_backend/get_pro_revocations_request_build
///
/// Builds the get-revocations request to POST, as a session_pro_backend_request (endpoint +
/// content_type + opaque data). Free it with `session_pro_backend_request_free`.
///
/// Inputs:
/// - `ticket` -- revocation-list ticket to resume from (0 for a full list).
LIBSESSION_EXPORT
session_pro_backend_request session_pro_backend_get_pro_revocations_request_build(int64_t ticket);

/// API: session_pro_backend/get_pro_details_request_build
///
/// Builds the get-details request to POST, as a session_pro_backend_request (endpoint +
/// content_type + opaque data). Free it with `session_pro_backend_request_free`. On a key-size
/// error `success` is false and `error`/`error_count` describe it.
///
/// Inputs:
/// - `master_privkey` / `master_privkey_len` -- Ed25519 master private key (32 or 64-byte
/// libsodium).
/// - `ts` -- Unix timestamp (seconds) for the request.
/// - `count` -- number of historical payments to request.
LIBSESSION_EXPORT
session_pro_backend_request session_pro_backend_get_pro_details_request_build(
        const uint8_t* master_privkey, size_t master_privkey_len, int64_t ts, uint32_t count)
        NON_NULL_ARG(1);

/// API: session_pro_backend/pro_proof_response_parse
///
/// Parses a JSON string into an `pro_proof_response` struct.
/// The caller must free the response using
/// `session_pro_backend_pro_proof_response_free`.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_pro_proof_response session_pro_backend_pro_proof_response_parse(
        const char* json, size_t json_len);

/// API: session_pro_backend/get_pro_revocations_response_parse
///
/// Parses a JSON string into a `session_pro_backend_get_pro_revocations_response` struct.
/// The caller must free the response using `session_pro_backend_get_pro_revocations_response_free`.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_get_pro_revocations_response
session_pro_backend_get_pro_revocations_response_parse(const char* json, size_t json_len);

/// API: session_pro_backend/get_pro_details_response_parse
///
/// Parses a JSON string into a GetProPaymentsResponse struct.
/// The caller must free the response using session_pro_backend_get_pro_details_response_free.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_get_pro_details_response session_pro_backend_get_pro_details_response_parse(
        const char* json, size_t json_len);

/// API: session_pro_backend/set_payment_refund_requested_request_build
///
/// Builds the set-refund-requested request to POST, as a session_pro_backend_request (endpoint +
/// content_type + opaque data). Free it with `session_pro_backend_request_free`. On a key-size
/// error `success` is false and `error`/`error_count` describe it.
///
/// Inputs:
/// - `master_privkey` / `master_privkey_len` -- Ed25519 master private key (32 or 64-byte
/// libsodium).
/// - `ts` -- Unix timestamp (seconds) for the request.
/// - `refund_requested_ts` -- Unix timestamp (seconds) to record the refund request at.
/// - `provider_code` -- null-terminated provider code
/// (SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*).
/// - `payment_id` / `payment_id_len` -- opaque provider payment identifier.
LIBSESSION_EXPORT
session_pro_backend_request session_pro_backend_set_payment_refund_requested_request_build(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        int64_t refund_requested_ts,
        const char* provider_code,
        const uint8_t* payment_id,
        size_t payment_id_len) NON_NULL_ARG(1, 5, 6);

/// API: session_pro_backend/set_payment_refund_requested_response_parse
///
/// Parses a JSON string into a GetProPaymentsResponse struct.
/// The caller must free the response using
/// `session_pro_backend_set_payment_refund_requested_response_free`.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT session_pro_backend_set_payment_refund_requested_response
session_pro_backend_set_payment_refund_requested_response_parse(const char* json, size_t json_len);

/// API: session_pro_backend/request_free
///
/// Frees a `session_pro_backend_request` returned by a `*_request_build` function.
LIBSESSION_EXPORT
void session_pro_backend_request_free(session_pro_backend_request* request);

/// API: session_pro_backend/pro_proof_response_free
///
/// Frees the response
LIBSESSION_EXPORT
void session_pro_backend_pro_proof_response_free(session_pro_backend_pro_proof_response* response);

/// API: session_pro_backend/get_pro_revocations_response_free
///
/// Frees the respone
LIBSESSION_EXPORT
void session_pro_backend_get_pro_revocations_response_free(
        session_pro_backend_get_pro_revocations_response* response);

/// API: session_pro_backend/get_pro_details_response_free
///
/// Frees the respone
LIBSESSION_EXPORT
void session_pro_backend_get_pro_details_response_free(
        session_pro_backend_get_pro_details_response* response);

/// API: session_pro_backend/session_pro_backend_set_payment_refund_requested_response_free
///
/// Frees the respone
LIBSESSION_EXPORT
void session_pro_backend_set_payment_refund_requested_response_free(
        session_pro_backend_set_payment_refund_requested_response* response);
#ifdef __cplusplus
}  // extern "C"
#endif
