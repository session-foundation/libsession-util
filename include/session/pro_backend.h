#pragma once

#include <session/session_protocol.h>
#include <session/types.h>
#include <stddef.h>
#include <stdint.h>

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Must match:
///   https://github.com/Doy-lee/session-pro-backend/blob/41a794e2998b528566d0c27d34c4faeed5602e26/server.py#L457
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

/// Must match:
///   https://github.com/Doy-lee/session-pro-backend/blob/f4e2c84794470e7932ba1a1968fdb49117bb5870/backend.py#L18
typedef enum SESSION_PRO_BACKEND_PAYMENT_STATUS {
    SESSION_PRO_BACKEND_PAYMENT_STATUS_NIL,
    SESSION_PRO_BACKEND_PAYMENT_STATUS_UNREDEEMED,
    SESSION_PRO_BACKEND_PAYMENT_STATUS_REDEEMED,
    SESSION_PRO_BACKEND_PAYMENT_STATUS_EXPIRED,
    SESSION_PRO_BACKEND_PAYMENT_STATUS_REVOKED,
    SESSION_PRO_BACKEND_PAYMENT_STATUS_COUNT,
} SESSION_PRO_BACKEND_PAYMENT_STATUS;

/// Must match:
///   https://github.com/Doy-lee/session-pro-backend/blob/a0e0ba24bc4ab3a062465d861aa57df2269b6dde/server.py#L373
typedef enum SESSION_PRO_BACKEND_USER_PRO_STATUS {
    SESSION_PRO_BACKEND_USER_PRO_STATUS_NEVER_BEEN_PRO,
    SESSION_PRO_BACKEND_USER_PRO_STATUS_ACTIVE,
    SESSION_PRO_BACKEND_USER_PRO_STATUS_EXPIRED,
    SESSION_PRO_BACKEND_USER_PRO_STATUS_COUNT,
} SESSION_PRO_BACKEND_USER_PRO_STATUS;

typedef enum SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT {
    SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_SUCCESS,
    SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_GENERIC_ERROR,
    SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_COUNT,
} SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT;

/// Must match:
///   https://github.com/Doy-lee/session-pro-backend/blob/41a794e2998b528566d0c27d34c4faeed5602e26/server.py#L461
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
    unsigned char*
            internal_arena_buf_;  /// Internal buffer for all the memory allocations, do not touch
};

typedef struct session_pro_backend_to_json session_pro_backend_to_json;
struct session_pro_backend_to_json {
    char error[256];
    size_t error_count;
    bool success;  /// True if conversion to JSON was successful, false if out-of-memory
    string8 json;
};

typedef struct session_pro_backend_master_rotating_signatures
        session_pro_backend_master_rotating_signatures;
struct session_pro_backend_master_rotating_signatures {
    bool success;
    char error[256];
    size_t error_count;
    cbytes64 master_sig;
    cbytes64 rotating_sig;
};

typedef struct session_pro_backend_signature session_pro_backend_signature;
struct session_pro_backend_signature {
    bool success;
    char error[256];
    size_t error_count;
    cbytes64 sig;
};

typedef struct session_pro_backend_add_pro_payment_user_transaction
        session_pro_backend_add_pro_payment_user_transaction;
struct session_pro_backend_add_pro_payment_user_transaction {
    /// Provider code string (see SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*); opaque slug
    char provider_code[64];
    size_t provider_code_count;
    /// Opaque payment identifier from the provider's purchase flow. Multi-part providers fold their
    /// parts into this one string per a backend-defined composite (e.g. Google "token|order_id");
    /// libsession treats it as opaque bytes hashed verbatim.
    char payment_id[128];
    size_t payment_id_count;
};

typedef struct session_pro_backend_add_pro_payment_request
        session_pro_backend_add_pro_payment_request;
struct session_pro_backend_add_pro_payment_request {
    uint8_t version;
    cbytes32 master_pkey;
    cbytes32 rotating_pkey;
    session_pro_backend_add_pro_payment_user_transaction payment_tx;
    cbytes64 master_sig;
    cbytes64 rotating_sig;
};

typedef struct session_pro_backend_generate_pro_proof_request
        session_pro_backend_generate_pro_proof_request;
struct session_pro_backend_generate_pro_proof_request {
    uint8_t version;
    cbytes32 master_pkey;
    cbytes32 rotating_pkey;
    int64_t ts;
    cbytes64 master_sig;
    cbytes64 rotating_sig;
};

typedef struct session_pro_backend_add_pro_payment_or_generate_pro_proof_response
        session_pro_backend_add_pro_payment_or_generate_pro_proof_response;
struct session_pro_backend_add_pro_payment_or_generate_pro_proof_response {
    session_pro_backend_response_header header;
    session_protocol_pro_proof proof;
};

typedef struct session_pro_backend_get_pro_revocations_request
        session_pro_backend_get_pro_revocations_request;
struct session_pro_backend_get_pro_revocations_request {
    uint8_t version;
    int64_t ticket;
};

typedef struct session_pro_backend_pro_revocation_item session_pro_backend_pro_revocation_item;
struct session_pro_backend_pro_revocation_item {
    cbytes32 revocation_tag;
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

typedef struct session_pro_backend_get_pro_details_request
        session_pro_backend_get_pro_details_request;
struct session_pro_backend_get_pro_details_request {
    uint8_t version;
    cbytes32 master_pkey;
    cbytes64 master_sig;
    int64_t ts;
    uint32_t count;
};

typedef struct session_pro_backend_pro_payment_item session_pro_backend_pro_payment_item;
struct session_pro_backend_pro_payment_item {
    SESSION_PRO_BACKEND_PAYMENT_STATUS status;
    /// Billing-period code (e.g. "1m"/"3m"/"1y"); opaque, may be free-form for non-period plans
    char plan[64];
    size_t plan_count;
    /// Provider code (e.g. "google_play"); opaque -- an unknown value passes through as-is
    char payment_provider[64];
    size_t payment_provider_count;

    bool auto_renewing;
    int64_t unredeemed_ts;
    int64_t redeemed_ts;
    int64_t expiry_ts;
    int64_t grace_period_duration;
    int64_t platform_refund_expiry_ts;
    int64_t revoked_ts;
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
    SESSION_PRO_BACKEND_USER_PRO_STATUS status;
    SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT error_report;
    bool auto_renewing;
    int64_t expiry_ts;
    int64_t grace_period_duration;
    int64_t refund_requested_ts;
    uint32_t payments_total;
};

typedef struct session_pro_backend_set_payment_refund_requested_request
        session_pro_backend_set_payment_refund_requested_request;
struct session_pro_backend_set_payment_refund_requested_request {
    uint8_t version;
    cbytes32 master_pkey;
    cbytes64 master_sig;
    int64_t ts;
    int64_t refund_requested_ts;
    session_pro_backend_add_pro_payment_user_transaction payment_tx;
};

typedef struct session_pro_backend_set_payment_refund_requested_response
        session_pro_backend_set_payment_refund_requested_response;
struct session_pro_backend_set_payment_refund_requested_response {
    session_pro_backend_response_header header;
    uint8_t version;
    bool updated;
};

/// API: session_pro_backend/add_pro_payment_request_build_sigs
///
/// Builds master and rotating signatures for an `add_pro_payment_request`.
/// Returns false if the keys (32-byte or 64-byte libsodium format) or payment token hash are
/// incorrectly sized. Using 64-byte libsodium keys is more efficient.
///
/// Inputs:
/// - `request_version` -- Version of the request.
/// - `master_privkey` -- Ed25519 master private key (32-byte or 64-byte libsodium format).
/// - `master_privkey_len` -- Length of master_privkey.
/// - `rotating_privkey` -- Ed25519 rotating private key (32-byte or 64-byte libsodium format).
/// - `rotating_privkey_len` -- Length of rotating_privkey.
/// - `payment_tx_provider_code` -- Null-terminated provider code string the payment is coming from
///   (see SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*)
/// - `payment_tx_payment_id` -- Opaque payment identifier from the provider. See
///   `AddProPaymentUserTransaction`
/// - `payment_tx_payment_id_len` -- Length of the `payment_tx_payment_id` payload
///
/// Outputs:
/// - `success` - True if signatures are built successfully, false otherwise.
/// - `error` - Backing error buffer for the signatures if `success` is false
/// - `errors_count` - length of the error if `success` is false
/// - `master_sig` - Generated master signature
/// - `rotating_sig` - Generated rotating signature
LIBSESSION_EXPORT
session_pro_backend_master_rotating_signatures
session_pro_backend_add_pro_payment_request_build_sigs(
        uint8_t request_version,
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        const unsigned char* rotating_privkey,
        size_t rotating_privkey_len,
        const char* payment_tx_provider_code,
        const unsigned char* payment_tx_payment_id,
        size_t payment_tx_payment_id_len) NON_NULL_ARG(2, 4, 6, 7);

/// API: session_pro_backend/add_pro_payment_request_build_to_json
///
/// Builds the JSON for a `add_pro_payment_request`. This function is the same as filling in the
/// struct and calling the corresponding `to_json` function.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
///
/// See: session_pro_backend_add_pro_payment_request_build_sigs
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_add_pro_payment_request_build_to_json(
        uint8_t request_version,
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        const unsigned char* rotating_privkey,
        size_t rotating_privkey_len,
        const char* payment_tx_provider_code,
        const unsigned char* payment_tx_payment_id,
        size_t payment_tx_payment_id_len) NON_NULL_ARG(2, 4, 6, 7);

/// API: session_pro_backend/generate_pro_proof_request_build_sigs
///
/// Builds master and rotating signatures for a `generate_pro_proof_request`.
/// Returns false if the keys (32-byte or 64-byte libsodium format) are incorrectly sized.
/// Using 64-byte libsodium keys is more efficient.
///
/// Inputs:
/// - `request_version` -- Version of the request.
/// - `master_privkey` -- Ed25519 master private key (32-byte or 64-byte libsodium format).
/// - `master_privkey_len` -- Length of master_privkey.
/// - `rotating_privkey` -- Ed25519 rotating private key (32-byte or 64-byte libsodium format).
/// - `rotating_privkey_len` -- Length of rotating_privkey.
/// - `ts` -- Unix timestamp for the request.
///
/// Outputs:
/// - `bool` - True if signatures are built successfully, false otherwise.
/// - `error` - Backing error buffer for the signatures if `success` is false
/// - `errors_count` - length of the error if `success` is false
/// - `master_sig` - Master signature
/// - `rotating_sig` - Rotating signature
LIBSESSION_EXPORT
session_pro_backend_master_rotating_signatures
session_pro_backend_generate_pro_proof_request_build_sigs(
        uint8_t request_version,
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        const unsigned char* rotating_privkey,
        size_t rotating_privkey_len,
        int64_t ts) NON_NULL_ARG(2, 4);

/// API: session_pro_backend/generate_pro_proof_request_build_to_json
///
/// Builds the JSON for a `generate_pro_proof_request`. This function is the same as filling in the
/// struct and calling the corresponding `to_json` function.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
///
/// See: `session_pro_backend_generate_pro_proof_request_build_sigs`
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_generate_pro_proof_request_build_to_json(
        uint8_t request_version,
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        const unsigned char* rotating_privkey,
        size_t rotating_privkey_len,
        int64_t ts) NON_NULL_ARG(2, 4);

/// API: session_pro_backend/get_pro_details_request_build_sig
///
/// Builds the JSON for a `get_pro_details_request`. Returns false if the keys (32-byte or
/// 64-byte libsodium format) are incorrectly sized. Using 64-byte libsodium keys is more efficient.
///
/// Inputs:
/// - `request_version` -- Version of the request.
/// - `master_privkey` -- Ed25519 master private key (32-byte or 64-byte libsodium format).
/// - `master_privkey_len` -- Length of master_privkey.
/// - `ts` -- Unix timestamp for the request.
/// - `count` -- Amount of historical payments to request
///
/// Outputs:
/// - `bool` -- True if signatures are built successfully, false otherwise.
/// - `error` -- Backing error buffer for the signatures if `success` is false
/// - `errors_count` -- length of the error if `success` is false
/// - `sig` -- The generated signature
LIBSESSION_EXPORT
session_pro_backend_signature session_pro_backend_get_pro_details_request_build_sig(
        uint8_t request_version,
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        uint32_t count) NON_NULL_ARG(2);

/// API: session_pro_backend/get_pro_details_request_build_to_json
///
/// Builds the JSON for a `get_pro_details_request`. This function is the same as filling in the
/// struct and calling the corresponding `to_json` function.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
///
/// See: `session_pro_backend_get_pro_details_request_build_sig`
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_get_pro_details_request_build_to_json(
        uint8_t request_version,
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        uint32_t count) NON_NULL_ARG(2);

/// API: session_pro_backend/add_pro_payment_request_to_json
///
/// Serializes an `add_pro_payment_request` to a JSON string.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
///
/// Inputs:
/// - `request` -- Pointer to the request struct.
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_add_pro_payment_request_to_json(
        const session_pro_backend_add_pro_payment_request* request);

/// API: session_pro_backend/generate_pro_proof_request_to_json
///
/// Serializes a `generate_pro_proof_request` to a JSON string.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
///
/// Inputs:
/// - `request` -- Pointer to the request struct.
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_generate_pro_proof_request_to_json(
        const session_pro_backend_generate_pro_proof_request* request);

/// API: session_pro_backend/get_pro_revocations_request_to_json
///
/// Serializes a `get_pro_revocations_request` to a JSON string.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_get_pro_revocations_request_to_json(
        const session_pro_backend_get_pro_revocations_request* request);

/// API: session_pro_backend/get_pro_details_request_to_json
///
/// Serializes a `get_pro_details_request` to a JSON string.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_get_pro_details_request_to_json(
        const session_pro_backend_get_pro_details_request* request);

/// API: session_pro_backend/add_pro_payment_or_generate_pro_proof_response_parse
///
/// Parses a JSON string into an `add_pro_payment_or_generate_pro_proof_response` struct.
/// The caller must free the response using
/// `session_pro_backend_add_pro_payment_or_generate_pro_proof_response_free`.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_add_pro_payment_or_generate_pro_proof_response
session_pro_backend_add_pro_payment_or_generate_pro_proof_response_parse(
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

/// API: session_pro_backend/set_payment_refund_requested_request_build_sigs
///
/// Builds master and rotating signatures for an `set_payment_refund_requested_request`.
/// Returns false if the keys (32-byte or 64-byte libsodium format) or payment token hash are
/// incorrectly sized. Using 64-byte libsodium keys is more efficient.
///
/// Inputs:
/// - `request_version` -- Version of the request.
/// - `master_privkey` -- Ed25519 master private key (32-byte or 64-byte libsodium format).
/// - `master_privkey_len` -- Length of master_privkey.
/// - `ts` -- Unix timestamp for the request
/// - `refund_requested_ts` -- Unix timestamp to set as the timestamp that a refund was
///   requested on this payment
/// - `payment_tx_provider_code` -- Null-terminated provider code string the payment is coming from
///   (see SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*)
/// - `payment_tx_payment_id` -- Opaque payment identifier from the provider. See
///   `AddProPaymentUserTransaction`
/// - `payment_tx_payment_id_len` -- Length of the `payment_tx_payment_id` payload
///
/// Outputs:
/// - `bool` -- True if signatures are built successfully, false otherwise.
/// - `error` -- Backing error buffer for the signatures if `success` is false
/// - `errors_count` -- length of the error if `success` is false
/// - `sig` -- The generated signature
LIBSESSION_EXPORT
session_pro_backend_signature session_pro_backend_set_payment_refund_requested_request_build_sigs(
        uint8_t request_version,
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        int64_t refund_requested_ts,
        const char* payment_tx_provider_code,
        const unsigned char* payment_tx_payment_id,
        size_t payment_tx_payment_id_len) NON_NULL_ARG(2, 6, 7);

/// API: session_pro_backend/set_payment_refund_requested_request_build_to_json
///
/// Builds the JSON for a `set_payment_refund_requested_request`. This function is the same as
/// filling in the struct and calling the corresponding `to_json` function. The caller must free the
/// returned string using `session_pro_backend_to_json_free`.
///
/// See: session_pro_backend_set_payment_refund_requested_request_build_sigs
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_set_payment_refund_requested_request_build_to_json(
        uint8_t request_version,
        const unsigned char* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        int64_t refund_requested_ts,
        const char* payment_tx_provider_code,
        const unsigned char* payment_tx_payment_id,
        size_t payment_tx_payment_id_len) NON_NULL_ARG(2, 6, 7);

/// API: session_pro_backend/set_payment_refund_requested_request_to_json
///
/// Serializes a `set_payment_refund_requested_request` to a JSON string.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_set_payment_refund_requested_request_to_json(
        const session_pro_backend_set_payment_refund_requested_request* request);

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

/// API: session_pro_backend/to_json_free
///
/// Frees the JSON
LIBSESSION_EXPORT
void session_pro_backend_to_json_free(session_pro_backend_to_json* to_json);

/// API: session_pro_backend/add_pro_payment_or_generate_pro_proof_response_free
///
/// Frees the response
LIBSESSION_EXPORT
void session_pro_backend_add_pro_payment_or_generate_pro_proof_response_free(
        session_pro_backend_add_pro_payment_or_generate_pro_proof_response* response);

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
