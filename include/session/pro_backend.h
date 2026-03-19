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

/// Store front that a Session Pro payment came from. Must match:
///   https://github.com/session-foundation/session-pro-backend/blob/8ec0aacca2e5975407df1b60f5346477e17de44d/base.py#L78
typedef enum SESSION_PRO_BACKEND_PAYMENT_PROVIDER {
    SESSION_PRO_BACKEND_PAYMENT_PROVIDER_NIL,
    SESSION_PRO_BACKEND_PAYMENT_PROVIDER_GOOGLE_PLAY_STORE,
    SESSION_PRO_BACKEND_PAYMENT_PROVIDER_IOS_APP_STORE,
    SESSION_PRO_BACKEND_PAYMENT_PROVIDER_RANGEPROOF,
    SESSION_PRO_BACKEND_PAYMENT_PROVIDER_COUNT,
} SESSION_PRO_BACKEND_PAYMENT_PROVIDER;

/// Must match:
///   https://github.com/Doy-lee/session-pro-backend/blob/f4e2c84794470e7932ba1a1968fdb49117bb5870/backend.py#L18
typedef enum SESSION_PRO_BACKEND_PAYMENT_STATUS {
    SESSION_PRO_BACKEND_PAYMENT_STATUS_NIL,
    SESSION_PRO_BACKEND_PAYMENT_STATUS_UNREDEEMED,
    SESSION_PRO_BACKEND_PAYMENT_STATUS_REDEEMED,
    SESSION_PRO_BACKEND_PAYMENT_STATUS_EXPIRED,
    SESSION_PRO_BACKEND_PAYMENT_STATUS_REFUNDED,
    SESSION_PRO_BACKEND_PAYMENT_STATUS_COUNT,
} SESSION_PRO_BACKEND_PAYMENT_STATUS;

/// Must match:
///   https://github.com/Doy-lee/session-pro-backend/blob/b9fb4301fecbd82e4631536fa378d4c1220b1a4d/base.py#L53
typedef enum SESSION_PRO_BACKEND_PLAN {
    SESSION_PRO_BACKEND_PLAN_NIL,
    SESSION_PRO_BACKEND_PLAN_ONE_MONTH,
    SESSION_PRO_BACKEND_PLAN_THREE_MONTHS,
    SESSION_PRO_BACKEND_PLAN_TWELVE_MONTHS,
    SESSION_PRO_BACKEND_PLAN_COUNT,
} SESSION_PRO_BACKEND_PLAN;

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

/// Bundle of hard-coded strings that are associated with each platform for clients to use for
/// string substitution typically. This structure is stored in a global table
/// `SESSION_PRO_BACKEND_PAYMENT_PROVIDER_METADATA` that is can be indexed into using the
/// SESSION_PRO_BACKEND_PAYMENT_PROVIDER value directly.
typedef struct session_pro_backend_payment_provider_metadata
        session_pro_backend_payment_provider_metadata;
struct session_pro_backend_payment_provider_metadata {
    string8 device;
    string8 store;
    string8 platform;
    string8 platform_account;
    string8 refund_platform_url;

    /// Some platforms disallow a refund via their native support channels after some time period
    /// (e.g. 48 hours after a purchase on Google, refunds must be dealt by the developers
    /// themselves). If a platform does not have this restriction, this URL is typically the same as
    /// the `refund_platform_url`.
    string8 refund_support_url;

    string8 refund_status_url;
    string8 update_subscription_url;
    string8 cancel_subscription_url;
};

/// The centralised list of common URLs and properties for handling payment provider specific
/// integrations. Especially useful for cross-device management of Session Pro subscriptions.
extern const session_pro_backend_payment_provider_metadata
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER_METADATA[SESSION_PRO_BACKEND_PAYMENT_PROVIDER_COUNT];

typedef struct session_pro_backend_response_header session_pro_backend_response_header;
struct session_pro_backend_response_header {
    uint32_t status;
    /// Array of error messages (NULL if no errors), with errors_count elements
    string8* errors;
    size_t errors_count;
    uint8_t* internal_arena_buf_;  /// Internal buffer for all the memory allocations, do not touch
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
    bytes64 master_sig;
    bytes64 rotating_sig;
};

typedef struct session_pro_backend_signature session_pro_backend_signature;
struct session_pro_backend_signature {
    bool success;
    char error[256];
    size_t error_count;
    bytes64 sig;
};

typedef struct session_pro_backend_add_pro_payment_user_transaction
        session_pro_backend_add_pro_payment_user_transaction;
struct session_pro_backend_add_pro_payment_user_transaction {
    SESSION_PRO_BACKEND_PAYMENT_PROVIDER provider;
    char payment_id[128];
    size_t payment_id_count;
    char order_id[128];
    size_t order_id_count;
};

typedef struct session_pro_backend_add_pro_payment_request
        session_pro_backend_add_pro_payment_request;
struct session_pro_backend_add_pro_payment_request {
    uint8_t version;
    bytes32 master_pkey;
    bytes32 rotating_pkey;
    session_pro_backend_add_pro_payment_user_transaction payment_tx;
    bytes64 master_sig;
    bytes64 rotating_sig;
};

typedef struct session_pro_backend_generate_pro_proof_request
        session_pro_backend_generate_pro_proof_request;
struct session_pro_backend_generate_pro_proof_request {
    uint8_t version;
    bytes32 master_pkey;
    bytes32 rotating_pkey;
    uint64_t unix_ts_ms;
    bytes64 master_sig;
    bytes64 rotating_sig;
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
    uint32_t ticket;
};

typedef struct session_pro_backend_pro_revocation_item session_pro_backend_pro_revocation_item;
struct session_pro_backend_pro_revocation_item {
    bytes32 gen_index_hash;
    uint64_t expiry_unix_ts_ms;
};

typedef struct session_pro_backend_get_pro_revocations_response
        session_pro_backend_get_pro_revocations_response;
struct session_pro_backend_get_pro_revocations_response {
    session_pro_backend_response_header header;
    uint32_t ticket;
    /// Array of items, with items_count elements
    session_pro_backend_pro_revocation_item* items;
    size_t items_count;
};

typedef struct session_pro_backend_get_pro_details_request
        session_pro_backend_get_pro_details_request;
struct session_pro_backend_get_pro_details_request {
    uint8_t version;
    bytes32 master_pkey;
    bytes64 master_sig;
    uint64_t unix_ts_ms;
    uint32_t count;
};

typedef struct session_pro_backend_pro_payment_item session_pro_backend_pro_payment_item;
struct session_pro_backend_pro_payment_item {
    SESSION_PRO_BACKEND_PAYMENT_STATUS status;
    SESSION_PRO_BACKEND_PLAN plan;
    SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_provider;
    /// Pointer to payment provider metadata. This pointer is always defined to be pointing to valid
    /// memory when the structure is received through the pro_backend APIs.
    const session_pro_backend_payment_provider_metadata* payment_provider_metadata;

    bool auto_renewing;
    uint64_t unredeemed_unix_ts_ms;
    uint64_t redeemed_unix_ts_ms;
    uint64_t expiry_unix_ts_ms;
    uint64_t grace_period_duration_ms;
    uint64_t platform_refund_expiry_unix_ts_ms;
    uint64_t revoked_unix_ts_ms;
    uint64_t refund_requested_unix_ts_ms;

    char google_payment_token[128];
    size_t google_payment_token_count;
    char google_order_id[128];
    size_t google_order_id_count;
    char apple_original_tx_id[128];
    size_t apple_original_tx_id_count;
    char apple_tx_id[128];
    size_t apple_tx_id_count;
    char apple_web_line_order_id[128];
    size_t apple_web_line_order_id_count;
    char rangeproof_order_id[128];
    size_t rangeproof_order_id_count;
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
    uint64_t expiry_unix_ts_ms;
    uint64_t grace_period_duration_ms;
    uint64_t refund_requested_unix_ts_ms;
    uint32_t payments_total;
};

typedef struct session_pro_backend_set_payment_refund_requested_request
        session_pro_backend_set_payment_refund_requested_request;
struct session_pro_backend_set_payment_refund_requested_request {
    uint8_t version;
    bytes32 master_pkey;
    bytes64 master_sig;
    uint64_t unix_ts_ms;
    uint64_t refund_requested_unix_ts_ms;
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
/// - `payment_tx_provider` -- Provider that the payment to register is coming from
/// - `payment_tx_payment_id` -- ID that is associated with the payment from the payment provider.
///   See `AddProPaymentUserTransaction`
/// - `payment_tx_payment_id_len` -- Length of the `payment_tx_payment_id` payload
/// - `payment_tx_order_id` -- Order ID that is associated with the payment see
///   `AddProPaymentUserTransaction`
/// - `payment_tx_order_id_len` -- Length of the `payment_tx_order_id` payload
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
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        const uint8_t* payment_tx_payment_id,
        size_t payment_tx_payment_id_len,
        const uint8_t* payment_tx_order_id,
        size_t payment_tx_order_id_len) NON_NULL_ARG(2, 4, 7, 9);

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
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        const uint8_t* payment_tx_payment_id,
        size_t payment_tx_payment_id_len,
        const uint8_t* payment_tx_order_id,
        size_t payment_tx_order_id_len) NON_NULL_ARG(2, 4, 7, 9);

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
/// - `unix_ts_ms` -- Unix timestamp for the request.
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
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        uint64_t unix_ts_ms) NON_NULL_ARG(2, 4);

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
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        uint64_t unix_ts_ms) NON_NULL_ARG(2, 4);

/// API: session_pro_backend/get_pro_details_request_build_sig
///
/// Builds the JSON for a `get_pro_details_request`. Returns false if the keys (32-byte or
/// 64-byte libsodium format) are incorrectly sized. Using 64-byte libsodium keys is more efficient.
///
/// Inputs:
/// - `request_version` -- Version of the request.
/// - `master_privkey` -- Ed25519 master private key (32-byte or 64-byte libsodium format).
/// - `master_privkey_len` -- Length of master_privkey.
/// - `unix_ts_ms` -- Unix timestamp for the request.
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
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        uint64_t unix_ts_ms,
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
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        uint64_t unix_ts_ms,
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
/// - `unix_ts_ms` -- Unix timestamp for the request
/// - `refund_requested_unix_ts_ms` -- Unix timestamp to set as the timestamp that a refund was
///   requested on this payment
/// - `payment_tx_provider` -- Provider that the payment to register is coming from
/// - `payment_tx_payment_id` -- ID that is associated with the payment from the payment provider.
///   See `AddProPaymentUserTransaction`
/// - `payment_tx_payment_id_len` -- Length of the `payment_tx_payment_id` payload
/// - `payment_tx_order_id` -- Order ID that is associated with the payment see
///   `AddProPaymentUserTransaction`
/// - `payment_tx_order_id_len` -- Length of the `payment_tx_order_id` payload
///
/// Outputs:
/// - `bool` -- True if signatures are built successfully, false otherwise.
/// - `error` -- Backing error buffer for the signatures if `success` is false
/// - `errors_count` -- length of the error if `success` is false
/// - `sig` -- The generated signature
LIBSESSION_EXPORT
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
        size_t payment_tx_order_id_len) NON_NULL_ARG(2, 7, 9);

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
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        uint64_t unix_ts_ms,
        uint64_t refund_requested_unix_ts_ms,
        SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
        const uint8_t* payment_tx_payment_id,
        size_t payment_tx_payment_id_len,
        const uint8_t* payment_tx_order_id,
        size_t payment_tx_order_id_len) NON_NULL_ARG(2, 7, 9);

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
