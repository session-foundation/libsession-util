#pragma once

#include <session/types.h>
#include <stddef.h>
#include <stdint.h>
#include <session/session_protocol.h>

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SESSION_PRO_BACKEND_STATUS_SUCCESS = 0,
    SESSION_PRO_BACKEND_STATUS_GENERIC_ERROR = 1,
};

typedef struct session_pro_backend_response_header {
    uint32_t status;
    /// Array of error messages (NULL if no errors), with errors_count elements
    string8* errors;
    size_t errors_count;
    uint8_t* internal_arena_buf_;  /// Internal buffer for all the memory allocations, do not touch
} session_pro_backend_response_header;

typedef struct {
    bool success;  /// True if conversion to JSON was successful, false if out-of-memory
    string8 json;
} session_pro_backend_to_json;

typedef struct session_pro_backend_master_rotating_signatures {
    bool success;
    char error[256];
    size_t error_count;
    bytes64 master_sig;
    bytes64 rotating_sig;
} session_pro_backend_master_rotating_signatures;

typedef struct session_pro_backend_signature {
    bool success;
    char error[256];
    size_t error_count;
    bytes64 sig;
} session_pro_backend_signature;

typedef struct session_pro_backend_add_pro_payment_request {
    uint8_t version;
    bytes32 master_pkey;
    bytes32 rotating_pkey;
    bytes32 payment_token;
    bytes64 master_sig;
    bytes64 rotating_sig;
} session_pro_backend_add_pro_payment_request;

typedef struct session_pro_backend_get_pro_proof_request {
    uint8_t version;
    bytes32 master_pkey;
    bytes32 rotating_pkey;
    uint64_t unix_ts_s;
    bytes64 master_sig;
    bytes64 rotating_sig;
} session_pro_backend_get_pro_proof_request;

typedef struct session_pro_backend_add_pro_payment_or_get_pro_proof_response {
    session_pro_backend_response_header header;
    pro_proof proof;
} session_pro_backend_add_pro_payment_or_get_pro_proof_response;

typedef struct session_pro_backend_get_pro_revocations_request {
    uint8_t version;
    uint32_t ticket;
} session_pro_backend_get_pro_revocations_request;

typedef struct session_pro_backend_pro_revocation_item {
    bytes32 gen_index_hash;
    uint64_t expiry_unix_ts_s;
} session_pro_backend_pro_revocation_item;

typedef struct session_pro_backend_get_pro_revocations_response {
    session_pro_backend_response_header header;
    uint32_t ticket;
    /// Array of items, with items_count elements
    session_pro_backend_pro_revocation_item* items;
    size_t items_count;
} session_pro_backend_get_pro_revocations_response;

typedef struct session_pro_backend_get_pro_payments_request {
    uint8_t version;
    bytes32 master_pkey;
    bytes64 master_sig;
    uint64_t unix_ts_s;
    uint32_t page;
} session_pro_backend_get_pro_payments_request;

typedef struct session_pro_backend_pro_payment_item {
    uint64_t activation_unix_ts_s;
    uint64_t archive_unix_ts_s;
    uint64_t creation_unix_ts_s;
    uint64_t subscription_duration;
    bytes32 payment_token_hash;
} session_pro_backend_pro_payment_item;

typedef struct session_pro_backend_get_pro_payments_response {
    session_pro_backend_response_header header;
    /// Array of payment items, with items_count elements
    session_pro_backend_pro_payment_item* items;
    size_t items_count;
    uint32_t pages;
    uint32_t payments;
} session_pro_backend_get_pro_payments_response;

/// API: session_pro_backend/add_pro_payment_request_build_sigs
///
/// Builds master and rotating signatures for an AddProPaymentRequest.
/// Returns false if the keys (32-byte or 64-byte libsodium format) or payment token hash are
/// incorrectly sized. Using 64-byte libsodium keys is more efficient.
///
/// Inputs:
/// - `request_version` -- Version of the request.
/// - `master_privkey` -- Ed25519 master private key (32-byte or 64-byte libsodium format).
/// - `master_privkey_len` -- Length of master_privkey.
/// - `rotating_privkey` -- Ed25519 rotating private key (32-byte or 64-byte libsodium format).
/// - `rotating_privkey_len` -- Length of rotating_privkey.
/// - `payment_token_hash` -- 32-byte hash of the payment token.
/// - `payment_token_hash_len` -- Length of payment_token_hash.
///
/// Outputs:
/// - `success` - True if signatures are built successfully, false otherwise.
/// - `error` - Backing error buffer for the signatures if `success` is false
/// - `errors_count` - length of the error if `success` is false
/// - `master_sig` - Master signature
/// - `rotating_sig` - Rotating signature
LIBSESSION_EXPORT
session_pro_backend_master_rotating_signatures
session_pro_backend_add_pro_payment_request_build_sigs(
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        const uint8_t* payment_token_hash,
        size_t payment_token_hash_len);

/// API: session_pro_backend/get_pro_proof_request_build_sigs
///
/// Builds master and rotating signatures for a GetProProofRequest.
/// Returns false if the keys (32-byte or 64-byte libsodium format) are incorrectly sized.
/// Using 64-byte libsodium keys is more efficient.
///
/// Inputs:
/// - `request_version` -- Version of the request.
/// - `master_privkey` -- Ed25519 master private key (32-byte or 64-byte libsodium format).
/// - `master_privkey_len` -- Length of master_privkey.
/// - `rotating_privkey` -- Ed25519 rotating private key (32-byte or 64-byte libsodium format).
/// - `rotating_privkey_len` -- Length of rotating_privkey.
/// - `unix_ts_s` -- Unix timestamp (seconds) for the request.
///
/// Outputs:
/// - `bool` - True if signatures are built successfully, false otherwise.
/// - `error` - Backing error buffer for the signatures if `success` is false
/// - `errors_count` - length of the error if `success` is false
/// - `master_sig` - Master signature
/// - `rotating_sig` - Rotating signature
LIBSESSION_EXPORT
session_pro_backend_master_rotating_signatures
session_pro_backend_get_pro_proof_request_build_sigs(
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        uint64_t unix_ts_s);

/// API: session_pro_backend/get_pro_payments_request_build_sig
///
/// Builds the signature for GetProPaymentsRequest
/// Returns false if the keys (32-byte or 64-byte libsodium format) are incorrectly sized.
/// Using 64-byte libsodium keys is more efficient.
///
/// Inputs:
/// - `request_version` -- Version of the request.
/// - `master_privkey` -- Ed25519 master private key (32-byte or 64-byte libsodium format).
/// - `master_privkey_len` -- Length of master_privkey.
/// - `unix_ts_s` -- Unix timestamp (seconds) for the request.
/// - `page` -- The page in the paginated list of historical payments to request
///
/// Outputs:
/// - `bool` - True if signature was built successfully, false otherwise.
/// - `error` - Backing error buffer for the signatures if `success` is false
/// - `errors_count` - length of the error if `success` is false
/// - `sig` - 64 byte signature
LIBSESSION_EXPORT
session_pro_backend_signature session_pro_backend_get_pro_payments_request_build_sig(
        uint8_t request_version,
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        uint64_t unix_ts_s,
        uint32_t page);

/// API: session_pro_backend/add_pro_payment_request_to_json
///
/// Serializes an `AddProPaymentRequest` to a JSON string.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
///
/// Inputs:
/// - `request` -- Pointer to the request struct.
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_add_pro_payment_request_to_json(
        const session_pro_backend_add_pro_payment_request* request);

/// API: session_pro_backend/get_pro_proof_request_to_json
///
/// Serializes a `GetProProofRequest` to a JSON string.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
///
/// Inputs:
/// - `request` -- Pointer to the request struct.
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_get_pro_proof_request_to_json(
        const session_pro_backend_get_pro_proof_request* request);

/// API: session_pro_backend/get_pro_revocations_request_to_json
///
/// Serializes a `GetProRevocationsRequest` to a JSON string.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_get_pro_revocations_request_to_json(
        const session_pro_backend_get_pro_revocations_request* request);

/// API: session_pro_backend/get_pro_payments_request_to_json
///
/// Serializes a `GetProPaymentsRequest` to a JSON string.
/// The caller must free the returned string using `session_pro_backend_to_json_free`.
LIBSESSION_EXPORT
session_pro_backend_to_json session_pro_backend_get_pro_payments_request_to_json(
        const session_pro_backend_get_pro_payments_request* request);

/// API: session_pro_backend/add_pro_payment_or_get_pro_proof_response_parse
///
/// Parses a JSON string into an `AddProPaymentOrGetProProofResponse` struct.
/// The caller must free the response using
/// `session_pro_backend_add_pro_payment_or_get_pro_proof_response_free`.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_add_pro_payment_or_get_pro_proof_response
session_pro_backend_add_pro_payment_or_get_pro_proof_response_parse(
        const char* json,
        size_t json_len);

/// API: session_pro_backend/get_pro_revocations_response_parse
///
/// Parses a JSON string into a GetProRevocationsResponse struct.
/// The caller must free the response using session_pro_backend_get_pro_revocations_response_free.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_get_pro_revocations_response
session_pro_backend_get_pro_revocations_response_parse(
        const char* json,
        size_t json_len);

/// API: session_pro_backend/get_pro_payments_response_parse
///
/// Parses a JSON string into a GetProPaymentsResponse struct.
/// The caller must free the response using session_pro_backend_get_pro_payments_response_free.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_get_pro_payments_response
session_pro_backend_get_pro_payments_response_parse(
        const char* json,
        size_t json_len);

/// API: session_pro_backend/to_json_free
///
/// Frees the JSON
LIBSESSION_EXPORT
void session_pro_backend_to_json_free(session_pro_backend_to_json* to_json);

/// API: session_pro_backend/add_pro_payment_or_get_pro_proof_response_free
///
/// Frees the response
LIBSESSION_EXPORT
void session_pro_backend_add_pro_payment_or_get_pro_proof_response_free(
        session_pro_backend_add_pro_payment_or_get_pro_proof_response* response);

/// API: session_pro_backend/get_pro_revocations_response_free
///
/// Frees the respone
LIBSESSION_EXPORT
void session_pro_backend_get_pro_revocations_response_free(
        session_pro_backend_get_pro_revocations_response* response);

/// API: session_pro_backend/get_pro_payments_response_free
///
/// Frees the respone
LIBSESSION_EXPORT
void session_pro_backend_get_pro_payments_response_free(
        session_pro_backend_get_pro_payments_response* response);

#ifdef __cplusplus
}  // extern "C"
#endif
