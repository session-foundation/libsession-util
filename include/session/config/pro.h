#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../export.h"
#include "../types.h"

typedef enum PRO_STATUS {  // See session::ProStatus
    PRO_STATUS_NIL,
    PRO_STATUS_INVALID_PRO_BACKEND_SIG,
    PRO_STATUS_INVALID_USER_SIG,
    PRO_STATUS_VALID,
    PRO_STATUS_EXPIRED,
} PRO_STATUS;

typedef struct pro_signed_message {
    span_u8 sig;
    span_u8 msg;
} pro_signed_message;

typedef struct pro_proof {
    uint8_t version;
    uint8_t gen_index_hash[32];
    uint8_t rotating_pubkey[32];
    uint64_t expiry_unix_ts;
    uint8_t sig[64];
} pro_proof;

typedef struct pro_config {
    uint8_t rotating_privkey[64];
    pro_proof proof;
} pro_pro_config;

/// API: pro/pro_proof_hash
///
/// Generate the 32 byte hash that is to be signed by the rotating key or Session Pro Backend key to
/// embed in the envelope or proof respectively which other clients use to authenticate the validity
/// of a proof.
///
/// Inputs:
/// - `proof` -- Proof to calculate the hash from
///
/// Outputs:
/// - `bytes32` -- The 32 byte hash calculated from the proof
LIBSESSION_EXPORT bytes32 pro_proof_hash(pro_proof const* proof);

/// API: pro/pro_proof_verify_signature
///
/// Verify the proof was signed by the `verify_pubkey`
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `verify_pubkey` -- Array of bytes containing the public key to (typically the Session Pro
///   Backend public key) verify the proof against.
/// - `verify_pubkey_len` -- Length of the `verify_pubkey` this must be 32 bytes, but is
///   parameterised to detect errors about incorrectly sized arrays by the caller.
///
/// Outputs:
/// - `bool` -- True if verified, false otherwise
LIBSESSION_EXPORT bool pro_proof_verify_signature(
        pro_proof const* proof, uint8_t const* verify_pubkey, size_t verify_pubkey_len);

/// API: pro/pro_proof_verify_message
///
/// Check if the `rotating_pubkey` in the proof was the signatory of the message and signature
/// passed in. This function throws if an signature is passed in that isn't 64 bytes.
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `sig` -- Signature to verify with the `rotating_pubkey`. The signature should have
///   originally been signed over `msg` passed in.
/// - `sig_len` -- Length of the signature, should be 64 bytes
/// - `msg` -- Message that the signature signed over with. It will be verified using the
///   embedded `rotating_pubkey`.
/// - `msg_len` -- Length of the message
///
/// Outputs:
/// - `bool` -- True if verified, false otherwise (bad signature, or, invalid arguments).
LIBSESSION_EXPORT bool pro_proof_verify_message(
        pro_proof const* proof,
        uint8_t const* sig,
        size_t sig_len,
        uint8_t const* msg,
        size_t msg_len);

/// API: pro/pro_proof_is_active
///
/// Check if the Pro proof is currently entitled to Pro given the `unix_ts` with respect to the
/// proof's `expiry_unix_ts`
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `unix_ts_s` -- The unix timestamp in seconds to check the proof expiry time against
///
/// Outputs:
/// - `bool` -- True if expired, false otherwise
LIBSESSION_EXPORT bool pro_proof_is_active(pro_proof const* proof, uint64_t unix_ts_s);

/// API: pro/pro_proof_status
///
/// Evaluate the status of the pro proof by checking it is signed by the `verify_pubkey`, it has
/// not expired via `unix_ts_s` and optionally verify that the `signed_msg` was signed by the
/// `rotating_pubkey` embedded in the proof.
///
/// Internally this function calls `pro_proof_verify_signature`, `pro_proof_verify_message` and
/// optionally `pro_proof_is_active` in sequence. This function fails if an invalidly sized public
/// key or signature are passed in. They must be 32 and 64 bytes respectively, the appropriate
/// invalid status will be returned.
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `verify_pubkey` -- 32 byte Ed25519 public key of the corresponding secret key to check if
///   they are the original signatory of the proof.
/// - `verify_pubkey_len` -- Length of the `verify_pubkey` should be 32 bytes
///   they are the original signatory of the proof.
/// - `unix_ts` -- Unix timestamp in seconds to compared against the embedded `expiry_unix_ts`
///   to determine if the proof has expired or not
/// - `signed_msg` -- Optionally set the payload to the message with the signature to verify if
///   the embedded `rotating_pubkey` in the proof signed the given message.
///
/// Outputs:
/// - `status` - The derived status given the components of the message. If `signed_msg` is
///   not set then this function can never return `PRO_STATUS_INVALID_USER_SIG` from the set of
///   possible enum values. Otherwise this funtion can return all possible values.
LIBSESSION_EXPORT PRO_STATUS pro_proof_status(
        pro_proof const* proof,
        const uint8_t* verify_pubkey,
        size_t verify_pubkey_len,
        uint64_t unix_ts_s,
        const pro_signed_message* signed_msg);

/// API: pro/pro_verify
///
/// Verify the proof was signed by the `verify_pubkey` and that the `rotating_privkey` in the `pro`
/// config rederives to the `rotating_pubkey` embedded in the proof.
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `verify_pubkey` -- Array of bytes containing the public key to (typically the Session Pro
///   Backend public key) verify the proof against.
/// - `verify_pubkey_len` -- Length of the `verify_pubkey` this must be 32 bytes, but is
///   parameterised to detect errors about incorrectly sized arrays by the caller.
///
/// Outputs:
/// - `bytes32` -- The 32 byte hash calculated from the proof
LIBSESSION_EXPORT bool pro_config_verify_signature(
        pro_config const* pro, uint8_t const* verify_pubkey, size_t verify_pubkey_len);

#ifdef __cplusplus
}  // extern "C"
#endif
