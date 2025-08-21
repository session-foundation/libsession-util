#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../export.h"
#include "../types.h"

typedef struct pro_proof {
    uint8_t version;
    uint8_t gen_index_hash[32];
    uint8_t rotating_pubkey[32];
    uint64_t expiry_unix_ts;
    uint8_t sig[64];
} pro_proof;

typedef struct pro_pro_config {
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

/// API: pro/pro_proof_verify
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
/// - `bytes32` -- The 32 byte hash calculated from the proof
LIBSESSION_EXPORT bool pro_proof_verify(
        pro_proof const* proof, uint8_t const* verify_pubkey, size_t verify_pubkey_len);

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
LIBSESSION_EXPORT bool pro_pro_verify(
        pro_pro_config const* pro, uint8_t const* verify_pubkey, size_t verify_pubkey_len);

#ifdef __cplusplus
}  // extern "C"
#endif
