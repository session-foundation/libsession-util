#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../export.h"
#include "session/session_protocol.h"

typedef struct pro_config {
    uint8_t rotating_privkey[64];
    pro_proof proof;
} pro_pro_config;

/// API: pro/pro_config_verify_signature
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
        pro_pro_config const* pro, uint8_t const* verify_pubkey, size_t verify_pubkey_len);

#ifdef __cplusplus
}  // extern "C"
#endif
