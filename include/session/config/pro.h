#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../export.h"

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

LIBSESSION_EXPORT pro_proof pro_proof_init(char const* dump, size_t dump_len);

LIBSESSION_EXPORT pro_pro_config pro_pro_init(char const* dump, size_t dump_len);

LIBSESSION_EXPORT bool pro_proof_verify(pro_proof const* proof, uint8_t const* verify_pubkey);

LIBSESSION_EXPORT bool pro_pro_verify(pro_pro_config const* pro, uint8_t const* verify_pubkey);

#ifdef __cplusplus
}  // extern "C"
#endif
