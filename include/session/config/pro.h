#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#include "../export.h"

struct pro_proof {
    uint8_t version;
    uint8_t gen_index_hash[32];
    uint8_t rotating_pubkey[32];
    uint64_t expiry_unix_ts;
    uint8_t sig[64];
};

struct pro_pro {
    uint8_t rotating_privkey[64];
    pro_proof proof;
};

LIBSESSION_EXPORT bool proof_verify(pro_proof const *proof, uint8_t const *verify_pubkey);

LIBSESSION_EXPORT bool pro_verify(pro_pro const *pro, uint8_t const *verify_pubkey);

#ifdef __cplusplus
}  // extern "C"
#endif
