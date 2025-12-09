#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../export.h"
#include "session/session_protocol.h"

typedef struct pro_pro_config pro_pro_config;
struct pro_pro_config {
    bytes64 rotating_privkey;
    session_protocol_pro_proof proof;
};

#ifdef __cplusplus
}  // extern "C"
#endif
