#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "../export.h"

typedef enum {
    SESSION_NETWORK_CATEGORY_STANDARD = 0,
    SESSION_NETWORK_CATEGORY_UPLOAD = 1,
    SESSION_NETWORK_CATEGORY_DOWNLOAD = 2
} SESSION_NETWORK_CATEGORY_TYPE;

#ifdef __cplusplus
}
#endif
