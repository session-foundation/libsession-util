#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Note: These values must match the values in spdlog::level::level_enum
typedef enum LOG_LEVEL {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_WARN = 3,
    LOG_LEVEL_ERROR = 4,
    LOG_LEVEL_CRITICAL = 5,
    LOG_LEVEL_OFF = 6,
} LOG_LEVEL;

#ifdef __cplusplus
}
#endif
