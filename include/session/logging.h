#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "export.h"
#include "log_level.h"

/// API: session/session_add_logger_simple
///
/// Registers a callback that is invoked when a message is logged.  This callback is invoked with
/// just the log message.
///
/// Inputs:
/// - `callback` -- [in] callback to be called when a new message should be logged.
LIBSESSION_EXPORT void session_add_logger_simple(void (*callback)(const char* msg, size_t msglen));

/// API: session/session_add_logger_full
///
/// Registers a callback that is invoked when a message is logged.  The callback is invoked with the
/// log message, the category name of the log message, and the level of the message.
///
/// Inputs:
/// - `callback` -- [in] callback to be called when a new message should be logged.
LIBSESSION_EXPORT void session_add_logger_full(void (*callback)(
        const char* msg, size_t msglen, const char* cat, size_t cat_len, LOG_LEVEL level));

/// API: session/session_logger_reset_level
///
/// Resets the log level of all existing category loggers, and sets a new default for any created
/// after this call.  If this has not been called, the default log level of category loggers is
/// info.
LIBSESSION_EXPORT void session_logger_reset_level(LOG_LEVEL level);

/// API: session/session_logger_set_level_default
///
/// Sets the log level of new category loggers initialized after this call, but does not change the
/// log level of already-initialized category loggers.
LIBSESSION_EXPORT void session_logger_set_level_default(LOG_LEVEL level);

/// API: session/session_logger_get_level_default
///
/// Gets the default log level of new loggers (since the last reset_level or set_level_default
/// call).
LIBSESSION_EXPORT LOG_LEVEL session_logger_get_level_default();

/// API: session/session_logger_set_level
///
/// Set the log level of a specific logger category
LIBSESSION_EXPORT void session_logger_set_level(const char* cat_name, LOG_LEVEL level);

/// API: session/session_logger_get_level
///
/// Gets the log level of a specific logger category
LIBSESSION_EXPORT LOG_LEVEL session_logger_get_level(const char* cat_name);

/// API: session/session_manual_log
///
/// Logs the provided value via oxen::log, can be used to test that the loggers are working
/// correctly
LIBSESSION_EXPORT void session_manual_log(const char* msg);

/// API: session/session_clear_loggers
///
/// Clears all currently set loggers
LIBSESSION_EXPORT void session_clear_loggers();

#ifdef __cplusplus
}
#endif
