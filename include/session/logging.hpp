#pragma once

#include <functional>
#include <string_view>

#include "log_level.h"

// forward declaration
namespace spdlog::level {
enum level_enum : int;
}

namespace session {

// This is working roughly like an enum class, but with some useful conversions and comparisons
// defined.  We allow implicit conversion to this from a spdlog level_enum, and explicit conversion
// *to* a level_enum, as well as comparison operators (so that, for example, LogLevel::warn >=
// LogLevel::info).
struct LogLevel {
    int level;

    LogLevel(spdlog::level::level_enum lvl);
    explicit constexpr LogLevel(int lvl) : level{lvl} {}

    // Returns the log level as an spdlog enum (which is also a oxen::log::Level).
    spdlog::level::level_enum spdlog_level() const;

    std::string_view to_string() const;

    static const LogLevel trace;
    static const LogLevel debug;
    static const LogLevel info;
    static const LogLevel warn;
    static const LogLevel error;
    static const LogLevel critical;

    auto operator<=>(const LogLevel& other) const { return level <=> other.level; }
};

inline const LogLevel LogLevel::trace{LOG_LEVEL_TRACE};
inline const LogLevel LogLevel::debug{LOG_LEVEL_DEBUG};
inline const LogLevel LogLevel::info{LOG_LEVEL_INFO};
inline const LogLevel LogLevel::warn{LOG_LEVEL_WARN};
inline const LogLevel LogLevel::error{LOG_LEVEL_ERROR};
inline const LogLevel LogLevel::critical{LOG_LEVEL_CRITICAL};

/// API: add_logger
///
/// Adds a logger callback for oxen-logging log messages (such as from the network object).
///
/// Inputs:
/// - `callback` -- [in] callback to be called when a new message should be logged.  This
///   callback must be callable as one of:
///
///     callback(std::string_view msg)
///     callback(std::string_view msg, std::string_view log_cat, LogLevel level)
///
void add_logger(std::function<void(std::string_view msg)> cb);
void add_logger(
        std::function<void(std::string_view msg, std::string_view category, LogLevel level)> cb);

/// API: session/logger_reset_level
///
/// Resets the log level of all existing category loggers, and sets a new default for any created
/// after this call.  If this has not been called, the default log level of category loggers is
/// info.
///
/// This function is simply a wrapper around oxen::log::reset_level
void logger_reset_level(LogLevel level);

/// API: session/logger_set_level_default
///
/// Sets the log level of new category loggers initialized after this call, but does not change the
/// log level of already-initialized category loggers.
///
/// This function is simply a wrapper around oxen::log::set_level_default
void logger_set_level_default(LogLevel level);

/// API: session/logger_get_level_default
///
/// Gets the default log level of new loggers (since the last reset_level or set_level_default
/// call).
///
/// This function is simply a wrapper around oxen::log::get_level_default
LogLevel logger_get_level_default();

/// API: session/logger_set_level
///
/// Set the log level of a specific logger category
///
/// This function is simply a wrapper around oxen::log::set_level
void logger_set_level(std::string cat_name, LogLevel level);

/// API: session/logger_get_level
///
/// Gets the log level of a specific logger category
///
/// This function is simply a wrapper around oxen::log::get_level
LogLevel logger_get_level(std::string cat_name);

/// API: session/manual_log
///
/// Logs the provided value via oxen::log, can be used to test that the loggers are working
/// correctly
void manual_log(std::string_view msg);

/// API: session/clear_loggers
///
/// Clears all currently set loggers
void clear_loggers();

}  // namespace session
