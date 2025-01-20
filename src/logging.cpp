#include "session/logging.hpp"

#include <spdlog/common.h>

#include <memory>
#include <oxen/log.hpp>
#include <oxen/log/formatted_callback_sink.hpp>

#include "oxen/log/level.hpp"
#include "session/export.h"

namespace session {

namespace log = oxen::log;

LogLevel::LogLevel(spdlog::level::level_enum lvl) : level{static_cast<int>(lvl)} {}

spdlog::level::level_enum LogLevel::spdlog_level() const {
    return static_cast<log::Level>(level);
}

std::string_view LogLevel::to_string() const {
    return log::to_string(spdlog_level());
}

void add_logger(std::function<void(std::string_view msg)> cb) {
    log::add_sink(std::make_shared<log::formatted_callback_sink>(std::move(cb)));
}
void add_logger(
        std::function<void(std::string_view msg, std::string_view category, LogLevel level)> cb) {
    log::add_sink(std::make_shared<log::formatted_callback_sink>(std::move(cb)));
}

void manual_log(std::string_view msg) {
    log::info(oxen::log::Cat("manual"), "{}", msg);
}

void logger_reset_level(LogLevel level) {
    log::reset_level(level.spdlog_level());
}
void logger_set_level_default(LogLevel level) {
    log::set_level_default(level.spdlog_level());
}
LogLevel logger_get_level_default() {
    return log::get_level_default();
}
void logger_set_level(std::string cat_name, LogLevel level) {
    log::set_level(std::move(cat_name), level.spdlog_level());
}
LogLevel logger_get_level(std::string cat_name) {
    return log::get_level(std::move(cat_name));
}

void clear_loggers() {
    log::clear_sinks();
}

}  // namespace session

extern "C" {

LIBSESSION_C_API void session_add_logger_simple(void (*callback)(const char* msg, size_t msglen)) {
    assert(callback);
    session::add_logger(
            [cb = std::move(callback)](std::string_view msg) { cb(msg.data(), msg.size()); });
}

LIBSESSION_C_API void session_add_logger_full(void (*callback)(
        const char* msg, size_t msglen, const char* cat, size_t cat_len, LOG_LEVEL level)) {
    assert(callback);
    session::add_logger(
            [cb = std::move(callback)](
                    std::string_view msg, std::string_view category, session::LogLevel level) {
                cb(msg.data(),
                   msg.size(),
                   category.data(),
                   category.size(),
                   static_cast<LOG_LEVEL>(level.level));
            });
}

LIBSESSION_C_API void session_logger_reset_level(LOG_LEVEL level) {
    oxen::log::reset_level(static_cast<oxen::log::Level>(level));
}
LIBSESSION_C_API void session_logger_set_level_default(LOG_LEVEL level) {
    oxen::log::set_level_default(static_cast<oxen::log::Level>(level));
}
LIBSESSION_C_API LOG_LEVEL session_logger_get_level_default() {
    return static_cast<LOG_LEVEL>(oxen::log::get_level_default());
}
LIBSESSION_C_API void session_logger_set_level(const char* cat_name, LOG_LEVEL level) {
    oxen::log::set_level(cat_name, static_cast<oxen::log::Level>(level));
}
LIBSESSION_C_API LOG_LEVEL session_logger_get_level(const char* cat_name) {
    return static_cast<LOG_LEVEL>(oxen::log::get_level(cat_name));
}

LIBSESSION_C_API void session_manual_log(const char* msg) {
    session::manual_log(msg);
}

LIBSESSION_C_API void session_clear_loggers() {
    session::clear_loggers();
}

}  // extern "C"