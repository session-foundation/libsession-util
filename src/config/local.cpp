#include "session/config/local.h"

#include <sodium/crypto_generichash_blake2b.h>

#include "internal.hpp"
#include "session/config/error.h"
#include "session/config/local.hpp"
#include "session/export.h"
#include "session/types.hpp"

using namespace session::config;

Local::Local(
        std::span<const unsigned char> ed25519_secretkey,
        std::optional<std::span<const unsigned char>> dumped) {
    init(dumped, std::nullopt, std::nullopt);
    load_key(ed25519_secretkey);
}

notify_content Local::get_notification_content() const {
    int notify_content_ = data["notify_content"].integer_or(0);
    if (notify_content_ >= static_cast<int>(notify_content::defaulted) &&
        notify_content_ <= static_cast<int>(notify_content::no_name_no_preview))
        return static_cast<notify_content>(notify_content_);
    else
        return notify_content::defaulted;
}

void Local::set_notification_content(notify_content value) {
    set_positive_int(data["notify_content"], static_cast<int>(value));
}

int64_t Local::get_ios_notification_sound() const {
    return data["notify_sound"].integer_or(0);
}

void Local::set_ios_notification_sound(int64_t value) {
    set_positive_int(data["notify_sound"], value);
}

theme Local::get_theme() const {
    int theme_ = data["theme"].integer_or(0);
    if (theme_ >= static_cast<int>(theme::defaulted) &&
        theme_ <= static_cast<int>(theme::ocean_light))
        return static_cast<theme>(theme_);
    else
        return theme::defaulted;
}

void Local::set_theme(theme value) {
    set_positive_int(data["theme"], static_cast<int>(value));
}

theme_primary_color Local::get_theme_primary_color() const {
    int theme_primary_color_ = data["theme_primary_color"].integer_or(0);
    if (theme_primary_color_ >= static_cast<int>(theme_primary_color::defaulted) &&
        theme_primary_color_ <= static_cast<int>(theme_primary_color::red))
        return static_cast<theme_primary_color>(theme_primary_color_);
    else
        return theme_primary_color::defaulted;
}

void Local::set_theme_primary_color(theme_primary_color value) {
    set_positive_int(data["theme_primary_color"], static_cast<int>(value));
}

std::optional<bool> Local::get_setting(std::string key) const {
    auto* settings_dict = data["settings"].dict();
    if (!settings_dict)
        return std::nullopt;

    if (auto it = maybe_int(*settings_dict, key.c_str()))
        return static_cast<bool>(*it);
    return std::nullopt;
}

void Local::set_setting(std::string key, std::optional<bool> enabled) {
    auto info = data["settings"];
    if (enabled) {
        set_flag(info[std::move(key)], *enabled);
    } else
        info[key].erase();
}

size_t Local::size_settings() const {
    if (auto* d = data["settings"].dict())
        return d->size();
    return 0;
}

extern "C" {

using namespace session;
using namespace session::config;

LIBSESSION_C_API int local_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey_bytes,
        const unsigned char* dumpstr,
        size_t dumplen,
        char* error) {
    return c_wrapper_init<Local>(conf, ed25519_secretkey_bytes, dumpstr, dumplen, error);
}

LIBSESSION_C_API CLIENT_NOTIFY_CONTENT local_get_notification_content(const config_object* conf) {
    return static_cast<CLIENT_NOTIFY_CONTENT>(unbox<Local>(conf)->get_notification_content());
}

LIBSESSION_C_API void local_set_notification_content(
        config_object* conf, CLIENT_NOTIFY_CONTENT value) {
    unbox<Local>(conf)->set_notification_content(static_cast<notify_content>(value));
}

LIBSESSION_C_API int64_t local_get_ios_notification_sound(const config_object* conf) {
    return unbox<Local>(conf)->get_ios_notification_sound();
}

LIBSESSION_C_API void local_set_ios_notification_sound(config_object* conf, int64_t value) {
    unbox<Local>(conf)->set_ios_notification_sound(value);
}

LIBSESSION_C_API CLIENT_THEME local_get_theme(const config_object* conf) {
    return static_cast<CLIENT_THEME>(unbox<Local>(conf)->get_theme());
}

LIBSESSION_C_API void local_set_theme(config_object* conf, CLIENT_THEME value) {
    unbox<Local>(conf)->set_theme(static_cast<theme>(value));
}

LIBSESSION_C_API CLIENT_THEME_PRIMARY_COLOR
local_get_theme_primary_color(const config_object* conf) {
    return static_cast<CLIENT_THEME_PRIMARY_COLOR>(unbox<Local>(conf)->get_theme_primary_color());
}

LIBSESSION_C_API void local_set_theme_primary_color(
        config_object* conf, CLIENT_THEME_PRIMARY_COLOR value) {
    unbox<Local>(conf)->set_theme_primary_color(static_cast<theme_primary_color>(value));
}

LIBSESSION_C_API int local_get_setting(const config_object* conf, const char* key) {
    if (auto opt = unbox<Local>(conf)->get_setting(key))
        return static_cast<int>(*opt);
    return -1;
}

LIBSESSION_C_API void local_set_setting(config_object* conf, const char* key, int value) {
    std::optional<bool> val;
    if (value >= 0)
        val = static_cast<bool>(value);
    unbox<Local>(conf)->set_setting(key, std::move(val));
}

LIBSESSION_C_API size_t local_size_settings(const config_object* conf) {
    return unbox<Local>(conf)->size_settings();
}

}  // extern "C"
