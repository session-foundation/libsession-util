#include "session/config/user_profile.h"

#include <sodium/crypto_generichash_blake2b.h>

#include "internal.hpp"
#include "session/config/contacts.hpp"
#include "session/config/error.h"
#include "session/config/user_profile.hpp"
#include "session/export.h"
#include "session/types.hpp"

using namespace session::config;

UserProfile::UserProfile(
        std::span<const unsigned char> ed25519_secretkey,
        std::optional<std::span<const unsigned char>> dumped) {
    init(dumped);
    load_key(ed25519_secretkey);
}

void UserProfile::extra_data(oxenc::bt_dict_producer&& extra) const {
    if (!local_settings.empty())
        extra.append_dict("local_settings").extend(local_settings.begin(), local_settings.end());
    if (notification_content_setting != notify_content::defaulted)
        extra.append("notify_content", static_cast<uint16_t>(notification_content_setting));
    if (notification_sound_setting != notify_sound::defaulted)
        extra.append("notify_sound", static_cast<uint16_t>(notification_sound_setting));
    if (theme_setting != theme::defaulted)
        extra.append("theme", static_cast<uint16_t>(theme_setting));
    if (theme_primary_color_setting != theme_primary_color::defaulted)
        extra.append("theme_primary_color", static_cast<uint16_t>(theme_primary_color_setting));
}

void UserProfile::load_extra_data(oxenc::bt_dict_consumer&& extra) {
    if (extra.skip_until("local_settings")) {
        auto dict = extra.consume_dict_consumer();
        while (!dict.is_finished()) {
            auto [key, value] = dict.next_integer<uint16_t>();
            local_settings.emplace(key, value);
        }
    }
    if (extra.skip_until("notify_content"))
        notification_content_setting =
                static_cast<notify_content>(extra.consume_integer<uint16_t>());
    if (extra.skip_until("notify_sound"))
        notification_sound_setting = static_cast<notify_sound>(extra.consume_integer<uint16_t>());
    if (extra.skip_until("theme"))
        theme_setting = static_cast<theme>(extra.consume_integer<uint16_t>());
    if (extra.skip_until("theme_primary_color"))
        theme_primary_color_setting =
                static_cast<theme_primary_color>(extra.consume_integer<uint16_t>());
}

std::optional<std::string_view> UserProfile::get_name() const {
    if (auto* s = data["n"].string(); s && !s->empty())
        return *s;
    return std::nullopt;
}

void UserProfile::set_name(std::string_view new_name) {
    if (new_name.size() > contact_info::MAX_NAME_LENGTH)
        throw std::invalid_argument{"Invalid profile name: exceeds maximum length"};
    set_nonempty_str(data["n"], new_name);
}
void UserProfile::set_name_truncated(std::string new_name) {
    set_name(utf8_truncate(std::move(new_name), contact_info::MAX_NAME_LENGTH));
}

profile_pic UserProfile::get_profile_pic() const {
    profile_pic pic{};
    if (auto* url = data["p"].string(); url && !url->empty())
        pic.url = *url;
    if (auto* key = data["q"].string(); key && key->size() == 32)
        pic.key.assign(
                reinterpret_cast<const unsigned char*>(key->data()),
                reinterpret_cast<const unsigned char*>(key->data()) + 32);
    return pic;
}

void UserProfile::set_profile_pic(std::string_view url, std::span<const unsigned char> key) {
    set_pair_if(!url.empty() && key.size() == 32, data["p"], url, data["q"], key);
}

void UserProfile::set_profile_pic(profile_pic pic) {
    set_profile_pic(pic.url, pic.key);
}

void UserProfile::set_nts_priority(int priority) {
    set_nonzero_int(data["+"], priority);
}

int UserProfile::get_nts_priority() const {
    return data["+"].integer_or(0);
}

void UserProfile::set_nts_expiry(std::chrono::seconds expiry) {
    set_positive_int(data["e"], expiry.count());
}

std::optional<std::chrono::seconds> UserProfile::get_nts_expiry() const {
    if (auto* e = data["e"].integer(); e && *e > 0)
        return std::chrono::seconds{*e};
    return std::nullopt;
}

void UserProfile::set_blinded_msgreqs(std::optional<bool> value) {
    if (!value)
        data["M"].erase();
    else
        data["M"] = static_cast<int>(*value);
}

std::optional<bool> UserProfile::get_blinded_msgreqs() const {
    if (auto* M = data["M"].integer(); M)
        return static_cast<bool>(*M);
    return std::nullopt;
}

notify_content UserProfile::get_notification_content() const {
    return notification_content_setting;
}

void UserProfile::set_notification_content(notify_content value) {
    if (value != notification_content_setting) {
        notification_content_setting = value;
        _needs_dump = true;
    }
}

notify_sound UserProfile::get_notification_sound() const {
    return notification_sound_setting;
}

void UserProfile::set_notification_sound(notify_sound value) {
    if (value != notification_sound_setting) {
        notification_sound_setting = value;
        _needs_dump = true;
    }
}

theme UserProfile::get_theme() const {
    return theme_setting;
}

void UserProfile::set_theme(theme value) {
    if (value != theme_setting) {
        theme_setting = value;
        _needs_dump = true;
    }
}

theme_primary_color UserProfile::get_theme_primary_color() const {
    return theme_primary_color_setting;
}

void UserProfile::set_theme_primary_color(theme_primary_color value) {
    if (value != theme_primary_color_setting) {
        theme_primary_color_setting = value;
        _needs_dump = true;
    }
}

std::optional<bool> UserProfile::get_local_setting(std::string key) const {
    if (auto it = local_settings.find(key); it != local_settings.end())
        return static_cast<bool>(it->second);
    return std::nullopt;
}

void UserProfile::set_local_setting(std::string key, std::optional<bool> enabled) {
    bool changed = false;
    if (enabled) {
        auto [it, inserted] = local_settings.try_emplace(std::move(key), *enabled);
        changed = inserted;

        if (!inserted && it->second != *enabled) {
            it->second = *enabled;
            changed = true;
        }
    } else
        changed = local_settings.erase(key);
    if (changed)
        _needs_dump = true;
}

extern "C" {

using namespace session;
using namespace session::config;

LIBSESSION_C_API const size_t PROFILE_PIC_MAX_URL_LENGTH = profile_pic::MAX_URL_LENGTH;

LIBSESSION_C_API int user_profile_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey_bytes,
        const unsigned char* dumpstr,
        size_t dumplen,
        char* error) {
    return c_wrapper_init<UserProfile>(conf, ed25519_secretkey_bytes, dumpstr, dumplen, error);
}

LIBSESSION_C_API const char* user_profile_get_name(const config_object* conf) {
    if (auto s = unbox<UserProfile>(conf)->get_name())
        return s->data();
    return nullptr;
}

LIBSESSION_C_API int user_profile_set_name(config_object* conf, const char* name) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<UserProfile>(conf)->set_name(name);
                return 0;
            },
            static_cast<int>(SESSION_ERR_BAD_VALUE));
}

LIBSESSION_C_API user_profile_pic user_profile_get_pic(const config_object* conf) {
    user_profile_pic p;
    if (auto pic = unbox<UserProfile>(conf)->get_profile_pic(); pic) {
        copy_c_str(p.url, pic.url);
        std::memcpy(p.key, pic.key.data(), 32);
    } else {
        p.url[0] = 0;
    }
    return p;
}

LIBSESSION_C_API int user_profile_set_pic(config_object* conf, user_profile_pic pic) {
    std::string_view url{pic.url};
    std::span<const unsigned char> key;
    if (!url.empty())
        key = {pic.key, 32};

    return wrap_exceptions(
            conf,
            [&] {
                unbox<UserProfile>(conf)->set_profile_pic(url, key);
                return 0;
            },
            static_cast<int>(SESSION_ERR_BAD_VALUE));
}

LIBSESSION_C_API int user_profile_get_nts_priority(const config_object* conf) {
    return unbox<UserProfile>(conf)->get_nts_priority();
}

LIBSESSION_C_API void user_profile_set_nts_priority(config_object* conf, int priority) {
    unbox<UserProfile>(conf)->set_nts_priority(priority);
}

LIBSESSION_C_API int user_profile_get_nts_expiry(const config_object* conf) {
    return unbox<UserProfile>(conf)->get_nts_expiry().value_or(0s).count();
}

LIBSESSION_C_API void user_profile_set_nts_expiry(config_object* conf, int expiry) {
    unbox<UserProfile>(conf)->set_nts_expiry(std::max(0, expiry) * 1s);
}

LIBSESSION_C_API int user_profile_get_blinded_msgreqs(const config_object* conf) {
    if (auto opt = unbox<UserProfile>(conf)->get_blinded_msgreqs())
        return static_cast<int>(*opt);
    return -1;
}

LIBSESSION_C_API void user_profile_set_blinded_msgreqs(config_object* conf, int enabled) {
    std::optional<bool> val;
    if (enabled >= 0)
        val = static_cast<bool>(enabled);
    unbox<UserProfile>(conf)->set_blinded_msgreqs(std::move(val));
}

LIBSESSION_C_API CLIENT_NOTIFY_CONTENT
user_profile_get_notification_content(const config_object* conf) {
    return static_cast<CLIENT_NOTIFY_CONTENT>(unbox<UserProfile>(conf)->get_notification_content());
}

LIBSESSION_C_API void user_profile_set_notification_content(
        config_object* conf, CLIENT_NOTIFY_CONTENT value) {
    unbox<UserProfile>(conf)->set_notification_content(static_cast<notify_content>(value));
}

LIBSESSION_C_API CLIENT_NOTIFY_SOUND
user_profile_get_notification_sound(const config_object* conf) {
    return static_cast<CLIENT_NOTIFY_SOUND>(unbox<UserProfile>(conf)->get_notification_sound());
}

LIBSESSION_C_API void user_profile_set_notification_sound(
        config_object* conf, CLIENT_NOTIFY_SOUND value) {
    unbox<UserProfile>(conf)->set_notification_sound(static_cast<notify_sound>(value));
}

LIBSESSION_C_API CLIENT_THEME user_profile_get_theme(const config_object* conf) {
    return static_cast<CLIENT_THEME>(unbox<UserProfile>(conf)->get_theme());
}

LIBSESSION_C_API void user_profile_set_theme(config_object* conf, CLIENT_THEME value) {
    unbox<UserProfile>(conf)->set_theme(static_cast<theme>(value));
}

LIBSESSION_C_API CLIENT_THEME_PRIMARY_COLOR
user_profile_get_theme_primary_color(const config_object* conf) {
    return static_cast<CLIENT_THEME_PRIMARY_COLOR>(
            unbox<UserProfile>(conf)->get_theme_primary_color());
}

LIBSESSION_C_API void user_profile_set_theme_primary_color(
        config_object* conf, CLIENT_THEME_PRIMARY_COLOR value) {
    unbox<UserProfile>(conf)->set_theme_primary_color(static_cast<theme_primary_color>(value));
}

LIBSESSION_C_API int user_profile_get_local_setting(const config_object* conf, const char* key) {
    if (auto opt = unbox<UserProfile>(conf)->get_local_setting(key))
        return static_cast<int>(*opt);
    return -1;
}

LIBSESSION_C_API void user_profile_set_local_setting(
        config_object* conf, const char* key, int value) {
    std::optional<bool> val;
    if (value >= 0)
        val = static_cast<bool>(value);
    unbox<UserProfile>(conf)->set_local_setting(key, std::move(val));
}

}  // extern "C"