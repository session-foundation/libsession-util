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
        std::optional<std::span<const unsigned char>> dumped) :
        ConfigBase{dumped} {
    load_key(ed25519_secretkey);
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
    
    const auto target_timestamp = (data["T"].integer_or(0) > data["t"].integer_or(0) ? "T" : "t");
    data[target_timestamp] = static_cast<int>(std::chrono::system_clock::now().time_since_epoch().count());
}
void UserProfile::set_name_truncated(std::string new_name) {
    set_name(utf8_truncate(std::move(new_name), contact_info::MAX_NAME_LENGTH));
}

profile_pic UserProfile::get_profile_pic() const {
    profile_pic pic{};

    const bool use_primary_keys = (data["T"].integer_or(0) > data["t"].integer_or(0));
    const auto url_key = (use_primary_keys ? "p" : "P");
    const auto key_key = (use_primary_keys ? "q" : "Q");
    
    if (auto* url = data[url_key].string(); url && !url->empty())
        pic.url = *url;
    if (auto* key = data[key_key].string(); key && key->size() == 32)
        pic.key.assign(
                reinterpret_cast<const unsigned char*>(key->data()),
                reinterpret_cast<const unsigned char*>(key->data()) + 32);
    return pic;
}

void UserProfile::set_profile_pic(std::string_view url, std::span<const unsigned char> key) {
    set_pair_if(!url.empty() && key.size() == 32, data["p"], url, data["q"], key);
    
    // If the profile was removed then we should remove the "reupload" version as well
    if (url.empty() || key.size() != 32) {
        set_reupload_profile_pic({});
    }

    data["t"] = static_cast<int>(std::chrono::system_clock::now().time_since_epoch().count());
}

void UserProfile::set_profile_pic(profile_pic pic) {
    set_profile_pic(pic.url, pic.key);
}

void UserProfile::set_reupload_profile_pic(std::string_view url, std::span<const unsigned char> key) {
    set_pair_if(!url.empty() && key.size() == 32, data["P"], url, data["Q"], key);
    data["T"] = static_cast<int>(std::chrono::system_clock::now().time_since_epoch().count());
}

void UserProfile::set_reupload_profile_pic(profile_pic pic) {
    set_reupload_profile_pic(pic.url, pic.key);
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

    const auto target_timestamp = (data["T"].integer_or(0) > data["t"].integer_or(0) ? "T" : "t");
    data[target_timestamp] = static_cast<int>(std::chrono::system_clock::now().time_since_epoch().count());
}

std::optional<bool> UserProfile::get_blinded_msgreqs() const {
    if (auto* M = data["M"].integer(); M)
        return static_cast<bool>(*M);
    return std::nullopt;
}

std::chrono::sys_seconds UserProfile::get_profile_updated() const {
    if (auto* t = data["t"].integer(); t) {
        if (auto* T = data["T"].integer(); T && T > t)
            return std::chrono::sys_seconds{std::chrono::seconds{*T}};
        return std::chrono::sys_seconds{std::chrono::seconds{*t}};
    }
    return std::chrono::sys_seconds{};
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

LIBSESSION_C_API int user_profile_set_reupload_pic(config_object* conf, user_profile_pic pic) {
    std::string_view url{pic.url};
    std::span<const unsigned char> key;
    if (!url.empty())
        key = {pic.key, 32};

    return wrap_exceptions(
            conf,
            [&] {
                unbox<UserProfile>(conf)->set_reupload_profile_pic(url, key);
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

LIBSESSION_C_API int64_t user_profile_get_profile_updated(config_object* conf) {
    return unbox<UserProfile>(conf)->get_profile_updated().time_since_epoch().count();
}

}  // extern "C"