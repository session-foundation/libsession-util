#include "session/config/user_profile.h"

#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include "internal.hpp"
#include "session/config/contacts.hpp"
#include "session/config/error.h"
#include "session/config/pro.h"
#include "session/config/pro.hpp"
#include "session/config/user_profile.hpp"
#include "session/export.h"
#include "session/types.hpp"

using namespace session::config;

UserProfile::UserProfile(
        std::span<const unsigned char> ed25519_secretkey,
        std::optional<std::span<const unsigned char>> dumped) {
    init(dumped, std::nullopt, std::nullopt);
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

    auto current_name = get_name();
    if (current_name && *current_name == new_name)
        return;

    set_nonempty_str(data["n"], new_name);

    const auto target_timestamp = (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
    data[target_timestamp] = ts_now();
}
void UserProfile::set_name_truncated(std::string new_name) {
    set_name(utf8_truncate(std::move(new_name), contact_info::MAX_NAME_LENGTH));
}

profile_pic UserProfile::get_profile_pic() const {
    profile_pic pic{};

    const bool use_primary_keys = (data["t"].integer_or(0) >= data["T"].integer_or(0));
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
    auto current_url = data["p"].string_view_or("");
    auto current_key_str = data["q"].string_view_or("");
    std::string_view new_key_str{reinterpret_cast<const char*>(key.data()), key.size()};
    bool changed = (current_url != url) || (current_key_str != new_key_str);

    if (!changed)
        return;

    set_pair_if(!url.empty() && key.size() == 32, data["p"], url, data["q"], key);

    // If the profile was removed then we should remove the "reupload" version as well
    if (url.empty() || key.size() != 32)
        set_reupload_profile_pic({});

    data["t"] = ts_now();
}

void UserProfile::set_profile_pic(profile_pic pic) {
    set_profile_pic(pic.url, pic.key);
}

void UserProfile::set_reupload_profile_pic(
        std::string_view url, std::span<const unsigned char> key) {
    auto current_url = data["P"].string_view_or("");
    auto current_key_str = data["Q"].string_view_or("");
    std::string_view new_key_str{reinterpret_cast<const char*>(key.data()), key.size()};
    bool changed = (current_url != url) || (current_key_str != new_key_str);

    if (!changed)
        return;

    set_pair_if(!url.empty() && key.size() == 32, data["P"], url, data["Q"], key);
    data["T"] = ts_now();
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
    std::optional<bool> current_value;
    if (data["M"].exists())
        current_value = static_cast<bool>(data["M"].integer_or(0));

    if (current_value == value)
        return;

    if (!value)
        data["M"].erase();
    else
        data["M"] = static_cast<int>(*value);

    const auto target_timestamp = (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
    data[target_timestamp] = ts_now();
}

std::optional<bool> UserProfile::get_blinded_msgreqs() const {
    if (auto* M = data["M"].integer(); M)
        return static_cast<bool>(*M);
    return std::nullopt;
}

std::chrono::sys_seconds UserProfile::get_profile_updated() const {
    if (auto t = data["t"].sys_seconds()) {
        if (auto T = data["T"].sys_seconds(); T && *T > *t)
            return *T;
        return *t;
    }
    return std::chrono::sys_seconds{};
}

std::optional<ProConfig> UserProfile::get_pro_config() const {
    std::optional<ProConfig> result = {};
    if (const config::dict* s = data["s"].dict()) {
        ProConfig pro = {};
        if (pro.load(*s))
            result = std::move(pro);
    }
    return result;
}

void UserProfile::set_pro_config(const ProConfig& pro) {
    std::optional<ProConfig> curr = get_pro_config();
    if (!curr || *curr != pro) {
        auto root = data["s"];
        root["r"] = std::span<const unsigned char>(
                pro.rotating_privkey.data(), crypto_sign_ed25519_SEEDBYTES);

        auto proof_dict = root["p"];
        proof_dict["@"] = pro.proof.version;
        proof_dict["g"] = pro.proof.gen_index_hash;
        proof_dict["e"] = pro.proof.expiry_unix_ts.time_since_epoch().count();
        proof_dict["s"] = pro.proof.sig;

        const auto target_timestamp =
                (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
        data[target_timestamp] = ts_now();
    }
}

bool UserProfile::remove_pro_config() {
    bool result = data["s"].exists();
    data["s"].erase();
    return result;
}

session::ProProfileBitset UserProfile::get_profile_bitset() const {
    ProProfileBitset result = {};
    if (const config::set* set = data["f"].set())
        result.data = bitset_from_set_of_int64_or_0(*set);
    return result;
}

void UserProfile::set_pro_badge(bool enabled) {
    auto feature = SESSION_PROTOCOL_PRO_PROFILE_FEATURES_PRO_BADGE;
    bool dirtied = enabled ? data["f"].set_insert(feature) : data["f"].set_erase(feature);
    if (dirtied) {
        const auto target_timestamp =
                (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
        data[target_timestamp] = ts_now();
    }
}

void UserProfile::set_animated_avatar(bool enabled) {
    auto feature = SESSION_PROTOCOL_PRO_PROFILE_FEATURES_ANIMATED_AVATAR;
    bool dirtied = enabled ? data["f"].set_insert(feature) : data["f"].set_erase(feature);
    if (dirtied) {
        const auto target_timestamp =
                (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
        data[target_timestamp] = ts_now();
    }
}

std::optional<std::chrono::sys_time<std::chrono::milliseconds>> UserProfile::get_pro_access_expiry()
        const {
    if (auto* E = data["E"].integer(); E)
        return std::chrono::sys_time<std::chrono::milliseconds>{std::chrono::milliseconds{*E}};
    return std::nullopt;
}

void UserProfile::set_pro_access_expiry(
        std::optional<std::chrono::sys_time<std::chrono::milliseconds>> access_expiry_ts_ms) {
    if (access_expiry_ts_ms)
        data["E"] = epoch_ms(*access_expiry_ts_ms);
    else
        data["E"].erase();
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
    return epoch_seconds(unbox<UserProfile>(conf)->get_profile_updated());
}

LIBSESSION_C_API bool user_profile_get_pro_config(const config_object* conf, pro_pro_config* pro) {
    if (auto val = unbox<UserProfile>(conf)->get_pro_config(); val) {
        static_assert(sizeof pro->proof.gen_index_hash == sizeof(val->proof.gen_index_hash));
        static_assert(sizeof pro->proof.rotating_pubkey == sizeof(val->proof.rotating_pubkey));
        static_assert(sizeof pro->proof.sig == sizeof(val->proof.sig));
        pro->proof.version = val->proof.version;
        std::memcpy(
                pro->proof.gen_index_hash.data,
                val->proof.gen_index_hash.data(),
                val->proof.gen_index_hash.size());
        std::memcpy(
                pro->proof.rotating_pubkey.data,
                val->proof.rotating_pubkey.data(),
                val->proof.rotating_pubkey.size());
        pro->proof.expiry_unix_ts_ms = epoch_ms(val->proof.expiry_unix_ts);
        std::memcpy(pro->proof.sig.data, val->proof.sig.data(), val->proof.sig.size());
        std::memcpy(
                pro->rotating_privkey.data,
                val->rotating_privkey.data(),
                val->rotating_privkey.size());
        return true;
    }
    return false;
}

LIBSESSION_C_API void user_profile_set_pro_config(config_object* conf, const pro_pro_config* pro) {
    ProConfig val = {};
    val.proof.version = pro->proof.version;
    std::memcpy(
            val.proof.gen_index_hash.data(),
            pro->proof.gen_index_hash.data,
            val.proof.gen_index_hash.size());
    std::memcpy(
            val.proof.rotating_pubkey.data(),
            pro->proof.rotating_pubkey.data,
            val.proof.rotating_pubkey.size());
    val.proof.expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
            std::chrono::milliseconds(pro->proof.expiry_unix_ts_ms));
    std::memcpy(val.proof.sig.data(), pro->proof.sig.data, val.proof.sig.size());
    std::memcpy(
            val.rotating_privkey.data(), pro->rotating_privkey.data, val.rotating_privkey.size());
    unbox<UserProfile>(conf)->set_pro_config(val);
}

LIBSESSION_C_API bool user_profile_remove_pro_config(config_object* conf) {
    return unbox<UserProfile>(conf)->remove_pro_config();
}

LIBSESSION_C_API session_protocol_pro_profile_bitset
user_profile_get_pro_features(const config_object* conf) {
    session_protocol_pro_profile_bitset result = {};
    result.data = unbox<UserProfile>(conf)->get_profile_bitset().data;
    return result;
}

LIBSESSION_C_API void user_profile_set_pro_badge(config_object* conf, bool enabled) {
    unbox<UserProfile>(conf)->set_pro_badge(enabled);
}

LIBSESSION_C_API void user_profile_set_animated_avatar(config_object* conf, bool enabled) {
    unbox<UserProfile>(conf)->set_animated_avatar(enabled);
}

LIBSESSION_C_API uint64_t user_profile_get_pro_access_expiry_ms(const config_object* conf) {
    if (auto expiry = unbox<UserProfile>(conf)->get_pro_access_expiry())
        return epoch_ms(*expiry);
    return 0;
}

LIBSESSION_C_API void user_profile_set_pro_access_expiry_ms(
        config_object* conf, uint64_t access_expiry_ts_ms) {
    if (access_expiry_ts_ms <= 0)
        unbox<UserProfile>(conf)->set_pro_access_expiry(std::nullopt);
    else
        unbox<UserProfile>(conf)->set_pro_access_expiry(
                std::chrono::sys_time<std::chrono::milliseconds>{
                        std::chrono::milliseconds{access_expiry_ts_ms}});
}

}  // extern "C"
