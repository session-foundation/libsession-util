#include "session/config/config_manager.hpp"

#include <fmt/format.h>
#include <fmt/ranges.h>
#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>

#include "internal.hpp"
#include "session/config/base.hpp"
#include "session/config/config_manager.h"

using namespace std::literals;
using namespace oxen::log::literals;

namespace session::config {

GroupConfigs::GroupConfigs(
        std::span<const unsigned char> group_ed25519_pubkey,
        std::optional<std::span<const unsigned char>> group_ed25519_secret_key,
        std::span<const unsigned char> user_ed25519_secretkey) {
    info = std::make_unique<groups::Info>(
            group_ed25519_pubkey, group_ed25519_secret_key, std::nullopt);
    members = std::make_unique<groups::Members>(
            group_ed25519_pubkey, group_ed25519_secret_key, std::nullopt);
    keys = std::make_unique<groups::Keys>(
            user_ed25519_secretkey,
            group_ed25519_pubkey,
            group_ed25519_secret_key,
            std::nullopt,
            *info,
            *members);
}

ConfigManager::ConfigManager(std::span<const unsigned char> ed25519_secretkey) {
    if (sodium_init() == -1)
        throw std::runtime_error{"libsodium initialization failed!"};
    if (ed25519_secretkey.size() != 64)
        throw std::invalid_argument{"Invalid ed25519_secretkey: expected 64 bytes"};

    // Setup the keys
    std::array<unsigned char, 32> user_x_pk;
    _user_sk.reset(64);
    std::memcpy(_user_sk.data(), ed25519_secretkey.data(), ed25519_secretkey.size());
    crypto_sign_ed25519_sk_to_pk(_user_pk.data(), _user_sk.data());

    if (0 != crypto_sign_ed25519_pk_to_curve25519(user_x_pk.data(), _user_pk.data()))
        throw std::runtime_error{"Ed25519 pubkey to x25519 pubkey conversion failed"};

    // Initialise empty config states for any missing required config types
    if (!_config_contacts)
        _config_contacts = std::make_unique<Contacts>(ed25519_secretkey, std::nullopt);

    if (!_config_convo_info_volatile)
        _config_convo_info_volatile =
                std::make_unique<ConvoInfoVolatile>(ed25519_secretkey, std::nullopt);

    if (!_config_user_groups)
        _config_user_groups = std::make_unique<UserGroups>(ed25519_secretkey, std::nullopt);

    if (!_config_user_profile)
        _config_user_profile = std::make_unique<UserProfile>(ed25519_secretkey, std::nullopt);
}

void ConfigManager::load(
        config::Namespace namespace_,
        std::optional<std::string> group_ed25519_pubkey_hex,
        std::optional<std::span<const unsigned char>> dump) {
    switch (namespace_) {
        case Namespace::Contacts:
            _config_contacts = std::make_unique<Contacts>(to_span(_user_sk), dump);
            return;

        case Namespace::UserGroups:
            _config_user_groups = std::make_unique<UserGroups>(to_span(_user_sk), dump);
            return;

        case Namespace::UserProfile:
            _config_user_profile = std::make_unique<UserProfile>(to_span(_user_sk), dump);
            return;

        case Namespace::ConvoInfoVolatile:
            _config_convo_info_volatile =
                    std::make_unique<ConvoInfoVolatile>(to_span(_user_sk), dump);
            prune_volatile_orphans();
            return;

        case Namespace::Local:
            _config_local = std::make_unique<Local>(to_span(_user_sk), dump);
            return;

        default: break;
    }

    // Other namespaces are unique for a given pubkey_hex_
    if (!group_ed25519_pubkey_hex)
        throw std::invalid_argument{
                "load: Invalid pubkey_hex - required for group config namespaces"};
    if (group_ed25519_pubkey_hex->size() != 66)
        throw std::invalid_argument{"load: Invalid pubkey_hex - expected 66 bytes"};

    // Retrieve any keys for the group
    std::string pubkey_hex = *group_ed25519_pubkey_hex;
    check_session_id(pubkey_hex, "03");
    auto user_group_info = _config_user_groups->get_group(pubkey_hex);

    if (!user_group_info)
        throw std::runtime_error{
                "Unable to retrieve group {} from user_groups config"_format(pubkey_hex)};

    std::span<const unsigned char> user_ed25519_secretkey = {_user_sk.data(), 64};
    std::span<const unsigned char> group_pubkey = to_span(oxenc::from_hex(pubkey_hex));
    std::optional<std::span<const unsigned char>> opt_dump = dump;
    std::optional<std::span<const unsigned char>> group_ed25519_secretkey;

    if (!user_group_info.value().secretkey.empty())
        group_ed25519_secretkey = {user_group_info.value().secretkey.data(), 64};

    // Create a fresh `GroupConfigs` state
    if (auto [it, b] = _config_groups.try_emplace(pubkey_hex, nullptr); b) {
        if (namespace_ == Namespace::GroupKeys)
            throw std::runtime_error{
                    "Attempted to load groups_keys config before groups_info or groups_members "
                    "configs"};

        _config_groups[pubkey_hex] = std::make_unique<GroupConfigs>(
                group_pubkey, group_ed25519_secretkey, user_ed25519_secretkey);
    }

    // Reload the specified namespace with the dump
    if (namespace_ == Namespace::GroupInfo)
        _config_groups.at(pubkey_hex)->info =
                std::make_unique<groups::Info>(group_pubkey, group_ed25519_secretkey, dump);
    else if (namespace_ == Namespace::GroupMembers)
        _config_groups.at(pubkey_hex)->members =
                std::make_unique<groups::Members>(group_pubkey, group_ed25519_secretkey, dump);
    else if (namespace_ == Namespace::GroupKeys) {
        auto info = _config_groups.at(pubkey_hex)->info.get();
        auto members = _config_groups.at(pubkey_hex)->members.get();
        auto keys = std::make_unique<groups::Keys>(
                user_ed25519_secretkey,
                group_pubkey,
                group_ed25519_secretkey,
                dump,
                *info,
                *members);
        _config_groups.at(pubkey_hex)->keys = std::move(keys);
    } else
        throw std::runtime_error{"Attempted to load unknown namespace"};
}

template Contacts& ConfigManager::config<Contacts>();
template ConvoInfoVolatile& ConfigManager::config<ConvoInfoVolatile>();
template UserGroups& ConfigManager::config<UserGroups>();
template UserProfile& ConfigManager::config<UserProfile>();
template Local& ConfigManager::config<Local>();

template <typename ConfigType>
ConfigType& ConfigManager::config() {
    if constexpr (std::is_same_v<ConfigType, Contacts>) {
        if (!_config_contacts)
            throw std::runtime_error("Contacts config is not initialized.");
        return *_config_contacts;
    }

    if constexpr (std::is_same_v<ConfigType, ConvoInfoVolatile>) {
        if (!_config_convo_info_volatile)
            throw std::runtime_error("ConvoInfoVolatile config is not initialized.");
        return *_config_convo_info_volatile;
    }

    if constexpr (std::is_same_v<ConfigType, UserGroups>) {
        if (!_config_user_groups)
            throw std::runtime_error("UserGroups config is not initialized.");
        return *_config_user_groups;
    }

    if constexpr (std::is_same_v<ConfigType, UserProfile>) {
        if (!_config_user_profile)
            throw std::runtime_error("UserProfile config is not initialized.");
        return *_config_user_profile;
    }

    if constexpr (std::is_same_v<ConfigType, Local>) {
        if (!_config_local)
            throw std::runtime_error("Local config is not initialized.");
        return *_config_local;
    }

    throw std::runtime_error{"Unsupported user config type requested."};
}

template groups::Info& ConfigManager::config<groups::Info>(std::string pubkey_hex);
template groups::Members& ConfigManager::config<groups::Members>(std::string pubkey_hex);
template groups::Keys& ConfigManager::config<groups::Keys>(std::string pubkey_hex);

template <typename ConfigType>
ConfigType& ConfigManager::config(std::string pubkey_hex) {
    if (pubkey_hex.size() != 66)
        throw std::invalid_argument("pubkey_hex_ must be 66 characters");

    auto it = _config_groups.find(pubkey_hex);

    if (it == _config_groups.end() || !it->second)
        throw std::out_of_range("GroupConfigs not found for key: {}"_format(pubkey_hex));

    GroupConfigs& group_cfg = *(it->second);

    if constexpr (std::is_same_v<ConfigType, groups::Info>) {
        if (!group_cfg.info)
            throw std::runtime_error(
                    "groups::Info not initialized for group: {}"_format(pubkey_hex));
        return *group_cfg.info;
    }

    if constexpr (std::is_same_v<ConfigType, groups::Members>) {
        if (!group_cfg.members)
            throw std::runtime_error(
                    "groups::Members not initialized for group: {}"_format(pubkey_hex));
        return *group_cfg.members;
    }

    if constexpr (std::is_same_v<ConfigType, groups::Keys>) {
        if (!group_cfg.keys)
            throw std::runtime_error(
                    "groups::Keys not initialized for group: {}"_format(pubkey_hex));
        return *group_cfg.keys;
    }

    throw std::runtime_error("Unsupported group config type requested.");
}

void ConfigManager::prune_volatile_orphans() {
    // Remove orphaned 1to1 conversations
    std::vector<std::string> stale;
    for (auto it = _config_convo_info_volatile->begin_1to1(); it != _config_convo_info_volatile->end(); ++it)
        if (!_config_contacts->get(it->session_id))
            stale.push_back(it->session_id);
    for (const auto& sid : stale)
        _config_convo_info_volatile->erase_1to1(sid);
        
    // Remove orphaned community conversdations
    std::vector<std::pair<std::string, std::string>> stale_comms;
    for (auto it = _config_convo_info_volatile->begin_communities(); it != _config_convo_info_volatile->end(); ++it)
        if (!_config_user_groups->get_community(it->base_url(), it->room_norm()))
            stale_comms.emplace_back(it->base_url(), it->room());
    for (const auto& [base, room] : stale_comms)
        _config_convo_info_volatile->erase_community(base, room);

    // Remove orphaned group conversations
    stale.clear();
    for (auto it = _config_convo_info_volatile->begin_groups(); it != _config_convo_info_volatile->end(); ++it)
        if (!_config_user_groups->get_group(it->id))
            stale.push_back(it->id);
    for (const auto& id : stale)
        _config_convo_info_volatile->erase_group(id);

    // Remove orphaned legacy group conversations
    stale.clear();
    for (auto it = _config_convo_info_volatile->begin_legacy_groups(); it != _config_convo_info_volatile->end(); ++it)
        if (!_config_user_groups->get_legacy_group(it->id))
            stale.push_back(it->id);
    for (const auto& id : stale)
        _config_convo_info_volatile->erase_legacy_group(id);
}

std::vector<conversation> ConfigManager::conversations() const {
    if (!_config_user_profile || !_config_contacts || !_config_user_groups || !_config_convo_info_volatile)
        throw std::runtime_error("Some configs are not initialized.");

    // We `+ 1` for the "Note to Self" conversation (in case it is visible)
    auto conversation_size = _config_contacts->size() + _config_user_groups->size() + 1;
    std::vector<conversation> conversations;
    conversations.reserve(conversation_size);

    // If the "Note to Self" conversation should be visible then add it to the list
    if (_config_user_profile->get_nts_priority() >= 0) {
        auto user_pubkey = "05{}"_format(oxenc::to_hex(_user_pk.begin(), _user_pk.end()));
        std::string name = std::string(_config_user_profile->get_name().value_or(""));
        conversations.emplace_back(one_to_one_conversation{
            user_pubkey,
            conversation_type::one_to_one,
            name,
            display_pic_item{
                user_pubkey,
                name,
                _config_user_profile->get_profile_pic()},
            0,                      // No "created" timestamp for NTS
            _config_user_profile->get_nts_last_active(),
            _config_user_profile->get_nts_priority(),
            notify_mode::disabled,  // notify_mode not supported in NTS
            0,                      // mute_until not supported in NTS
            false,                  // is_message_request not supported in NTS
            false                   // is_blocked not supported in NTS
        });
    }
    
    // One to one conversations
    for (auto it = _config_contacts->begin(); it != _config_contacts->end(); ++it) {
        auto display_name = it->nickname;
        int64_t last_active = 0;

        if (display_name.empty())
            display_name = it->name;

        if (auto v = _config_convo_info_volatile->get_1to1(it->session_id))
            last_active = v->last_active;

        conversations.emplace_back(one_to_one_conversation{
            it->session_id,
            conversation_type::one_to_one,
            display_name,
            display_pic_item{
                it->session_id,
                display_name,
                it->profile_picture},
            it->created,
            last_active,
            it->priority,
            it->notifications,
            it->mute_until,
            !it->approved,
            it->blocked
        });
    }

    // Community conversations
    for (auto it = _config_user_groups->begin_communities(); it != _config_user_groups->end(); ++it) {
        int64_t last_active = 0;

        if (auto v = _config_convo_info_volatile->get_community(it->base_url(), it->room_norm()))
            last_active = v->last_active;

        conversations.emplace_back(community_conversation{
            it->full_url(),
            conversation_type::community,
            it->room(),
            display_pic_item{it->full_url(), it->room(), profile_pic{}},
            it->joined_at,
            last_active,
            it->priority,
            it->notifications,
            it->mute_until,
            true,
            true,
            true 
        });
    }

    // Group conversations
    for (auto it = _config_user_groups->begin_groups(); it != _config_user_groups->end(); ++it) {
        auto name = it->name;
        int64_t last_active = 0;

        // Retrieve the name from the `groups::Info` config if available since that's the source of truth
        if (auto group = _config_groups.find(it->id); group != _config_groups.end())
            name = group->second->info->get_name().value_or(name);

        if (auto v = _config_convo_info_volatile->get_group(it->id))
            last_active = v->last_active;
        
        conversations.emplace_back(group_conversation{
            it->id,
            conversation_type::group,
            name,
            display_pic_item{it->id, name, profile_pic{}},
            it->joined_at,
            last_active,
            it->priority,
            it->notifications,
            it->mute_until,
            it->invited
        });
    }

    // Legacy group conversations
    for (auto it = _config_user_groups->begin_legacy_groups(); it != _config_user_groups->end(); ++it) {
        int64_t last_active = 0;

        if (auto v = _config_convo_info_volatile->get_legacy_group(it->session_id))
            last_active = v->last_active;

        conversations.emplace_back(legacy_group_conversation{
            it->session_id,
            conversation_type::legacy_group,
            it->name,
            display_pic_item{it->session_id, it->name, profile_pic{}},
            it->joined_at,
            last_active,
            it->priority,
            it->notifications,
            it->mute_until
        });
    }
    
    // Sort the conversations
    std::sort(conversations.begin(), conversations.end(), [](const auto& a, const auto& b) {
        auto get = [](const auto& conv, auto ptr) {
            return std::visit([ptr](const auto& c) { return c.*ptr; }, conv);
        };
        auto get_string = [](const auto& conv, auto ptr) -> const std::string& {
            return std::visit([ptr](const auto& c) -> const std::string& { return c.*ptr; }, conv);
       };

        // 1. Sort by last_active (descending)
        int64_t last_active_a = get(a, &base_conversation::last_active);
        int64_t last_active_b = get(b, &base_conversation::last_active);
        bool has_last_active_a = (last_active_a != 0);
        bool has_last_active_b = (last_active_b != 0);
        
        if (has_last_active_a != has_last_active_b)
            return has_last_active_a;
        else if (last_active_a != last_active_b)
            return last_active_a > last_active_b;

        // 2. Sort by first_active (descending)
        int64_t first_active_a = get(a, &base_conversation::first_active);
        int64_t first_active_b = get(b, &base_conversation::first_active);
        bool has_first_active_a = (first_active_a != 0);
        bool has_first_active_b = (first_active_b != 0);
        
        if (has_first_active_a != has_first_active_b)
            return has_first_active_a;
        else if (first_active_a != first_active_b)
            return first_active_a > first_active_b;

        // 3. Sort by id (ascending)
        const std::string& id_a = get_string(a, &base_conversation::id);
        const std::string& id_b = get_string(b, &base_conversation::id);
        
        return id_a < id_b;
    });

    return conversations;
}

}  // namespace session::config

using namespace session;
using namespace session::config;

namespace {

ConfigManager& unbox(config_manager* manager) {
    assert(manager && manager->internals);
    return *static_cast<ConfigManager*>(manager->internals);
}
const ConfigManager& unbox(const config_manager* manager) {
    assert(manager && manager->internals);
    return *static_cast<const ConfigManager*>(manager->internals);
}
template <typename ConfigT>
[[nodiscard]] bool c_wrapper_for_config(config_object** conf, ConfigT& config) {
    auto c = std::make_unique<internals<ConfigT>>(static_cast<ConfigBase*>(&config));
    auto c_conf = std::make_unique<config_object>();
    c_conf->internals = c.release();
    c_conf->last_error = nullptr;
    *conf = c_conf.release();
    return true;
}
[[nodiscard]] bool c_wrapper_for_keys_config(config_group_keys** conf, groups::Keys& config) {
    auto c_conf = std::make_unique<config_group_keys>();
    c_conf->internals = &config;
    c_conf->last_error = nullptr;
    *conf = c_conf.release();
    return true;
}
inline bool set_error_value(char* error, std::string_view e) {
    if (!error)
        return false;

    std::string msg = {e.data(), e.size()};
    if (msg.size() > 255)
        msg.resize(255);
    std::memcpy(error, msg.c_str(), msg.size() + 1);
    return false;
}

}  // namespace

extern "C" {

LIBSESSION_C_API bool config_manager_init(
        config_manager** manager, const unsigned char* ed25519_secretkey_bytes, char* error) {
    auto c_manager = std::make_unique<config_manager>();

    try {
        std::span<const unsigned char> ed25519_secretkey = {ed25519_secretkey_bytes, 64};
        auto m = std::make_unique<ConfigManager>(ed25519_secretkey);
        c_manager->internals = m.release();
    } catch (const std::exception& e) {
        return set_error_value(error, e.what());
    }

    *manager = c_manager.release();
    return true;
}

LIBSESSION_C_API void config_manager_free(config_manager* manager) {
    delete static_cast<ConfigManager*>(manager->internals);
    delete manager;
}

LIBSESSION_C_API bool config_manager_load(
        config_manager* manager,
        int16_t namespace_,
        const char* group_ed25519_pubkey_hex_,
        const unsigned char* dump_,
        size_t dumplen,
        char* error) {
    try {
        std::optional<std::string> group_ed25519_pubkey_hex;
        if (group_ed25519_pubkey_hex_)
            group_ed25519_pubkey_hex = {group_ed25519_pubkey_hex_, 64};

        std::optional<std::span<const unsigned char>> dump;
        if (dump_ && dumplen > 0)
            dump = {dump_, dumplen};

        unbox(manager).load(
                static_cast<config::Namespace>(namespace_), group_ed25519_pubkey_hex, dump);
        return true;
    } catch (const std::exception& e) {
        return set_error_value(error, e.what());
    }
}

LIBSESSION_C_API bool config_manager_get_config(
        config_manager* manager,
        const uint16_t namespace_,
        const char* pubkey_hex,
        config_object** config,
        char* error) {
    try {
        if (!manager || !config)
            throw std::invalid_argument{"Null argument(s) provided."};

        switch (static_cast<Namespace>(namespace_)) {
            case Namespace::Contacts:
                return c_wrapper_for_config(config, unbox(manager).config<Contacts>());

            case Namespace::ConvoInfoVolatile:
                return c_wrapper_for_config(config, unbox(manager).config<ConvoInfoVolatile>());

            case Namespace::UserGroups:
                return c_wrapper_for_config(config, unbox(manager).config<UserGroups>());

            case Namespace::UserProfile:
                return c_wrapper_for_config(config, unbox(manager).config<UserProfile>());

            case Namespace::Local:
                return c_wrapper_for_config(config, unbox(manager).config<Local>());

            case Namespace::GroupInfo:
                if (!pubkey_hex)
                    throw std::invalid_argument{"Invalid pubkey_hex - required for group configs"};
                return c_wrapper_for_config(config, unbox(manager).config<groups::Info>({pubkey_hex, 66}));

            case Namespace::GroupMembers:
                if (!pubkey_hex)
                    throw std::invalid_argument{"Invalid pubkey_hex - required for group configs"};
                return c_wrapper_for_config(
                        config, unbox(manager).config<groups::Members>({pubkey_hex, 66}));

            case Namespace::GroupKeys:
                throw std::runtime_error{"Use 'config_manager_get_keys_config' to retrieve the group keys config"};

            default:
                throw std::runtime_error{"Attempted to get config for unknown namespace"};
        }
    } catch (const std::exception& e) {
        return set_error_value(error, e.what());
    }
}

LIBSESSION_C_API bool config_manager_get_keys_config(
    config_manager* manager,
    const char* pubkey_hex,
    config_group_keys** config,
    char* error) {
    try {
        if (!manager || !config || !pubkey_hex)
            throw std::invalid_argument{"Null argument(s) provided."};

        return c_wrapper_for_keys_config(config, unbox(manager).config<groups::Keys>());
    } catch (const std::exception& e) {
        return set_error_value(error, e.what());
    }
}

LIBSESSION_C_API void config_manager_free_config(config_object* config) {
    if (config->internals) {
        delete static_cast<IInternalsBase*>(config->internals);
    }
    delete config;
}

LIBSESSION_C_API void config_manager_free_keys_config(config_group_keys* config) {
    // We intentionally don't delete config->internals because that owned by the ConfigManager
    delete config;
}

LIBSESSION_C_API bool config_manager_get_conversations(const config_manager* manager, config_convo** conversations, size_t* conversations_len, char* error) {
    try {
        if (!manager || !conversations || !conversations_len)
            throw std::invalid_argument{"Null argument(s) provided."};

        auto cpp_conversations = unbox(manager).conversations();
        *conversations_len = cpp_conversations.size();

        if (cpp_conversations.size() == 0) {
            return true;
        }
        
        *conversations = static_cast<config_convo*>(std::malloc(cpp_conversations.size() * sizeof(config_convo)));
        if (!conversations) {
            *conversations_len = 0;
            throw std::runtime_error{"Memory allocation failed."};
        }

        unsigned char* pos = reinterpret_cast<unsigned char*>(*conversations);
        memset(*conversations, 0, cpp_conversations.size() * sizeof(config_convo));

        for (size_t i = 0; i < cpp_conversations.size(); ++i) {
            config_convo* conversation = (config_convo*)pos;
            const auto& cpp_conversation_variant = cpp_conversations[i];

            std::visit([&](const auto& cpp_conversation) {
                copy_c_str(conversation->id, cpp_conversation.id);
                copy_c_str(conversation->name, cpp_conversation.name);
                conversation->type = static_cast<CONVERSATION_TYPE>(cpp_conversation.type);
                conversation->first_active = cpp_conversation.first_active;
                conversation->last_active = cpp_conversation.last_active;
                conversation->priority = cpp_conversation.priority;
                conversation->notifications = static_cast<CONVO_NOTIFY_MODE>(cpp_conversation.notifications);
                conversation->mute_until = cpp_conversation.mute_until;

                // Assign type-specific fields
                if constexpr (std::is_same_v<std::decay_t<decltype(cpp_conversation)>, one_to_one_conversation>) {
                    conversation->specific_data.one_to_one.is_message_request = cpp_conversation.is_message_request;
                    conversation->specific_data.one_to_one.is_blocked = cpp_conversation.is_blocked;
                } else if constexpr (std::is_same_v<std::decay_t<decltype(cpp_conversation)>, community_conversation>) {
                    conversation->specific_data.community.read = cpp_conversation.read;
                    conversation->specific_data.community.write = cpp_conversation.write;
                    conversation->specific_data.community.upload = cpp_conversation.upload;
                } else if constexpr (std::is_same_v<std::decay_t<decltype(cpp_conversation)>, group_conversation>) {
                    conversation->specific_data.group.is_message_request = cpp_conversation.is_message_request;
                }
            }, cpp_conversation_variant);

            pos += sizeof(config_convo);
        }
        
        return true;
    } catch (const std::exception& e) {
        return set_error_value(error, e.what());
    }
}

}  // extern "C"
