#pragma once

#include <chrono>
#include <cstddef>
#include <iterator>
#include <map>
#include <memory>
#include <session/config.hpp>
#include <session/config/base.hpp>
#include <session/config/contacts.hpp>
#include <session/config/convo_info_volatile.hpp>
#include <session/config/groups/info.hpp>
#include <session/config/groups/keys.hpp>
#include <session/config/groups/members.hpp>
#include <session/config/local.hpp>
#include <session/config/user_groups.hpp>
#include <session/config/user_profile.hpp>
#include <session/ed25519.hpp>
#include <session/types.hpp>
#include <session/util.hpp>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <variant>

using namespace std::literals;
using namespace session;

namespace session::config {

enum class conversation_type {
    one_to_one = 0,
    community = 1,
    group = 2,
    blinded_one_to_one = 3,
    legacy_group = 100,
};

struct display_pic_item {
    profile_pic pic;
    std::string fallback_name;

    display_pic_item(
        std::string_view id,
        std::optional<std::string_view> name,
        profile_pic pic): pic{pic}, fallback_name{name.value_or(id)} {}
};

struct multi_display_pic {
    display_pic_item first_pic;
    std::optional<display_pic_item> additional_pic;
};

using display_pic = std::variant<display_pic_item, multi_display_pic>;

/// Common base type with fields shared by all the conversations
struct base_conversation {
    std::string id;
    conversation_type type;
    std::string name;
    display_pic pic;

    int64_t first_active;
    int64_t last_active;
    int priority;
    notify_mode notifications;
    int64_t mute_until;

    base_conversation(
        std::string id,
        conversation_type type,
        std::string name,
        display_pic pic,
        int64_t first_active = 0,
        int64_t last_active = 0,
        int priority = 0,
        notify_mode notifications = notify_mode::defaulted,
        int64_t mute_until = 0) : id{id}, type{type}, name{name}, pic{pic}, first_active{first_active}, last_active{last_active}, priority{priority}, notifications{notifications}, mute_until{mute_until} {}
};

struct one_to_one_conversation : base_conversation {
    bool is_message_request;
    bool is_blocked;

    one_to_one_conversation(
        std::string id,
        conversation_type type,
        std::string name,
        display_pic pic,
        int64_t first_active = 0,
        int64_t last_active = 0,
        int priority = 0,
        notify_mode notifications = notify_mode::defaulted,
        int64_t mute_until = 0,
        bool is_message_request = false,
        bool is_blocked = false) : is_message_request{is_message_request}, is_blocked{is_blocked}, base_conversation{id, type, name, pic, first_active, last_active, priority, notifications, mute_until} {}
};

struct community_conversation : base_conversation {
    community_conversation(
        std::string id,
        conversation_type type,
        std::string name,
        display_pic pic,
        int64_t first_active = 0,
        int64_t last_active = 0,
        int priority = 0,
        notify_mode notifications = notify_mode::defaulted,
        int64_t mute_until = 0) : base_conversation{id, type, name, pic, first_active, last_active, priority, notifications, mute_until} {}
};

struct group_conversation : base_conversation {
    bool is_message_request;

    group_conversation(
        std::string id,
        conversation_type type,
        std::string name,
        display_pic pic,
        int64_t first_active = 0,
        int64_t last_active = 0,
        int priority = 0,
        notify_mode notifications = notify_mode::defaulted,
        int64_t mute_until = 0,
        bool is_message_request = false) : is_message_request{is_message_request}, base_conversation{id, type, name, pic, first_active, last_active, priority, notifications, mute_until} {}
};

struct legacy_group_conversation : base_conversation {
    legacy_group_conversation(
        std::string id,
        conversation_type type,
        std::string name,
        display_pic pic,
        int64_t first_active = 0,
        int64_t last_active = 0,
        int priority = 0,
        notify_mode notifications = notify_mode::defaulted,
        int64_t mute_until = 0) : base_conversation{id, type, name, pic, first_active, last_active, priority, notifications, mute_until} {}
};

struct blinded_one_to_one_conversation : base_conversation {
    std::string community_base_url;
    std::string community_public_key;
    bool legacy_blinding;

    blinded_one_to_one_conversation(
        std::string id,
        conversation_type type,
        std::string name,
        display_pic pic,
        std::string community_base_url,
        std::string community_public_key,
        bool legacy_blinding,
        int64_t first_active = 0,
        int64_t last_active = 0,
        int priority = 0,
        notify_mode notifications = notify_mode::defaulted,
        int64_t mute_until = 0,
        bool is_message_request = false,
        bool is_blocked = false) : community_base_url{community_base_url}, community_public_key{community_public_key}, legacy_blinding{legacy_blinding}, base_conversation{id, type, name, pic, first_active, last_active, priority, notifications, mute_until} {}
};

using conversation = std::variant<one_to_one_conversation, community_conversation, group_conversation, legacy_group_conversation, blinded_one_to_one_conversation>;

class GroupConfigs {
  public:
    GroupConfigs(
            std::span<const unsigned char> group_ed25519_pubkey,
            std::optional<std::span<const unsigned char>> group_ed25519_secret_key,
            std::span<const unsigned char> user_ed25519_secretkey);

    GroupConfigs(GroupConfigs&&) = delete;
    GroupConfigs(const GroupConfigs&) = delete;
    GroupConfigs& operator=(GroupConfigs&&) = delete;
    GroupConfigs& operator=(const GroupConfigs&) = delete;

    std::unique_ptr<groups::Info> info;
    std::unique_ptr<groups::Members> members;
    std::unique_ptr<groups::Keys> keys;
};

class ConfigManager {
  private:
    Ed25519PubKey _user_pk;
    Ed25519Secret _user_sk;

    std::unique_ptr<Contacts> _config_contacts;
    std::unique_ptr<ConvoInfoVolatile> _config_convo_info_volatile;
    std::unique_ptr<UserGroups> _config_user_groups;
    std::unique_ptr<UserProfile> _config_user_profile;
    std::unique_ptr<Local> _config_local;
    std::map<std::string, std::unique_ptr<GroupConfigs>> _config_groups;

  public:
    // Constructs a ConfigManager with a secretkey that will be used for signing.
    ConfigManager(std::span<const unsigned char> ed25519_secretkey);

    // Constructs a new ConfigManager, this will generate a random secretkey and should only be used
    // for creating a new account.
    ConfigManager() : ConfigManager(to_span(ed25519::ed25519_key_pair().second)) {};

    // Object is non-movable and non-copyable; you need to hold it in a smart pointer if it needs to
    // be managed.
    ConfigManager(ConfigManager&&) = delete;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(ConfigManager&&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    /// API: ConfigManager/ConfigManager::load
    ///
    /// Loads a dump into the ConfigManager. Calling this will replace the current config instance
    /// with with a new instance initialised with the provided dump. The configs must be loaded
    /// according to the order 'namespace_load_order' in 'namespaces.hpp' or an exception will be
    /// thrown.
    ///
    /// Inputs:
    /// - `namespace` -- the namespace where config messages for this dump are stored.
    /// - `group_ed25519_pubkey` -- optional pubkey the dump is associated to (in hex, with prefix -
    /// 66 bytes).  Required for group dumps.
    /// - `dump` --  binary state data that was previously dumped by calling `dump()`.
    ///
    /// Outputs: None
    void load(
            config::Namespace namespace_,
            std::optional<std::string> group_ed25519_pubkey_hex,
            std::optional<std::span<const unsigned char>> dump);

    /// API: ConfigManager/ConfigManager::config
    ///
    /// Retrieves a user config from the config manager
    ///
    /// Outputs:
    /// - `ConfigType&` -- The instance of the user config requested
    template <typename ConfigType>
    ConfigType& config();

    /// API: ConfigManager/ConfigManager::config
    ///
    /// Retrieves a group config for the given public key
    ///
    /// Inputs:
    /// - `pubkey_hex` -- pubkey for the group to retrieve the config for (in hex, with prefix - 66
    /// bytes).
    ///
    /// Outputs:
    /// - `std::optional<ConfigType&>` -- The instance of the group config requested or
    /// `std::nullopt` if not present
    template <typename ConfigType>
    ConfigType& config(std::string pubkey_hex);

    void prune_volatile_orphans();
    std::vector<conversation> conversations() const;
};

} // namespace session::config
