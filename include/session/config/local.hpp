#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <session/config.hpp>

#include "base.hpp"
#include "namespaces.hpp"
#include "notify.hpp"
#include "theme.hpp"

namespace session::config {

using namespace std::literals;

/// keys used in this config, either currently or in the past (so that we don't reuse):
///
/// notify_content - setting which indicates what content should be shown when receiving a
/// notification. notify_sound - setting which indicates which sound should be played when receiving
/// a notification (iOS only). theme - setting which controls the theme that should be used for the
/// client UI. theme_primary_color - setting which controls the primary color that should be used
/// for the client UI. settings - KV store for arbitrary boolean settings for the client.

class Local : public ConfigBase {

  public:
    // No default constructor
    Local() = delete;

    /// API: local/Local::Local
    ///
    /// Constructs a local store from existing data (stored from `dump()`) and the user's secret
    /// key for generating the data encryption key.  To construct a blank local store (i.e. with no
    /// pre-existing dumped data to load) pass `std::nullopt` as the second argument.
    ///
    /// Inputs:
    /// - `ed25519_secretkey` -- contains the libsodium secret key used to encrypt/decrypt the
    /// data when pushing/pulling from the swarm.  This can either be the full 64-byte value (which
    /// is technically the 32-byte seed followed by the 32-byte pubkey), or just the 32-byte seed of
    /// the secret key.
    /// - `dumped` -- either `std::nullopt` to construct a new, empty object; or binary state data
    /// that was previously dumped from an instance of this class by calling `dump()`.
    ///
    /// Outputs:
    /// - `Local` - Constructor
    Local(std::span<const unsigned char> ed25519_secretkey,
          std::optional<std::span<const unsigned char>> dumped);

    /// API: local/Local::storage_namespace
    ///
    /// The local config should never be pushed so just provide the UserProfile namespace as a
    /// fallback. Is constant, will always return 2
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `Namespace` - Will return 2
    Namespace storage_namespace() const override { return Namespace::UserProfile; }

    /// API: local/Local::encryption_domain
    ///
    /// Returns the domain. Is constant, will always return "Local"
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `const char*` - Will return "Local"
    const char* encryption_domain() const override { return "Local"; }

    /// API: local/Local::needs_push
    ///
    /// Always returns false as the local store should never be pushed to the swarm.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `bool` -- Returns false
    bool needs_push() const override { return false; };

    /// API: local/Local::push
    ///
    /// Since the loal store should never be pushed this functions is overwritten to always return
    /// empty data in case a client doesn't respect the `needs_push` flag.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::tuple<seqno_t, std::vector<unsigned char>, std::vector<std::string>>` - Returns a
    /// tuple containing
    ///   - `seqno_t` -- sequence number of 0
    ///   - `std::vector<unsigned char>` -- empty data vector
    ///   - `std::vector<std::string>` -- empty list of message hashes
    std::tuple<seqno_t, std::vector<std::vector<unsigned char>>, std::vector<std::string>> push()
            override {
        return {0, {}, {}};
    };

    /// API: local/Local::get_notification_content
    ///
    /// Returns the setting indicating what notification content should be displayed.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `notify_content` -- enum indicating the content that should be shown within a
    /// notification.
    notify_content get_notification_content() const;

    /// API: local/Local::set_notification_content
    ///
    /// Sets the setting indicating what notification content should be displayed.
    ///
    /// Inputs:
    /// - `value` -- Updated notification content setting
    void set_notification_content(notify_content value);

    /// API: local/Local::get_ios_notification_sound
    ///
    /// Returns the setting indicating which sound should play when receiving a
    /// notification on iOS.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `notify_sound` -- integer indicating the sound that should be played when receiving a
    /// notification on iOS.
    int64_t get_ios_notification_sound() const;

    /// API: local/Local::set_ios_notification_sound
    ///
    /// Sets the setting indicating which sound should be played when
    /// receiving receiving a notification on iOS.
    ///
    /// Inputs:
    /// - `value` -- Updated notification sound setting
    void set_ios_notification_sound(int64_t value);

    /// API: local/Local::get_theme
    ///
    /// Returns the setting indicating which theme the client should use.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `theme` -- enum indicating which theme the client should use.
    theme get_theme() const;

    /// API: local/Local::set_theme
    ///
    /// Sets the setting indicating which theme the client should use.
    ///
    /// Inputs:
    /// - `value` -- Updated theme setting
    void set_theme(theme value);

    /// API: local/Local::get_theme_primary_color
    ///
    /// Returns the setting indicating which primary color the client should use.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `theme_primary_color` -- enum indicating which primary color the client should use.
    theme_primary_color get_theme_primary_color() const;

    /// API: user_profile/UserProfile::set_theme_primary_color
    ///
    /// Sets the setting indicating which primary color the client should use.
    ///
    /// Inputs:
    /// - `value` -- Updated primary color setting
    void set_theme_primary_color(theme_primary_color value);

    /// API: local/Local::get_setting
    ///
    /// Accesses the setting for the provided key.  Can have three
    /// values:
    ///
    /// - std::nullopt -- the value has not been given an explicit value so the client should use
    ///   its default.
    /// - true -- the value is explicitly enabled
    /// - false -- the value is explicitly disabled
    ///
    /// Inputs:
    /// - `key` -- key that a setting was previously stored against.
    ///
    /// Outputs:
    /// - `std::optional<bool>` - true/false if the value has been set;
    ///   `std::nullopt` if the value has not been set.
    std::optional<bool> get_setting(std::string key) const;

    /// API: local/Local::set_setting
    ///
    /// Sets the setting.  This is typically invoked with either `true` or `false,
    /// but can also be called with `std::nullopt` to explicitly clear the value.
    ///
    /// Inputs:
    /// - `key` -- key that a setting was previously stored against.
    /// - `enabled` -- value that should be stored locally against the key, or `std::nullopt` to
    /// drop the setting from the local storage (and thus use the client's default).
    void set_setting(std::string key, std::optional<bool> enabled);

    /// API: local/Local::size_settings
    ///
    /// Returns the number of settings
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `size_t` - Returns the number of settings
    size_t size_settings() const;
};

}  // namespace session::config
