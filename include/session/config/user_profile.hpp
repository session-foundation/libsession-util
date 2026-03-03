#pragma once

#include <chrono>
#include <optional>
#include <session/config.hpp>

#include "base.hpp"
#include "namespaces.hpp"
#include "pro.hpp"
#include "profile_pic.hpp"

namespace session::config {

using namespace std::literals;

/// keys used in this config, either currently or in the past (so that we don't reuse):
///
/// n - user profile name
/// p - user profile url
/// q - user profile decryption key (binary)
/// + - the priority value for the "Note to Self" pseudo-conversation (higher = higher in the
///     conversation list).  Omitted when 0.  -1 means hidden.
/// e - the expiry timer (in seconds) for the "Note to Self" pseudo-conversation.  Omitted when 0.
/// M - set to 1 if blinded message request retrieval is enabled, 0 if retrieval is *disabled*, and
///     omitted if the setting has not been explicitly set (or has been explicitly cleared for some
///     reason).
/// f - session pro features bitset
/// t - The unix timestamp (seconds) that the user last explicitly updated their profile information
///     (automatically updates when changing `name`, `profile_pic` or `set_blinded_msgreqs`).
/// E - user pro access expiry unix timestamp (in milliseconds). Note: This can be different from
///     the pro proof expiry which can be sooner.
/// P - user profile url after re-uploading (should take precedence over `p` when `T > t`).
/// Q - user profile decryption key (binary) after re-uploading (should take precedence over `q`
///     when `T > t`).
/// T - The unix timestamp (seconds) that the user last re-uploaded their profile information
///    (automatically updates when calling `set_reupload_profile_pic`).
class UserProfile : public ConfigBase {
  public:
    friend class UserProfileTester;

    // No default constructor
    UserProfile() = delete;

    /// API: user_profile/UserProfile::UserProfile
    ///
    /// Constructs a user profile from existing data (stored from `dump()`) and the user's secret
    /// key for generating the data encryption key.  To construct a blank profile (i.e. with no
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
    /// - `UserProfile` - Constructor
    UserProfile(
            std::span<const unsigned char> ed25519_secretkey,
            std::optional<std::span<const unsigned char>> dumped);

    /// API: user_profile/UserProfile::storage_namespace
    ///
    /// Returns the UserProfile namespace. Is constant, will always return 2
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `Namespace` - Will return 2
    Namespace storage_namespace() const override { return Namespace::UserProfile; }

    /// API: user_profile/UserProfile::encryption_domain
    ///
    /// Returns the domain. Is constant, will always return "UserProfile"
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `const char*` - Will return "UserProfile"
    const char* encryption_domain() const override { return "UserProfile"; }

    /// API: user_profile/UserProfile::get_name
    ///
    /// Returns the user profile name, or std::nullopt if there is no profile name set.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::optional<std::string>` - Returns the user profile name if it exists
    std::optional<std::string_view> get_name() const;

    /// API: user_profile/UserProfile::set_name
    ///
    /// Sets the user profile name; if given an empty string then the name is removed.
    ///
    /// Inputs:
    /// - `new_name` -- The name to be put into the user profile
    void set_name(std::string_view new_name);

    /// API: user_profile/UserProfile::set_name_truncated
    ///
    /// Sets the user profile name; if given an empty string then the name is removed. Same as the
    /// `set_name` function but truncates the name if it's too long.
    ///
    /// Inputs:
    /// - `new_name` -- The name to be put into the user profile
    void set_name_truncated(std::string new_name);

    /// API: user_profile/UserProfile::get_profile_pic
    ///
    /// Gets the user's current profile pic URL and decryption key.  The returned object will
    /// evaluate as false if the URL and/or key are not set.  The returned value will be the latest
    /// profile pic between when the user last set their profile and when it was last re-uploaded.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `profile_pic` - Returns the profile pic
    profile_pic get_profile_pic() const;

    /// API: user_profile/UserProfile::set_profile_pic
    ///
    /// Sets the user's current profile pic to a new URL and decryption key.  Clears both as well as
    /// the reupload values if either one is empty.
    ///
    /// Declaration:
    /// ```cpp
    /// void set_profile_pic(std::string_view url, std::span<const unsigned char> key);
    /// void set_profile_pic(profile_pic pic);
    /// ```
    ///
    /// Inputs:
    /// - First function:
    ///    - `url` -- URL pointing to the profile pic
    ///    - `key` -- Decryption key
    /// - Second function:
    ///    - `pic` -- Profile pic object
    void set_profile_pic(std::string_view url, std::span<const unsigned char> key);
    void set_profile_pic(profile_pic pic);

    /// API: user_profile/UserProfile::set_reupload_profile_pic
    ///
    /// Sets the user's profile pic to a new URL and decryption key after reuploading.
    ///
    /// Declaration:
    /// ```cpp
    /// void set_reupload_profile_pic(std::string_view url, std::span<const unsigned char> key);
    /// void set_reupload_profile_pic(profile_pic pic);
    /// ```
    ///
    /// Inputs:
    /// - First function:
    ///    - `url` -- URL pointing to the profile pic
    ///    - `key` -- Decryption key
    /// - Second function:
    ///    - `pic` -- Profile pic object
    void set_reupload_profile_pic(std::string_view url, std::span<const unsigned char> key);
    void set_reupload_profile_pic(profile_pic pic);

    /// API: user_profile/UserProfile::get_nts_priority
    ///
    /// Gets the Note-to-self conversation priority.  Negative means hidden; 0 means unpinned;
    /// higher means higher priority (i.e. hidden in the convo list).
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `int` -- Returns a numeric representing prioritity
    int get_nts_priority() const;

    /// API: user_profile/UserProfile::set_nts_priority
    ///
    /// Sets the Note-to-self conversation priority. -1 for hidden, 0 for unpinned, higher for
    /// pinned higher.
    ///
    /// Inputs:
    /// - `priority` -- Numeric representing priority
    void set_nts_priority(int priority);

    /// API: user_profile/UserProfile::get_nts_expiry
    ///
    /// Returns the current Note-to-self message expiry timer, if set, or std::nullopt if there is
    /// no current expiry timer set.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::optional<std::chrono::seconds>` -- Returns the timestamp representing the message
    /// expiry timer if the timer is set
    std::optional<std::chrono::seconds> get_nts_expiry() const;

    /// API: user_profile/UserProfile::set_nts_expiry
    ///
    /// Sets the Note-to-self message expiry timer.  Call without arguments (or pass a zero time) to
    /// disable the expiry timer.
    ///
    /// Inputs:
    /// - `timer` -- Default to 0 seconds, will set the expiry timer
    void set_nts_expiry(std::chrono::seconds timer = 0s);

    /// API: user_profile/UserProfile::get_blinded_msgreqs
    ///
    /// Accesses whether or not blinded message requests are enabled for the client.  Can have three
    /// values:
    ///
    /// - std::nullopt -- the value has not been given an explicit value so the client should use
    ///   its default.
    /// - true -- the value is explicitly enabled (i.e. user wants blinded message requests)
    /// - false -- the value is explicitly disabled (i.e. user disabled blinded message requests)
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::optional<bool>` - true/false if blinded message requests are enabled or disabled;
    ///   `std::nullopt` if the option has not been set either way.
    std::optional<bool> get_blinded_msgreqs() const;

    /// API: user_profile/UserProfile::set_blinded_msgreqs
    ///
    /// Sets whether blinded message requests (i.e. from SOGS servers you are connected to) should
    /// be enabled or not.  This is typically invoked with either `true` or `false`, but can also be
    /// called with `std::nullopt` to explicitly clear the value.
    ///
    /// Inputs:
    /// - `enabled` -- true if blinded message requests should be retrieved, false if they should
    ///   not, and `std::nullopt` to drop the setting from the config (and thus use the client's
    ///   default).
    void set_blinded_msgreqs(std::optional<bool> enabled);

    /// API: user_profile/UserProfile::get_profile_updated
    ///
    /// Returns the timestamp that the user last updated their profile information; or `0` if it's
    /// never been updated.  This value will return the latest timestamp between when the user last
    /// set their profile and when it was last re-uploaded.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::chrono::sys_seconds` - timestamp that the user last updated their profile
    /// information.  Will be `0` if it's never been updated.
    std::chrono::sys_seconds get_profile_updated() const;

    bool accepts_protobuf() const override { return true; }

    /// API: user_profile/UserProfile::get_pro_config
    ///
    /// Get the Session Pro data if any, for the current user profile. This may be missing if the
    /// user does not have any entitlement to Session Pro config.
    ///
    /// Inputs: None
    std::optional<ProConfig> get_pro_config() const;

    /// API: user_profile/UserProfile::set_pro_config
    ///
    /// Attach the Session Pro components to the user profile including the proof entitling the user
    /// to use Session Pro features as well as the Ed25519 key pair known as the Rotating Session
    /// Pro key authorised to use the proof.
    ///
    /// Inputs:
    /// - `pro` -- The Session Pro components to assign to the current user profile. This will
    ///   overwrite any existing Session Pro config if it exists. No verification of `pro` is done.
    void set_pro_config(const ProConfig& pro);

    /// API: user_profile/UserProfile::remove_pro_config
    ///
    /// Remove the Session Pro components from the user profile.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `bool` - Flag indicating whether the config had Session Pro config removed or not.
    bool remove_pro_config();

    /// API: user_profile/UserProfile::get_pro_features
    ///
    /// Retrieves the bitset indicating which pro features the user currently has enabled.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - Bitset with individual bits set on it corresponding to
    /// SESSION_PROTOCOL_PRO_PROFILE_FEATURES_BITSET. It is possible to receive bits set that don't
    /// have a corresponding enum value if you are receiving a bitset from a newer client with newer
    /// features enabled. These flags should be ignored by clients that do not recognise them.
    ProProfileBitset get_profile_bitset() const;

    /// API: user_profile/UserProfile::set_pro_badge
    ///
    /// Updates the bitset to specify whether the user wants their profile to show the pro badge.
    ///
    /// Inputs:
    /// - `enabled` -- Flag which specifies whether the user wants the pro badge to appear on their
    /// profile or not.
    void set_pro_badge(bool enabled);

    /// API: user_profile/UserProfile::set_animated_avatar
    ///
    /// Updates the bitset to specify whether the user has an animated profile picture, should be
    /// set when uploading a profile picture. Note: This doesn't prevent a users profile picture
    /// from animating, it's just a way to more easily synchronise the state between devices when
    /// sending messages so we don't need the device to have successfully download the current
    /// display picture in order to be able to determine this.
    ///
    /// Inputs:
    /// - `enabled` -- Flag which specifies whether the users display picture is animated or not.
    void set_animated_avatar(bool enabled);

    /// API: user_profile/UserProfile::get_pro_access_expiry
    ///
    /// Retrieves the Session Pro access expiry unix timestamp if it has been set, this should
    /// generally be the expiry value returned from /get_pro_details.
    ///
    /// Inputs:  None
    ///
    /// Outputs:
    /// - `std::optional<sys_ms>` - The unix timestamp in
    /// milliseconds that the users pro access will expire, or nullopt if unset.
    std::optional<sys_ms> get_pro_access_expiry() const;

    /// API: user_profile/UserProfile::set_pro_access_expiry
    ///
    /// Updates the Session Pro access expiry unix timestamp.
    ///
    /// Inputs:
    /// - `access_expiry_ts_ms` -- The timestamp that the users Session Pro access will expire, or
    /// nullopt to remove the value.
    void set_pro_access_expiry(
            std::optional<std::chrono::sys_time<std::chrono::milliseconds>> access_expiry_ts_ms);
};

}  // namespace session::config
