#pragma once

#include <oxenc/bt_value.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <session/clock.hpp>
#include <session/sodium_array.hpp>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "component.hpp"
#include "swarm_message.hpp"

namespace session {
class TestHelper;
}  // namespace session

namespace session::core {

using namespace std::literals;

class Core;

namespace device {

    enum class Type {
        Unknown,
        Session_iOS,
        Session_Desktop,
        Session_Android,
        Session_CLI,
    };

    // The Type a stored or encoded type string denotes; Unknown for anything else, which a caller
    // keeps verbatim in `Info::other_device`.  The inverse of `Info::encoded_type()`.
    inline Type type_from_encoded(std::string_view t) {
        if (t == "i")
            return Type::Session_iOS;
        if (t == "a")
            return Type::Session_Android;
        if (t == "d")
            return Type::Session_Desktop;
        if (t == "c")
            return Type::Session_CLI;
        return Type::Unknown;
    }

    enum class State {
        Registered = 0,  ///< Device is in the account's registered device set
        Pending = 1,     ///< A device with a pending link request.  This is used for two cases:
                      ///< - This device has sent a request to join the account's device group and
                      ///<   is awaiting acceptance by an existing device.
                      ///< - Another device has sent a link request that has been received but not
                      ///<   yet accepted, ignored, or rejected by this device.
        Unregistered = 2,  ///< Local device info that cannot be pushed because the device is not
                           /// currently in the device group.
    };

    // Value returned to indicate the push status of a device info or account keys update.
    enum class PushStatus {
        Synced = 0,      // We have pushed and confirmed (i.e. fetched the update)
        Pushed = 1,      // We have pushed, but not yet confirmed
        Pending = 2,     // We need to push, but haven't yet done so
        NotInGroup = 3,  // We are not in the device group and so can't push
    };

    struct Info {
        // Unique device id, in raw bytes.  Typically randomized during device initial setup.
        std::array<std::byte, 32> id;

        // Device seqno.  Incremented on device key rotation and/or info updates.
        int64_t seqno;

        // Timestamp of the most recent update.
        std::chrono::sys_seconds timestamp;

        // The device type; one of the above enum values, or DevType::Unknown if the device type is
        // not one of the standard Session clients.
        Type type = device::Type::Unknown;

        // When device type is not one of the standard session clients, this will be set to a
        // free-form string indicating the device type.  Will be empty if no device type is provided
        // in the device info at all.  When DevType has a non-Unknown value, this will be
        // empty/ignored.
        std::string other_device;

        // Device-provided description of itself.  This could contain the OS type or version,
        // possible a device nickname, but is generally free-form data.
        std::string description;

        // Indicates whether the device is registered, pending registration, or not registered.
        State state;

        // For state == State::Unregistered, this timestamp (if set) indicates that the device was
        // removed from the device group at that timestamp.  It will be nullopt for a device that
        // was never in the device group.
        std::optional<std::chrono::sys_seconds> kicked;

        // Application version triplet as reported by the device.  The 2nd and 3rd values will
        // always be in [0, 999].  (If setting device info, they will be clamped if outside this
        // range).
        std::array<int, 3> version;

        // The current device-specific X25519 pubkey
        std::array<std::byte, 32> pk_x25519;

        // The current device-specific MLKEM-768 pubkey
        std::array<std::byte, 1184> pk_mlkem768;

        // Fields from a device running a newer libsession than ours, kept so that we republish them
        // rather than silently dropping what we do not understand.
        //
        // Space for future versions of libsession, not for client data: everything here is carried
        // by every other device on the account, and the payload is padded in buckets sized on the
        // assumption that a record stays within its budget.  Anything added must fit it.
        oxenc::bt_dict extra;

        // Returns the encoded device type string: "i", "a", or "d" for the standard Session
        // client types, `other_device` for unknown types, or "" if unknown with no other_device.
        std::string_view encoded_type() const {
            switch (type) {
                case Type::Session_iOS: return "i";
                case Type::Session_Android: return "a";
                case Type::Session_Desktop: return "d";
                case Type::Session_CLI: return "c";
                default: return other_device;
            }
        }

        // Returns true if the user-settable fields (those controlled by update_info()) are equal to
        // the corresponding fields in `other`.  Does NOT compare id, seqno, timestamp, state, pk_*,
        // or kicked.  The unknown `extra` fields are included in the comparison.
        bool same_user_fields(const Info& other) const;
    };

    using map = std::map<std::array<std::byte, 32>, Info>;

    struct decryption_failed : std::runtime_error {
        using std::runtime_error::runtime_error;
    };
};  // namespace device

class Devices final : detail::CoreComponent {
  public:
  private:
    friend class Core;
    friend class Globals;
    friend class session::TestHelper;
    explicit Devices(Core& c) : detail::CoreComponent{c} {}

    void init() override;

    // Records that this account owes a device group, for `establish_group()` to act on.  Called by
    // Globals when it generates an account, which is before this component has initialised -- hence
    // a stored flag rather than doing the work there.
    void _mark_group_owed();

    std::array<std::byte, 32> self_id;

    // Encrypts the inner device data for all the members of the device group.
    std::vector<std::byte> encrypt_device_data(const device::map& devices);

    // Processes a single incoming device group ("D") or link request ("L") message.  `data` is the
    // full raw message bytes including the outer bt-dict wrapper with the "" type key.
    void receive_device_group_message(std::span<const std::byte> data);
    void receive_link_request(std::span<const std::byte> data);

    // Handlers for incoming swarm messages by namespace, called from Core::receive_messages.
    void parse_device_messages(std::span<const SwarmMessage> messages, bool is_final);
    void parse_account_pubkeys(std::span<const SwarmMessage> messages, bool is_final);

    // Decrypts an incoming encrypted device group ("G") message, returning the bt-encoded group
    // payload plaintext (a bt-dict containing at minimum a "D" devices subdict and optionally a
    // "K" account keys list).  Throws if parsing or decryption fails.  Throws
    // `device::decryption_failed` if we could not find a key that successfully decrypts the data
    // (i.e. we are not in the device group, or all our keys have rotated past this message).
    std::vector<std::byte> decrypt_device_data(std::span<const std::byte> data);

  public:
    // Returns the current device's random identifier, in hex.
    std::string device_id() const;

    // Returns info for all registered and/or pending devices and/or unregistered devices for this
    // account.  If `only_device` is non-empty it must be a 32-byte device id that is used to
    // filter the results to just that one device.
    device::map devices(
            bool include_registered = true,
            bool include_pending = false,
            bool include_unregistered = false,
            std::span<const std::byte> only_device = {});

    // Returns *this* device's info and whether it is registered in the device group.
    std::pair<device::Info, bool> device_info();

    struct LinkRequestResult {
        std::vector<std::byte> message;        // encrypted bytes to push to Namespace::Devices
        std::array<std::string_view, 21> sas;  // emoji SAS sequence for user display
    };

    // Builds an outgoing link request message to upload to Namespace::Devices.  This should
    // only be called when this device is not currently registered in the device group; throws
    // std::logic_error if it is already registered.  The returned message is to be pushed to
    // Namespace::Devices with a 10-minute TTL.  The sas field contains the short authentication
    // string that should be displayed to the user for verification against the accepting device.
    LinkRequestResult build_link_request();

    // Updates this device's info locally to match the given info; if the current device is
    // registered then this dirties the device config data, requiring a push.
    //
    // The state and pk_* fields of the input value are ignored.
    void update_info(const device::Info& info);

    // Creates the account's device group with this device as its only member, if one is owed.
    //
    // Owed means the account was *generated* here rather than restored: a brand new account has no
    // group and nothing else will ever make one, whereas a restored account may already have a
    // group belonging to devices that are merely offline, and inventing a second one would orphan
    // them.  `Globals` records which happened; this acts on that record and clears it, so it runs
    // exactly once per account and survives a crash between creating the account and getting here.
    //
    // Does nothing if this device is already registered, so it is safe to call at any time.
    //
    // Registering ourselves is what breaks the deadlock the rest of this class sits behind:
    // `needs_push()` only reports a device group push for a registered device, and the only other
    // thing that registers one is receiving a group message we can decrypt -- which cannot happen
    // until some device has pushed one.
    //
    // Also mints the account's first shared key seed, since the group payload carries it.  That is
    // not the same as *publishing* PFS keys: nothing goes to Namespace::AccountPubkeys here, and
    // until it does no other account treats this one as supporting v2 encryption.
    void establish_group();

    // Stores the X25519 + MLKEM768 keys that make up an "X-Wing" key
    struct XWingKeys {
        cleared_b32 x25519_sec;
        std::array<std::byte, 32> x25519_pub;
        cleared_array<std::byte, 2400> mlkem768_sec;
        std::array<std::byte, 1184> mlkem768_pub;
    };

    struct DeviceKeys : XWingKeys {
        std::chrono::sys_seconds created;
        std::optional<std::chrono::sys_seconds> rotated;
    };

    // Rotates the device keys used for encrypting device group data.  This also implicitly updates
    // the current device's public keys.  If the current device is registered, calling this will
    // dirty the config data and require another push.
    //
    // This returns the newly created keys.  (It can be safely discarded as it will already be
    // stored in the database).
    DeviceKeys rotate_device_keys();

    // Returns current and recent local device private keys.  This will be sorted with most recent
    // key first.  If there is no current key at all, this generates one.
    std::vector<DeviceKeys> active_device_keys();

    struct AccountKeys : XWingKeys {
        std::chrono::sys_seconds created;
        std::optional<std::chrono::sys_seconds> rotated;
    };

    // How long after rotation to keep an old account key.  14 days is the maximum 1-to-1 message
    // TTL, plus 24h for sender key update lag, plus 24h safety margin.
    static constexpr auto ACCOUNT_KEY_RETENTION = 16 * 24h;

    // Base rotation period and jitter window for account key rotation.  The formula is designed so
    // that the minimum rotation time across all N devices in the group is Unif[PERIOD-WINDOW/2,
    // PERIOD+WINDOW/2], regardless of N, masking the number of devices in the group.
    static constexpr auto ACCOUNT_KEY_ROTATION_PERIOD = 12h;
    static constexpr auto ACCOUNT_KEY_ROTATION_WINDOW = 2h;

    // How long to keep a pending link request before pruning it as stale.
    static constexpr auto LINK_REQUEST_MAX_AGE = 10min;

    // Rotates the shared account keys used for PFS+PQ message encryption.  Generates a new random
    // seed, stores it in the database, marks the previous active key as rotated, and prunes keys
    // older than ACCOUNT_KEY_RETENTION.  Should be called when account_rotation_due() is true and
    // when a device first joins the device group with no existing account keys.
    void rotate_account_keys();

    // Returns the current active account keys after pruning obsolete ones: that is, the current key
    // plus all keys that were rotated away fewer than ACCOUNT_KEY_RETENTION ago.  Keys are returned
    // sorted from newest to oldest.  If there are no keys at all, generates an initial one.
    // Returns account keys, ordered with the active (unrotated) key first then
    // most-recently-rotated first.  Expired rotated keys are pruned before querying.  If
    // key_indicator is given, only keys whose ML-KEM-768 pubkey begins with those two bytes are
    // returned (using the indexed key_indicator virtual column); otherwise all retained keys are
    // returned and a new key is auto-generated if none is currently active.
    std::vector<AccountKeys> active_account_keys(
            std::optional<std::span<const std::byte, 2>> key_indicator = std::nullopt);

    // Returns the time when this device's unique device key is due to be rotated.  Returns nullopt
    // if this device is not currently part of the device group.
    std::optional<std::chrono::system_clock::time_point> next_device_rotation();

    bool device_rotation_due() {
        auto t = next_device_rotation();
        return t && *t <= clock_now();
    }

    // Return true if the account key is due to be rotated by this device.  Returns nullopt if this
    // device is not currently part of the device group.
    std::optional<std::chrono::system_clock::time_point> next_account_rotation();

    bool account_rotation_due() {
        auto t = next_account_rotation();
        return t && *t <= clock_now();
    }

    struct DeviceGroupPush {
        std::vector<std::byte> message;  // encrypted bytes to push to Namespace::Devices
        int64_t seqno;                   // this device's seqno at the moment the message was built
    };

    // Builds the account's device group ("G") message for upload to Namespace::Devices.
    //
    // Throws std::logic_error if this device is not registered: a device outside the group has
    // nothing to say about it, and pushing anyway would announce a group of one that every other
    // device would merge in as authoritative.
    //
    // `seqno` comes back rather than being read again afterwards because the message is built from
    // a snapshot: pass it to mark_device_group_pushed() once the swarm confirms the store, so that
    // a change made while the push was in flight stays dirty.
    DeviceGroupPush build_device_group_message();

    // Builds the signed account public key message for upload to namespace -21.  The message is a
    // bt-encoded dict containing the current active ML-KEM-768 pubkey ("M"), X25519 pubkey ("X"),
    // and a "positive alternative" Ed25519 signature ("~") over the preceding fields, allowing
    // recipients who only know the account's Session ID (X25519) to verify the keys.
    // Throws if there are no active account keys.
    std::vector<std::byte> build_account_pubkey_message();

    // Flags indicating which messages need to be pushed to the swarm.
    struct NeedsPush {
        bool device_group;    ///< True if an updated device group message needs to be pushed
        bool account_pubkey;  ///< True if an updated account pubkey message needs to be pushed
    };

    // Returns whether a push is currently needed.  Should be called after processing a final swarm
    // message batch (or at startup) to determine whether outgoing pushes are required.
    //
    // device_group is true when this device is registered AND any of the following hold:
    //   - our own device info has changed since the last confirmed device group push
    //   - any device has a state transition (registered/removed) that needs broadcasting
    //   - any account key seed has not yet been distributed via a confirmed push
    //
    // account_pubkey is true when the current active account key has not yet been seen confirmed
    // on the swarm (i.e. neither we nor another device has pushed it and we've received it back).
    NeedsPush needs_push();

    // Marks the device group message as successfully pushed with the given own-device seqno (which
    // the caller reads from device_info() before building the push message).  Updates pushed_seqno,
    // clears broadcast_needed on all device rows, and marks all account key seeds as distributed.
    void mark_device_group_pushed(int64_t seqno);
};

}  // namespace session::core
