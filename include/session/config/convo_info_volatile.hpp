#pragma once

#include <chrono>
#include <cstddef>
#include <iterator>
#include <memory>
#include <session/config.hpp>
#include <vector>

#include "base.hpp"
#include "community.hpp"

using namespace std::literals;

extern "C" {
struct convo_info_volatile_1to1;
struct convo_info_volatile_community;
struct convo_info_volatile_group;
struct convo_info_volatile_legacy_group;
struct convo_info_volatile_blinded_1to1;
}

namespace session::config {

class ConvoInfoVolatile;
class val_loader;

/// keys used in this config, either currently or in the past (so that we don't reuse):
///
/// Note that this is a high-frequency object, intended only for properties that change frequently (
/// (currently just the read timestamp for each conversation).
///
/// 1 - dict of one-to-one conversations.  Each key is the Session ID of the contact (in hex).
///     Values are dicts with keys:
///     e - contacts pro expiry unix timestamp (in milliseconds)
///     g - contacts pro gen_index_hash
///     r - the unix timestamp (in integer milliseconds) of the last-read message.  Always
///         included, but will be 0 if no messages are read.
///     u - will be present and set to 1 if this conversation is specifically marked unread.
///
/// o - community conversations.  This is a nested dict where the outer keys are the BASE_URL of the
///     community and the outer value is a dict containing:
///     - `#` -- the 32-byte server pubkey
///     - `R` -- dict of rooms on the server; each key is the lower-case room name, value is a dict
///       containing keys:
///       r - the unix timestamp (in integer milliseconds) of the last-read message.  Always
///           included, but will be 0 if no messages are read.
///       u - will be present and set to 1 if this conversation is specifically marked unread.
///
/// g - group conversations (aka new, non-legacy groups).  The key is the group identifier
///     (beginning with 03).  Values are dicts with keys:
///     r - the unix timestamp (in integer milliseconds) of the last-read message.  Always
///         included, but will be 0 if no messages are read.
///     u - will be present and set to 1 if this conversation is specifically marked unread.
///
/// C - legacy group conversations (aka groups).  The key is the group identifier (which
///     looks indistinguishable from a Session ID, but isn't really a proper Session ID).  Values
///     are dicts with keys:
///     r - the unix timestamp (integer milliseconds) of the last-read message.  Always included,
///         but will be 0 if no messages are read.
///     u - will be present and set to 1 if this conversation is specifically marked unread.
///
/// b - outgoing blinded message request conversations.  The key is the blinded Session ID without
///     the prefix.  Values are dicts with keys:
///     e - contacts pro expiry unix timestamp (in milliseconds)
///     g - contacts pro gen_index_hash
///     r - the unix timestamp (integer milliseconds) of the last-read message.  Always included,
///         but will be 0 if no messages are read.
///     u - will be present and set to 1 if this conversation is specifically marked unread.
///     y - flag indicating whether the blinded message request is using legac"y" blinding.

namespace convo {

    struct base {
        int64_t last_read = 0;
        bool unread = false;

        virtual ~base() = default;

      protected:
        virtual void load(const dict& info_dict);
        friend class session::config::val_loader;
        friend class session::config::ConvoInfoVolatile;

        base() = default;
        base(int64_t last_read, bool unread) : last_read(last_read), unread(unread) {}
    };

    struct pro_base : base {
        /// Hash of the generation index set by the Session Pro Backend
        std::optional<array_uc32> pro_gen_index_hash;

        /// Unix epoch timestamp to which this proof's entitlement to Session Pro features is valid
        /// to
        std::chrono::sys_time<std::chrono::milliseconds> pro_expiry_unix_ts{};

      protected:
        using base::base;

        void load(const dict& info_dict) override;
        friend class session::config::val_loader;
        friend class session::config::ConvoInfoVolatile;
    };

    struct one_to_one : pro_base {
        std::string session_id;  // in hex

        /// API: convo_info_volatile/one_to_one::one_to_one
        ///
        /// Constructs an empty one_to_one from a session_id.  Session ID can be either bytes (33)
        /// or hex (66).
        ///
        /// Declaration:
        /// ```cpp
        /// explicit one_to_one(std::string&& session_id);
        /// explicit one_to_one(std::string_view session_id);
        /// ```
        ///
        /// Inputs:
        /// - `session_id` -- Hex string of the session id
        explicit one_to_one(std::string&& session_id);
        explicit one_to_one(std::string_view session_id);

        // Internal ctor/method for C API implementations:
        one_to_one(const struct convo_info_volatile_1to1& c);  // From c struct
        void into(convo_info_volatile_1to1& c) const;          // Into c struct
    };

    struct community : config::community, base {

        using config::community::community;

        /// API: convo_info_volatile/community::community
        ///
        /// Internal ctor/method for C API implementations:
        ///
        /// Inputs:
        /// - `c` -- From  c struct
        community(const convo_info_volatile_community& c);  // From c struct
        void into(convo_info_volatile_community& c) const;  // Into c struct

        friend class session::config::ConvoInfoVolatile;
        friend struct session::config::comm_iterator_helper;
    };

    struct group : base {
        std::string id;  // 66 hex digits starting with "03"

        /// API: convo_info_volatile/group::group
        ///
        /// Constructs an empty group from an id
        ///
        /// Inputs:
        /// - `group_id` -- hex string of group_id, 66 hex bytes starting with "03"
        explicit group(std::string&& group_id);
        explicit group(std::string_view group_id);

        // Internal ctor/method for C API implementations:
        group(const struct convo_info_volatile_group& c);  // From c struct
        void into(convo_info_volatile_group& c) const;     // Into c struct
    };

    struct legacy_group : base {
        std::string id;  // in hex, indistinguishable from a Session ID

        /// API: convo_info_volatile/legacy_group::legacy_group
        ///
        /// Constructs an empty legacy_group from a quasi-session_id
        ///
        /// Declaration:
        /// ```cpp
        /// explicit legacy_group(std::string&& group_id);
        /// explicit legacy_group(std::string_view group_id);
        /// ```
        ///
        /// Inputs:
        /// - `group_id` -- hex string of group_id, similar to a session_id
        explicit legacy_group(std::string&& group_id);
        explicit legacy_group(std::string_view group_id);

        // Internal ctor/method for C API implementations:
        legacy_group(const struct convo_info_volatile_legacy_group& c);  // From c struct
        void into(convo_info_volatile_legacy_group& c) const;            // Into c struct
    };

    struct blinded_one_to_one : pro_base {
        std::string blinded_session_id;  // in hex
        bool legacy_blinding;

        /// API: convo_info_volatile/blinded_one_to_one::blinded_one_to_one
        ///
        /// Constructs an empty blinded_one_to_one from a blinded_session_id.  Session ID can be
        /// either bytes (33) or hex (66).
        ///
        /// Declaration:
        /// ```cpp
        /// explicit blinded_one_to_one(std::string&& blinded_session_id);
        /// explicit blinded_one_to_one(std::string_view blinded_session_id);
        /// ```
        ///
        /// Inputs:
        /// - `blinded_session_id` -- Hex string of the blinded session id
        explicit blinded_one_to_one(std::string&& blinded_session_id);
        explicit blinded_one_to_one(std::string_view blinded_session_id);

        // Internal ctor/method for C API implementations:
        blinded_one_to_one(const struct convo_info_volatile_blinded_1to1& c);  // From c struct
        void into(convo_info_volatile_blinded_1to1& c) const;                  // Into c struct
    };

    using any = std::variant<one_to_one, community, group, legacy_group, blinded_one_to_one>;
}  // namespace convo

class ConvoInfoVolatile : public ConfigBase {

  public:
    // No default constructor
    ConvoInfoVolatile() = delete;

    /// API: convo_info_volatile/ConvoInfoVolatile::ConvoInfoVolatile
    ///
    /// Constructs a conversation list from existing data (stored from `dump()`) and the user's
    /// secret key for generating the data encryption key.  To construct a blank list (i.e. with no
    /// pre-existing dumped data to load) pass `std::nullopt` as the second argument.
    ///
    /// Inputs:
    /// - `ed25519_secretkey` -- contains the libsodium secret key used to encrypt/decrypt the
    /// data when pushing/pulling from the swarm.  This can either be the full 64-byte value (which
    /// is technically the 32-byte seed followed by the 32-byte pubkey), or just the 32-byte seed of
    /// the secret key.
    /// - `dumped` -- either `std::nullopt` to construct a new, empty object; or binary state data
    /// that was previously dumped from an instance of this class by calling `dump()`.
    ConvoInfoVolatile(
            std::span<const unsigned char> ed25519_secretkey,
            std::optional<std::span<const unsigned char>> dumped);

    /// API: convo_info_volatile/ConvoInfoVolatile::storage_namespace
    ///
    /// Returns the ConvoInfoVolatile namespace. Is constant, will always return 4
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `Namespace` - Will return 4
    Namespace storage_namespace() const override { return Namespace::ConvoInfoVolatile; }

    /// API: convo_info_volatile/ConvoInfoVolatile::encryption_domain
    ///
    /// Returns the domain. Is constant, will always return "ConvoInfoVolatile"
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `const char*` - Will return "ConvoInfoVolatile"
    const char* encryption_domain() const override { return "ConvoInfoVolatile"; }

    /// Our archiving ages.
    /// Adding or updating conversations that are older than ARCHIVE_AFTER before now will push them
    /// to the archived list. Otherwise, they will be added to the active list (and synced between
    /// devices).
    ///
    /// Clients can mostly ignore that value and just add all conversations; the
    /// class will transparently archive old entries after a `push()` or `merge()`.
    static constexpr auto ARCHIVE_AFTER = 30 * 24h;

    /// API: convo_info_volatile/ConvoInfoVolatile::archive_stale
    ///
    /// Archives any "stale" conversations: that is, ones with a last read more than `ARCHIVE_AFTER`
    /// ago.
    /// This method is called automatically by `push()` or `merge()` and does not typically need to
    /// be invoked directly.
    ///
    /// Outputs:
    /// - returns nothing.
    void archive_stale();

    /// API: convo_info_volatile/ConvoInfoVolatile::push
    ///
    /// Overrides push() to archive stale last-read values before we do the push.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::tuple<seqno_t, std::vector<unsigned char>, std::vector<std::string>>` - Returns a
    /// tuple containing
    ///   - `seqno_t` -- sequence number
    ///   - `std::vector<std::vector<unsigned char>>` -- data message(s) to push to the server
    ///   - `std::vector<std::string>` -- list of known message hashes
    std::tuple<seqno_t, std::vector<std::vector<unsigned char>>, std::vector<std::string>> push()
            override;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_1to1
    ///
    /// Looks up and returns a contact by session ID (hex).  Returns nullopt if the session ID was
    /// not found, otherwise returns a filled out `convo::one_to_one`.
    ///
    /// Inputs:
    /// - `session_id` -- Hex string of the Session ID
    /// - `include_archived` -- Defaults to true, if false, only an active entry is returned
    ///
    /// Outputs:
    /// - `std::optional<convo::one_to_one>` - Returns a contact
    std::optional<convo::one_to_one> get_1to1(
            std::string_view session_id, bool include_archived = true) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_community
    ///
    /// Looks up and returns a community conversation.  Takes the base URL and room name (case
    /// insensitive).  Retuns nullopt if the community was not found, otherwise a filled out
    /// `convo::community`.
    ///
    /// Inputs:
    /// - `base_url` -- String of the base URL
    /// - `room` -- String of the room
    /// - `include_archived` -- Defaults to true, if false, only an active entry is returned
    ///
    /// Outputs:
    /// - `std::optional<convo::community>` - Returns a community
    std::optional<convo::community> get_community(
            std::string_view base_url, std::string_view room, bool include_archived = true) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_community(partial_url)
    ///
    /// Shortcut for calling community::parse_partial_url then calling the above with the base url
    /// and room.  The URL is not required to contain the pubkey (if present it will be ignored).
    ///
    /// Inputs:
    /// - `partial_url` -- String of the partial URL
    /// - `include_archived` -- Defaults to true, if false, only an active entry is returned
    ///
    /// Outputs:
    /// - `std::optional<convo::community>` - Returns a community
    std::optional<convo::community> get_community(
            std::string_view partial_url, bool include_archived = true) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_group
    ///
    /// Looks up and returns a group conversation by ID.  The ID is a 66-character hex string
    /// beginning with "03".  Returns nullopt if there is no record of the group conversation.
    ///
    /// Inputs:
    /// - `pubkey_hex` -- Hex string of the group ID
    /// - `include_archived` -- Defaults to true, if false, only an active entry is returned
    ///
    /// Outputs:
    /// - `std::optional<convo::group>` - Returns a group
    std::optional<convo::group> get_group(
            std::string_view pubkey_hex, bool include_archived = true) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_legacy_group
    ///
    /// Looks up and returns a legacy group conversation by ID.  The ID looks like a hex Session ID,
    /// but isn't really a Session ID.  Returns nullopt if there is no record of the group
    /// conversation.
    ///
    /// Inputs:
    /// - `pubkey_hex` -- Hex string of the legacy group Session ID
    /// - `include_archived` -- Defaults to true, if false, only an active entry is returned
    ///
    /// Outputs:
    /// - `std::optional<convo::legacy_group>` - Returns a group
    std::optional<convo::legacy_group> get_legacy_group(
            std::string_view pubkey_hex, bool include_archived = true) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_blinded_1to1
    ///
    /// Looks up and returns a blinded contact by blinded session ID (hex).  Returns nullopt if the
    /// blinded session ID was not found, otherwise returns a filled out
    /// `convo::blinded_one_to_one`.
    ///
    /// Inputs:
    /// - `blinded_session_id` -- Hex string of the blinded Session ID
    /// - `include_archived` -- Defaults to true, if false, only an active entry is returned
    ///
    /// Outputs:
    /// - `std::optional<convo::blinded_one_to_one>` - Returns a contact
    std::optional<convo::blinded_one_to_one> get_blinded_1to1(
            std::string_view blinded_session_id, bool include_archived = true) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_or_construct_1to1
    ///
    /// These are the same as the above `get` methods (without "_or_construct" in the name), except
    /// that when the conversation doesn't exist a new one is created, prefilled with the
    /// pubkey/url/etc.
    ///
    /// Inputs:
    /// - `session_id` -- Hex string Session ID
    ///
    /// Outputs:
    /// - `convo::one_to_one` - Returns a contact
    convo::one_to_one get_or_construct_1to1(std::string_view session_id) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_or_construct_group
    ///
    /// These are the same as the above `get` methods (without "_or_construct" in the name), except
    /// that when the conversation doesn't exist a new one is created, prefilled with the
    /// pubkey/url/etc.
    ///
    /// Inputs:
    /// - `pubkey_hex` -- Hex string pubkey
    ///
    /// Outputs:
    /// - `convo::group` - Returns a group
    convo::group get_or_construct_group(std::string_view pubkey_hex) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_or_construct_legacy_group
    ///
    /// These are the same as the above `get` methods (without "_or_construct" in the name), except
    /// that when the conversation doesn't exist a new one is created, prefilled with the
    /// pubkey/url/etc.
    ///
    /// Inputs:
    /// - `pubkey_hex` -- Hex string pubkey
    ///
    /// Outputs:
    /// - `convo::legacy_group` - Returns a group
    convo::legacy_group get_or_construct_legacy_group(std::string_view pubkey_hex) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_or_construct_community
    ///
    /// This is similar to get_community, except that it also takes the pubkey; the community is
    /// looked up by the url & room; if not found, it is constructed using room, url, and pubkey; if
    /// it *is* found, then it will always have the *input* pubkey, not the stored pubkey
    /// (effectively the provided pubkey replaces the stored one in the returned object; this is not
    /// applied to storage, however, unless/until the instance is given to `set()`).
    ///
    /// Note, however, that when modifying an object like this the update is *only* applied to the
    /// returned object; like other fields, it is not updated in the internal state unless/until
    /// that community instance is passed to `set()`.
    ///
    /// Declaration:
    /// ```cpp
    /// convo::community get_or_construct_community(
    ///         std::string_view base_url, std::string_view room, std::string_view pubkey_hex)
    ///         const;
    /// convo::community get_or_construct_community(
    ///         std::string_view base_url, std::string_view room, std::span<const unsigned char>
    ///         pubkey) const;
    /// ```
    ///
    /// Inputs:
    /// - `base_url` -- String of the base URL
    /// - `room` -- String of the room
    /// - `pubkey` -- Pubkey either as a hex string or binary
    ///
    /// Outputs:
    /// - `convo::community` - Returns a group
    convo::community get_or_construct_community(
            std::string_view base_url, std::string_view room, std::string_view pubkey_hex) const;
    convo::community get_or_construct_community(
            std::string_view base_url,
            std::string_view room,
            std::span<const unsigned char> pubkey) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_or_construct_community(full_url)
    ///
    /// Shortcut for calling community::parse_full_url then calling the above
    /// get_or_construct_community`
    ///
    /// Inputs:
    /// - `full_url` -- String of the full URL
    ///
    /// Outputs:
    /// - `convo::community` - Returns a group
    convo::community get_or_construct_community(std::string_view full_url) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::get_or_construct_blinded_1to1
    ///
    /// These are the same as the above `get` methods (without "_or_construct" in the name), except
    /// that when the conversation doesn't exist a new one is created, prefilled with the
    /// pubkey/url/etc.
    ///
    /// Inputs:
    /// - `blinded_session_id` -- Hex string blinded Session ID
    ///
    /// Outputs:
    /// - `convo::blinded_one_to_one` - Returns a blinded contact
    convo::blinded_one_to_one get_or_construct_blinded_1to1(
            std::string_view blinded_session_id) const;

    /// API: convo_info_volatile/ConvoInfoVolatile::set
    ///
    /// Inserts or replaces existing conversation info.  For example, to update a 1-to-1
    /// conversation last read time you would do:
    ///
    /// ```cpp
    ///     auto info = conversations.get_or_construct_1to1(some_session_id);
    ///     info.last_read = new_unix_timestamp;
    ///     conversations.set(info);
    /// ```
    ///
    /// Declaration:
    /// ```cpp
    /// void set(const convo::one_to_one& c);
    /// void set(const convo::group& c);
    /// void set(const convo::legacy_group& c);
    /// void set(const convo::community& c);
    /// void set(const convo::blinded_one_to_one& c);
    /// void set(const convo::any& c);  // Variant which can be any of the above
    /// ```
    ///
    /// Inputs:
    /// - `c` -- struct containing any contact, community or group
    void set(const convo::one_to_one& c);
    void set(const convo::legacy_group& c);
    void set(const convo::group& c);
    void set(const convo::community& c);
    void set(const convo::blinded_one_to_one& c);
    void set(const convo::any& c);  // Variant which can be any of the above

  protected:
    /// Sets the base of the convo struct, and returns true if the struct was set (i.e. is active)
    bool set_base(const convo::base& c, DictFieldProxy& info);

    /// Shared helper for the flat-archive set() overloads.  Calls set_base();
    /// - on success erases from arch and returns true (so the caller can write extra fields into
    /// info);
    /// - on failure inserts into arch, marks `_needs_dump`, and returns false.
    template <typename C, typename Map>
    bool set_or_archive(const C& c, DictFieldProxy& info, const std::string& key, Map& arch) {
        if (set_base(c, info)) {
            arch.erase(key);
            return true;
        }
        // remove from active dict if present
        // Note: we consider that we are about to write is more up to date that what is currently in
        // info (if any)
        info.erase();
        arch.insert_or_assign(key, c);
        _needs_dump = true;
        return false;
    }

    /// Shared helper for the flat-archive erase() overloads.  Erases from both the archive map
    /// (marking _needs_dump if found) and the active dict.  Returns true if the entry existed in
    /// the active dict.
    template <typename Map>
    bool erase_from_both(DictFieldProxy info, const std::string& key, Map& arch) {
        if (arch.erase(key))
            _needs_dump = true;
        bool ret = info.exists();
        info.erase();
        return ret;
    }

    // Drills into the nested dicts to access community details; if the second argument is
    // non-nullptr then it will be set to the community's pubkey, if it exists.
    DictFieldProxy community_field(
            const convo::community& og, std::span<const unsigned char>* get_pubkey = nullptr) const;

    void extra_data(oxenc::bt_dict_producer&&) const override;
    void load_extra_data(oxenc::bt_dict_consumer&&) override;
    void after_merge() override;

  private:
    // Type aliases for the archive maps (keyed by binary ID, matching the active data dicts).
    using arch_1to1_map_t = std::map<std::string, convo::one_to_one>;
    using arch_legacy_map_t = std::map<std::string, convo::legacy_group>;
    using arch_blinded_map_t = std::map<std::string, convo::blinded_one_to_one>;
    using arch_group_map_t = std::map<std::string, convo::group>;
    using arch_comm_rooms_t = std::map<std::string, convo::community>;  // room_norm → community
    using arch_comm_map_t = std::map<std::string, arch_comm_rooms_t>;   // base_url → rooms

    // Conversations archived from _config->data() by archive_stale() that should still be kept
    // locally (per type). Serialized into dump() via extra_data() but never included in push().
    arch_1to1_map_t _arch_1to1;
    arch_legacy_map_t _arch_legacy;
    arch_blinded_map_t _arch_blinded;
    arch_group_map_t _arch_group;
    arch_comm_map_t _arch_comm;

  public:
    /// API: convo_info_volatile/ConvoInfoVolatile::erase_1to1
    ///
    /// Removes a one-to-one conversation.  Returns true if found and removed, false if not present.
    ///
    /// Inputs:
    /// - `pubkey` -- hex session id
    ///
    /// Outputs:
    /// - `bool` - Returns true if found and removed, otherwise false
    bool erase_1to1(std::string_view pubkey);

    /// API: convo_info_volatile/ConvoInfoVolatile::erase_community
    ///
    /// Removes a community conversation record.  Returns true if found and removed, false if not
    /// present.  Arguments are the same as `get_community`.
    ///
    /// Inputs:
    /// - `base_url` -- String of the base URL
    /// - `room` -- String of the room
    ///
    /// Outputs:
    /// - `bool` - Returns true if found and removed, otherwise false
    bool erase_community(std::string_view base_url, std::string_view room);

    /// API: convo_info_volatile/ConvoInfoVolatile::erase_group
    ///
    /// Removes a group conversation.  Returns true if found and removed, false if not present.
    ///
    /// Inputs:
    /// - `pubkey_hex` -- String of the group pubkey
    ///
    /// Outputs:
    /// - `bool` - Returns true if found and removed, otherwise false
    bool erase_group(std::string_view pubkey_hex);

    /// API: convo_info_volatile/ConvoInfoVolatile::erase_legacy_group
    ///
    /// Removes a legacy group conversation.  Returns true if found and removed, false if not
    /// present.
    ///
    /// Inputs:
    /// - `pubkey_hex` -- String of the legacy groups pubkey
    ///
    /// Outputs:
    /// - `bool` - Returns true if found and removed, otherwise false
    bool erase_legacy_group(std::string_view pubkey_hex);

    /// API: convo_info_volatile/ConvoInfoVolatile::erase_blinded_1to1
    ///
    /// Removes a blinded one-to-one conversation.  Returns true if found and removed, false if not
    /// present.
    ///
    /// Inputs:
    /// - `pubkey` -- hex blinded session id
    ///
    /// Outputs:
    /// - `bool` - Returns true if found and removed, otherwise false
    bool erase_blinded_1to1(std::string_view pubkey);

    /// API: convo_info_volatile/ConvoInfoVolatile::erase
    ///
    /// Removes a conversation taking the convo::whatever record (rather than the pubkey/url).
    ///
    /// Declaration:
    /// ```cpp
    /// bool erase(const convo::one_to_one& c);
    /// bool erase(const convo::community& c);
    /// bool erase(const convo::legacy_group& c);
    /// bool erase(const convo::blinded_one_to_one& c);
    /// bool erase(const convo::any& c);  // Variant of any of them
    /// ```
    ///
    /// Inputs:
    /// - `c` -- Any contact, group or community
    ///
    /// Outputs:
    /// - `bool` - Returns true if found and removed, otherwise false
    bool erase(const convo::one_to_one& c);
    bool erase(const convo::community& c);
    bool erase(const convo::group& c);
    bool erase(const convo::legacy_group& c);
    bool erase(const convo::blinded_one_to_one& c);

    bool erase(const convo::any& c);  // Variant of any of them

    /// API: convo_info_volatile/ConvoInfoVolatile::size
    ///
    /// Returns the number of conversations, if `size()` is called it will return the total of any
    /// conversations. Utilising the other functions to get specific counts of 1-to-1, community and
    /// legacy group converstations.
    ///
    /// Declaration:
    /// ```cpp
    /// size_t size() const;
    /// size_t size_1to1() const;
    /// size_t size_communities() const;
    /// size_t size_groups() const;
    /// size_t size_legacy_groups() const;
    /// size_t size_blinded_1to1() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `size_t` - Returns the number of conversations
    size_t size() const;

    /// Returns the total number of locally-archived conversations across all types.
    /// Archived entries are conversations that were removed from the active config (by
    /// archive_stale() or by set() when last_read is older than ARCHIVE_AFTER) but are kept
    /// locally and never pushed to the network.
    size_t size_archived() const;

    /// Returns the number of 1-to-1, community, group, and legacy group conversations,
    /// respectively.
    size_t size_1to1() const;
    size_t size_communities() const;
    size_t size_groups() const;
    size_t size_legacy_groups() const;
    size_t size_blinded_1to1() const;

    /// Returns the number of locally-archived conversations of each type.
    /// Archived entries were removed from the active config (by archive_stale() or by set() when
    /// last_read is older than ARCHIVE_AFTER) but are kept locally and never pushed to the network.
    size_t size_1to1_archived() const;
    size_t size_communities_archived() const;
    size_t size_groups_archived() const;
    size_t size_legacy_groups_archived() const;
    size_t size_blinded_1to1_archived() const;

    /// API: convo_info_volatile/ConvoInfoVolatile::empty
    ///
    /// Returns true if the conversation list is empty.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `bool` -- Returns true if the conversation list is empty
    bool empty() const { return size() == 0; }

    bool accepts_protobuf() const override { return true; }

    struct iterator;
    /// API: convo_info_volatile/ConvoInfoVolatile::begin
    ///
    /// Iterators for iterating through all conversations.  Typically you access this implicit via a
    /// for loop over the `ConvoInfoVolatile` object:
    ///
    /// ```cpp
    ///     for (auto& convo : conversations) {
    ///         if (const auto* dm = std::get_if<convo::one_to_one>(&convo)) {
    ///             // use dm->session_id, dm->last_read, etc.
    ///         } else if (const auto* og = std::get_if<convo::community>(&convo)) {
    ///             // use og->base_url, og->room, om->last_read, etc.
    ///         } else if (const auto* cg = std::get_if<convo::group>(&convo)) {
    ///             // use cg->id, cg->last_read
    ///         } else if (const auto* lcg = std::get_if<convo::legacy_group>(&convo)) {
    ///             // use lcg->id, lcg->last_read
    ///         } else if (const auto* bc = std::get_if<convo::blinded_one_to_one>(&convo)) {
    ///             // use bc->id, bc->last_read
    ///         }
    ///     }
    /// ```
    ///
    /// This iterates through all conversations in sorted order (sorted first by convo type, then by
    /// id within the type).
    ///
    /// The `begin_TYPE()` versions of the iterator return an iterator that loops only through the
    /// given `TYPE` of conversations.  (The .end() iterator works for all the iterator variations).
    ///
    /// It is NOT permitted to add/modify/remove records while iterating; performing modifications
    /// based on a condition requires two passes: one to collect the required changes, and another
    /// to apply them key by key.
    ///
    /// Declaration:
    /// ```cpp
    /// iterator begin() const;
    /// subtype_iterator<convo::one_to_one> begin_1to1() const;
    /// subtype_iterator<convo::community> begin_communities() const;
    /// subtype_iterator<convo::group> begin_groups() const;
    /// subtype_iterator<convo::legacy_group> begin_legacy_groups() const;
    /// subtype_iterator<convo::blinded_one_to_one> begin_blinded_one_to_one() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `iterator` - Returns an iterator for the beginning of the contacts
    iterator begin(bool include_archived = true) const {
        return iterator{
                data,
                true,
                true,
                true,
                true,
                true,
                include_archived ? &_arch_1to1 : nullptr,
                include_archived ? &_arch_legacy : nullptr,
                include_archived ? &_arch_blinded : nullptr,
                include_archived ? &_arch_group : nullptr,
                include_archived ? &_arch_comm : nullptr};
    }

    /// API: convo_info_volatile/ConvoInfoVolatile::end
    ///
    /// Iterator for passing the end of the conversations.  This works for both the all-convo
    /// iterator (`begin()`) and the type-specific iterators (e.g. `begin_groups()`).
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `iterator` - Returns an iterator for the end of the conversations
    iterator end() const { return iterator{}; }

    template <typename ConvoType>
    struct subtype_iterator;

    /// Returns an iterator that iterates only through one type of conversations.
    /// Pass `include_archived = false` to skip archived entries.
    subtype_iterator<convo::one_to_one> begin_1to1(bool include_archived = true) const {
        return {data, include_archived ? &_arch_1to1 : nullptr};
    }
    subtype_iterator<convo::community> begin_communities(bool include_archived = true) const {
        return {data, nullptr, nullptr, nullptr, nullptr, include_archived ? &_arch_comm : nullptr};
    }
    subtype_iterator<convo::group> begin_groups(bool include_archived = true) const {
        return {data, nullptr, nullptr, nullptr, include_archived ? &_arch_group : nullptr};
    }
    subtype_iterator<convo::legacy_group> begin_legacy_groups(bool include_archived = true) const {
        return {data, nullptr, include_archived ? &_arch_legacy : nullptr};
    }
    /// Returns an iterator that visits only locally-archived entries, in the same order
    /// as the archive section of begin(true).  Useful for display or debugging.
    iterator begin_archived() const {
        return iterator{
                data,
                false,
                false,
                false,
                false,
                false,
                &_arch_1to1,
                &_arch_legacy,
                &_arch_blinded,
                &_arch_group,
                &_arch_comm};
    }

    subtype_iterator<convo::blinded_one_to_one> begin_blinded_1to1(
            bool include_archived = true) const {
        return {data, nullptr, nullptr, include_archived ? &_arch_blinded : nullptr};
    }

    using iterator_category = std::input_iterator_tag;
    using value_type = std::variant<
            convo::one_to_one,
            convo::community,
            convo::group,
            convo::legacy_group,
            convo::blinded_one_to_one>;
    using reference = value_type&;
    using pointer = value_type*;
    using difference_type = std::ptrdiff_t;

    struct iterator {
      protected:
        std::shared_ptr<convo::any> _val;
        std::optional<dict::const_iterator> _it_11, _end_11, _it_group, _end_group, _it_lgroup,
                _end_lgroup, _it_b11, _end_b11;
        std::optional<comm_iterator_helper> _it_comm;

        // Archive support: typed pointers into ConvoInfoVolatile::_arch_* maps.
        const arch_1to1_map_t* _arch_1to1 = nullptr;
        const arch_legacy_map_t* _arch_legacy = nullptr;
        const arch_blinded_map_t* _arch_blinded = nullptr;
        const arch_group_map_t* _arch_group = nullptr;
        const arch_comm_map_t* _arch_comm = nullptr;
        // Archive iteration phase — ordered to match extra_data key order ("1"<"C"<"b"<"g"<"o").
        enum class ArchPhase : uint8_t {
            s_1to1 = 0,
            s_legacy = 1,
            s_blinded = 2,
            s_group = 3,
            s_comm = 4,
            done = 5
        };
        ArchPhase _arch_section = ArchPhase::done;

        // Per-section map iterators; only the one matching _arch_section is meaningful.
        arch_1to1_map_t::const_iterator _arch_1to1_it;
        arch_group_map_t::const_iterator _arch_group_it;
        arch_comm_map_t::const_iterator _arch_comm_it;
        arch_comm_rooms_t::const_iterator _arch_comm_room_it;
        arch_legacy_map_t::const_iterator _arch_legacy_it;
        arch_blinded_map_t::const_iterator _arch_blinded_it;
        void _load_val();
        iterator() = default;  // Constructs an end tombstone
        iterator(
                const DictFieldRoot& data,
                bool oneto1,
                bool communities,
                bool groups,
                bool legacy_groups,
                bool blinded_1to1,
                const arch_1to1_map_t* arch_1to1 = nullptr,
                const arch_legacy_map_t* arch_legacy = nullptr,
                const arch_blinded_map_t* arch_blinded = nullptr,
                const arch_group_map_t* arch_group = nullptr,
                const arch_comm_map_t* arch_comm = nullptr);
        explicit iterator(
                const DictFieldRoot& data,
                const arch_1to1_map_t* arch_1to1 = nullptr,
                const arch_legacy_map_t* arch_legacy = nullptr,
                const arch_blinded_map_t* arch_blinded = nullptr,
                const arch_group_map_t* arch_group = nullptr,
                const arch_comm_map_t* arch_comm = nullptr) :
                iterator(
                        data,
                        true,
                        true,
                        true,
                        true,
                        true,
                        arch_1to1,
                        arch_legacy,
                        arch_blinded,
                        arch_group,
                        arch_comm) {}
        friend class ConvoInfoVolatile;

      public:
        bool operator==(const iterator& other) const;
        bool operator!=(const iterator& other) const { return !(*this == other); }
        bool done() const;  // Equivalent to comparing against the end iterator
        convo::any& operator*() const { return *_val; }
        convo::any* operator->() const { return _val.get(); }
        iterator& operator++();
        iterator operator++(int) {
            auto copy{*this};
            ++*this;
            return copy;
        }
    };

    template <typename ConvoType>
    struct subtype_iterator : iterator {
      protected:
        subtype_iterator(
                const DictFieldRoot& data,
                const arch_1to1_map_t* a1to1 = nullptr,
                const arch_legacy_map_t* a_legacy_group = nullptr,
                const arch_blinded_map_t* a_blinded = nullptr,
                const arch_group_map_t* a_group = nullptr,
                const arch_comm_map_t* a_comm = nullptr) :
                iterator(
                        data,
                        std::is_same_v<convo::one_to_one, ConvoType>,
                        std::is_same_v<convo::community, ConvoType>,
                        std::is_same_v<convo::group, ConvoType>,
                        std::is_same_v<convo::legacy_group, ConvoType>,
                        std::is_same_v<convo::blinded_one_to_one, ConvoType>,
                        a1to1,
                        a_legacy_group,
                        a_blinded,
                        a_group,
                        a_comm) {}
        friend class ConvoInfoVolatile;

      public:
        ConvoType& operator*() const { return std::get<ConvoType>(*_val); }
        ConvoType* operator->() const { return &std::get<ConvoType>(*_val); }
        subtype_iterator& operator++() {
            iterator::operator++();
            return *this;
        }
        subtype_iterator operator++(int) {
            auto copy{*this};
            ++*this;
            return copy;
        }
    };
};

}  // namespace session::config
