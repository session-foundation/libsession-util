#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <session/network/key_types.hpp>
#include <session/secure_buffer.hpp>
#include <session/sodium_array.hpp>
#include <string>
#include <variant>
#include <vector>

#include "component.hpp"

namespace session::core {

class Core;

// Core component contains one-off global values that don't make sense storing in a table, typically
// because the value is highly special purpose or is only used in one single place.  If you ever
// find yourself wanting to put multiple values in here under the same key, that is a sign that you
// should not be using this class and should instead refactor to use proper table relations.
//
// A note on keys: to avoid conflicts, external users of these globals should use prefix names that
// are unlikely to conflict with other uses.  For example, "session_ios_dark_mode" is a decent name,
// but "pubkey" is a terrible one.  All internal libsession keys in this table begin with an
// underscore, and should never be accesses outside libsession itself.
//
class Globals final : detail::CoreComponent {

  private:
    friend class Core;
    explicit Globals(Core& c) : detail::CoreComponent{c} {}

    // Holds the account seed; loaded during initialization (created if it doesn't exist).  A new
    // account seed is generated during initialization if the database doesn't contain one (e.g. if
    // brand new).
    //
    // Read-only access is available via the account_seed() method, or via the `seed()`
    // CoreComponent base class method from other components.
    session::secure_buffer _account_seed;
    network::ed25519_pubkey _pubkey_ed25519;
    network::x25519_pubkey _pubkey_x25519;
    std::array<unsigned char, 33> _session_id;  // AKA pubkey_x25519 with a 0x05 byte prefix

    void init() override;

    // If set by the Core constructor before init(), used as the initial account seed when the
    // database does not yet contain one.  Cleared after use in init().
    std::optional<cleared_b32> _predefined_seed;

  public:
    // Retrieval methods.  These query for the given key and, if the type matches, return the given
    // value.  You get back nullopt if the database key does not exist, or if it contains
    std::optional<int64_t> get_integer(std::string_view key);
    std::optional<double> get_real(std::string_view key);
    std::optional<std::string> get_text(std::string_view key);
    std::optional<std::vector<std::byte>> get_blob(std::string_view key);
    // Same as get_blob, but allocates a libsodium secure buffer to old the value.
    //
    // Do not use this to access the "seed" value: that value is cached in the Core object and
    // accessible via CoreComponent::access_seed().
    std::optional<session::secure_buffer> get_blob_secure(std::string_view key);
    // Reads a fixed size blob into `to`.  If the database does not contain a BLOB value of byte
    // length `to.size()`, returns false; other writes the blob value to `to` and returns true.
    bool get_blob_to(std::string_view key, std::span<std::byte> to);

    // Retrieves the value of whatever type it currently contains.  Returns a std::monostate if the
    // database key is not set at all, otherwise of of the other variant values.
    std::variant<std::monostate, int64_t, double, std::string, std::vector<std::byte>> get(
            std::string_view key);
    std::variant<std::monostate, int64_t, double, std::string, session::secure_buffer> get_secure(
            std::string_view key);

    // Assignment.  If the database key already exists, this overwrites it.
    void set(std::string_view key, int64_t integer);
    void set(std::string_view key, double real);
    void set(std::string_view key, std::string_view text);
    void set(std::string_view key, std::span<const std::byte> blob);

    session::secure_buffer::r_accessor account_seed() { return _account_seed.access(); }
    // These are computed from the account_seed during construction:
    std::span<const unsigned char, 33> session_id() { return _session_id; }
    const network::ed25519_pubkey& pubkey_ed25519() const { return _pubkey_ed25519; }
    const network::x25519_pubkey& pubkey_x25519() const { return _pubkey_x25519; }
};

}  // namespace session::core
