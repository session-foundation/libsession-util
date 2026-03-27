#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <session/mnemonics.hpp>
#include <session/network/key_types.hpp>
#include <session/secure_buffer.hpp>
#include <session/sodium_array.hpp>
#include <string>
#include <string_view>
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
    // Read-only access is available via the account_seed() method.
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

    /// RAII accessor returned by account_seed().  Holds the underlying secure buffer open for
    /// reading while alive; the buffer becomes unreadable again when the last copy is destroyed.
    struct AccountSeedAccess {
      private:
        friend class Globals;
        explicit AccountSeedAccess(const session::secure_buffer::r_accessor& acc) : _acc{acc} {}
        session::secure_buffer::r_accessor _acc;

        auto ubuf() const {
            return std::span<const unsigned char, 96>{
                    reinterpret_cast<const unsigned char*>(_acc.buf.data()), 96};
        }

      public:
        /// The raw 32-byte account seed (identical to ed25519_secret().first<32>()).
        std::span<const unsigned char, 32> seed() const& { return ubuf().first<32>(); }
        std::span<const unsigned char, 32> seed() const&& = delete;
        /// The 64-byte Ed25519 secret key in libsodium format (seed || pubkey).
        std::span<const unsigned char, 64> ed25519_secret() const& { return ubuf().first<64>(); }
        std::span<const unsigned char, 64> ed25519_secret() const&& = delete;
        /// The 32-byte X25519 secret key derived from the account seed.  This is also the clamped
        /// private scalar of the Ed25519 key, usable for advanced scalar-multiplication operations.
        std::span<const unsigned char, 32> x25519_key() const& { return ubuf().last<32>(); }
        std::span<const unsigned char, 32> x25519_key() const&& = delete;
    };

    AccountSeedAccess account_seed() {
        auto acc = _account_seed.access();
        return AccountSeedAccess{acc};
    }
    // These are computed from the account_seed during construction:
    std::span<const unsigned char, 33> session_id() { return _session_id; }
    const network::ed25519_pubkey& pubkey_ed25519() const { return _pubkey_ed25519; }
    const network::x25519_pubkey& pubkey_x25519() const { return _pubkey_x25519; }

    /// Returns the account seed as a mnemonic word list with checksum, stored in secure memory.
    ///
    /// If `force_24` is false (the default), returns 13 words when the upper 16 bytes of the
    /// seed are all zero (128-bit entropy), or 25 words otherwise.  If `force_24` is true,
    /// always returns 25 words.
    mnemonics::secure_mnemonic seed_mnemonic(
            const mnemonics::Mnemonics& lang, bool force_24 = false);
    mnemonics::secure_mnemonic seed_mnemonic(
            std::string_view lang_name = "English", bool force_24 = false);
};

}  // namespace session::core
