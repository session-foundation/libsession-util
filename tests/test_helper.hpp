#pragma once

#include <fmt/format.h>

#include <atomic>
#include <filesystem>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/network/key_types.hpp>
#include <session/sodium_array.hpp>
#include <session/sqlite.hpp>

namespace session {

// Smart-pointer-like RAII wrapper around a Core backed by a unique temporary DB file.
// The DB file is removed on destruction.  Default encryption uses a zeroed raw_key.
struct TempCore {
    std::filesystem::path path;
    std::unique_ptr<core::Core> core;

    template <core::CoreOption... Opts>
    explicit TempCore(Opts&&... opts) :
            path{[] {
                static std::atomic<int> n{0};
                return std::filesystem::temp_directory_path() / fmt::format("test_core_{}.db", ++n);
            }()},
            core{std::make_unique<core::Core>(path, std::forward<Opts>(opts)...)} {}

    ~TempCore() {
        core.reset();  // close DB before removing the file
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }

    core::Core* operator->() { return core.get(); }
    core::Core& operator*() { return *core; }
};

class TestHelper {
  public:
    static void poll(core::Core& core) { core._poll(); }

    // Returns the last_hash stored for the given namespace+sn_pubkey pair (or nullopt if none).
    static std::optional<std::string> namespace_last_hash(
            core::Core& core,
            int16_t ns,
            const network::ed25519_pubkey& sn_pubkey) {
        return core.db.conn().prepared_maybe_get<std::string>(
                "SELECT last_hash FROM namespace_sync WHERE namespace = ? AND sn_pubkey = ?",
                ns,
                sn_pubkey);
    }

    // Returns the raw 32-byte seed for the account key identified by the given x25519 public key.
    static cleared_b32 account_key_seed(
            core::Devices& d, std::span<const unsigned char, 32> x25519_pub) {
        cleared_b32 seed;
        auto c = d.conn();
        auto blob = c.prepared_get<sqlite::blob_guts<std::array<std::byte, 32>>>(
                "SELECT seed FROM device_account_keys WHERE pubkey_x25519 = ?",
                std::as_bytes(x25519_pub));
        std::ranges::copy(blob, seed.begin());
        return seed;
    }
};

}  // namespace session
