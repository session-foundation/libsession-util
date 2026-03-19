#pragma once

#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/sodium_array.hpp>
#include <session/sqlite.hpp>

namespace session {

class TestHelper {
  public:
    static void poll(core::Core& core) { core._poll(); }

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
