#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

#include "util.hpp"

namespace session::xed25519 {

/// XEd25519-signs a message given the curve25519 privkey and message.
b64 sign(std::span<const std::byte, 32> curve25519_privkey, std::span<const std::byte> msg);

/// "Softer" version that takes and returns strings of regular chars.  Throws invalid_argument if
/// the privkey is not 32 bytes.
std::string sign(std::string_view curve25519_privkey /* 32 bytes */, std::string_view msg);

/// Verifies a curve25519 message allegedly signed by the given curve25519 pubkey
[[nodiscard]] bool verify(
        std::span<const std::byte, 64> signature,
        std::span<const std::byte, 32> curve25519_pubkey,
        std::span<const std::byte> msg);

/// "Softer" version that takes strings of regular chars.  Throws invalid_argument if the signature
/// is not 64 bytes or the pubkey is not 32 bytes (a wrong-sized input is a caller bug, not a failed
/// verification, so it is not reported as a false return).
[[nodiscard]] bool verify(
        std::string_view signature /* 64 bytes */,
        std::string_view curve25519_pubkey /* 32 bytes */,
        std::string_view msg);

/// Given a curve25519 pubkey, this returns the associated XEd25519-derived Ed25519 pubkey.  Note,
/// however, that there are *two* possible Ed25519 pubkeys that could result in a given curve25519
/// pubkey: this always returns the positive value.  You can get the other possibility (the
/// negative) by setting the sign bit, i.e. `returned_pubkey[31] |= 0x80`.
b32 pubkey(std::span<const std::byte, 32> curve25519_pubkey) noexcept;

/// "Softer" version that takes/returns strings of regular chars.  Throws invalid_argument if the
/// input is not 32 bytes.
std::string pubkey(std::string_view curve25519_pubkey);

/// Utility function that provides a constant-time `if (b) f = g;` implementation for byte arrays.
template <size_t N>
void constant_time_conditional_assign(
        std::array<std::byte, N>& f, const std::array<std::byte, N>& g, bool b) {
    std::array<std::byte, N> x;
    for (size_t i = 0; i < x.size(); i++)
        x[i] = f[i] ^ g[i];
    auto mask = static_cast<std::byte>(-(signed char)b);
    for (size_t i = 0; i < x.size(); i++)
        x[i] &= mask;
    for (size_t i = 0; i < x.size(); i++)
        f[i] ^= x[i];
}

}  // namespace session::xed25519
