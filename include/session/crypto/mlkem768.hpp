#pragma once

#include <cstddef>
#include <span>
#include <utility>

#include "session/util.hpp"

namespace session::mlkem768 {

inline constexpr size_t PUBLICKEYBYTES = 1184;
inline constexpr size_t SECRETKEYBYTES = 2400;
inline constexpr size_t CIPHERTEXTBYTES = 1088;
inline constexpr size_t SHAREDSECRETBYTES = 32;
inline constexpr size_t SEEDBYTES = 64;  // 2 * MLKEM_SYMBYTES

/// Generates a keypair deterministically from a 64-byte seed.  Throws on failure.
void keygen(
        std::span<std::byte, PUBLICKEYBYTES> pk,
        std::span<std::byte, SECRETKEYBYTES> sk,
        std::span<const std::byte, SEEDBYTES> seed);

/// Encapsulates a shared secret to `pk` using a 32-byte random seed, writing the ciphertext and
/// shared secret into the provided spans.  Throws on failure.
void encapsulate(
        std::span<std::byte, CIPHERTEXTBYTES> ciphertext,
        std::span<std::byte, SHAREDSECRETBYTES> shared_secret,
        std::span<const std::byte, PUBLICKEYBYTES> pk,
        std::span<const std::byte, SHAREDSECRETBYTES> seed);

/// Decapsulates a shared secret from `ciphertext` using `sk`.  Returns false on failure.
bool decapsulate(
        std::span<std::byte, SHAREDSECRETBYTES> shared_secret,
        std::span<const std::byte, CIPHERTEXTBYTES> ciphertext,
        std::span<const std::byte, SECRETKEYBYTES> sk);

}  // namespace session::mlkem768
