#pragma once

#include <mlkem_native.h>

#include <cstddef>
#include <span>
#include <stdexcept>

namespace session::mlkem768 {

/// Generates a keypair deterministically from a 64-byte seed.  Throws on failure.
inline void keygen(
        std::span<std::byte, MLKEM768_PUBLICKEYBYTES> pk,
        std::span<std::byte, MLKEM768_SECRETKEYBYTES> sk,
        std::span<const std::byte, 2 * MLKEM_SYMBYTES> seed) {
    if (0 != sr_mlkem768_keypair_derand(
                     reinterpret_cast<unsigned char*>(pk.data()),
                     reinterpret_cast<unsigned char*>(sk.data()),
                     reinterpret_cast<const unsigned char*>(seed.data())))
        throw std::runtime_error{"ML-KEM-768 keygen failed"};
}

/// Encapsulates a shared secret to `pk` using a 32-byte random seed, writing the ciphertext and
/// shared secret into the provided spans.  Throws on failure.
inline void encapsulate(
        std::span<std::byte, MLKEM768_CIPHERTEXTBYTES> ciphertext,
        std::span<std::byte, MLKEM_SYMBYTES> shared_secret,
        std::span<const std::byte, MLKEM768_PUBLICKEYBYTES> pk,
        std::span<const std::byte, MLKEM_SYMBYTES> seed) {
    if (0 != sr_mlkem768_enc_derand(
                     reinterpret_cast<unsigned char*>(ciphertext.data()),
                     reinterpret_cast<unsigned char*>(shared_secret.data()),
                     reinterpret_cast<const unsigned char*>(pk.data()),
                     reinterpret_cast<const unsigned char*>(seed.data())))
        throw std::runtime_error{"ML-KEM-768 encapsulation failed"};
}

/// Decapsulates a shared secret from `ciphertext` using `sk`.  Returns false on failure.
inline bool decapsulate(
        std::span<std::byte, MLKEM_SYMBYTES> shared_secret,
        std::span<const std::byte, MLKEM768_CIPHERTEXTBYTES> ciphertext,
        std::span<const std::byte, MLKEM768_SECRETKEYBYTES> sk) {
    return 0 == sr_mlkem768_dec(
                        reinterpret_cast<unsigned char*>(shared_secret.data()),
                        reinterpret_cast<const unsigned char*>(ciphertext.data()),
                        reinterpret_cast<const unsigned char*>(sk.data()));
}

}  // namespace session::mlkem768
