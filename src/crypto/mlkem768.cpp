#include "session/crypto/mlkem768.hpp"

#include <mlkem_native.h>

#include <stdexcept>

namespace session::mlkem768 {

static_assert(PUBLICKEYBYTES == MLKEM768_PUBLICKEYBYTES);
static_assert(SECRETKEYBYTES == MLKEM768_SECRETKEYBYTES);
static_assert(CIPHERTEXTBYTES == MLKEM768_CIPHERTEXTBYTES);
static_assert(SHAREDSECRETBYTES == MLKEM_SYMBYTES);
static_assert(SEEDBYTES == 2 * MLKEM_SYMBYTES);

void keygen(
        std::span<std::byte, PUBLICKEYBYTES> pk,
        std::span<std::byte, SECRETKEYBYTES> sk,
        std::span<const std::byte, SEEDBYTES> seed) {
    if (0 != sr_mlkem768_keypair_derand(
                     to_unsigned(pk.data()), to_unsigned(sk.data()), to_unsigned(seed.data())))
        throw std::runtime_error{"ML-KEM-768 keygen failed"};
}

void encapsulate(
        std::span<std::byte, CIPHERTEXTBYTES> ciphertext,
        std::span<std::byte, SHAREDSECRETBYTES> shared_secret,
        std::span<const std::byte, PUBLICKEYBYTES> pk,
        std::span<const std::byte, SHAREDSECRETBYTES> seed) {
    if (0 != sr_mlkem768_enc_derand(
                     to_unsigned(ciphertext.data()),
                     to_unsigned(shared_secret.data()),
                     to_unsigned(pk.data()),
                     to_unsigned(seed.data())))
        throw std::runtime_error{"ML-KEM-768 encapsulation failed"};
}

bool decapsulate(
        std::span<std::byte, SHAREDSECRETBYTES> shared_secret,
        std::span<const std::byte, CIPHERTEXTBYTES> ciphertext,
        std::span<const std::byte, SECRETKEYBYTES> sk) {
    return 0 == sr_mlkem768_dec(
                        to_unsigned(shared_secret.data()),
                        to_unsigned(ciphertext.data()),
                        to_unsigned(sk.data()));
}

}  // namespace session::mlkem768
