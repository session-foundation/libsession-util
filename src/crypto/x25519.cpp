#include "session/crypto/x25519.hpp"

#include <sodium/crypto_box.h>
#include <sodium/crypto_scalarmult_curve25519.h>

namespace session::x25519 {

void keypair(std::span<std::byte, 32> pk, std::span<std::byte, 32> sk) {
    crypto_box_keypair(to_unsigned(pk.data()), to_unsigned(sk.data()));
}

std::pair<b32, cleared_b32> keypair() {
    std::pair<b32, cleared_b32> kp;
    keypair(kp.first, kp.second);
    return kp;
}

void seed_keypair(
        std::span<std::byte, 32> pk,
        std::span<std::byte, 32> sk,
        std::span<const std::byte, 32> seed) {
    crypto_box_seed_keypair(
            to_unsigned(pk.data()), to_unsigned(sk.data()), to_unsigned(seed.data()));
}

std::pair<b32, cleared_b32> seed_keypair(std::span<const std::byte, 32> seed) {
    std::pair<b32, cleared_b32> kp;
    seed_keypair(kp.first, kp.second, seed);
    return kp;
}

void scalarmult_base(std::span<std::byte, 32> out, std::span<const std::byte, 32> scalar) {
    crypto_scalarmult_curve25519_base(to_unsigned(out.data()), to_unsigned(scalar.data()));
}

b32 scalarmult_base(std::span<const std::byte, 32> scalar) {
    b32 out;
    scalarmult_base(out, scalar);
    return out;
}

bool scalarmult(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> scalar,
        std::span<const std::byte, 32> point) {
    return 0 ==
           crypto_scalarmult_curve25519(
                   to_unsigned(out.data()), to_unsigned(scalar.data()), to_unsigned(point.data()));
}

b32 scalarmult(std::span<const std::byte, 32> scalar, std::span<const std::byte, 32> point) {
    b32 out;
    if (!scalarmult(out, scalar, point))
        throw std::runtime_error{"x25519 scalarmult failed (degenerate point)"};
    return out;
}

}  // namespace session::x25519
