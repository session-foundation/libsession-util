#include "session/crypto/ed25519.hpp"

#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>

#include <session/format.hpp>
#include <stdexcept>

#include "session/export.h"
#include "session/hash.hpp"
#include "session/pro_backend.hpp"
#include "session/sodium_array.hpp"
#include "session/util.hpp"

namespace session::ed25519 {

PrivKeySpan::PrivKeySpan(const std::byte* data, size_t size) {
    if (size == 64)
        data_ = data;
    else if (size == 32) {
        expand_seed(std::span<const std::byte, 32>{data, 32});
        data_ = storage_->data();
    } else
        throw std::invalid_argument{
                "Ed25519 private key must be 32 or 64 bytes (got {})"_format(size)};
}

void PrivKeySpan::expand_seed(std::span<const std::byte, 32> seed) {
    auto& buf = storage_.emplace();
    b32 ignore_pk;
    crypto_sign_ed25519_seed_keypair(
            to_unsigned(ignore_pk.data()), to_unsigned(buf.data()), to_unsigned(seed.data()));
}

void PrivKeySpan::expand_seed(std::span<const unsigned char, 32> seed) {
    auto& buf = storage_.emplace();
    b32 ignore_pk;
    crypto_sign_ed25519_seed_keypair(
            to_unsigned(ignore_pk.data()), to_unsigned(buf.data()), seed.data());
}

void keypair(std::span<std::byte, 32> pk, std::span<std::byte, 64> sk) {
    crypto_sign_ed25519_keypair(to_unsigned(pk.data()), to_unsigned(sk.data()));
}

std::pair<b32, cleared_b64> keypair() {
    std::pair<b32, cleared_b64> kp;
    keypair(kp.first, kp.second);
    return kp;
}

void seed_keypair(
        std::span<std::byte, 32> pk,
        std::span<std::byte, 64> sk,
        std::span<const std::byte, 32> seed) {
    crypto_sign_ed25519_seed_keypair(
            to_unsigned(pk.data()), to_unsigned(sk.data()), to_unsigned(seed.data()));
}

std::pair<b32, cleared_b64> keypair(std::span<const std::byte, 32> ed25519_seed) {
    std::pair<b32, cleared_b64> kp;
    seed_keypair(kp.first, kp.second, ed25519_seed);
    return kp;
}

void sk_to_pk(std::span<std::byte, 32> pk, const PrivKeySpan& sk) {
    crypto_sign_ed25519_sk_to_pk(to_unsigned(pk.data()), to_unsigned(sk.data()));
}

b32 sk_to_pk(const PrivKeySpan& sk) {
    b32 pk;
    sk_to_pk(pk, sk);
    return pk;
}

void pk_to_x25519(std::span<std::byte, 32> out, std::span<const std::byte, 32> pk) {
    if (0 != crypto_sign_ed25519_pk_to_curve25519(to_unsigned(out.data()), to_unsigned(pk.data())))
        throw std::runtime_error{"Failed to convert Ed25519 pubkey to X25519: invalid key"};
}

b32 pk_to_x25519(std::span<const std::byte, 32> pk) {
    b32 xpk;
    pk_to_x25519(xpk, pk);
    return xpk;
}

void pk_to_session_id(std::span<std::byte, 33> out, std::span<const std::byte, 32> pk) {
    out[0] = std::byte{0x05};
    pk_to_x25519(out.last<32>(), pk);
}

b33 pk_to_session_id(std::span<const std::byte, 32> pk) {
    b33 sid;
    pk_to_session_id(sid, pk);
    return sid;
}

void sk_to_x25519(std::span<std::byte, 32> out, std::span<const std::byte, 32> seed) {
    crypto_sign_ed25519_sk_to_curve25519(to_unsigned(out.data()), to_unsigned(seed.data()));
}

std::pair<cleared_b32, b32> x25519_keypair(const PrivKeySpan& sk) {
    return {sk_to_x25519(sk), pk_to_x25519(sk.pubkey())};
}

void scalarmult_base(std::span<std::byte, 32> out, std::span<const std::byte, 32> scalar) {
    if (0 != crypto_scalarmult_ed25519_base(to_unsigned(out.data()), to_unsigned(scalar.data())))
        throw std::runtime_error{"crypto_scalarmult_ed25519_base failed"};
}

b32 scalarmult_base(std::span<const std::byte, 32> scalar) {
    b32 out;
    scalarmult_base(out, scalar);
    return out;
}

void scalarmult_base_noclamp(std::span<std::byte, 32> out, std::span<const std::byte, 32> scalar) {
    if (0 !=
        crypto_scalarmult_ed25519_base_noclamp(to_unsigned(out.data()), to_unsigned(scalar.data())))
        throw std::runtime_error{"crypto_scalarmult_ed25519_base_noclamp failed"};
}

b32 scalarmult_base_noclamp(std::span<const std::byte, 32> scalar) {
    b32 out;
    scalarmult_base_noclamp(out, scalar);
    return out;
}

void scalarmult_noclamp(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> scalar,
        std::span<const std::byte, 32> point) {
    if (0 !=
        crypto_scalarmult_ed25519_noclamp(
                to_unsigned(out.data()), to_unsigned(scalar.data()), to_unsigned(point.data())))
        throw std::runtime_error{"crypto_scalarmult_ed25519_noclamp failed"};
}

b32 scalarmult_noclamp(
        std::span<const std::byte, 32> scalar, std::span<const std::byte, 32> point) {
    b32 out;
    scalarmult_noclamp(out, scalar, point);
    return out;
}

void scalar_reduce(std::span<std::byte, 32> out, std::span<const std::byte, 64> in) {
    crypto_core_ed25519_scalar_reduce(to_unsigned(out.data()), to_unsigned(in.data()));
}

b32 scalar_reduce(std::span<const std::byte, 64> in) {
    b32 out;
    scalar_reduce(out, in);
    return out;
}

void scalar_negate(std::span<std::byte, 32> out, std::span<const std::byte, 32> in) {
    crypto_core_ed25519_scalar_negate(to_unsigned(out.data()), to_unsigned(in.data()));
}

b32 scalar_negate(std::span<const std::byte, 32> in) {
    b32 out;
    scalar_negate(out, in);
    return out;
}

void scalar_mul(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> x,
        std::span<const std::byte, 32> y) {
    crypto_core_ed25519_scalar_mul(
            to_unsigned(out.data()), to_unsigned(x.data()), to_unsigned(y.data()));
}

b32 scalar_mul(std::span<const std::byte, 32> x, std::span<const std::byte, 32> y) {
    b32 out;
    scalar_mul(out, x, y);
    return out;
}

void scalar_add(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> x,
        std::span<const std::byte, 32> y) {
    crypto_core_ed25519_scalar_add(
            to_unsigned(out.data()), to_unsigned(x.data()), to_unsigned(y.data()));
}

b32 scalar_add(std::span<const std::byte, 32> x, std::span<const std::byte, 32> y) {
    b32 out;
    scalar_add(out, x, y);
    return out;
}

void sign(
        std::span<std::byte, 64> sig,
        const PrivKeySpan& ed25519_privkey,
        std::span<const std::byte> msg) {
    if (0 != crypto_sign_ed25519_detached(
                     to_unsigned(sig.data()),
                     nullptr,
                     to_unsigned(msg.data()),
                     msg.size(),
                     to_unsigned(ed25519_privkey.data())))
        throw std::runtime_error{"Failed to sign; perhaps the secret key is invalid?"};
}

b64 sign(const PrivKeySpan& ed25519_privkey, std::span<const std::byte> msg) {
    b64 sig;
    sign(sig, ed25519_privkey, msg);
    return sig;
}

bool verify(
        std::span<const std::byte, 64> sig,
        std::span<const std::byte, 32> pubkey,
        std::span<const std::byte> msg) {
    return (0 == crypto_sign_ed25519_verify_detached(
                         to_unsigned(sig.data()),
                         to_unsigned(msg.data()),
                         msg.size(),
                         to_unsigned(pubkey.data())));
}

std::pair<b32, cleared_b64> derive_subkey(
        std::span<const std::byte, 32> ed25519_seed, std::span<const std::byte> domain) {
    // Construct seed for derived key:
    //   new_seed = Blake2b32(ed25519_seed, key=domain)
    cleared_b32 derived_seed;
    hash::blake2b_key(derived_seed, domain, ed25519_seed);
    return keypair(derived_seed);
}

}  // namespace session::ed25519

using namespace session;

LIBSESSION_C_API bool session_ed25519_key_pair(
        unsigned char* ed25519_pk_out, unsigned char* ed25519_sk_out) {
    try {
        auto [ed_pk, ed_sk] = session::ed25519::keypair();
        std::memcpy(ed25519_pk_out, ed_pk.data(), ed_pk.size());
        std::memcpy(ed25519_sk_out, ed_sk.data(), ed_sk.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_ed25519_key_pair_seed(
        const unsigned char* ed25519_seed,
        unsigned char* ed25519_pk_out,
        unsigned char* ed25519_sk_out) {
    try {
        auto [ed_pk, ed_sk] = session::ed25519::keypair(to_byte_span<32>(ed25519_seed));
        std::memcpy(ed25519_pk_out, ed_pk.data(), ed_pk.size());
        std::memcpy(ed25519_sk_out, ed_sk.data(), ed_sk.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_seed_for_ed_privkey(
        const unsigned char* ed25519_privkey, unsigned char* ed25519_seed_out) {
    try {
        auto result = session::ed25519::extract_seed(to_byte_span<64>(ed25519_privkey));
        std::memcpy(ed25519_seed_out, result.data(), result.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_ed25519_sign(
        const unsigned char* ed25519_privkey,
        const unsigned char* msg,
        size_t msg_len,
        unsigned char* ed25519_sig_out) {
    try {
        auto result = session::ed25519::sign(
                to_byte_span<64>(ed25519_privkey), to_byte_span(msg, msg_len));
        std::memcpy(ed25519_sig_out, result.data(), result.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_ed25519_verify(
        const unsigned char* sig,
        const unsigned char* pubkey,
        const unsigned char* msg,
        size_t msg_len) {
    return session::ed25519::verify(
            to_byte_span<64>(sig), to_byte_span<32>(pubkey), to_byte_span(msg, msg_len));
}

LIBSESSION_C_API bool session_ed25519_pro_privkey_for_ed25519_seed(
        const unsigned char* ed25519_seed, unsigned char* ed25519_sk_out) {
    try {
        auto [pub, sk] = session::ed25519::derive_subkey(
                to_byte_span<32>(ed25519_seed), session::pro_backend::pro_subkey_domain);
        std::memcpy(ed25519_sk_out, sk.data(), sk.size());
        return true;
    } catch (...) {
        return false;
    }
}
