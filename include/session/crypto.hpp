#pragma once

#include <sodium/crypto_box.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign_ed25519.h>

#include <cstddef>
#include <span>
#include <string_view>

#include "util.hpp"

namespace session::crypto {

// ─── Ed25519 ─────────────────────────────────────────────────────────────────

/// Generates a random Ed25519 keypair.
inline void ed25519_keypair(
        std::span<std::byte, crypto_sign_ed25519_PUBLICKEYBYTES> pk,
        std::span<std::byte, crypto_sign_ed25519_SECRETKEYBYTES> sk) {
    crypto_sign_ed25519_keypair(ucdata(pk), ucdata(sk));
}

/// Generates a deterministic Ed25519 keypair from a 32-byte seed.
inline void ed25519_seed_keypair(
        std::span<std::byte, crypto_sign_ed25519_PUBLICKEYBYTES> pk,
        std::span<std::byte, crypto_sign_ed25519_SECRETKEYBYTES> sk,
        std::span<const std::byte, crypto_sign_ed25519_SEEDBYTES> seed) {
    crypto_sign_ed25519_seed_keypair(ucdata(pk), ucdata(sk), ucdata(seed));
}

/// Signs `msg` with `sk`, writing the 64-byte detached signature into `sig`.
inline void ed25519_sign(
        std::span<std::byte, crypto_sign_ed25519_BYTES> sig,
        std::span<const std::byte> msg,
        std::span<const std::byte, crypto_sign_ed25519_SECRETKEYBYTES> sk) {
    crypto_sign_ed25519_detached(ucdata(sig), nullptr, ucdata(msg), msg.size(), ucdata(sk));
}

/// Verifies a detached Ed25519 signature.  Returns true if valid.
inline bool ed25519_verify(
        std::span<const std::byte, crypto_sign_ed25519_BYTES> sig,
        std::span<const std::byte> msg,
        std::span<const std::byte, crypto_sign_ed25519_PUBLICKEYBYTES> pk) {
    return 0 ==
           crypto_sign_ed25519_verify_detached(ucdata(sig), ucdata(msg), msg.size(), ucdata(pk));
}

/// Extracts the Ed25519 public key from a secret key.
inline void ed25519_sk_to_pk(
        std::span<std::byte, crypto_sign_ed25519_PUBLICKEYBYTES> pk,
        std::span<const std::byte, crypto_sign_ed25519_SECRETKEYBYTES> sk) {
    crypto_sign_ed25519_sk_to_pk(ucdata(pk), ucdata(sk));
}

/// Converts an Ed25519 public key to an X25519 public key.  Returns false on failure.
inline bool ed25519_pk_to_x25519(
        std::span<std::byte, crypto_scalarmult_curve25519_BYTES> x25519_pk,
        std::span<const std::byte, crypto_sign_ed25519_PUBLICKEYBYTES> ed25519_pk) {
    return 0 == crypto_sign_ed25519_pk_to_curve25519(ucdata(x25519_pk), ucdata(ed25519_pk));
}

/// Converts an Ed25519 secret key to an X25519 secret key.  Returns false on failure.
inline bool ed25519_sk_to_x25519(
        std::span<std::byte, crypto_scalarmult_curve25519_BYTES> x25519_sk,
        std::span<const std::byte, crypto_sign_ed25519_SECRETKEYBYTES> ed25519_sk) {
    return 0 == crypto_sign_ed25519_sk_to_curve25519(ucdata(x25519_sk), ucdata(ed25519_sk));
}

// ─── Ed25519 group / scalar operations ───────────────────────────────────────

/// Reduces a 64-byte value modulo the Ed25519 group order, writing 32 bytes into `out`.
inline void ed25519_scalar_reduce(std::span<std::byte, 32> out, std::span<const std::byte, 64> in) {
    crypto_core_ed25519_scalar_reduce(ucdata(out), ucdata(in));
}

/// Negates a scalar modulo the Ed25519 group order.
inline void ed25519_scalar_negate(std::span<std::byte, 32> out, std::span<const std::byte, 32> in) {
    crypto_core_ed25519_scalar_negate(ucdata(out), ucdata(in));
}

/// Multiplies two scalars modulo the Ed25519 group order.
inline void ed25519_scalar_mul(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> x,
        std::span<const std::byte, 32> y) {
    crypto_core_ed25519_scalar_mul(ucdata(out), ucdata(x), ucdata(y));
}

/// Adds two scalars modulo the Ed25519 group order.
inline void ed25519_scalar_add(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> x,
        std::span<const std::byte, 32> y) {
    crypto_core_ed25519_scalar_add(ucdata(out), ucdata(x), ucdata(y));
}

/// Computes `scalar * B` (clamped) where B is the Ed25519 base point.
/// Returns false if the scalar is zero.
inline bool ed25519_scalarmult_base(
        std::span<std::byte, 32> out, std::span<const std::byte, 32> scalar) {
    return 0 == crypto_scalarmult_ed25519_base(ucdata(out), ucdata(scalar));
}

/// Computes `scalar * B` (unclamped) where B is the Ed25519 base point.
/// Returns false if the scalar is zero.
inline bool ed25519_scalarmult_base_noclamp(
        std::span<std::byte, 32> out, std::span<const std::byte, 32> scalar) {
    return 0 == crypto_scalarmult_ed25519_base_noclamp(ucdata(out), ucdata(scalar));
}

/// Computes `scalar * point` (unclamped) on the Ed25519 curve.
/// Returns false if the result is the identity element.
inline bool ed25519_scalarmult_noclamp(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> scalar,
        std::span<const std::byte, 32> point) {
    return 0 == crypto_scalarmult_ed25519_noclamp(ucdata(out), ucdata(scalar), ucdata(point));
}

// ─── X25519 ──────────────────────────────────────────────────────────────────

/// Generates a random X25519 keypair.
inline void x25519_keypair(
        std::span<std::byte, crypto_box_PUBLICKEYBYTES> pk,
        std::span<std::byte, crypto_box_SECRETKEYBYTES> sk) {
    crypto_box_keypair(ucdata(pk), ucdata(sk));
}

/// Generates a deterministic X25519 keypair from a 32-byte seed.
inline void x25519_seed_keypair(
        std::span<std::byte, crypto_box_PUBLICKEYBYTES> pk,
        std::span<std::byte, crypto_box_SECRETKEYBYTES> sk,
        std::span<const std::byte, crypto_box_SEEDBYTES> seed) {
    crypto_box_seed_keypair(ucdata(pk), ucdata(sk), ucdata(seed));
}

/// Computes the X25519 public key corresponding to `sk`.
inline void x25519_scalarmult_base(
        std::span<std::byte, crypto_scalarmult_curve25519_BYTES> pk,
        std::span<const std::byte, crypto_scalarmult_curve25519_BYTES> sk) {
    crypto_scalarmult_curve25519_base(ucdata(pk), ucdata(sk));
}

/// Computes the X25519 shared secret from a secret key and a remote public key.
/// Returns false if the result is the all-zeros point (degenerate case).
inline bool x25519_scalarmult(
        std::span<std::byte, crypto_scalarmult_curve25519_BYTES> shared,
        std::span<const std::byte, crypto_scalarmult_curve25519_BYTES> sk,
        std::span<const std::byte, crypto_scalarmult_curve25519_BYTES> pk) {
    return 0 == crypto_scalarmult_curve25519(ucdata(shared), ucdata(sk), ucdata(pk));
}

// ─── Password hashing ────────────────────────────────────────────────────────

/// Derives a key from a password using Argon2.  Returns false on failure (e.g. out of memory).
inline bool pwhash(
        std::span<std::byte> out,
        std::string_view passwd,
        std::span<const std::byte, crypto_pwhash_SALTBYTES> salt,
        unsigned long long opslimit,
        size_t memlimit,
        int alg) {
    return 0 == crypto_pwhash(
                        ucdata(out),
                        out.size(),
                        passwd.data(),
                        passwd.size(),
                        ucdata(salt),
                        opslimit,
                        memlimit,
                        alg);
}

}  // namespace session::crypto
