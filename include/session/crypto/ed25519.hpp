#pragma once

#include <array>
#include <span>
#include <stdexcept>
#include <vector>

#include "session/sodium_array.hpp"
#include "session/util.hpp"

namespace session::ed25519 {

/// A span-like type representing a fully-expanded Ed25519 private key (always 64 bytes).
/// Implicitly constructible from any fixed-extent 32- or 64-byte byte/unsigned-char spannable:
/// - 32-byte input (seed): the 64-byte key is computed via libsodium and stored internally.
/// - 64-byte input: holds a non-owning span into the caller's data — no copy or allocation.
///
/// Non-copyable and non-moveable to avoid dangling references to internal storage.

/// Concept for types that implicitly convert to a 32- or 64-byte byte/unsigned-char span.
/// Used by PrivKeySpan and OptionalPrivKeySpan to accept Ed25519 seeds and full keys.
template <typename T>
concept Ed25519KeySpannable = std::convertible_to<const T&, std::span<const std::byte, 64>> ||
                              std::convertible_to<const T&, std::span<const std::byte, 32>> ||
                              std::convertible_to<const T&, std::span<const unsigned char, 64>> ||
                              std::convertible_to<const T&, std::span<const unsigned char, 32>>;

struct PrivKeySpan {
    template <Ed25519KeySpannable T>
    PrivKeySpan(const T& src) {
        if constexpr (std::convertible_to<const T&, std::span<const std::byte, 64>>)
            data_ = std::span<const std::byte, 64>{src}.data();
        else if constexpr (std::convertible_to<const T&, std::span<const unsigned char, 64>>)
            data_ = reinterpret_cast<const std::byte*>(
                    std::span<const unsigned char, 64>{src}.data());
        else if constexpr (std::convertible_to<const T&, std::span<const std::byte, 32>>) {
            expand_seed(std::span<const std::byte, 32>{src});
            data_ = storage_->data();
        } else {
            expand_seed(std::span<const unsigned char, 32>{src});
            data_ = storage_->data();
        }
    }

    // Constructor for runtime-known sizes (e.g. at C API boundaries).
    // Throws std::invalid_argument if size is not 32 or 64.
    PrivKeySpan(const std::byte* data, size_t size);
    PrivKeySpan(const unsigned char* data, size_t size) :
            PrivKeySpan{reinterpret_cast<const std::byte*>(data), size} {}

    // Named factory for dynamic-span input (runtime size check, throws if not 32 or 64).
    static PrivKeySpan from(std::span<const std::byte> key) { return {key.data(), key.size()}; }
    static PrivKeySpan from(std::span<const unsigned char> key) { return {key.data(), key.size()}; }

    PrivKeySpan(const PrivKeySpan&) = delete;
    PrivKeySpan& operator=(const PrivKeySpan&) = delete;
    PrivKeySpan(PrivKeySpan&&) = delete;
    PrivKeySpan& operator=(PrivKeySpan&&) = delete;

    std::span<const std::byte, 64> span() const {
        return std::span<const std::byte, 64>(data_, 64);
    }
    operator std::span<const std::byte, 64>() const { return span(); }
    operator std::span<const std::byte>() const { return span(); }
    const std::byte* data() const { return data_; }
    auto begin() const { return data_; }
    auto end() const { return data_ + 64; }
    static constexpr size_t size() { return 64; }
    // Returns the 32-byte seed (first half of the libsodium key).
    std::span<const std::byte, 32> seed() const { return span().first<32>(); }
    // Returns the 32-byte Ed25519 public key (second half of the libsodium key).
    std::span<const std::byte, 32> pubkey() const { return span().last<32>(); }

  private:
    void expand_seed(std::span<const std::byte, 32> seed);
    void expand_seed(std::span<const unsigned char, 32> seed);

    const std::byte* data_ = nullptr;
    std::optional<cleared_b64> storage_;
};

/// Like PrivKeySpan but with an optional (nullable) state.  Use this when a private key parameter
/// is optional; PrivKeySpan retains its always-has-value guarantee.
///
/// Implicitly constructible from the same 32- or 64-byte sources as PrivKeySpan, plus from
/// default/nullopt for the empty state.  Non-copyable and non-moveable for the same reason as
/// PrivKeySpan.
struct OptionalPrivKeySpan {
    /// Constructs a null (no-key) state.
    OptionalPrivKeySpan() = default;
    OptionalPrivKeySpan(std::nullopt_t) {}

    template <Ed25519KeySpannable T>
    OptionalPrivKeySpan(const T& src) : key_{std::in_place, src} {}

    // Constructor for runtime-known sizes (e.g. at C API boundaries).
    // size == 0 produces the null state; size == 32 or 64 constructs the key.
    // Throws std::invalid_argument if size is not 0, 32, or 64.
    OptionalPrivKeySpan(const unsigned char* data, size_t size) {
        if (size)
            key_.emplace(data, size);
    }

    OptionalPrivKeySpan(const OptionalPrivKeySpan&) = delete;
    OptionalPrivKeySpan& operator=(const OptionalPrivKeySpan&) = delete;
    OptionalPrivKeySpan(OptionalPrivKeySpan&&) = delete;
    OptionalPrivKeySpan& operator=(OptionalPrivKeySpan&&) = delete;

    bool has_value() const { return key_.has_value(); }
    explicit operator bool() const { return has_value(); }

    const PrivKeySpan& value() const { return key_.value(); }
    const PrivKeySpan& operator*() const { return *key_; }
    const PrivKeySpan* operator->() const { return &*key_; }

  private:
    std::optional<PrivKeySpan> key_;
};

/// Generates a random Ed25519 key pair.
/// Write-to-output form.
void keypair(std::span<std::byte, 32> pk, std::span<std::byte, 64> sk);
/// Return-value form: returns {pubkey, seckey} where seckey uses cleared memory.
std::pair<b32, cleared_b64> keypair();

/// Generates a deterministic Ed25519 key pair from a 32-byte seed.
/// Write-to-output form.
void seed_keypair(
        std::span<std::byte, 32> pk,
        std::span<std::byte, 64> sk,
        std::span<const std::byte, 32> seed);
/// Return-value form: returns {pubkey, seckey} where seckey uses cleared memory.
std::pair<b32, cleared_b64> keypair(std::span<const std::byte, 32> ed25519_seed);

/// Returns the seed portion of an Ed25519 key as a non-owning span into the caller's data.
/// The overload accepting a 64-byte (libsodium-style) key returns the first 32 bytes (the seed).
/// The overload accepting a 32-byte value returns that span unchanged (it is already a seed).
inline std::span<const std::byte, 32> extract_seed(
        std::span<const std::byte, 64> ed25519_privkey) noexcept {
    return ed25519_privkey.first<32>();
}
inline std::span<const std::byte, 32> extract_seed(
        std::span<const std::byte, 32> ed25519_seed) noexcept {
    return ed25519_seed;
}

/// Generates a signature for the message using the libsodium-style ed25519 secret key, 64 bytes.
///
/// Inputs:
/// - `ed25519_privkey` -- the Ed25519 private key; accepts a 32-byte seed or 64-byte libsodium key.
/// - `msg` -- the data to generate a signature for.
///
/// Outputs:
/// - The 64-byte ed25519 signature
///
/// Write-to-output form.
void sign(
        std::span<std::byte, 64> sig,
        const PrivKeySpan& ed25519_privkey,
        std::span<const std::byte> msg);
/// Return-value form.
b64 sign(const PrivKeySpan& ed25519_privkey, std::span<const std::byte> msg);

/// Verify a message and signature for a given pubkey.
///
/// Inputs:
/// - `sig` -- the signature to verify, 64 bytes.
/// - `pubkey` -- the pubkey for the secret key that was used to generate the signature, 32 bytes.
/// - `msg` -- the data to verify the signature for.
///
/// Outputs:
/// - A flag indicating whether the signature is valid
bool verify(
        std::span<const std::byte, 64> sig,
        std::span<const std::byte, 32> pubkey,
        std::span<const std::byte> msg);

/// Derives a deterministic Ed25519 keypair from a seed and a domain string.
///
/// The derived seed is: Blake2b32(data=ed25519_seed, hash_key=domain)
///
/// This is a general subkey derivation primitive; use a distinct domain string per use case
/// to produce independent derived keys from the same root seed.
///
/// Returns the (pubkey, seckey) pair; the secret key uses cleared memory.
std::pair<b32, cleared_b64> derive_subkey(
        std::span<const std::byte, 32> ed25519_seed, std::span<const std::byte> domain);

/// Extracts the 32-byte public key from a 64-byte libsodium Ed25519 secret key.
/// Write-to-output form.
void sk_to_pk(std::span<std::byte, 32> pk, const PrivKeySpan& sk);
/// Return-value form.
b32 sk_to_pk(const PrivKeySpan& sk);

/// Converts an Ed25519 public key to an X25519 public key.
/// Throws std::runtime_error if the key is invalid.
/// Write-to-output form: result written into `out`.
void pk_to_x25519(std::span<std::byte, 32> out, std::span<const std::byte, 32> pk);
/// Return-value form.
b32 pk_to_x25519(std::span<const std::byte, 32> pk);

/// Converts an Ed25519 public key to a 33-byte 0x05-prefixed Session ID by converting the
/// Ed25519 pubkey to X25519 and prefixing 0x05.
/// Write-to-output form: result written into `out`.
void pk_to_session_id(std::span<std::byte, 33> out, std::span<const std::byte, 32> pk);
/// Return-value form.
b33 pk_to_session_id(std::span<const std::byte, 32> pk);

/// Converts an Ed25519 secret key to an X25519 secret key.
/// Write-to-output form.
void sk_to_x25519(std::span<std::byte, 32> out, std::span<const std::byte, 32> seed);
/// Return-value form (using cleared memory).
inline cleared_b32 sk_to_x25519(std::span<const std::byte, 32> seed) {
    cleared_b32 xsk;
    sk_to_x25519(xsk, seed);
    return xsk;
}
/// Overload for a full 64-byte Ed25519 secret key (seed || pubkey); only the seed (first 32
/// bytes) is used.
inline cleared_b32 sk_to_x25519(std::span<const std::byte, 64> full_key) {
    return sk_to_x25519(full_key.first<32>());
}
/// Overload for PrivKeySpan (deduced exactly, suppressing implicit conversions).
template <std::same_as<PrivKeySpan> T>
inline cleared_b32 sk_to_x25519(const T& sk) {
    return sk_to_x25519(sk.seed());
}

/// Derives the X25519 {secret, public} key pair from an Ed25519 private key.
/// Equivalent to `{sk_to_x25519(sk), pk_to_x25519(sk.pubkey())}` but as a single call.
std::pair<cleared_b32, b32> x25519_keypair(const PrivKeySpan& sk);

/// Returns the private Ed25519 scalar `a` from a seed or PrivKeySpan (using cleared memory).
///
/// Ed25519 and X25519 share the same private scalar: the Ed25519-to-X25519 conversion is
/// defined by using that same scalar on X25519's base point instead of Ed25519's.  Use this
/// alias wherever the goal is to obtain the private scalar `a` rather than an X25519 key.
template <typename... Args>
    requires requires(Args&&... args) { sk_to_x25519(std::forward<Args>(args)...); }
inline decltype(auto) sk_to_private(Args&&... args) {
    return sk_to_x25519(std::forward<Args>(args)...);
}

/// Computes the Ed25519 group element from a scalar (clamped).
/// Write-to-output form: result written into `out`.
void scalarmult_base(std::span<std::byte, 32> out, std::span<const std::byte, 32> scalar);
/// Return-value form.
b32 scalarmult_base(std::span<const std::byte, 32> scalar);

/// Computes the Ed25519 group element from a scalar (no clamping).
/// Write-to-output form: result written into `out`.
void scalarmult_base_noclamp(std::span<std::byte, 32> out, std::span<const std::byte, 32> scalar);
/// Return-value form.
b32 scalarmult_base_noclamp(std::span<const std::byte, 32> scalar);

/// Multiplies an Ed25519 point by a scalar (no clamping).
/// Write-to-output form: result written into `out`.
void scalarmult_noclamp(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> scalar,
        std::span<const std::byte, 32> point);
/// Return-value form.
b32 scalarmult_noclamp(std::span<const std::byte, 32> scalar, std::span<const std::byte, 32> point);

/// Reduces a 64-byte scalar modulo the Ed25519 group order to 32 bytes.
/// Write-to-output form: result written into `out`.
void scalar_reduce(std::span<std::byte, 32> out, std::span<const std::byte, 64> in);
/// Return-value form.
b32 scalar_reduce(std::span<const std::byte, 64> in);

/// Negates a 32-byte Ed25519 scalar.
/// Write-to-output form: result written into `out` (safe to alias `in`).
void scalar_negate(std::span<std::byte, 32> out, std::span<const std::byte, 32> in);
/// Return-value form.
b32 scalar_negate(std::span<const std::byte, 32> in);

/// Multiplies two 32-byte Ed25519 scalars.
/// Write-to-output form: result written into `out` (safe to alias `x` or `y`).
void scalar_mul(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> x,
        std::span<const std::byte, 32> y);
/// Return-value form.
b32 scalar_mul(std::span<const std::byte, 32> x, std::span<const std::byte, 32> y);

/// Adds two 32-byte Ed25519 scalars.
/// Write-to-output form: result written into `out` (safe to alias `x` or `y`).
void scalar_add(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> x,
        std::span<const std::byte, 32> y);
/// Return-value form.
b32 scalar_add(std::span<const std::byte, 32> x, std::span<const std::byte, 32> y);

}  // namespace session::ed25519
