#pragma once

#include <array>
#include <span>
#include <stdexcept>
#include <vector>

#include "session/sodium_array.hpp"

namespace session {

/// A span-like type representing a fully-expanded Ed25519 private key (always 64 bytes).
/// Implicitly constructible from any fixed-extent 32- or 64-byte unsigned char spannable:
/// - 32-byte input (seed): the 64-byte key is computed via libsodium and stored internally.
/// - 64-byte input: holds a non-owning span into the caller's data — no copy or allocation.
///
/// Non-copyable and non-moveable to avoid dangling references to internal storage.
struct Ed25519PrivKeySpan {
    template <typename T>
        requires(
                std::constructible_from<std::span<const unsigned char, 64>, const T&> ||
                std::constructible_from<std::span<const unsigned char, 32>, const T&>)
    Ed25519PrivKeySpan(const T& src) {
        if constexpr (std::constructible_from<std::span<const unsigned char, 64>, const T&>)
            data_ = std::span<const unsigned char, 64>{src}.data();
        else {
            expand_seed(std::span<const unsigned char, 32>{src});
            data_ = storage_->data();
        }
    }

    // Constructor for runtime-known sizes (e.g. at C API boundaries).
    // Throws std::invalid_argument if size is not 32 or 64.
    Ed25519PrivKeySpan(const unsigned char* data, size_t size) {
        if (size == 64)
            data_ = data;
        else if (size == 32) {
            expand_seed(std::span<const unsigned char, 32>{data, 32});
            data_ = storage_->data();
        } else
            throw std::invalid_argument{"Ed25519 private key must be 32 or 64 bytes"};
    }

    // Named factory alias for dynamic-span input.
    static Ed25519PrivKeySpan from(std::span<const unsigned char> key) {
        return {key.data(), key.size()};
    }

    Ed25519PrivKeySpan(const Ed25519PrivKeySpan&) = delete;
    Ed25519PrivKeySpan& operator=(const Ed25519PrivKeySpan&) = delete;
    Ed25519PrivKeySpan(Ed25519PrivKeySpan&&) = delete;
    Ed25519PrivKeySpan& operator=(Ed25519PrivKeySpan&&) = delete;

    std::span<const unsigned char, 64> span() const {
        return std::span<const unsigned char, 64>(data_, 64);
    }
    operator std::span<const unsigned char, 64>() const { return span(); }
    operator std::span<const unsigned char>() const { return span(); }
    const unsigned char* data() const { return data_; }
    auto begin() const { return data_; }
    auto end() const { return data_ + 64; }
    static constexpr size_t size() { return 64; }
    // Returns the 32-byte seed (first half of the libsodium key).
    std::span<const unsigned char, 32> seed() const { return span().first<32>(); }
    // Returns the 32-byte Ed25519 public key (second half of the libsodium key).
    std::span<const unsigned char, 32> pubkey() const { return span().last<32>(); }

  private:
    void expand_seed(std::span<const unsigned char, 32> seed);

    const unsigned char* data_ = nullptr;
    std::optional<cleared_uc64> storage_;
};

/// Like Ed25519PrivKeySpan but with an optional (nullable) state.  Use this when a private key
/// parameter is optional; Ed25519PrivKeySpan retains its always-has-value guarantee.
///
/// Implicitly constructible from the same 32- or 64-byte sources as Ed25519PrivKeySpan, plus from
/// default/nullopt for the empty state.  Non-copyable and non-moveable for the same reason as
/// Ed25519PrivKeySpan.
struct OptionalEd25519PrivKeySpan {
    /// Constructs a null (no-key) state.
    OptionalEd25519PrivKeySpan() = default;
    OptionalEd25519PrivKeySpan(std::nullopt_t) {}

    template <typename T>
        requires(
                std::constructible_from<std::span<const unsigned char, 64>, const T&> ||
                std::constructible_from<std::span<const unsigned char, 32>, const T&>)
    OptionalEd25519PrivKeySpan(const T& src) : key_{std::in_place, src} {}

    // Constructor for runtime-known sizes (e.g. at C API boundaries).
    // size == 0 produces the null state; size == 32 or 64 constructs the key.
    // Throws std::invalid_argument if size is not 0, 32, or 64.
    OptionalEd25519PrivKeySpan(const unsigned char* data, size_t size) {
        if (size)
            key_.emplace(data, size);
    }

    OptionalEd25519PrivKeySpan(const OptionalEd25519PrivKeySpan&) = delete;
    OptionalEd25519PrivKeySpan& operator=(const OptionalEd25519PrivKeySpan&) = delete;
    OptionalEd25519PrivKeySpan(OptionalEd25519PrivKeySpan&&) = delete;
    OptionalEd25519PrivKeySpan& operator=(OptionalEd25519PrivKeySpan&&) = delete;

    bool has_value() const { return key_.has_value(); }
    explicit operator bool() const { return has_value(); }

    const Ed25519PrivKeySpan& value() const { return key_.value(); }
    const Ed25519PrivKeySpan& operator*() const { return *key_; }
    const Ed25519PrivKeySpan* operator->() const { return &*key_; }

  private:
    std::optional<Ed25519PrivKeySpan> key_;
};

}  // namespace session

namespace session::ed25519 {

/// Generates a random Ed25519 key pair
std::pair<std::array<unsigned char, 32>, std::array<unsigned char, 64>> ed25519_key_pair();

/// Given an Ed25519 seed this returns the associated Ed25519 key pair
std::pair<std::array<unsigned char, 32>, std::array<unsigned char, 64>> ed25519_key_pair(
        std::span<const unsigned char> ed25519_seed);

/// API: ed25519/seed_for_ed_privkey
///
/// Returns the seed for an ed25519 key pair given either the libsodium-style secret key, 64
/// bytes.  If a 32-byte value is provided it is assumed to be the seed and the value will just
/// be returned directly.
///
/// Inputs:
/// - `ed25519_privkey` -- the libsodium-style secret key of the sender, 64 bytes.  Can also be
///   passed as a 32-byte seed.
///
/// Outputs:
/// - The ed25519 seed
std::array<unsigned char, 32> seed_for_ed_privkey(std::span<const unsigned char> ed25519_privkey);

/// API: ed25519/sign
///
/// Generates a signature for the message using the libsodium-style ed25519 secret key, 64 bytes.
///
/// Inputs:
/// - `ed25519_privkey` -- the Ed25519 private key; accepts a 32-byte seed or 64-byte libsodium key.
/// - `msg` -- the data to generate a signature for.
///
/// Outputs:
/// - The ed25519 signature
std::vector<unsigned char> sign(
        const Ed25519PrivKeySpan& ed25519_privkey, std::span<const unsigned char> msg);

/// API: ed25519/verify
///
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
        std::span<const unsigned char> sig,
        std::span<const unsigned char> pubkey,
        std::span<const unsigned char> msg);

/// API: ed25519/ed25519_pro_privkey_for_ed25519_seed
///
/// Generate the deterministic Master Session Pro key for signing requests to interact with the
/// Session Pro features of the protocol.
///
/// Inputs:
/// - `ed25519_seed` -- the seed to the long-term key for the Session account to derive the
///   deterministic key from.
///
/// Outputs:
/// - The libsodium-style Master Session Pro Ed25519 secret key, 64 bytes.
std::array<unsigned char, 64> ed25519_pro_privkey_for_ed25519_seed(
        std::span<const unsigned char> ed25519_seed);

}  // namespace session::ed25519
