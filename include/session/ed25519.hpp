#pragma once

#include <array>
#include <span>
#include <vector>

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
/// - `ed25519_privkey` -- the libsodium-style secret key, 64 bytes.
/// - `msg` -- the data to generate a signature for.
///
/// Outputs:
/// - The ed25519 signature
std::vector<unsigned char> sign(
        std::span<const unsigned char> ed25519_privkey, std::span<const unsigned char> msg);

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
