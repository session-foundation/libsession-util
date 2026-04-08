#pragma once

#include <array>
#include <span>
#include <stdexcept>
#include <utility>

#include "session/sodium_array.hpp"
#include "session/util.hpp"

namespace session::x25519 {

/// Generates a random X25519 keypair.
/// Write-to-output form.
void keypair(std::span<std::byte, 32> pk, std::span<std::byte, 32> sk);
/// Return-value form: returns {pubkey, seckey}.
std::pair<b32, cleared_b32> keypair();

/// Generates a deterministic X25519 keypair from a 32-byte seed.
/// Write-to-output form.
void seed_keypair(
        std::span<std::byte, 32> pk,
        std::span<std::byte, 32> sk,
        std::span<const std::byte, 32> seed);
/// Return-value form: returns {pubkey, seckey}.
std::pair<b32, cleared_b32> seed_keypair(std::span<const std::byte, 32> seed);

/// Computes the X25519 public key corresponding to `sk`: out = sk * G.
/// Write-to-output form.
void scalarmult_base(std::span<std::byte, 32> out, std::span<const std::byte, 32> scalar);
/// Return-value form.
b32 scalarmult_base(std::span<const std::byte, 32> scalar);

/// Computes X25519 scalar multiplication: out = scalar * point.
/// Returns false if the result is the all-zeros point (degenerate case).
/// Write-to-output form.
bool scalarmult(
        std::span<std::byte, 32> out,
        std::span<const std::byte, 32> scalar,
        std::span<const std::byte, 32> point);
/// Return-value form.  Throws on degenerate case.
b32 scalarmult(std::span<const std::byte, 32> scalar, std::span<const std::byte, 32> point);

}  // namespace session::x25519
