#pragma once

#include <session/config/pro.h>

#include <chrono>
#include <cstdint>
#include <session/config.hpp>
#include <session/config/base.hpp>
#include <session/sodium_array.hpp>
#include <session/types.hpp>

namespace session::config {

enum ProProofVersion { ProProofVersion_v0 };

enum class ProStatus {
    // Pro proof sig was not signed by the Pro backend key
    InvalidProBackendSig = PRO_STATUS_INVALID_PRO_BACKEND_SIG,
    // Pro sig in the envelope was not signed by the Rotating key
    InvalidUserSig = PRO_STATUS_INVALID_USER_SIG,
    Valid = PRO_STATUS_VALID,      // Proof is verified; has not expired
    Expired = PRO_STATUS_EXPIRED,  // Proof is verified; has expired
};

struct ProSignedMessage {
    std::span<const uint8_t> sig;
    std::span<const uint8_t> msg;
};

/// keys used currently or in the past (so that we don't reuse):
///
/// @ - version
/// g - gen_index_hash
/// r - rotating ed25519 pubkey
/// e - expiry unix timestamp (in seconds)
/// s - proof signature, signed by the Session Pro Backend's ed25519 key
class ProProof {
  public:
    /// Version of the proof set by the Session Pro Backend
    std::uint8_t version;

    /// Hash of the generation index set by the Session Pro Backend
    array_uc32 gen_index_hash;

    /// The public key that the Session client registers their Session Pro entitlement under.
    /// Session clients must sign messages with this key along side the sending of this proof for
    /// the network to authenticate their usage of the proof
    array_uc32 rotating_pubkey;

    /// Unix epoch timestamp to which this proof's entitlement to Session Pro features is valid to
    std::chrono::sys_seconds expiry_unix_ts;

    /// Signature over the contents of the proof. It is signed by the Session Pro Backend key which
    /// is the entity responsible for issueing tamper-proof Sesison Pro certificates for Session
    /// clients.
    array_uc64 sig;

    /// API: pro/Proof::verify_signature
    ///
    /// Verify that the proof's contents was not tampered with by hashing the proof and checking
    /// that the hash was signed by the secret key of the given Ed25519 public key.
    ///
    /// For Session Pro intents and purposes, we expect proofs to be signed by the Session Pro
    /// Backend public key. This function throws if an incorrectly sized key is passed in.
    ///
    /// Inputs:
    /// - `verify_pubkey` -- 32 byte Ed25519 public key of the corresponding secret key to check if
    /// they are the original signatory of the proof.
    ///
    /// Outputs:
    /// - `bool` - True if the given key was the signatory of the proof, false otherwise
    bool verify_signature(const std::span<const uint8_t>& verify_pubkey) const;

    /// API: pro/Proof::verify_message
    ///
    /// Check if the `rotating_pubkey` in the proof was the signatory of the message and signature
    /// passed in. This function throws if an signature is passed in that isn't 64 bytes.
    ///
    /// Inputs:
    /// - `sig` -- Signature to verify with the `rotating_pubkey`. The signature should have
    ///   originally been signed over `msg` passed in.
    /// - `msg` -- Message that the signature signed over with. It will be verified using the
    ///   embedded `rotating_pubkey`.
    ///
    /// Outputs:
    /// - `bool` - True if the message was signed by the embedded `rotating_pubkey` false otherwise.
    bool verify_message(std::span<const uint8_t> sig, const std::span<const uint8_t> msg) const;

    /// API: pro/Proof::is_active
    ///
    /// Check if Pro proof is currently entitled to Pro given the `unix_ts` with respect to the
    /// proof's `expiry_unix_ts`
    ///
    /// Inputs:
    /// - `unix_ts` -- Unix timestamp in seconds to compared against the embedded `expiry_unix_ts`
    ///   to determine if the proof has expired or not
    ///
    /// Outputs:
    /// - `bool` - True if proof is active (i.e. has not expired), false otherwise.
    bool is_active(std::chrono::sys_seconds unix_ts) const;

    /// API: pro/Proof::status
    ///
    /// Evaluate the status of the pro proof by checking it is signed by the `verify_pubkey`, it has
    /// not expired via `unix_ts` and optionally verify that the `signed_msg` was signed by the
    /// `rotating_pubkey` embedded in the proof.
    ///
    /// Internally this function calls `verify_signature`, `verify_message` and optionally
    /// `is_active` in sequence. This function throws if an invalidly sized public key or signature
    /// are passed in. They must be 32 and 64 bytes respectively.
    ///
    /// Inputs:
    /// - `verify_pubkey` -- 32 byte Ed25519 public key of the corresponding secret key to check if
    ///   they are the original signatory of the proof.
    /// - `unix_ts` -- Unix timestamp in seconds to compared against the embedded `expiry_unix_ts`
    ///   to determine if the proof has expired or not
    /// - `signed_msg` -- Optionally set the payload to the message with the signature to verify if
    ///   the embedded `rotating_pubkey` in the proof signed the given message.
    ///
    /// Outputs:
    /// - `ProStatus` - The derived status given the components of the message. If `signed_msg` is
    ///   not set then this function can never return `ProStatus::InvalidUserSig` from the set of
    ///   possible enum values. Otherwise this funtion can return all possible values.
    ProStatus status(
            std::span<const uint8_t> verify_pubkey,
            std::chrono::sys_seconds unix_ts,
            const std::optional<ProSignedMessage>& signed_msg);

    /// API: pro/Proof::hash
    ///
    /// Create a 32-byte hash from the proof. This hash is the payload that is signed in the proof.
    array_uc32 hash() const;

    bool load(const dict& root);
};

/// keys used currently or in the past (so that we don't reuse):
///
/// r - rotating ed25519 privkey
/// p - proof
class ProConfig {
  public:
    /// Private key for the public key key specified in the proof. This is synced between clients
    /// to allow multiple clients to synchronise the Session Pro Proof and also the keys necessary
    /// to use the proof.
    cleared_uc64 rotating_privkey;

    /// A cryptographic proof for entitling an Ed25519 key to Session Pro
    ProProof proof;

    /// API: pro/Pro::verify
    ///
    /// Verify the proof and that the proof's rotating public key matches the public key of the
    /// `rotating_privkey`
    ///
    /// Inputs:
    /// - `verify_pubkey` -- Ed25519 public key of the corresponding secret key to check if they are
    /// the original signatory of the proof.
    ///
    /// Outputs:
    /// - `bool` - True if the proof was verified and the proof's rotating public key corresponds to
    /// the public component of the `rotating_privkey`.
    bool verify_signature(const array_uc32& verify_pubkey) const;

    bool load(const dict& root);
};
};  // namespace session::config
