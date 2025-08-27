#pragma once

#include <session/config.hpp>
#include <session/config/base.hpp>
#include <session/session_protocol.hpp>

namespace session::config {

/// keys used currently or in the past (so that we don't reuse):
///
/// p + pro data
///   |
///   +-- @ - version
///   +-- g - gen_index_hash
///   +-- r - rotating ed25519 pubkey
///   +-- e - expiry unix timestamp (in seconds)
///   +-- s - proof signature, signed by the Session Pro Backend's ed25519 key
///   +-- r - rotating ed25519 privkey
///   +-- p - proof
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
