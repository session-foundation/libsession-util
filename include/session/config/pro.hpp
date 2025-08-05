#include <chrono>
#include <cstdint>
#include <session/config.hpp>
#include <session/config/base.hpp>
#include <session/sodium_array.hpp>
#include <session/types.hpp>

namespace session::config {

/// keys used currently or in the past (so that we don't reuse):
///
/// v - version
/// g - gen_index_hash
/// r - rotating ed25519 pubkey
/// e - expiry unix timestamp (in seconds)
/// s - proof signature, signed by the Session Pro Backend's ed25519 key
class Proof {
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

    /// API: pro/Proof::verify
    ///
    /// Verify that the proof's contents was not tampered with by hashing the proof and checking
    /// that the hash was signed by the secret key of the given Ed25519 public key.
    ///
    /// For Session Pro intents and purposes, we expect proofs to be signed by the Session Pro
    /// Backend public key.
    ///
    /// Inputs:
    /// - `verify_pubkey` -- Ed25519 public key of the corresponding secret key to check if they are
    /// the original signatory of the proof.
    ///
    /// Outputs:
    /// - `bool` - True if the given key was the signatory of the proof, false otherwise
    bool verify(const array_uc32& verify_pubkey) const;

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
class Pro {
  public:
    /// Private key for the public key key specified in the proof. This is synced between clients
    /// to allow multiple clients to synchronise the Session Pro Proof and also the keys necessary
    /// to use the proof.
    cleared_uc64 rotating_privkey;

    /// A cryptographic proof for entitling an Ed25519 key to Session Pro
    Proof proof;

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
    bool verify(const array_uc32& verify_pubkey) const;

    bool load(const dict& root);
};
};  // namespace session::config
