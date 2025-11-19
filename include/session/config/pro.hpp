#pragma once

#include <session/config.hpp>
#include <session/config/base.hpp>
#include <session/session_protocol.hpp>

namespace session::config {

/// keys used currently or in the past (so that we don't reuse):
///
/// s + session pro data
///   |
///   +-- p + proof
///   |     |
///   |     +-- @ - version
///   |     +-- e - expiry unix timestamp (in milliseconds)
///   |     +-- g - gen_index_hash
///   |     +-- r - rotating ed25519 privkey
///   |     +-- s - proof signature, signed by the Session Pro Backend's ed25519 key
///   |
///   +-- r - rotating ed25519 pubkey
class ProConfig {
  public:
    /// Private key for the public key key specified in the proof.
    cleared_uc64 rotating_privkey;

    /// A cryptographic proof for entitling an Ed25519 key to Session Pro
    ProProof proof;

    bool load(bt_dict_consumer& root);

    bool operator==(const ProConfig& other) const {
        return rotating_privkey == other.rotating_privkey && proof == other.proof;
    }
};
};  // namespace session::config
