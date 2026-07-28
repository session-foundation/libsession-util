#include <session/config/pro.h>
#include <session/pro_backend.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include <session/config/pro.hpp>
#include <session/sodium_array.hpp>

#include "internal.hpp"

namespace session::config {

bool ProConfig::load(const dict& root) {
    // Get proof fields from session pro data sitting in the 'p' (proof) dictionary
    auto p_it = root.find("p");
    if (p_it == root.end())
        return false;

    // Lookup and get 'p'
    const config::dict* p = std::get_if<config::dict>(&p_it->second);
    if (!p)
        return false;

    std::optional<std::vector<unsigned char>> maybe_rotating_seed = maybe_vector(root, "r");
    if (!maybe_rotating_seed || maybe_rotating_seed->size() != crypto_sign_ed25519_SEEDBYTES)
        return false;

    // NOTE: Load into the proof object
    {
        std::optional<std::vector<unsigned char>> maybe_revocation_tag = maybe_vector(*p, "g");
        std::optional<std::chrono::sys_seconds> maybe_expiry = maybe_ts(*p, "e");
        std::optional<std::vector<unsigned char>> maybe_sig = maybe_vector(*p, "s");

        if (!maybe_revocation_tag || maybe_revocation_tag->size() != proof.revocation_tag.size())
            return false;
        if (!maybe_sig || maybe_sig->size() != proof.sig.max_size())
            return false;
        if (!maybe_expiry)
            return false;

        // The proof version is NOT persisted in the config: dicts merge per-key/non-atomically, so
        // an in-dict version field can't reliably describe its sibling fields (a concurrent edit
        // could stitch one update's version onto another's fields). The config proof format is v0
        // by definition; a future format would take a new key, not a version marker here.
        proof.version = ProProofVersion_v0;
        std::memcpy(
                proof.revocation_tag.data(),
                maybe_revocation_tag->data(),
                proof.revocation_tag.size());
        proof.expiry_at = *maybe_expiry;
        std::memcpy(proof.sig.data(), maybe_sig->data(), proof.sig.size());
    }

    // Derive the rotating public key from the seed and populate the proof's pubkey and the outer
    // private key
    crypto_sign_ed25519_seed_keypair(
            proof.rotating_pubkey.data(), rotating_privkey.data(), maybe_rotating_seed->data());
    return true;
}

};  // namespace session::config
