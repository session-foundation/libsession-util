#include <session/config/pro.h>
#include <session/pro_backend.h>

#include <session/config/pro.hpp>
#include <session/crypto/ed25519.hpp>
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

    std::optional<std::vector<std::byte>> maybe_rotating_seed = maybe_vector(root, "r");
    if (!maybe_rotating_seed || maybe_rotating_seed->size() != 32)
        return false;

    // NOTE: Load into the proof object
    {
        std::optional<uint8_t> version = maybe_int(*p, "@");
        std::optional<std::vector<std::byte>> maybe_revocation_tag = maybe_vector(*p, "g");
        std::optional<std::chrono::sys_seconds> maybe_expiry = maybe_ts(*p, "e");
        std::optional<std::vector<std::byte>> maybe_sig = maybe_vector(*p, "s");

        if (!version)
            return false;
        if (!maybe_revocation_tag || maybe_revocation_tag->size() != proof.revocation_tag.size())
            return false;
        if (!maybe_sig || maybe_sig->size() != proof.sig.max_size())
            return false;
        if (!maybe_expiry)
            return false;

        proof.version = *version;
        std::memcpy(
                proof.revocation_tag.data(),
                maybe_revocation_tag->data(),
                proof.revocation_tag.size());
        proof.expiry_unix_ts = *maybe_expiry;
        std::memcpy(proof.sig.data(), maybe_sig->data(), proof.sig.size());
    }

    // Derive the rotating public key from the seed and populate the proof's pubkey and the outer
    // private key
    ed25519::seed_keypair(
            proof.rotating_pubkey, rotating_privkey, std::span{*maybe_rotating_seed}.first<32>());
    return true;
}

};  // namespace session::config
