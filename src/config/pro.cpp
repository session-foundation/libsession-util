#include <session/config/pro.h>
#include <session/pro_backend.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include <session/config/pro.hpp>
#include <session/sodium_array.hpp>

#include "internal.hpp"

namespace session::config {

bool ProConfig::load(bt_dict_consumer& root) {
    // Get proof fields from session pro data sitting in the 'p' (proof) dictionary
    if (!root.skip_until("p"))
        return false;

    // Lookup and get 'p'
    auto pd = root.consume_dict_consumer();

    if (!root.skip_until("r"))
        return false;

    auto rotating_privkey_ = root.consume_string_view();

    if (rotating_privkey_.size() != rotating_privkey.max_size())
        return false;

    // NOTE: Load into the proof object
    {
        if (!pd.skip_until("@"))
            return false;

        proof.version = pd.consume_integer<uint8_t>();

        if (!pd.skip_until("e"))
            return false;

        proof.expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                std::chrono::milliseconds(pd.consume_integer<uint64_t>()));

        if (!pd.skip_until("g"))
            return false;

        auto gen_index_hash = pd.consume_string_view();
        if (gen_index_hash.size() != proof.gen_index_hash.size())
            return false;

        if (!pd.skip_until("r"))
            return false;

        auto rotating_pubkey = pd.consume_string_view();
        if (rotating_pubkey.size() != proof.rotating_pubkey.max_size())
            return false;

        if (!pd.skip_until("s"))
            return false;

        auto sig = pd.consume_string_view();
        if (sig.size() != proof.sig.max_size())
            return false;

        std::memcpy(
                proof.gen_index_hash.data(), gen_index_hash.data(), proof.gen_index_hash.size());
        std::memcpy(
                proof.rotating_pubkey.data(), rotating_pubkey.data(), proof.rotating_pubkey.size());
        std::memcpy(proof.sig.data(), sig.data(), proof.sig.size());
    }

    std::memcpy(rotating_privkey.data(), rotating_privkey_.data(), rotating_privkey.size());
    return true;
}

};  // namespace session::config
