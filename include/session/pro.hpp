#pragma once

#include <session/config/pro.hpp>
#include <session/types.hpp>

namespace session::pro {

struct add_payment_request {
    std::uint8_t version;
    array_uc32 master_pkey;
    array_uc32 rotating_pkey;
    array_uc32 payment_token;
    array_uc32 master_sig;
    array_uc32 rotating_sig;
    std::string to_json() const;
};

struct get_proof_request {
    std::uint8_t version;
    array_uc32 master_pkey;
    array_uc32 rotating_pkey;
    std::chrono::seconds unix_ts_s;
    array_uc32 master_sig;
    array_uc32 rotating_sig;
    std::string to_json() const;
};

struct master_rotating_sigs {
    array_uc64 master_sig;
    array_uc64 rotating_sig;
};

struct revocation_item {
    array_uc32 gen_index_hash;
    std::chrono::seconds expiry_unix_ts;
};

enum class Status {
    Nil,      // Pro proof was not set
    Invalid,  // Pro proof was set; signature validation failed
    Valid,    // Pro proof was set, is verified; has not expired
    Expired,  // Pro proof was set, is verified; has expired
};

typedef std::uint32_t FeatureFlag;
enum FeatureFlag_ {
    FeatureFlag_HigherCharacterLimit = 0 << 1,
    FeatureFlag_ProBadge = 1 << 1,
    FeatureFlag_AnimatedAvatar = 2 << 1,
    FeatureFlag_All =
            FeatureFlag_HigherCharacterLimit | FeatureFlag_ProBadge | FeatureFlag_AnimatedAvatar,
};

struct DecryptIncomingWithPro
{
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ed25519_pubkey;
    config::ProProof pro_proof;
    Status pro_status;
    FeatureFlag pro_flags;
};

master_rotating_sigs build_get_proof_sigs(const array_uc64& master_privkey, const array_uc64& rotating_privkey, std::chrono::seconds unix_ts);
master_rotating_sigs build_add_payment_sigs(const array_uc64& master_privkey, const array_uc64& rotating_privkey, const array_uc32& payment_token_hash, std::chrono::seconds unix_ts);

constexpr array_uc32 BACKEND_PUBKEY = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


}  // namespace session::pro
