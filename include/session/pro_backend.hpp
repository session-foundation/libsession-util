#pragma once

#include <chrono>
#include <session/types.hpp>
#include <string>

namespace session::pro_backend {

/// TODO: Assign the Session Pro backend public key for verifying proofs to allow users of the
/// library to have the pubkey available for verifying proofs.
constexpr array_uc32 PUBKEY = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static_assert(sizeof(PUBKEY) == array_uc32{}.size());

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

master_rotating_sigs build_get_proof_sigs(
        const array_uc64& master_privkey,
        const array_uc64& rotating_privkey,
        std::chrono::seconds unix_ts);
master_rotating_sigs build_add_payment_sigs(
        const array_uc64& master_privkey,
        const array_uc64& rotating_privkey,
        const array_uc32& payment_token_hash,
        std::chrono::seconds unix_ts);

}  // namespace session::pro_backend
