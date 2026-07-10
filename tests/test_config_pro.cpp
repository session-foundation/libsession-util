#include <oxenc/bt_producer.h>
#include <oxenc/hex.h>
#include <session/config/pro.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <iostream>
#include <session/config/pro.hpp>
using namespace oxenc::literals;

TEST_CASE("Pro", "[config][pro]") {
    // Setup keys
    std::array<uint8_t, crypto_sign_ed25519_PUBLICKEYBYTES> rotating_pk, signing_pk;
    session::cleared_uc64 rotating_sk, signing_sk;
    {
        crypto_sign_ed25519_keypair(rotating_pk.data(), rotating_sk.data());
        crypto_sign_ed25519_keypair(signing_pk.data(), signing_sk.data());
    }

    // Setup the Pro data structure
    session::config::ProConfig pro_cpp = {};
    pro_pro_config pro = {};
    {
        // CPP
        pro_cpp.rotating_privkey = rotating_sk;
        pro_cpp.proof.version = 2;
        pro_cpp.proof.rotating_pubkey = rotating_pk;
        pro_cpp.proof.expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(1s);
        constexpr auto gen_index_hash =
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_u;
        static_assert(pro_cpp.proof.gen_index_hash.max_size() == gen_index_hash.size());
        std::memcpy(
                pro_cpp.proof.gen_index_hash.data(), gen_index_hash.data(), gen_index_hash.size());

        // C
        std::memcpy(pro.rotating_privkey.data, rotating_sk.data(), rotating_sk.size());
        pro.proof.version = pro_cpp.proof.version;
        std::memcpy(pro.proof.rotating_pubkey.data, rotating_pk.data(), rotating_pk.size());
        pro.proof.expiry_unix_ts_ms = pro_cpp.proof.expiry_unix_ts.time_since_epoch().count();
        std::memcpy(pro.proof.gen_index_hash.data, gen_index_hash.data(), gen_index_hash.size());
    }

    // Generate and write the hashes that are signed by the faux pro backend into the proof
    {
        // Generate the hashes
        static_assert(crypto_sign_ed25519_BYTES == pro_cpp.proof.sig.max_size());
        std::array<uint8_t, 32> hash_to_sign_cpp = pro_cpp.proof.hash();
        bytes32 hash_to_sign = session_protocol_pro_proof_hash(&pro.proof);

        static_assert(hash_to_sign_cpp.size() == sizeof(hash_to_sign));
        CHECK(std::memcmp(hash_to_sign_cpp.data(), hash_to_sign.data, hash_to_sign_cpp.size()) ==
              0);

        // Write the signature into the proof
        int sig_result = crypto_sign_ed25519_detached(
                pro_cpp.proof.sig.data(),
                nullptr,
                hash_to_sign_cpp.data(),
                hash_to_sign_cpp.size(),
                signing_sk.data());
        CHECK(sig_result == 0);

        sig_result = crypto_sign_ed25519_detached(
                pro.proof.sig.data,
                nullptr,
                hash_to_sign.data,
                sizeof(hash_to_sign.data),
                signing_sk.data());
        CHECK(sig_result == 0);
    }

    // Verify expiry
    {
        CHECK(pro_cpp.proof.is_active(pro_cpp.proof.expiry_unix_ts));
        CHECK_FALSE(pro_cpp.proof.is_active(pro_cpp.proof.expiry_unix_ts + 1ms));

        CHECK(session_protocol_pro_proof_is_active(&pro.proof, pro.proof.expiry_unix_ts_ms));
        CHECK_FALSE(
                session_protocol_pro_proof_is_active(&pro.proof, pro.proof.expiry_unix_ts_ms + 1));
    }

    // Verify it can verify messages signed with the rotating public key
    {
        std::string_view body = "hello world";
        std::array<uint8_t, crypto_sign_ed25519_BYTES> sig = {};
        int sign_result = crypto_sign_ed25519_detached(
                sig.data(),
                nullptr,
                reinterpret_cast<const uint8_t*>(body.data()),
                body.size(),
                rotating_sk.data());
        CHECK(sign_result == 0);
        CHECK(pro_cpp.proof.verify_message(sig, session::to_span(body)));
        CHECK(session_protocol_pro_proof_verify_message(
                &pro.proof,
                sig.data(),
                sig.size(),
                reinterpret_cast<const uint8_t*>(body.data()),
                body.size()));
    }

    // Try loading the proof from dict
    {
        const session::ProProof& proof = pro_cpp.proof;
        // clang-format off
        session::config::dict good_dict = {
            {"r", std::string(reinterpret_cast<const char *>(rotating_sk.data()), crypto_sign_ed25519_SEEDBYTES)},
            {"p", session::config::dict{
                /*version*/         {"@", proof.version},
                /*gen_index_hash*/  {"g", std::string(reinterpret_cast<const char *>(proof.gen_index_hash.data()), proof.gen_index_hash.size())},
                /*rotating pubkey*/ {"r", std::string(reinterpret_cast<const char *>(proof.rotating_pubkey.data()), proof.rotating_pubkey.size())},
                /*expiry unix ts*/  {"e", proof.expiry_unix_ts.time_since_epoch().count()},
                /*signature*/       {"s", std::string{reinterpret_cast<const char *>(proof.sig.data()), proof.sig.size()}},
            }}
        };
        // clang-format on

        session::config::ProConfig loaded_pro = {};
        CHECK(loaded_pro.load(good_dict));
        CHECK(loaded_pro.rotating_privkey == pro_cpp.rotating_privkey);
        CHECK(loaded_pro.proof.version == pro_cpp.proof.version);
        CHECK(loaded_pro.proof.gen_index_hash == pro_cpp.proof.gen_index_hash);
        CHECK(loaded_pro.proof.rotating_pubkey == pro_cpp.proof.rotating_pubkey);
        CHECK(loaded_pro.proof.expiry_unix_ts == pro_cpp.proof.expiry_unix_ts);
        CHECK(loaded_pro.proof.sig == pro_cpp.proof.sig);
        CHECK(loaded_pro.proof.verify_signature(signing_pk));
    }

    // Try loading a proof with a bad signature in it from dict
    {
        std::array<uint8_t, 64> broken_sig = pro_cpp.proof.sig;
        broken_sig[0] = ~broken_sig[0];  // Break the sig
        const session::ProProof& proof = pro_cpp.proof;

        // clang-format off
        session::config::dict bad_dict = {
            {"r", std::string(reinterpret_cast<const char *>(rotating_sk.data()), crypto_sign_ed25519_SEEDBYTES)},
            {"p", session::config::dict{
                /*version*/         {"@", proof.version},
                /*gen_index_hash*/  {"g", std::string(reinterpret_cast<const char *>(proof.gen_index_hash.data()), proof.gen_index_hash.size())},
                /*rotating pubkey*/ {"r", std::string(reinterpret_cast<const char *>(proof.rotating_pubkey.data()), proof.rotating_pubkey.size())},
                /*expiry unix ts*/  {"e", proof.expiry_unix_ts.time_since_epoch().count()},
                /*signature*/       {"s", std::string{reinterpret_cast<const char *>(broken_sig.data()), broken_sig.size()}},
            }}
        };
        // clang-format on

        session::config::ProConfig loaded_pro = {};
        CHECK(loaded_pro.load(bad_dict));
        CHECK_FALSE(loaded_pro.proof.verify_signature(signing_pk));
    }
}
