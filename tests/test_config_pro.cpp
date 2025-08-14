#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/config/pro.hpp>

using namespace oxenc::literals;

TEST_CASE("Pro", "[config][pro]") {
    // Setup keys
    std::array<unsigned char, crypto_sign_ed25519_PUBLICKEYBYTES> rotating_pk, signing_pk;
    session::cleared_uc64 rotating_sk, signing_sk;
    {
        crypto_sign_ed25519_keypair(rotating_pk.data(), rotating_sk.data());
        crypto_sign_ed25519_keypair(signing_pk.data(), signing_sk.data());
    }

    // Setup the Pro data structure
    session::config::ProConfig pro = {};
    {
        pro.rotating_privkey = rotating_sk;
        pro.proof.version = 0;
        pro.proof.rotating_pubkey = rotating_pk;
        pro.proof.expiry_unix_ts = std::chrono::sys_seconds(1s);

        constexpr auto gen_index_hash =
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_u;
        static_assert(pro.proof.gen_index_hash.max_size() == gen_index_hash.size());
        std::memcpy(pro.proof.gen_index_hash.data(), gen_index_hash.data(), gen_index_hash.size());
    }

    // Do the signing
    {
        static_assert(crypto_sign_ed25519_BYTES == pro.proof.sig.max_size());
        std::array<uint8_t, 32> hash_to_sign = pro.proof.hash();
        int sig_result = crypto_sign_ed25519_detached(
                pro.proof.sig.data(),
                nullptr,
                hash_to_sign.data(),
                hash_to_sign.size(),
                signing_sk.data());
        CHECK(sig_result == 0);
    }

    // Verify the proof
    {
        CHECK_FALSE(pro.verify(rotating_pk));
        CHECK(pro.verify(signing_pk));
    }

    // Try loading the proof from dict
    session::config::dict good_dict;
    {
        // clang-format off
        const session::config::ProProof& proof = pro.proof;
        good_dict = {
            {"r", std::string(reinterpret_cast<const char *>(rotating_sk.data()), rotating_sk.size())},
            {"p", session::config::dict{
                /*version*/         {"@", 0},
                /*gen_index_hash*/  {"g", std::string(reinterpret_cast<const char *>(proof.gen_index_hash.data()), proof.gen_index_hash.size())},
                /*rotating pubkey*/ {"r", std::string(reinterpret_cast<const char *>(proof.rotating_pubkey.data()), proof.rotating_pubkey.size())},
                /*expiry unix ts*/  {"e", proof.expiry_unix_ts.time_since_epoch().count()},
                /*signature*/       {"s", std::string{reinterpret_cast<const char *>(proof.sig.data()), proof.sig.size()}},
            }}
        };
        // clang-format on

        session::config::ProConfig loaded_pro = {};
        CHECK(loaded_pro.load(good_dict));
        CHECK(loaded_pro.rotating_privkey == pro.rotating_privkey);
        CHECK(loaded_pro.proof.version == pro.proof.version);
        CHECK(loaded_pro.proof.gen_index_hash == pro.proof.gen_index_hash);
        CHECK(loaded_pro.proof.rotating_pubkey == pro.proof.rotating_pubkey);
        CHECK(loaded_pro.proof.expiry_unix_ts == pro.proof.expiry_unix_ts);
        CHECK(loaded_pro.proof.sig == pro.proof.sig);
        CHECK(loaded_pro.verify(signing_pk));
    }

    // Try loading a proof with a bad signature in it from dict
    {
        session::config::dict bad_dict = good_dict;
        std::array<uint8_t, 64> broken_sig = pro.proof.sig;
        broken_sig[0] = ~broken_sig[0];  // Break the sig

        // clang-format off
        const session::config::ProProof& proof = pro.proof;
        bad_dict = {
            {"r", std::string(reinterpret_cast<const char *>(rotating_sk.data()), rotating_sk.size())},
            {"p", session::config::dict{
                /*version*/         {"@", 0},
                /*gen_index_hash*/  {"g", std::string(reinterpret_cast<const char *>(proof.gen_index_hash.data()), proof.gen_index_hash.size())},
                /*rotating pubkey*/ {"r", std::string(reinterpret_cast<const char *>(proof.rotating_pubkey.data()), proof.rotating_pubkey.size())},
                /*expiry unix ts*/  {"e", proof.expiry_unix_ts.time_since_epoch().count()},
                /*signature*/       {"s", std::string{reinterpret_cast<const char *>(broken_sig.data()), broken_sig.size()}},
            }}
        };
        // clang-format on

        session::config::ProConfig loaded_pro = {};
        CHECK(loaded_pro.load(bad_dict));
        CHECK_FALSE(loaded_pro.verify(signing_pk));
    }
}
