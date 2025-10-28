#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <session/util.hpp>

#include "session/ed25519.hpp"

TEST_CASE("Ed25519 key pair generation", "[ed25519][keypair]") {
    // Generate two random key pairs and make sure they don't match
    auto [pk1, sk1] = session::ed25519::ed25519_key_pair();
    auto [pk2, sk2] = session::ed25519::ed25519_key_pair();

    CHECK(pk1.size() == 32);
    CHECK(sk1.size() == 64);
    CHECK(pk1 != pk2);
    CHECK(sk1 != sk2);
}

TEST_CASE("Ed25519 key pair generation seed", "[ed25519][keypair]") {
    using namespace session;

    constexpr auto ed_seed1 =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hex_u;
    constexpr auto ed_seed2 =
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hex_u;
    constexpr auto ed_seed_invalid = "010203040506070809"_hex_u;

    auto [pk1, sk1] = session::ed25519::ed25519_key_pair(ed_seed1);
    auto [pk2, sk2] = session::ed25519::ed25519_key_pair(ed_seed2);
    CHECK_THROWS(session::ed25519::ed25519_key_pair(ed_seed_invalid));

    CHECK(pk1.size() == 32);
    CHECK(sk1.size() == 64);
    CHECK(pk1 != pk2);
    CHECK(sk1 != sk2);
    CHECK(oxenc::to_hex(pk1) == "8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f");
    CHECK(oxenc::to_hex(pk2) == "cd83ca3d13ad8a954d5011aa7861abe3a29ac25b70c4ed5234aff74d34ef5786");

    auto kp_sk1 =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f";
    auto kp_sk2 =
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876cd83ca3d13a"
            "d8a954d5011aa7861abe3a29ac25b70c4ed5234aff74d34ef5786";
    CHECK(oxenc::to_hex(sk1) == kp_sk1);
    CHECK(oxenc::to_hex(sk2) == kp_sk2);
}

TEST_CASE("Ed25519 seed for private key", "[ed25519][seed]") {
    using namespace session;

    constexpr auto ed_sk1 =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hex_u;
    constexpr auto ed_sk2 =
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hex_u;
    constexpr auto ed_sk_invalid = "010203040506070809"_hex_u;

    auto seed1 = session::ed25519::seed_for_ed_privkey(ed_sk1);
    auto seed2 = session::ed25519::seed_for_ed_privkey(ed_sk2);
    CHECK_THROWS(session::ed25519::seed_for_ed_privkey(ed_sk_invalid));

    CHECK(oxenc::to_hex(seed1) ==
          "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    CHECK(oxenc::to_hex(seed2) ==
          "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876");
}

TEST_CASE("Ed25519 pro key pair generation seed", "[ed25519][keypair]") {
    using namespace session;

    // Test vectors generated from Python
    //
    // clang-format off
    //
    //   import nacl.bindings
    //   import hashlib
    //   import os
    //
    //   seed0                = os.urandom(32)
    //   seed1                = hashlib.blake2b(seed0, key=b'SessionProRandom', digest_size=32).digest()
    //   (pkey, skey)         = nacl.bindings.crypto_sign_seed_keypair(seed=seed0)
    //   (pro_pkey, pro_skey) = nacl.bindings.crypto_sign_seed_keypair(seed=seed1)
    //
    //   print(f'Seed0:   {seed0.hex()}')
    //   print(f'Pro:     {bytes(pro_skey)[:32].hex()} / {bytes(pro_pkey).hex()}')
    //
    // Output
    //
    //   Seed0:   e5481635020d6f7b327e94e6d63e33a431fccabc4d2775845c43a8486a9f2884
    //   Pro:     a4ec87e2346b25ee6394211cb682640a09dd8d297016fe241fe5b06fefef416c / b6d20c075eddd2edb69d4d7da9b7e580f187ce0537585da2b5e454b77980d0c8
    //
    //   Seed0:   743d646706b6b04b97b752036dd6cf5f2adc4b339fcfdfb4b496f0764bb93a84
    //   Pro:     7da256ba427cf5419cefea81f8ebb3395c261e4dfc2c91ee4d3ce9def67aa21c / 539d0a3be9658ebb6ba3ce97b25d4f6b716f7ef6d6ae6343bd0733519f5a51e8
    //
    // clang-format on

    constexpr auto seed1 = "e5481635020d6f7b327e94e6d63e33a431fccabc4d2775845c43a8486a9f2884"_hex_u;
    constexpr auto seed2 = "743d646706b6b04b97b752036dd6cf5f2adc4b339fcfdfb4b496f0764bb93a84"_hex_u;
    constexpr auto seed_invalid = "010203040506070809"_hex_u;

    auto sk1 = session::ed25519::ed25519_pro_privkey_for_ed25519_seed(seed1);
    auto sk2 = session::ed25519::ed25519_pro_privkey_for_ed25519_seed(seed2);
    CHECK_THROWS(session::ed25519::ed25519_pro_privkey_for_ed25519_seed(seed_invalid));

    CHECK(sk1.size() == 64);
    CHECK(sk1 != sk2);

    auto kp_sk1 =
            "a4ec87e2346b25ee6394211cb682640a09dd8d297016fe241fe5b06fefef416c"
            "b6d20c075eddd2edb69d4d7da9b7e580f187ce0537585da2b5e454b77980d0c8";
    auto kp_sk2 =
            "7da256ba427cf5419cefea81f8ebb3395c261e4dfc2c91ee4d3ce9def67aa21c"
            "539d0a3be9658ebb6ba3ce97b25d4f6b716f7ef6d6ae6343bd0733519f5a51e8";

    CHECK(oxenc::to_hex(sk1) == kp_sk1);
    CHECK(oxenc::to_hex(sk2) == kp_sk2);
}

TEST_CASE("Ed25519", "[ed25519][signature]") {
    using namespace session;

    constexpr auto ed_seed =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hex_u;
    constexpr auto ed_pk = "8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hex_u;
    constexpr auto ed_invalid = "010203040506070809"_hex_u;

    auto sig1 = session::ed25519::sign(ed_seed, to_span("hello"));
    CHECK_THROWS(session::ed25519::sign(ed_invalid, to_span("hello")));

    auto expected_sig_hex =
            "e03b6e87a53d83f202f2501e9b52193dbe4a64c6503f88244948dee53271"
            "85011574589aa7b59bc9757f9b9c31b7be9c9212b92ac7c81e029ee21c338ee12405";
    CHECK(oxenc::to_hex(sig1) == expected_sig_hex);

    CHECK(session::ed25519::verify(sig1, ed_pk, to_span("hello")));
    CHECK_THROWS(session::ed25519::verify(ed_invalid, ed_pk, to_span("hello")));
    CHECK_THROWS(session::ed25519::verify(ed_pk, ed_invalid, to_span("hello")));
}
