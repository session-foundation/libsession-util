#include <mlkem_native.h>
#include <session/session_encrypt.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/blinding.hpp>
#include <session/session_encrypt.hpp>
#include <session/util.hpp>

#include "utils.hpp"

TEST_CASE("Session protocol encryption", "[session-protocol][encrypt]") {

    using namespace session;

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(ed_pk.data(), ed_sk.data(), seed.data());
    REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data()));
    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    auto sid = "05" + oxenc::to_hex(curve_pk.begin(), curve_pk.end());
    std::vector<unsigned char> sid_raw;
    oxenc::from_hex(sid.begin(), sid.end(), std::back_inserter(sid_raw));
    REQUIRE(sid == "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    REQUIRE(sid_raw ==
            "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"_hexbytes);

    const auto seed2 = "00112233445566778899aabbccddeeff00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk2, curve_pk2;
    std::array<unsigned char, 64> ed_sk2;
    crypto_sign_ed25519_seed_keypair(ed_pk2.data(), ed_sk2.data(), seed2.data());
    REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(curve_pk2.data(), ed_pk2.data()));
    REQUIRE(oxenc::to_hex(ed_pk2.begin(), ed_pk2.end()) ==
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876");
    REQUIRE(oxenc::to_hex(curve_pk2.begin(), curve_pk2.end()) ==
            "aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
    auto sid2 = "05" + oxenc::to_hex(curve_pk2.begin(), curve_pk2.end());
    REQUIRE(sid2 == "05aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
    std::vector<unsigned char> sid_raw2;
    oxenc::from_hex(sid2.begin(), sid2.end(), std::back_inserter(sid_raw2));
    REQUIRE(sid_raw2 ==
            "05aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74"_hexbytes);

    SECTION("full secret, prefixed sid") {
        auto enc = encrypt_for_recipient(to_span(ed_sk), sid_raw2, to_span("hello"));
        CHECK(to_string(enc) != "hello");

        CHECK_THROWS(decrypt_incoming(to_span(ed_sk), enc));

        auto [msg, sender] = decrypt_incoming(to_span(ed_sk2), enc);
        CHECK(to_hex(sender) == oxenc::to_hex(ed_pk.begin(), ed_pk.end()));
        CHECK(to_string(msg) == "hello");

        auto broken = enc;
        broken[2] ^= 0x02;
        CHECK_THROWS(decrypt_incoming(to_span(ed_sk2), broken));
    }
    SECTION("only seed, unprefixed sid") {
        constexpr auto lorem_ipsum =
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor "
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis "
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
                "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu "
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
                "culpa qui officia deserunt mollit anim id est laborum."sv;
        auto enc =
                encrypt_for_recipient(to_span(ed_sk).first<32>(), sid_raw2, to_span(lorem_ipsum));
        CHECK(std::search(
                      enc.begin(),
                      enc.end(),
                      to_unsigned("dolore magna"),
                      to_unsigned("dolore magna") + strlen("dolore magna")) == enc.end());

        CHECK_THROWS(decrypt_incoming(to_span(ed_sk), enc));

        auto [msg, sender] = decrypt_incoming(to_span(ed_sk2), enc);
        CHECK(to_hex(sender) == oxenc::to_hex(ed_pk.begin(), ed_pk.end()));
        CHECK(to_string(msg) == lorem_ipsum);

        auto broken = enc;
        broken[14] ^= 0x80;
        CHECK_THROWS(decrypt_incoming(to_span(ed_sk2), broken));
    }
}

TEST_CASE("Session protocol deterministic encryption", "[session-protocol][encrypt]") {

    using namespace session;

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(ed_pk.data(), ed_sk.data(), seed.data());
    REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data()));
    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    auto sid = "05" + oxenc::to_hex(curve_pk.begin(), curve_pk.end());
    std::vector<unsigned char> sid_raw;
    oxenc::from_hex(sid.begin(), sid.end(), std::back_inserter(sid_raw));
    REQUIRE(sid == "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    REQUIRE(sid_raw ==
            "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"_hexbytes);

    const auto seed2 = "00112233445566778899aabbccddeeff00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk2, curve_pk2;
    std::array<unsigned char, 64> ed_sk2;
    crypto_sign_ed25519_seed_keypair(ed_pk2.data(), ed_sk2.data(), seed2.data());
    REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(curve_pk2.data(), ed_pk2.data()));
    REQUIRE(oxenc::to_hex(ed_pk2.begin(), ed_pk2.end()) ==
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876");
    REQUIRE(oxenc::to_hex(curve_pk2.begin(), curve_pk2.end()) ==
            "aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
    auto sid2 = "05" + oxenc::to_hex(curve_pk2.begin(), curve_pk2.end());
    REQUIRE(sid2 == "05aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
    std::vector<unsigned char> sid_raw2;
    oxenc::from_hex(sid2.begin(), sid2.end(), std::back_inserter(sid_raw2));
    REQUIRE(sid_raw2 ==
            "05aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74"_hexbytes);

    auto enc1 = encrypt_for_recipient(to_span(ed_sk), sid_raw2, to_span("hello"));
    auto enc2 = encrypt_for_recipient(to_span(ed_sk), sid_raw2, to_span("hello"));
    REQUIRE(enc1 != enc2);

    auto enc_det = encrypt_for_recipient_deterministic(to_span(ed_sk), sid_raw2, to_span("hello"));
    CHECK(enc_det != enc1);
    CHECK(enc_det != enc2);
    CHECK(enc_det.size() == enc1.size());
    CHECK(to_hex(enc_det) ==
          "208f96785db92319bc7a14afecc01e17bde912d17bbb32834c03ea63b1862c2a1b730e0725ef75b2f1a276db"
          "584c59a0ed9b5497bcb9f4effa893b5cb8b04dbe7a6ab457ebf972f03b006dd4572980a725399616d40184b8"
          "6aa3b7b218bdc6dd7c1adccda8ef4897f0f458492240b39079c27a6c791067ab26a03067a7602b50f0434639"
          "906f93e548f909d5286edde365ebddc146");

    auto [msg, sender] = decrypt_incoming(to_span(ed_sk2), enc_det);
    CHECK(to_hex(sender) == oxenc::to_hex(ed_pk.begin(), ed_pk.end()));
    CHECK(to_string(msg) == "hello");
}

static std::array<unsigned char, 33> prefixed(unsigned char prefix, const session::uc32& pubkey) {
    std::array<unsigned char, 33> result;
    result[0] = prefix;
    std::memcpy(result.data() + 1, pubkey.data(), 32);
    return result;
}

TEST_CASE("Session blinding protocol encryption", "[session-blinding-protocol][encrypt]") {

    using namespace session;

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    constexpr auto server_pk =
            "1d7e7f92b1ed3643855c98ecac02fc7274033a3467653f047d6e433540c03f17"_hex_u;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(ed_pk.data(), ed_sk.data(), seed.data());
    REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data()));
    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    auto sid = "05" + oxenc::to_hex(curve_pk.begin(), curve_pk.end());
    std::vector<unsigned char> sid_raw;
    oxenc::from_hex(sid.begin(), sid.end(), std::back_inserter(sid_raw));
    REQUIRE(sid == "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    REQUIRE(sid_raw ==
            "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"_hexbytes);
    auto [blind15_pk, blind15_sk] = blind15_key_pair(to_span(ed_sk), server_pk);
    auto [blind25_pk, blind25_sk] = blind25_key_pair(to_span(ed_sk), server_pk);
    auto blind15_pk_prefixed = prefixed(0x15, blind15_pk);
    auto blind25_pk_prefixed = prefixed(0x25, blind25_pk);

    const auto seed2 = "00112233445566778899aabbccddeeff00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk2, curve_pk2;
    std::array<unsigned char, 64> ed_sk2;
    crypto_sign_ed25519_seed_keypair(ed_pk2.data(), ed_sk2.data(), seed2.data());
    REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(curve_pk2.data(), ed_pk2.data()));
    REQUIRE(oxenc::to_hex(ed_pk2.begin(), ed_pk2.end()) ==
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876");
    REQUIRE(oxenc::to_hex(curve_pk2.begin(), curve_pk2.end()) ==
            "aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
    auto sid2 = "05" + oxenc::to_hex(curve_pk2.begin(), curve_pk2.end());
    REQUIRE(sid2 == "05aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
    std::vector<unsigned char> sid_raw2;
    oxenc::from_hex(sid2.begin(), sid2.end(), std::back_inserter(sid_raw2));
    REQUIRE(sid_raw2 ==
            "05aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74"_hexbytes);
    auto [blind15_pk2, blind15_sk2] = blind15_key_pair(to_span(ed_sk2), server_pk);
    auto [blind25_pk2, blind25_sk2] = blind25_key_pair(to_span(ed_sk2), server_pk);
    auto blind15_pk2_prefixed = prefixed(0x15, blind15_pk2);
    auto blind25_pk2_prefixed = prefixed(0x25, blind25_pk2);

    SECTION("blind15, full secret, recipient decrypt") {
        auto enc = encrypt_for_blinded_recipient(
                to_span(ed_sk), server_pk, blind15_pk2_prefixed, to_span("hello"));
        CHECK(to_string(enc) != "hello");

        auto [msg, sender] = decrypt_from_blinded_recipient(
                to_span(ed_sk2), server_pk, blind15_pk_prefixed, blind15_pk2_prefixed, enc);
        CHECK(sender == sid);
        CHECK(to_string(msg) == "hello");

        auto broken = enc;
        broken[23] ^= 0x80;  // 1 + 5 + 16 = 22 is the start of the nonce
        CHECK_THROWS(decrypt_from_blinded_recipient(
                to_span(ed_sk2), server_pk, blind15_pk_prefixed, blind15_pk2_prefixed, broken));
    }
    SECTION("blind15, only seed, sender decrypt") {
        constexpr auto lorem_ipsum =
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor "
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis "
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
                "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu "
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
                "culpa qui officia deserunt mollit anim id est laborum."sv;
        auto enc = encrypt_for_blinded_recipient(
                to_span(ed_sk).first<32>(), server_pk, blind15_pk2_prefixed, to_span(lorem_ipsum));
        CHECK(std::search(
                      enc.begin(),
                      enc.end(),
                      to_unsigned("dolore magna"),
                      to_unsigned("dolore magna") + strlen("dolore magna")) == enc.end());

        auto [msg, sender] = decrypt_from_blinded_recipient(
                to_span(ed_sk).first<32>(),
                server_pk,
                blind15_pk_prefixed,
                blind15_pk2_prefixed,
                enc);
        CHECK(sender == sid);
        CHECK(to_string(msg) == lorem_ipsum);

        auto broken = enc;
        broken[463] ^= 0x80;  // 1 + 445 + 16 = 462 is the start of the nonce
        CHECK_THROWS(decrypt_from_blinded_recipient(
                to_span(ed_sk).first<32>(),
                server_pk,
                blind15_pk_prefixed,
                blind15_pk2_prefixed,
                broken));
    }
    SECTION("blind15, only seed, recipient decrypt") {
        constexpr auto lorem_ipsum =
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor "
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis "
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
                "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu "
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
                "culpa qui officia deserunt mollit anim id est laborum."sv;
        auto enc = encrypt_for_blinded_recipient(
                to_span(ed_sk).first<32>(), server_pk, blind15_pk2_prefixed, to_span(lorem_ipsum));
        CHECK(std::search(
                      enc.begin(),
                      enc.end(),
                      to_unsigned("dolore magna"),
                      to_unsigned("dolore magna") + strlen("dolore magna")) == enc.end());

        auto [msg, sender] = decrypt_from_blinded_recipient(
                to_span(ed_sk2).first<32>(),
                server_pk,
                blind15_pk_prefixed,
                blind15_pk2_prefixed,
                enc);
        CHECK(sender == sid);
        CHECK(to_string(msg) == lorem_ipsum);

        auto broken = enc;
        broken[463] ^= 0x80;  // 1 + 445 + 16 = 462 is the start of the nonce
        CHECK_THROWS(decrypt_from_blinded_recipient(
                to_span(ed_sk2).first<32>(),
                server_pk,
                blind15_pk_prefixed,
                blind15_pk2_prefixed,
                broken));
    }
    SECTION("blind25, full secret, sender decrypt") {
        auto enc = encrypt_for_blinded_recipient(
                to_span(ed_sk), server_pk, blind25_pk2_prefixed, to_span("hello"));
        CHECK(to_string(enc) != "hello");

        auto [msg, sender] = decrypt_from_blinded_recipient(
                to_span(ed_sk), server_pk, blind25_pk_prefixed, blind25_pk2_prefixed, enc);
        CHECK(sender == sid);
        CHECK(to_string(msg) == "hello");

        auto broken = enc;
        broken[23] ^= 0x80;  // 1 + 5 + 16 = 22 is the start of the nonce
        CHECK_THROWS(decrypt_from_blinded_recipient(
                to_span(ed_sk), server_pk, blind25_pk_prefixed, blind25_pk2_prefixed, broken));
    }
    SECTION("blind25, full secret, recipient decrypt") {
        auto enc = encrypt_for_blinded_recipient(
                to_span(ed_sk), server_pk, blind25_pk2_prefixed, to_span("hello"));
        CHECK(to_string(enc) != "hello");

        auto [msg, sender] = decrypt_from_blinded_recipient(
                to_span(ed_sk2), server_pk, blind25_pk_prefixed, blind25_pk2_prefixed, enc);
        CHECK(sender == sid);
        CHECK(to_string(msg) == "hello");

        auto broken = enc;
        broken[23] ^= 0x80;  // 1 + 5 + 16 = 22 is the start of the nonce
        CHECK_THROWS(decrypt_from_blinded_recipient(
                to_span(ed_sk2), server_pk, blind25_pk_prefixed, blind25_pk2_prefixed, broken));
    }
    SECTION("blind25, only seed, recipient decrypt") {
        constexpr auto lorem_ipsum =
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor "
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis "
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
                "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu "
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
                "culpa qui officia deserunt mollit anim id est laborum."sv;
        auto enc = encrypt_for_blinded_recipient(
                to_span(ed_sk).first<32>(), server_pk, blind25_pk2_prefixed, to_span(lorem_ipsum));
        CHECK(std::search(
                      enc.begin(),
                      enc.end(),
                      to_unsigned("dolore magna"),
                      to_unsigned("dolore magna") + strlen("dolore magna")) == enc.end());

        auto [msg, sender] = decrypt_from_blinded_recipient(
                to_span(ed_sk2).first<32>(),
                server_pk,
                blind25_pk_prefixed,
                blind25_pk2_prefixed,
                enc);
        CHECK(sender == sid);
        CHECK(to_string(msg) == lorem_ipsum);

        auto broken = enc;
        broken[463] ^= 0x80;  // 1 + 445 + 16 = 462 is the start of the nonce
        CHECK_THROWS(decrypt_from_blinded_recipient(
                to_span(ed_sk2).first<32>(),
                server_pk,
                blind25_pk_prefixed,
                blind25_pk2_prefixed,
                broken));
    }
}

TEST_CASE("Session ONS response decryption", "[session-ons][decrypt]") {
    using namespace session;

    std::string_view name = "test";
    auto ciphertext =
            "3575802dd9bfea72672a208840f37ca289ceade5d3ffacabe2d231f109d204329fc33e28c33"
            "1580d9a8c9b8a64cacfec97"_hexbytes;
    auto ciphertext_legacy =
            "dbd4bc89bd2c9e5322fd9f4cadcaa66a0c38f15d0c927a86cc36e895fe1f3c532a3958d972563f52ca858e94eec22dc360"_hexbytes;
    constexpr auto nonce = "00112233445566778899aabbccddeeff00ffeeddccbbaa99"_hex_u;

    CHECK(decrypt_ons_response(name, ciphertext, nonce) ==
          "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(decrypt_ons_response(name, ciphertext_legacy, std::nullopt) ==
          "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK_THROWS(decrypt_ons_response(name, to_span("invalid"), nonce));
}

TEST_CASE("Session ONS response decryption C API", "[session-ons][session_decrypt_ons_response]") {
    using namespace session;

    auto name = "test\0";
    auto ciphertext =
            "3575802dd9bfea72672a208840f37ca289ceade5d3ffacabe2d231f109d204329fc33e28c33"
            "1580d9a8c9b8a64cacfec97"_hexbytes;
    auto ciphertext_legacy =
            "dbd4bc89bd2c9e5322fd9f4cadcaa66a0c38f15d0c927a86cc36e895fe1f3c532a3958d972563f52ca858e94eec22dc360"_hexbytes;
    auto nonce = "00112233445566778899aabbccddeeff00ffeeddccbbaa99"_hexbytes;

    char ons1[67];
    CHECK(session_decrypt_ons_response(
            name, ciphertext.data(), ciphertext.size(), nonce.data(), ons1));
    CHECK(ons1 == "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"sv);

    char ons2[67];
    CHECK(session_decrypt_ons_response(
            name, ciphertext_legacy.data(), ciphertext_legacy.size(), nullptr, ons2));
    CHECK(ons2 == "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"sv);
}

TEST_CASE("Session push notification decryption", "[session-notification][decrypt]") {
    using namespace session;

    auto payload =
            "00112233445566778899aabbccddeeff00ffeeddccbbaa991bcba42892762dbeecbfb1a375f"
            "ab4aca5f0991e99eb0344ceeafa"_hexbytes;
    auto payload_padded =
            "00112233445566778899aabbccddeeff00ffeeddccbbaa991bcba42892762dbeecbfb1a375f"
            "ab4aca5f0991e99eb0344ceeafa"_hexbytes;
    constexpr auto enc_key =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hex_u;

    CHECK(decrypt_push_notification(payload, enc_key) == to_vector("TestMessage"));
    CHECK(decrypt_push_notification(payload_padded, enc_key) == to_vector("TestMessage"));
    CHECK_THROWS(decrypt_push_notification(to_span("invalid"), enc_key));
}

TEST_CASE("xchacha20", "[session][xchacha20]") {
    using namespace session;

    auto payload =
            "da74ac6e96afda1c5a07d5bde1b8b1e1c05be73cb3c84112f31f00369d67154d00ff029090b069b48c3cf603d838d4ef623d54"_hexbytes;
    constexpr auto enc_key =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hex_u;

    CHECK(decrypt_xchacha20(payload, enc_key) == to_vector("TestMessage"));
    CHECK_THROWS(decrypt_xchacha20(to_span("invalid"), enc_key));

    auto ciphertext = encrypt_xchacha20(to_span("TestMessage"), enc_key);
    CHECK(decrypt_xchacha20(ciphertext, enc_key) == to_vector("TestMessage"));
}

TEST_CASE("v2 PFS+PQ message encryption", "[session-protocol][encrypt][v2]") {
    using namespace session;

    // Sender: existing well-known test keypair 1
    const auto seed1 = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> sender_ed_pk;
    std::array<unsigned char, 64> sender_ed_sk;
    crypto_sign_ed25519_seed_keypair(sender_ed_pk.data(), sender_ed_sk.data(), seed1.data());

    // Recipient: long-term session identity from test keypair 2
    const auto seed2 = "00112233445566778899aabbccddeeff00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> recip_ed_pk, recip_curve_pk;
    std::array<unsigned char, 64> recip_ed_sk;
    crypto_sign_ed25519_seed_keypair(recip_ed_pk.data(), recip_ed_sk.data(), seed2.data());
    REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(recip_curve_pk.data(), recip_ed_pk.data()));

    std::array<unsigned char, 32> recip_x25519_sec;
    REQUIRE(0 == crypto_sign_ed25519_sk_to_curve25519(recip_x25519_sec.data(), recip_ed_sk.data()));

    std::array<unsigned char, 33> recip_session_id;
    recip_session_id[0] = 0x05;
    std::copy(recip_curve_pk.begin(), recip_curve_pk.end(), recip_session_id.begin() + 1);

    // Recipient PFS X25519 account key (deterministic)
    const auto pfs_x25519_seed =
            "aabbccddeeff0011223344556677889900112233445566778899aabbccddeeff"_hexbytes;
    std::array<unsigned char, 32> pfs_x25519_sec, pfs_x25519_pub;
    std::copy(pfs_x25519_seed.begin(), pfs_x25519_seed.end(), pfs_x25519_sec.begin());
    crypto_scalarmult_curve25519_base(pfs_x25519_pub.data(), pfs_x25519_sec.data());

    // Recipient PFS ML-KEM-768 account key (deterministic, needs 64-byte seed)
    const auto pfs_mlkem_seed =
            "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef"
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"_hexbytes;
    std::array<unsigned char, MLKEM768_PUBLICKEYBYTES> pfs_mlkem_pub;
    std::array<unsigned char, MLKEM768_SECRETKEYBYTES> pfs_mlkem_sec;
    REQUIRE(0 == sr_mlkem768_keypair_derand(
                         pfs_mlkem_pub.data(), pfs_mlkem_sec.data(), pfs_mlkem_seed.data()));

    // Encrypt a message from sender to recipient
    auto ct = encrypt_for_recipient_v2(
            to_span(sender_ed_sk),
            recip_session_id,
            pfs_x25519_pub,
            pfs_mlkem_pub,
            to_span("hello world"),
            std::nullopt);

    // Ciphertext is padded to a multiple of 256 bytes
    CHECK(ct.size() % 256 == 0);

    // decrypt_incoming_v2_prefix recovers the 2-byte ML-KEM pubkey prefix using the
    // recipient's long-term X25519 keys (cheap; no PFS keys needed at this stage)
    auto prefix = decrypt_incoming_v2_prefix(recip_x25519_sec, recip_curve_pk, ct);
    CHECK(prefix[0] == pfs_mlkem_pub[0]);
    CHECK(prefix[1] == pfs_mlkem_pub[1]);

    // Decrypt with the correct keys succeeds
    auto result = decrypt_incoming_v2(
            recip_session_id, pfs_x25519_sec, pfs_x25519_pub, pfs_mlkem_sec, ct);
    CHECK(result.content == to_vector("hello world"));
    CHECK(result.sender_session_id[0] == 0x05);
    CHECK(!result.pro_signature);

    // The recovered sender session ID matches the sender's X25519 pubkey
    std::array<unsigned char, 32> sender_curve_pk;
    REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(sender_curve_pk.data(), sender_ed_pk.data()));
    CHECK(std::equal(
            result.sender_session_id.begin() + 1,
            result.sender_session_id.end(),
            sender_curve_pk.begin()));

    // Wrong X25519 key throws DecryptV2Error (wrong-key failure, not a format error)
    auto wrong_x25519_sec = pfs_x25519_sec;
    wrong_x25519_sec[0] ^= 0xff;
    std::array<unsigned char, 32> wrong_x25519_pub;
    crypto_scalarmult_curve25519_base(wrong_x25519_pub.data(), wrong_x25519_sec.data());
    CHECK_THROWS_AS(
            decrypt_incoming_v2(
                    recip_session_id, wrong_x25519_sec, wrong_x25519_pub, pfs_mlkem_sec, ct),
            DecryptV2Error);

    // Truncated ciphertext throws before key matching (unrecoverable format error)
    auto truncated = std::vector<unsigned char>(ct.begin(), ct.begin() + 100);
    CHECK_THROWS_AS(
            decrypt_incoming_v2_prefix(recip_x25519_sec, recip_curve_pk, truncated),
            std::runtime_error);

    // Encrypting and decrypting with a pro private key
    uc32 pro_pk;
    cleared_uc64 pro_sk;
    crypto_sign_ed25519_keypair(pro_pk.data(), pro_sk.data());
    auto ct_pro = encrypt_for_recipient_v2(
            to_span(sender_ed_sk),
            recip_session_id,
            pfs_x25519_pub,
            pfs_mlkem_pub,
            to_span("hello world"),
            pro_sk);
    auto result_pro = decrypt_incoming_v2(
            recip_session_id, pfs_x25519_sec, pfs_x25519_pub, pfs_mlkem_sec, ct_pro);
    REQUIRE(result_pro.pro_signature.has_value());
    // The signature should be 64 bytes and verifiable with the pro public key.
    CHECK(result_pro.pro_signature->size() == 64);
}
