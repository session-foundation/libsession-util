#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>

#include "session/hash.h"
#include "session/hash.hpp"
#include "session/util.hpp"
#include "utils.hpp"

using namespace session::literals;

TEST_CASE("Hash generation", "[hash][hash]") {
    auto hash1 = session::hash::hash(32, session::to_span("TestMessage"), std::nullopt);
    auto hash2 = session::hash::hash(32, session::to_span("TestMessage"), std::nullopt);
    auto hash3 =
            session::hash::hash(32, session::to_span("TestMessage"), session::to_span("TestKey"));
    auto hash4 =
            session::hash::hash(32, session::to_span("TestMessage"), session::to_span("TestKey"));
    auto hash5 = session::hash::hash(64, session::to_span("TestMessage"), std::nullopt);
    auto hash6 =
            session::hash::hash(64, session::to_span("TestMessage"), session::to_span("TestKey"));
    CHECK_THROWS(session::hash::hash(10, session::to_span("TestMessage"), std::nullopt));
    CHECK_THROWS(session::hash::hash(100, session::to_span("TestMessage"), std::nullopt));
    CHECK_THROWS(session::hash::hash(
            32,
            session::to_span("TestMessage"),
            session::to_span("KeyThatIsTooLongKeyThatIsTooLongKeyThatIsTooLongKeyThatIsTooLongKeyTh"
                             "atIsTooLon"
                             "g")));

    CHECK(hash1.size() == 32);
    CHECK(hash2.size() == 32);
    CHECK(hash3.size() == 32);
    CHECK(hash4.size() == 32);
    CHECK(hash5.size() == 64);
    CHECK(hash6.size() == 64);
    CHECK(hash1 == hash2);
    CHECK(hash1 != hash3);
    CHECK(hash3 == hash4);
    CHECK(hash1 != hash5);
    CHECK(hash3 != hash6);
    CHECK(to_hex(hash1) == "2a48a12262e4548afb97fe2b04a912a02297d451169ee7ef2d01a28ea20286ab");
    CHECK(to_hex(hash2) == "2a48a12262e4548afb97fe2b04a912a02297d451169ee7ef2d01a28ea20286ab");
    CHECK(to_hex(hash3) == "3d643e479b626bb2907476e32ccf7bdbd1ac3efa0da6e2c335255c48dcc216b6");
    CHECK(to_hex(hash4) == "3d643e479b626bb2907476e32ccf7bdbd1ac3efa0da6e2c335255c48dcc216b6");

    auto expected_hash5 =
            "9d9085ac026fe3542abbeb2ea2ec05f5c37aecd7695f6cc41e9ccf39014196a39c02db69c44"
            "16d5c45acc2e9469b7f274992b2858f3bb2746becb48c8b56ce4b";
    auto expected_hash6 =
            "6a2faad89cf9010a4270cba07cc96cfb36688106e080b15fef66bb03c68e877874c9059edf5"
            "3d03c1330b2655efdad6e4aa259118b6ea88698ea038efb9d52ce";
    CHECK(to_hex(hash5) == expected_hash5);
    CHECK(to_hex(hash6) == expected_hash6);
}

TEST_CASE("SHA3-256 and SHAKE-256 known-answer tests", "[hash][sha3_256][shake256]") {
    // This test case serves two purposes:
    // 1. Verify SHA3-256 against NIST FIPS 202 known-answer test vectors.
    // 2. Verify SHAKE-256 against NIST FIPS 202 known-answer test vectors.
    // 3. Confirm that SHA3-256 and SHAKE-256 produce different output on identical input,
    //    verifying that the domain suffix byte (0x06 vs 0x1F) is actually applied.
    //
    // SHA3-256 KATs:
    // https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/sha3/sha-3bittestvectors.zip
    // SHAKE-256 KATs: NIST FIPS 202, Appendix A / CAVS test data

    using session::hash::sha3_256;
    using session::hash::shake256;

    std::array<unsigned char, 32> sha3_out, shake_out;

    // --- SHA3-256 NIST vectors ---

    // Empty input
    sha3_256(sha3_out, ""_uc);
    CHECK(oxenc::to_hex(sha3_out) ==
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

    // "abc" (24 bits)
    sha3_256(sha3_out, "abc"_uc);
    CHECK(oxenc::to_hex(sha3_out) ==
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    // 448-bit message
    sha3_256(sha3_out, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"_uc);
    CHECK(oxenc::to_hex(sha3_out) ==
          "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");

    // 896-bit message
    sha3_256(
            sha3_out,
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklm"
            "nopqklmnopqrlmnopqrsmnopqrstnopqrstu"_uc);
    CHECK(oxenc::to_hex(sha3_out) ==
          "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");

    // --- SHAKE-256 NIST vectors (32-byte output) ---

    // Empty input; first 32 bytes from FIPS 202 Appendix B.2 sample output
    shake256(""_uc)(shake_out);
    CHECK(oxenc::to_hex(shake_out) ==
          "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");

    // "abc" (24 bits)
    shake256("abc"_uc)(shake_out);
    CHECK(oxenc::to_hex(shake_out) ==
          "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");

    // --- Cross-check: same input must produce different output ---
    sha3_256(sha3_out, "abc"_uc);
    shake256("abc"_uc)(shake_out);
    CHECK(sha3_out != shake_out);
}
