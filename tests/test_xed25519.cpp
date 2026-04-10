#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>

#include "session/crypto/ed25519.hpp"
#include "session/util.hpp"
#include "session/xed25519.h"
#include "session/xed25519.hpp"

using namespace session;
using namespace session::literals;

// Full 64-byte libsodium-style Ed25519 keys (32-byte seed || 32-byte pubkey)
constexpr auto seed1 =
        "fecd9a6034bc9aba273925dee7062b123334587c3c6257341afae2d7fe85e122"
        "f4ef873908f6a5377ba3853f0e2fa326eed9e741edf9f7d0311a3ecc66a57b32"_hex_b;
constexpr auto seed2 =
        "8659efdcbe0949e0f81141e6d397e8be75f45d09262f209d5950e97989eb43c7"
        "3570b69a47dc094544c1c5089c40414bbda1ffdde8aab2617fe937ee74a5ee81"_hex_b;

// Ed25519 pubkeys (second half of the seed arrays)
constexpr auto pub1 = seed1.last<32>();
constexpr auto pub2 = seed2.last<32>();

// Expected X25519 pubkeys derived from the Ed25519 pubkeys
constexpr auto xpub1 = "fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
constexpr auto xpub2 = "05c9a9bf178fa644d44bebf628716dc7f2df3d0842e97881962c723699152073"_hex_b;

// The "absolute" (positive) version of pub2's Ed25519 pubkey
constexpr auto pub2_abs = "3570b69a47dc094544c1c5089c40414bbda1ffdde8aab2617fe937ee74a5ee01"_hex_b;

TEST_CASE("XEd25519 pubkey conversion", "[xed25519][pubkey]") {
    auto xpk1 = ed25519::pk_to_x25519(pub1);
    REQUIRE(oxenc::to_hex(xpk1) == oxenc::to_hex(xpub1));

    auto xpk2 = ed25519::pk_to_x25519(pub2);
    REQUIRE(oxenc::to_hex(xpk2) == oxenc::to_hex(xpub2));

    auto xed1 = xed25519::pubkey(xpub1);
    REQUIRE(oxenc::to_hex(xed1) == oxenc::to_hex(pub1));

    // This one fails because the original Ed pubkey is negative
    auto xed2 = xed25519::pubkey(xpub2);
    REQUIRE(oxenc::to_hex(xed2) != oxenc::to_hex(pub2));
    // After making the xed negative we should be okay:
    xed2[31] |= std::byte{0x80};
    REQUIRE(oxenc::to_hex(xed2) == oxenc::to_hex(pub2));
}

TEST_CASE("XEd25519 signing", "[xed25519][sign]") {
    auto xsk1 = ed25519::sk_to_x25519(ed25519::PrivKeySpan{seed1});
    auto xsk2 = ed25519::sk_to_x25519(seed2.first<32>());

    const auto msg = "hello world"_bytes;

    auto xed_sig1 = xed25519::sign(xsk1, msg);

    REQUIRE(ed25519::verify(xed_sig1, pub1, msg));

    auto xed_sig2 = xed25519::sign(xsk2, msg);

    // This one will fail, because Xed signing always uses the positive but our actual pub2 is the
    // negative:
    REQUIRE_FALSE(ed25519::verify(xed_sig2, pub2, msg));

    // Flip it, though, and it should work:
    REQUIRE(ed25519::verify(xed_sig2, pub2_abs, msg));
}

TEST_CASE("XEd25519 verification", "[xed25519][verify]") {
    auto xsk1 = ed25519::sk_to_x25519(ed25519::PrivKeySpan{seed1});
    auto xsk2 = ed25519::sk_to_x25519(seed2.first<32>());

    const auto msg = "hello world"_bytes;

    auto xed_sig1 = xed25519::sign(xsk1, msg);
    auto xed_sig2 = xed25519::sign(xsk2, msg);

    REQUIRE(xed25519::verify(xed_sig1, xpub1, msg));
    REQUIRE(xed25519::verify(xed_sig2, xpub2, msg));

    // Unlike regular Ed25519, XEd25519 uses randomness in the signature, so signing the same value
    // a second should give us a different signature:
    auto xed_sig1b = xed25519::sign(xsk1, msg);
    REQUIRE(oxenc::to_hex(xed_sig1b) != oxenc::to_hex(xed_sig1));
}

TEST_CASE("XEd25519 pubkey conversion (C wrapper)", "[xed25519][pubkey][c]") {
    auto xed1 = xed25519::pubkey(xpub1);
    REQUIRE(oxenc::to_hex(xed1) == oxenc::to_hex(pub1));

    // This one fails because the original Ed pubkey is negative
    auto xed2 = xed25519::pubkey(xpub2);
    REQUIRE(oxenc::to_hex(xed2) != oxenc::to_hex(pub2));
    // After making the xed negative we should be okay:
    xed2[31] |= std::byte{0x80};
    REQUIRE(oxenc::to_hex(xed2) == oxenc::to_hex(pub2));
}

TEST_CASE("XEd25519 signing (C wrapper)", "[xed25519][sign][c]") {
    auto xsk1 = ed25519::sk_to_x25519(ed25519::PrivKeySpan{seed1});
    auto xsk2 = ed25519::sk_to_x25519(seed2.first<32>());

    const auto msg = "hello world"_bytes;

    b64 xed_sig1, xed_sig2;
    REQUIRE(session_xed25519_sign(
            to_unsigned(xed_sig1.data()),
            to_unsigned(xsk1.data()),
            to_unsigned(msg.data()),
            msg.size()));
    REQUIRE(session_xed25519_sign(
            to_unsigned(xed_sig2.data()),
            to_unsigned(xsk2.data()),
            to_unsigned(msg.data()),
            msg.size()));

    REQUIRE(ed25519::verify(xed_sig1, pub1, msg));
    REQUIRE_FALSE(ed25519::verify(xed_sig2, pub2, msg));  // Failure expected (pub2 is negative)
    REQUIRE(ed25519::verify(xed_sig2, pub2_abs, msg));    // Flipped sign should work
}

TEST_CASE("XEd25519 std::byte overloads", "[xed25519][byte]") {
    auto xsk1 = ed25519::sk_to_x25519(ed25519::PrivKeySpan{seed1});

    const auto msg = "hello world"_bytes;

    // sign() byte overload should return a std::byte array.
    auto sig_b = xed25519::sign(std::span<const std::byte, 32>{xsk1}, msg);
    static_assert(std::same_as<decltype(sig_b), std::array<std::byte, 64>>);

    // The signature must verify via the ed25519 helper.
    REQUIRE(ed25519::verify(sig_b, pub1, msg));

    // verify() byte overload.
    REQUIRE(xed25519::verify(sig_b, xpub1, msg));

    // pubkey() byte overload should return a std::byte array.
    auto ed_pk_b = xed25519::pubkey(xpub1);
    static_assert(std::same_as<decltype(ed_pk_b), std::array<std::byte, 32>>);
    REQUIRE(oxenc::to_hex(ed_pk_b) == oxenc::to_hex(pub1));
}

TEST_CASE("XEd25519 verification (C wrapper)", "[xed25519][verify][c]") {
    auto xsk1 = ed25519::sk_to_x25519(ed25519::PrivKeySpan{seed1});
    auto xsk2 = ed25519::sk_to_x25519(seed2.first<32>());

    const auto msg = "hello world"_bytes;

    b64 xed_sig1, xed_sig2;
    REQUIRE(session_xed25519_sign(
            to_unsigned(xed_sig1.data()),
            to_unsigned(xsk1.data()),
            to_unsigned(msg.data()),
            msg.size()));
    REQUIRE(session_xed25519_sign(
            to_unsigned(xed_sig2.data()),
            to_unsigned(xsk2.data()),
            to_unsigned(msg.data()),
            msg.size()));

    REQUIRE(session_xed25519_verify(
            to_unsigned(xed_sig1.data()),
            to_unsigned(xpub1.data()),
            to_unsigned(msg.data()),
            msg.size()));
    REQUIRE(session_xed25519_verify(
            to_unsigned(xed_sig2.data()),
            to_unsigned(xpub2.data()),
            to_unsigned(msg.data()),
            msg.size()));
}
