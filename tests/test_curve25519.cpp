#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/crypto/x25519.hpp>
#include <session/util.hpp>

#include "session/curve25519.h"
#include "utils.hpp"

using namespace session;
using namespace session::literals;

TEST_CASE("X25519 key pair generation", "[curve25519][keypair]") {
    auto [pk1, sk1] = x25519::keypair();
    auto [pk2, sk2] = x25519::keypair();

    CHECK(pk1.size() == 32);
    CHECK(sk1.size() == 32);
    CHECK(pk1 != pk2);
    CHECK(sk1 != sk2);
}

TEST_CASE("X25519 conversion", "[curve25519][to curve25519 pubkey]") {
    auto ed_pk1 = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hex_b;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hex_b;

    auto x_pk1 = ed25519::pk_to_x25519(ed_pk1);
    auto x_pk2 = ed25519::pk_to_x25519(ed_pk2);

    CHECK(to_hex(x_pk1) == "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(to_hex(x_pk2) == "aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
}

TEST_CASE("X25519 conversion", "[curve25519][to curve25519 seckey]") {
    auto ed_sk1 =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hex_b;
    auto ed_sk2 =
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876cd83ca3d13a"
            "d8a954d5011aa7861abe3a29ac25b70c4ed5234aff74d34ef5786"_hex_b;
    auto x_sk1 = ed25519::sk_to_x25519(ed_sk1);
    auto x_sk2 = ed25519::sk_to_x25519(ed_sk2);

    CHECK(to_hex(x_sk1) == "207e5d97e761300f96c10adc11efdd6d5c15188a9a7682ec05b30ca017e9b447");
    CHECK(to_hex(x_sk2) == "904943eff27142a8e5cd37c84e2437c9979a560b044bf9a65a8d644b325fe56a");
}
