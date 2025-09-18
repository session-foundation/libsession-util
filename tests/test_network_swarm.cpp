#include <catch2/catch_test_macros.hpp>
#include <session/network/key_types.hpp>
#include <session/network/service_node.hpp>
#include <session/network/swarm.hpp>
#include <tuple>

#include "utils.hpp"

using namespace session;
using namespace session::network;
using namespace session::network::swarm;

swarm_id_t get_swarm_id(
        std::string swarm_pubkey_hex,
        std::vector<std::pair<swarm_id_t, std::vector<service_node>>> swarms) {
    if (swarm_pubkey_hex.size() == 66)
        swarm_pubkey_hex = swarm_pubkey_hex.substr(2);

    auto pk = x25519_pubkey::from_hex(swarm_pubkey_hex);
    return get_swarm(pk, swarms).first;
}

TEST_CASE("Swarm", "[network][swarm][pubkey_to_swarm_space]") {
    x25519_pubkey pk;

    pk = x25519_pubkey::from_hex(
            "3506f4a71324b7dd114eddbf4e311f39dde243e1f2cb97c40db1961f70ebaae8");
    CHECK(pubkey_to_swarm_space(pk) == 17589930838143112648ULL);
    pk = x25519_pubkey::from_hex(
            "cf27da303a50ac8c4b2d43d27259505c9bcd73fc21cf2a57902c3d050730b604");
    CHECK(pubkey_to_swarm_space(pk) == 10370619079776428163ULL);
    pk = x25519_pubkey::from_hex(
            "d3511706b8b34f6e8411bf07bd22ba6b2435ca56846fbccf6eb1e166a6cd15cc");
    CHECK(pubkey_to_swarm_space(pk) == 2144983569669512198ULL);
    pk = x25519_pubkey::from_hex(
            "0f06693428fca9102a451e3f28d9cc743d8ea60a89ab6aa69eb119470c11cbd3");
    CHECK(pubkey_to_swarm_space(pk) == 9690840703409570833ULL);
    pk = x25519_pubkey::from_hex(
            "ffba630924aa1224bb930dde21c0d11bf004608f2812217f8ac812d6c7e3ad48");
    CHECK(pubkey_to_swarm_space(pk) == 4532060000165252872ULL);
    pk = x25519_pubkey::from_hex(
            "eeeeeeeeeeeeeeee777777777777777711111111111111118888888888888888");
    CHECK(pubkey_to_swarm_space(pk) == 0);
    pk = x25519_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(pubkey_to_swarm_space(pk) == 0);
    pk = x25519_pubkey::from_hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
    CHECK(pubkey_to_swarm_space(pk) == 1);
    pk = x25519_pubkey::from_hex(
            "ffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffff");
    CHECK(pubkey_to_swarm_space(pk) == 1ULL << 63);
    pk = x25519_pubkey::from_hex(
            "000000000000000000000000000000000000000000000000ffffffffffffffff");
    CHECK(pubkey_to_swarm_space(pk) == (uint64_t)-1);
    pk = x25519_pubkey::from_hex(
            "0000000000000000000000000000000000000000000000000123456789abcdef");
    CHECK(pubkey_to_swarm_space(pk) == 0x0123456789abcdefULL);
}

TEST_CASE("Swarm", "[network][swarm][get_swarm]") {
    std::vector<std::pair<swarm_id_t, std::vector<service_node>>> swarms = {
            {100, {}}, {200, {}}, {300, {}}, {399, {}}, {498, {}}, {596, {}}, {694, {}}};

    // Exact matches:
    // 0x64 = 100, 0xc8 = 200, 0x1f2 = 498
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000064", swarms) ==
          100);
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000000c8", swarms) ==
          200);
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000001f2", swarms) ==
          498);

    // Nearest
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000000", swarms) ==
          100);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000001", swarms) ==
          100);

    // Nearest, with wraparound
    // 0x8000... is closest to the top value
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000008000000000000000", swarms) ==
          694);

    // 0xa000... is closest (via wraparound) to the smallest
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000a000000000000000", swarms) ==
          100);

    // This is the invalid swarm id for swarms, but should still work for a client
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000ffffffffffffffff", swarms) ==
          100);
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000fffffffffffffffe", swarms) ==
          100);

    // Midpoint tests; we prefer the lower value when exactly in the middle between two swarms.
    // 0x96 = 150
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000095", swarms) ==
          100);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000096", swarms) ==
          100);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000097", swarms) ==
          200);

    // 0xfa = 250
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000000f9", swarms) ==
          200);
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000000fa", swarms) ==
          200);
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000000fb", swarms) ==
          300);

    // 0x15d = 349
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000000000000000015d", swarms) ==
          300);
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000000000000000015e", swarms) ==
          399);

    // 0x1c0 = 448
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000001c0", swarms) ==
          399);
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000001c1", swarms) ==
          498);

    // 0x223 = 547
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000222", swarms) ==
          498);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000223", swarms) ==
          498);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000224", swarms) ==
          596);

    // 0x285 = 645
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000285", swarms) ==
          596);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000286", swarms) ==
          694);

    // 0x800....d is the midpoint between 694 and 100 (the long way).  We always round "down" (which
    // in this case, means wrapping to the largest swarm).
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000800000000000018c", swarms) ==
          694);
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000800000000000018d", swarms) ==
          694);
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000800000000000018e", swarms) ==
          100);

    // With a swarm at -20 the midpoint is now 40 (=0x28).  When our value is the *low* value we
    // prefer the *last* swarm in the case of a tie (while consistent with the general case of
    // preferring the left edge, it means we're inconsistent with the other wraparound case, above.
    // *sigh*).
    swarms.push_back({(uint64_t)-20, {}});
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000027", swarms) ==
          swarms.back().first);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000028", swarms) ==
          swarms.back().first);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000029", swarms) ==
          swarms.front().first);

    // The code used to have a broken edge case if we have a swarm at zero and a client at max-u64
    // because of an overflow in how the distance is calculated (the first swarm will be calculated
    // as max-u64 away, rather than 1 away), and so the id always maps to the highest swarm (even
    // though 0xfff...fe maps to the lowest swarm; the first check here, then, would fail.
    swarms.insert(swarms.begin(), {0, {}});
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000ffffffffffffffff", swarms) ==
          0);
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000fffffffffffffffe", swarms) ==
          0);
}
