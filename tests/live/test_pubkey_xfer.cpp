#include <catch2/catch_test_macros.hpp>

#include "../utils.hpp"
#include "live_utils.hpp"

using namespace session;
using namespace std::literals;

// Default timeout for live network operations.
static constexpr auto LIVE_TIMEOUT = 30s;

TEST_CASE("Live: PFS key prefetch returns NAK for account with no published keys", "[live][pfs]") {
    // Core A is a fresh account that has never published its AccountPubkeys to the swarm.
    // Core B fetches keys for Core A's session id and should receive a NAK (empty namespace).
    auto core_a = make_live_core();
    auto core_b = make_live_core();

    b33 sid_a;
    std::ranges::copy(core_a->globals.session_id(), sid_a.begin());

    core_b->prefetch_pfs_keys(sid_a);

    auto entry = wait_for(
            [&] { return session::TestHelper::pfs_cache_entry(*core_b, sid_a); }, LIVE_TIMEOUT);
    REQUIRE(entry.has_value());
    // NAK: fetch completed but no keys were present.
    CHECK_FALSE(entry->fetched_at.has_value());
    CHECK(entry->nak_at.has_value());
}

TEST_CASE("Live: PFS key prefetch retrieves keys after store to swarm", "[live][pfs]") {
    // Core A stores its AccountPubkeys to the swarm; Core B then fetches them.
    auto core_a = make_live_core();
    auto core_b = make_live_core();

    // Store Core A's account pubkeys to its swarm.
    REQUIRE(store_account_pubkeys(*core_a, LIVE_TIMEOUT));

    // Now fetch from Core B's perspective.
    b33 sid_a;
    std::ranges::copy(core_a->globals.session_id(), sid_a.begin());

    core_b->prefetch_pfs_keys(sid_a);

    auto entry = wait_for(
            [&] { return session::TestHelper::pfs_cache_entry(*core_b, sid_a); }, LIVE_TIMEOUT);
    REQUIRE(entry.has_value());
    // Successful fetch: keys present, no NAK.
    REQUIRE(entry->fetched_at.has_value());
    CHECK_FALSE(entry->nak_at.has_value());

    // The fetched pubkeys must match what Core A has as its active account keys.
    auto [expected_x25519, expected_mlkem768] =
            session::TestHelper::active_account_pubkeys(*core_a);
    REQUIRE(entry->pubkey_x25519.has_value());
    REQUIRE(entry->pubkey_mlkem768.has_value());
    CHECK(*entry->pubkey_x25519 == expected_x25519);
    CHECK(*entry->pubkey_mlkem768 == expected_mlkem768);
}
