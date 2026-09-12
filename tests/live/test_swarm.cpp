#include <catch2/catch_test_macros.hpp>

#include "../utils.hpp"
#include "live_utils.hpp"

using namespace session;
using namespace std::literals;

// Default timeout for live network operations.
static constexpr auto LIVE_TIMEOUT = 30s;

TEST_CASE("Live: network bootstraps snode pool from testnet", "[live][swarm]") {
    auto core = make_live_core();
    auto& net = *core->network();

    std::vector<network::service_node> result;
    callback_waiter waiter{
            [&](std::vector<network::service_node> nodes) { result = std::move(nodes); }};
    net.get_random_nodes(5, waiter);
    REQUIRE(waiter.wait(LIVE_TIMEOUT));
    CHECK(result.size() >= 1);
}

TEST_CASE("Live: network resolves swarm for a locally-generated session id", "[live][swarm]") {
    auto core = make_live_core();
    auto& net = *core->network();

    std::vector<network::service_node> swarm_result;
    callback_waiter waiter{[&](network::swarm_id_t, std::vector<network::service_node> swarm) {
        swarm_result = std::move(swarm);
    }};
    net.get_swarm(core->globals.pubkey_x25519(), false, waiter);
    REQUIRE(waiter.wait(LIVE_TIMEOUT));
    CHECK(swarm_result.size() >= 1);
}
