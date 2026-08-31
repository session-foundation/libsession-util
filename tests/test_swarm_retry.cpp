#include <catch2/catch_test_macros.hpp>
#include <future>
#include <session/network/session_network.hpp>
#include <thread>

#include "test_helper.hpp"

using namespace session;
using namespace session::network;
using namespace std::literals;

namespace {

/// A swarm member.  Only the pubkey distinguishes them here; the addresses are never dialled,
/// because FakeRouter answers without going anywhere.
std::string key_hex(uint8_t n) {
    return fmt::format("{:02x}{}", n, std::string(62, '0'));
}

service_node node_at(uint8_t n) {
    return service_node{
            ed25519_pubkey::from_hex(key_hex(n)),
            oxen::quic::ipv4{127, 0, 0, 1},
            static_cast<uint16_t>(1000 + n),
            static_cast<uint16_t>(2000 + n),
            {2, 8, 0},
            0,
            0};
}

/// A Network with its router replaced and one swarm primed, which is the least a test needs to
/// exercise anything Network does above routing.
struct ScriptedNetwork {
    std::shared_ptr<Network> net;
    std::shared_ptr<FakeRouter> router = std::make_shared<FakeRouter>();
    x25519_pubkey swarm_pubkey;
    std::vector<service_node> swarm;

    explicit ScriptedNetwork(size_t members) {
        net = std::make_shared<Network>(network::config::Config{});
        swarm_pubkey = x25519_pubkey::from_hex(key_hex(0xAA));

        for (size_t i = 0; i < members; i++)
            swarm.push_back(node_at(static_cast<uint8_t>(i + 1)));

        TestHelper::set_router(*net, router);
        TestHelper::seed_swarm(TestHelper::snode_pool(*net), swarm_pubkey, swarm);
    }

    /// A request addressed to the swarm, starting at whichever member the caller would have picked.
    Request to(const service_node& first, std::optional<std::chrono::milliseconds> overall = 60s) {
        Request req{
                first,
                "store",
                std::vector<std::byte>{},
                RequestCategory::standard_small,
                10s};
        req.swarm_pubkey = swarm_pubkey;
        req.overall_timeout = overall;
        return req;
    }

    /// The answer is delivered from the loop, not from send_request, so this waits for it.  The
    /// promise is shared rather than captured by reference: if the callback never comes, a
    /// reference to a local here would dangle rather than merely time out.
    std::pair<bool, int16_t> send(Request req) {
        auto done = std::make_shared<std::promise<std::pair<bool, int16_t>>>();
        auto waiter = done->get_future();
        net->send_request(std::move(req), [done](bool ok, bool, int16_t status, auto, auto) {
            done->set_value({ok, status});
        });
        REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
        return waiter.get();
    }
};

}  // namespace

/// Whether every entry is distinct -- what "once per node" means, given get_swarm hands members
/// back in a shuffled order rather than a fixed one.
bool all_distinct(const std::vector<ed25519_pubkey>& tried) {
    auto sorted = tried;
    std::ranges::sort(sorted, [](const auto& a, const auto& b) { return a.hex() < b.hex(); });
    return std::ranges::adjacent_find(sorted) == sorted.end();
}

TEST_CASE("Network: an unreachable node moves the request to the next swarm member", "[network]") {
    ScriptedNetwork n{4};

    // Only one member participates in session routing; the rest have no relay contact.
    n.router->replies[n.swarm[2].remote_pubkey] = {};

    auto [ok, status] = n.send(n.to(n.swarm[0]));
    CHECK(ok);
    CHECK(status == 200);

    // It reached the one that works, having spent no member twice on the way.  Which members it
    // tried first is not asserted: get_swarm shuffles, so the order is deliberately not fixed.
    REQUIRE(n.router->tried.size() >= 2);
    CHECK(n.router->tried.size() <= n.swarm.size());
    CHECK(n.router->tried.back() == n.swarm[2].remote_pubkey);
    CHECK(all_distinct(n.router->tried));
}

TEST_CASE("Network: running out of swarm members reports the original failure", "[network]") {
    ScriptedNetwork n{3};
    // Nobody answers.

    auto [ok, status] = n.send(n.to(n.swarm[0]));
    CHECK_FALSE(ok);
    // The reason each member was unusable, not "no members left" -- which would tell the caller
    // less than what it already had.
    CHECK(status == ERROR_INVALID_DESTINATION);

    // Every member tried, once each: it ends when selection has nothing left rather than at a
    // fixed count, and never revisits one already spent.
    REQUIRE(n.router->tried.size() == 3);
    CHECK(all_distinct(n.router->tried));
}

TEST_CASE("Network: a failure that is not the node's fault is not retried elsewhere", "[network]") {
    ScriptedNetwork n{3};

    // A 500 says the request was carried and the server disliked it.  Asking a different member of
    // the same swarm the same question gets the same answer, so this is not what the walk is for.
    n.router->replies[n.swarm[0].remote_pubkey] = {false, false, 500, "nope"};

    auto [ok, status] = n.send(n.to(n.swarm[0]));
    CHECK_FALSE(ok);
    CHECK(status == 500);
    CHECK(n.router->tried.size() == 1);
}

TEST_CASE("Network: a request with no swarm has nowhere else to go", "[network]") {
    ScriptedNetwork n{3};

    // Something aimed at a node rather than at an account -- a cache refresh, a clock resync --
    // has no swarm to walk, so the failure is simply reported.
    auto req = n.to(n.swarm[0]);
    req.swarm_pubkey.reset();

    auto [ok, status] = n.send(std::move(req));
    CHECK_FALSE(ok);
    CHECK(status == ERROR_INVALID_DESTINATION);
    CHECK(n.router->tried.size() == 1);
}

TEST_CASE("Network: attempts are bounded by the overall budget", "[network]") {
    SECTION("each attempt gets the per-request timeout while there is budget for it") {
        ScriptedNetwork n{3};
        n.send(n.to(n.swarm[0], 60s));

        REQUIRE(n.router->timeouts.size() == 3);
        for (auto t : n.router->timeouts)
            CHECK(t == 10s);
    }

    SECTION("a shrinking budget shortens the retry rather than overrunning it") {
        ScriptedNetwork n{3};
        // Less than one full attempt's worth of budget, but more than the minimum worth starting.
        n.send(n.to(n.swarm[0], 6s));

        REQUIRE(n.router->timeouts.size() >= 2);
        // The first attempt is the caller's own request, untouched -- the budget only governs what
        // this layer *adds*.
        CHECK(n.router->timeouts[0] == 10s);
        // Every retry after it is capped by what remains of the operation.
        for (size_t i = 1; i < n.router->timeouts.size(); i++)
            CHECK(n.router->timeouts[i] <= 6s);
    }

    SECTION("too little left to be worth starting stops the walk early") {
        ScriptedNetwork n{4};
        // Below MIN_RETRY_BUDGET, so the first failure ends it rather than starting an attempt
        // that cannot finish.
        n.send(n.to(n.swarm[0], 1s));

        CHECK(n.router->tried.size() == 1);
    }
}

TEST_CASE(
        "Network: an owner reference dropped mid-callback does not tear the Network down from its "
        "own loop",
        "[network]") {
    // Two members so that the first, unreachable one sends the request through
    // _retry_next_swarm_node: that goes via SnodePool::get_swarm, which answers from the loop, so
    // the second attempt -- and the callback below -- run on the loop thread rather than on this
    // one.
    ScriptedNetwork n{2};
    n.router->replies[n.swarm[1].remote_pubkey] = {};

    auto reached_callback = std::promise<void>{};
    auto in_callback = reached_callback.get_future();
    std::atomic<bool> answered = false;

    n.net->send_request(
            n.to(n.swarm[0]), [&reached_callback, &answered](bool ok, bool, int16_t, auto, auto) {
                answered = ok;
                reached_callback.set_value();

                // Stay on the loop thread while the reference below goes, which is the interleaving
                // that used to abort: the callback held a shared_ptr<Network> of its own, so
                // dropping the owner's left the loop thread as the last owner, and ~Network joins
                // that thread.
                std::this_thread::sleep_for(50ms);
            });

    REQUIRE(in_callback.wait_for(5s) == std::future_status::ready);

    auto observer = std::weak_ptr<Network>{n.net};
    n.net.reset();

    // Waits for the Network to actually be gone rather than merely unreferenced from here: the
    // teardown is what fails, so it has to happen while this test is still running.  Nothing else
    // holds a reference, so this returns as soon as the callback has finished.
    for (int i = 0; i < 500 && !observer.expired(); i++)
        std::this_thread::sleep_for(10ms);

    // Surviving to here is the assertion: the failure was an abort out of a destructor rather than
    // a wrong answer.
    CHECK(observer.expired());
    CHECK(answered);
}
