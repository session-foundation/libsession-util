#include <catch2/catch_test_macros.hpp>
#include <session/network/snode_pool.hpp>

#include "utils.hpp"

using namespace session;
using namespace session::network;

namespace session::network {

class TestSnodePool : public SnodePool {
  public:
    std::optional<std::vector<service_node>> mock_unused_nodes;

    TestSnodePool(
            config::SnodePool config,
            std::shared_ptr<oxen::quic::Loop> loop,
            std::shared_ptr<oxen::quic::Loop> disk_loop,
            network_fetcher_t direct_fetcher = [](Request, network_response_callback_t) {}) :
            SnodePool(
                    std::move(config),
                    std::move(loop),
                    std::move(disk_loop),
                    std::move(direct_fetcher)) {}

    void reset_state_with_cache(std::vector<service_node> cache) {
        _loop->call_get([this, cache] {
            _snode_cache = cache;
            _snode_strikes.clear();
        });
    }

    void refresh_if_needed(
            const std::vector<service_node>& /*in_use_nodes*/,
            std::function<void()> /*on_refresh_complete*/ = nullptr) override {
        // Do nothing (don't want to trigger a cache refresh)
    }

    void debug_queue_post_refresh_callback(std::function<void()> cb) {
        _loop->call_get([this, cb = std::move(cb)]() mutable {
            _after_snode_cache_refresh.push_back(std::move(cb));
        });
    }

    // Removes the spare capacity from the pending-callback vector, so that a callback registering
    // another callback while they're being run is *guaranteed* to reallocate the vector.  Without
    // this the re-registration can land in spare capacity, nothing reallocates, and iterating the
    // vector by reference stays accidentally valid - which is exactly why the real crash only
    // showed up on some launches.
    //
    // Copy-then-move-back rather than `shrink_to_fit`, which is only a hint the stdlib may ignore
    // outright.  The move-assign is required to take over the copy's buffer, so we inherit the
    // copy's capacity - but that is only guaranteed to be *at least* `size()`, so this is still
    // best-effort.  The return value is what actually makes it safe: it confirms the capacity
    // really is tight rather than letting the test quietly stop exercising the bug.
    bool debug_remove_post_refresh_callback_spare_capacity() {
        return _loop->call_get([this] {
            auto exact_sized_copy = _after_snode_cache_refresh;
            _after_snode_cache_refresh = std::move(exact_sized_copy);
            return _after_snode_cache_refresh.capacity() == _after_snode_cache_refresh.size();
        });
    }

    size_t pending_post_refresh_callbacks() {
        return _loop->call_get([this] { return _after_snode_cache_refresh.size(); });
    }

    // Called from the test thread, so this also covers `_update_cache` being entered from off the
    // loop thread
    void update_cache(std::vector<service_node> nodes) { _update_cache("test", std::move(nodes)); }

    bool debug_refresh_in_progress() {
        return _loop->call_get([this] { return _current_snode_cache_refresh_id.has_value(); });
    }

    // Backdates the pool snapshot so the age-based policies can be exercised without waiting
    void debug_age_pool(std::chrono::seconds by) {
        _loop->call_get([this, by] { _last_snode_cache_update -= by; });
    }

    void debug_age_evidence_refresh(std::chrono::seconds by) {
        _loop->call_get([this, by] { _last_evidence_refresh -= by; });
    }

    std::chrono::seconds debug_evidence_backoff() {
        return _loop->call_get([this] { return _evidence_refresh_backoff; });
    }

    // Runs `fn` on the loop thread, which is what makes `get_swarm` / `invalidate_swarm` resolve
    // inline rather than being queued: a test observing them from off the loop has no ordering
    // guarantee at all
    void debug_run_on_loop(std::function<void()> fn) {
        _loop->call_get([fn = std::move(fn)] { fn(); });
    }

    void debug_on_refresh_complete(std::vector<std::vector<std::byte>> raw_results) {
        auto total_requests = static_cast<uint8_t>(raw_results.size());
        _loop->call_get([&] {
            _on_refresh_complete("test", std::move(raw_results), false, true, total_requests);
        });
    }
};

// `TestSnodePool` stubs out `refresh_if_needed` so tests don't kick off real refreshes; the swarm
// invalidation test needs the real age-based policy to compare against, so it uses this instead
class TestSnodePoolAgePolicy : public TestSnodePool {
  public:
    using TestSnodePool::TestSnodePool;

    void refresh_if_needed(
            const std::vector<service_node>& in_use_nodes,
            std::function<void()> on_refresh_complete = nullptr) override {
        SnodePool::refresh_if_needed(in_use_nodes, std::move(on_refresh_complete));
    }
};

// Encodes nodes the way the storage server returns them, so they can be fed to
// `_on_refresh_complete`: 51 bytes per node, all multi-byte fields big-endian
std::vector<std::byte> to_snode_cache_bin(const std::vector<service_node>& nodes) {
    std::vector<std::byte> result;
    result.reserve(nodes.size() * 51);

    auto append = [&result](uint64_t value, size_t bytes) {
        for (size_t i = bytes; i-- > 0;)
            result.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xff));
    };

    for (const auto& node : nodes) {
        for (auto byte : node.view_remote_key())
            result.push_back(static_cast<std::byte>(byte));

        append(node.swarm_id, 8);
        append(node.ip.addr, 4);
        append(node.https_port, 2);
        append(node.omq_port, 2);

        for (auto part : node.storage_server_version)
            append(part, 1);
    }

    return result;
}
}  // namespace session::network

TEST_CASE("Network", "[network][get_unused_nodes]") {
    session::network::config::SnodePool pool_config = {
            std::nullopt,
            std::nullopt,
            std::chrono::minutes{5},
            std::chrono::minutes{5},
            false,  // enforce_subnet_diversity
            network::opt::retry_delay{50ms, 200ms},
            opt::netid::Target::testnet,
            {},
            0,
            0,
            3,  // cache_node_strike_threshold
            false};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;
    auto ed_pk3 = "e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5"_hexbytes;
    auto ed_pk4 = "7b633fa6fb462b90db6f0f50384190ce7715e31b7aa93d87dbd7e94e33d4251f"_hexbytes;
    std::vector<service_node> snode_cache;
    std::vector<service_node> unused_nodes;

    for (uint16_t i = 0; i < 5; ++i) {
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                0});
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk2),
                oxen::quic::ipv4{"192.168.1.{}"_format(i)},
                static_cast<uint16_t>(20100 + i),
                static_cast<uint16_t>(30100 + i),
                {2, 11, 0},
                1});
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk3),
                oxen::quic::ipv4{"192.168.2.{}"_format(i)},
                static_cast<uint16_t>(20200 + i),
                static_cast<uint16_t>(30200 + i),
                {2, 11, 0},
                2});
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk4),
                oxen::quic::ipv4{"192.168.3.{}"_format(i)},
                static_cast<uint16_t>(20300 + i),
                static_cast<uint16_t>(30300 + i),
                {2, 11, 0},
                3});
    }
    std::sort(snode_cache.begin(), snode_cache.end());

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    snode_pool->reset_state_with_cache(snode_cache);

    // Should return a result in a different order (since this is random, it's possible that it
    // could return the same order so repeat up to 5 times to make the chance of this negligible)
    snode_pool->reset_state_with_cache(snode_cache);
    auto results_differed = false;
    auto first_result = snode_pool->get_unused_nodes(20);

    for (auto i = 0; i < 5; ++i) {
        auto next_result = snode_pool->get_unused_nodes(20);

        if (next_result != first_result) {
            results_differed = true;
            break;
        }
    }
    INFO("get_unused_nodes() produced the same result 5 times in a row.");
    CHECK(results_differed);

    // Should contain the entire snode cache initially
    snode_pool->reset_state_with_cache(snode_cache);
    unused_nodes = snode_pool->get_unused_nodes(20);
    std::sort(unused_nodes.begin(), unused_nodes.end());
    CHECK(unused_nodes == snode_cache);

    // Should exclude nodes in the exclusion list
    snode_pool->reset_state_with_cache(snode_cache);
    std::vector<service_node> excluded(snode_cache.begin(), snode_cache.begin() + 10);
    std::vector<service_node> remaining(snode_cache.begin() + 10, snode_cache.end());
    unused_nodes = snode_pool->get_unused_nodes(24, excluded);
    std::sort(unused_nodes.begin(), unused_nodes.end());
    CHECK(unused_nodes == remaining);

    // Should exclude nodes which have passed the failure threshold
    snode_pool->reset_state_with_cache(snode_cache);
    for (uint16_t i = 0; i < 10; ++i) {
        snode_pool->record_node_failure(snode_cache[i], true);
    }
    unused_nodes = snode_pool->get_unused_nodes(10);
    std::sort(unused_nodes.begin(), unused_nodes.end());
    CHECK(unused_nodes == remaining);

    // Should exclude nodes which have the same subnet
    pool_config = {
            std::nullopt,
            std::nullopt,
            std::chrono::minutes{5},
            std::chrono::minutes{5},
            true,  // enforce_subnet_diversity
            network::opt::retry_delay{50ms, 200ms},
            opt::netid::Target::testnet,
            {},
            0,
            0,
            3,  // cache_node_strike_threshold
            false};
    snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    snode_pool->reset_state_with_cache(snode_cache);
    unused_nodes = snode_pool->get_unused_nodes(20);
    std::sort(unused_nodes.begin(), unused_nodes.end());
    CHECK(unused_nodes.size() == 4);

    std::set<oxen::quic::ipv4> result_subnets;
    for (const auto& node : unused_nodes)
        result_subnets.insert(node.ip.to_base(24));
    CHECK(result_subnets.size() == 4);
}

TEST_CASE("Network", "[network][update_cache]") {
    session::network::config::SnodePool pool_config = {
            std::nullopt,
            std::nullopt,
            5min,
            5min,
            false,  // enforce_subnet_diversity
            network::opt::retry_delay{50ms, 200ms},
            opt::netid::Target::testnet,
            {},
            0,
            0,
            3,  // cache_node_strike_threshold
            false};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    std::vector<service_node> snode_cache;

    for (uint16_t i = 0; i < 5; ++i)
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                0});

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);

    // Should tolerate a post-refresh callback registering another post-refresh callback (which is
    // what a deferred `get_swarm` does when the refresh left the cache empty) rather than
    // invalidating the vector it's iterating
    std::vector<int> callbacks_run;
    snode_pool->debug_queue_post_refresh_callback([&] {
        callbacks_run.push_back(0);
        snode_pool->debug_queue_post_refresh_callback([&] { callbacks_run.push_back(3); });
    });
    snode_pool->debug_queue_post_refresh_callback([&] { callbacks_run.push_back(1); });
    snode_pool->debug_queue_post_refresh_callback([&] { callbacks_run.push_back(2); });
    REQUIRE(snode_pool->debug_remove_post_refresh_callback_spare_capacity());
    snode_pool->update_cache({});
    CHECK(callbacks_run == std::vector<int>{0, 1, 2});

    // The callback registered during the run should be kept for the next refresh, not discarded
    CHECK(snode_pool->pending_post_refresh_callbacks() == 1);
    snode_pool->update_cache({});
    CHECK(callbacks_run == std::vector<int>{0, 1, 2, 3});
    CHECK(snode_pool->pending_post_refresh_callbacks() == 0);

    // Should have stored the nodes by the time it returns
    snode_pool->update_cache(snode_cache);
    CHECK(snode_pool->size() == snode_cache.size());
}

TEST_CASE("Network", "[network][refresh_min_cache_size]") {
    session::network::config::SnodePool pool_config = {
            std::nullopt,
            std::nullopt,
            5min,
            5min,
            false,  // enforce_subnet_diversity
            network::opt::retry_delay{50ms, 200ms},
            opt::netid::Target::testnet,
            {},
            12,  // cache_min_size
            0,
            0,
            3,  // cache_node_strike_threshold
            false};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    std::vector<service_node> snode_cache;

    for (uint16_t i = 0; i < 20; ++i)
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                0});

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    snode_pool->reset_state_with_cache(snode_cache);
    REQUIRE(snode_pool->size() == 20);

    // The encoding needs to round-trip or the rest of this test proves nothing
    REQUIRE(service_node::process_snode_cache_bin(to_snode_cache_bin(snode_cache)).first ==
            snode_cache);

    // A refresh returning fewer than `cache_min_size` nodes should be discarded rather than
    // replacing the perfectly good cache we already have
    std::vector<service_node> too_few(snode_cache.begin(), snode_cache.begin() + 11);
    snode_pool->debug_on_refresh_complete({to_snode_cache_bin(too_few)});
    CHECK(snode_pool->size() == 20);

    // ... and an empty refresh likewise
    snode_pool->debug_on_refresh_complete({{}});
    CHECK(snode_pool->size() == 20);

    // A refresh with enough nodes should still replace it
    std::vector<service_node> enough(snode_cache.begin(), snode_cache.begin() + 12);
    snode_pool->debug_on_refresh_complete({to_snode_cache_bin(enough)});
    CHECK(snode_pool->size() == 12);
}

TEST_CASE("Network", "[network][invalidate_swarm]") {
    session::network::config::SnodePool pool_config{
            .cache_expiration = 2h,
            .cache_min_lifetime = 2s,
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .cache_min_size = 12,
            .cache_min_swarm_size = 3,
            .cache_num_nodes_to_use_for_refresh = 1,
            .cache_min_num_refresh_presence_to_include_node = 1,
            .cache_node_strike_threshold = 3};

    auto ed_pk_before = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk_after = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;

    // Two snapshots of the same two swarms, with an entirely different set of nodes serving them.
    // Which swarm the pubkey lands in doesn't matter; what matters is that the correct answer
    // changed and no node is common to both.
    auto pool_snapshot = [](const std::vector<unsigned char>& ed_pk, uint8_t subnet) {
        std::vector<service_node> nodes;

        for (uint16_t i = 0; i < 12; ++i)
            nodes.emplace_back(service_node{
                    ed25519_pubkey::from_bytes(ed_pk),
                    oxen::quic::ipv4{"192.168.{}.{}"_format(subnet, i)},
                    static_cast<uint16_t>(20000 + i),
                    static_cast<uint16_t>(30000 + i),
                    {2, 11, 0},
                    static_cast<uint64_t>(i < 6 ? 0 : 1)});

        return nodes;
    };
    auto nodes_before = pool_snapshot(ed_pk_before, 0);
    auto nodes_after = pool_snapshot(ed_pk_after, 1);

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePoolAgePolicy>(pool_config, loop, disk_loop);
    snode_pool->update_cache(nodes_before);
    snode_pool->debug_age_pool(10min);

    auto swarm_pubkey = x25519_pubkey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000");

    std::vector<service_node> rejected_swarm, recovered_swarm;
    bool age_policy_started_refresh = false, recovery_ran = false;

    snode_pool->debug_run_on_loop([&] {
        snode_pool->get_swarm(
                swarm_pubkey, true, [&](swarm::swarm_id_t, std::vector<service_node> nodes) {
                    rejected_swarm = std::move(nodes);
                });

        // Asking by age is what the 421 path used to do, and on a cache this far short of
        // `cache_expiration` it declines - which is what left the disproven mapping in place
        snode_pool->refresh_if_needed({});
        age_policy_started_refresh = snode_pool->debug_refresh_in_progress();

        snode_pool->invalidate_swarm(swarm_pubkey, [&] {
            recovery_ran = true;
            snode_pool->get_swarm(
                    swarm_pubkey, true, [&](swarm::swarm_id_t, std::vector<service_node> nodes) {
                        recovered_swarm = std::move(nodes);
                    });
        });
    });

    REQUIRE_FALSE(rejected_swarm.empty());
    CHECK_FALSE(age_policy_started_refresh);

    // The rejection has to produce a refresh, and the retry has to wait for it rather than being
    // handed the answer that was just rejected
    REQUIRE(snode_pool->debug_refresh_in_progress());
    CHECK_FALSE(recovery_ran);

    snode_pool->update_cache(nodes_after);
    REQUIRE(recovery_ran);
    REQUIRE_FALSE(recovered_swarm.empty());

    for (const auto& node : recovered_swarm)
        CHECK(std::ranges::find(rejected_swarm, node) == rejected_swarm.end());

    // A rejection that arrives after we already refreshed on one has to be held off, or a node that
    // rejects everything keeps a client refreshing from three nodes forever
    CHECK(snode_pool->debug_evidence_backoff() == 1min);
    snode_pool->debug_age_pool(10min);
    snode_pool->debug_run_on_loop([&] { snode_pool->invalidate_swarm(swarm_pubkey); });
    CHECK_FALSE(snode_pool->debug_refresh_in_progress());

    // Once it has elapsed the next one runs, and the one after it waits twice as long again
    snode_pool->debug_age_evidence_refresh(90s);
    snode_pool->debug_run_on_loop([&] { snode_pool->invalidate_swarm(swarm_pubkey); });
    CHECK(snode_pool->debug_refresh_in_progress());
    CHECK(snode_pool->debug_evidence_backoff() == 2min);

    // Staying quiet for twice the interval means the next incident starts from the base delay
    // rather than inheriting an escalated one
    snode_pool->update_cache(nodes_after);
    snode_pool->debug_age_pool(10min);
    snode_pool->debug_age_evidence_refresh(10min);
    snode_pool->debug_run_on_loop([&] { snode_pool->invalidate_swarm(swarm_pubkey); });
    CHECK(snode_pool->debug_refresh_in_progress());
    CHECK(snode_pool->debug_evidence_backoff() == 1min);
}
