#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <thread>
#include <vector>

#include "session/network/key_types.hpp"
#include "session/network/network_config.hpp"
#include "session/network/service_node.hpp"
#include "swarm.hpp"

namespace session::network {

namespace config {
    struct SnodePoolConfig {
        std::optional<std::filesystem::path> cache_directory;
        std::chrono::minutes cache_expiration;
        std::chrono::milliseconds cache_min_lifetime;
        bool enforce_subnet_diversity;
        network::opt::retry_delay retry_delay;

        opt::netid::Target netid;
        std::vector<service_node> seed_nodes;

        size_t cache_min_size;
        uint8_t cache_num_nodes_to_use_for_refresh;
        uint16_t cache_node_failure_threshold;
        bool cache_refresh_using_legacy_endpoint;
    };
}  // namespace config

class SnodePool {
  public:
    using network_fetcher_t = std::function<void(Request, network_response_callback_t)>;
    using fetcher_connectivity_check_t = std::function<bool()>;

    SnodePool(
            config::SnodePoolConfig config,
            std::shared_ptr<oxen::quic::Loop> loop,
            network_fetcher_t direct_fetcher);
    ~SnodePool();

    void suspend();
    void resume();

    // Sets the network fetcher which should be used once the snode cache exists
    void set_routed_fetcher(
            network_fetcher_t routed_fetcher, fetcher_connectivity_check_t connectivity_check);

    // Returns the number of nodes currently in the pool
    size_t size();

    // Forcibly clears the cache from memory and disk
    void clear_cache();

    // Records that a specific node has failed a request
    virtual void record_node_failure(const service_node& node, bool permanent = false);
    virtual void record_node_failure(const ed25519_pubkey& key, bool permanent = false);
    uint16_t node_failure_count(const service_node& node);
    uint16_t node_failure_count(const ed25519_pubkey& key);
    void clear_node_failure_counts();

    // Checks if the pool is empty or stale and triggers a refresh if needed
    virtual void refresh_if_needed(
            const std::vector<service_node>& in_use_nodes,
            std::function<void()> on_refresh_complete = nullptr);

    virtual void get_swarm(
            session::network::x25519_pubkey swarm_pubkey,
            std::function<void(swarm::swarm_id_t, std::vector<service_node>)> callback);

    virtual std::vector<service_node> get_unused_nodes(
            size_t count, const std::vector<service_node>& exclude = {});

  private:
    bool _suspended = false;
    config::SnodePoolConfig _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    network_fetcher_t _direct_fetcher;
    std::optional<network_fetcher_t> _routed_fetcher;
    std::optional<fetcher_connectivity_check_t> _routed_fetcher_connectivity_check;

    // Data (protected by '_cache_mutex')
    std::vector<service_node> _snode_cache;
    std::vector<std::pair<swarm::swarm_id_t, std::vector<service_node>>> _all_swarms;
    std::unordered_map<x25519_pubkey, std::pair<swarm::swarm_id_t, std::vector<service_node>>>
            _swarm_cache;
    std::unordered_map<ed25519_pubkey, uint16_t> _snode_failure_counts;

    // Disk I/O
    std::filesystem::path _snode_cache_file_path;
    std::thread _disk_write_thread;
    std::condition_variable _disk_write_cv;
    std::mutex _cache_mutex;
    bool _need_write = false;
    bool _need_clear_cache = false;
    bool _shut_down_disk_thread = false;

    // Refresh logic (protected by '_cache_mutex')
    std::chrono::system_clock::time_point _last_snode_cache_update;
    std::optional<std::string> _current_snode_cache_refresh_id;
    int _snode_cache_refresh_failure_count = 0;
    std::vector<service_node> _refresh_candidate_nodes;
    std::vector<std::vector<std::byte>> _snode_refresh_results;
    std::vector<std::function<void()>> _after_snode_cache_refresh;

    // Disk I/O functions
    void _load_from_disk();
    void _disk_write_loop();

    // Refresh functions
    void _refresh_snode_cache(std::optional<std::string> request_id = std::nullopt);
    void _launch_next_refresh_request(
            const std::string& request_id,
            const bool use_direct_fetcher,
            const uint8_t total_requests);
    void _retry_refresh_request(
            const std::string& request_id,
            const bool use_direct_fetcher,
            const uint8_t total_requests);
    void _on_refresh_complete(
            std::string refresh_id,
            std::vector<std::vector<std::byte>> raw_results,
            const bool use_direct_fetcher,
            const uint8_t total_requests,
            const bool from_legacy_endpoint);
};

}  // namespace session::network
