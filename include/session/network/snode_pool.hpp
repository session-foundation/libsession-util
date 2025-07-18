#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <thread>
#include <vector>

#include "session/network/service_node.hpp"
#include "session/network/session_network_config.hpp"
#include "session/onionreq/key_types.hpp"
#include "swarm.hpp"

namespace session::network {

class SnodePool {
  public:
    using network_fetcher_t = std::function<void(
            service_node target,
            std::function<void(
                    std::vector<service_node> nodes, std::optional<std::string> error)>)>;

    SnodePool(Config& config, network_fetcher_t network_fetcher);
    ~SnodePool();

    // Returns the number of nodes currently in the pool
    size_t size();

    // Forcibly clears the cache from memory and disk
    void clear_cache();

    // Records that a specific node has failed a request
    void record_node_failure(const service_node& node);

    // Checks if the pool is empty or stale and triggers a refresh if needed
    void refresh_if_needed();

    void get_swarm(
            session::onionreq::x25519_pubkey swarm_pubkey,
            std::function<void(swarm::swarm_id_t, std::vector<service_node>)> callback);

    std::vector<service_node> get_unused_nodes(
            size_t count, const std::vector<service_node>& exclude = {});

  private:
    Config& _config;
    network_fetcher_t _network_fetcher;

    // Data (protected by '_cache_mutex')
    std::vector<service_node> _snode_cache;
    std::vector<std::pair<swarm::swarm_id_t, std::vector<service_node>>> _all_swarms;
    std::unordered_map<std::string, std::pair<swarm::swarm_id_t, std::vector<service_node>>>
            _swarm_cache;
    std::unordered_map<std::string, uint16_t> _snode_failure_counts;

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
    std::shared_ptr<std::vector<std::vector<service_node>>> _snode_refresh_results;
    std::vector<std::function<void()>> _after_snode_cache_refresh;

    // Disk I/O functions
    void _load_from_disk();
    void _disk_write_loop();

    // Refresh functions
    void _launch_next_refresh_request(bool is_bootstrap_request);
    void _refresh_snode_cache(std::optional<std::string> request_id = std::nullopt);
    void _process_and_complete_refresh();
    void _on_refresh_complete(std::vector<service_node> new_nodes);
};

}  // namespace session::network
