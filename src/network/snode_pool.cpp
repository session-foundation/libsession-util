#include "session/network/snode_pool.hpp"

#include <fstream>
#include <oxenc/hex.h>
#include <oxen/log.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/utils.hpp>
#include <fmt/ranges.h>

#include "session/file.hpp"
#include "session/hash.hpp"
#include "session/random.hpp"

using namespace oxen;
using namespace std::literals;

namespace session::network {

namespace fs = std::filesystem;

namespace {
    inline auto cat = log::Cat("snode_pool");
}

SnodePool::SnodePool(config::SnodePoolConfig config, network_fetcher_t network_fetcher) : _config{config}, _network_fetcher{std::move(network_fetcher)} {
    if (_config.cache_directory) {
        std::string cache_file_name;

        switch (_config.netid) {
            case opt::netid::Target::mainnet: cache_file_name = "snode_pool"; break;
            case opt::netid::Target::testnet: cache_file_name = "snode_pool_testnet"; break;
            case opt::netid::Target::devnet:
                std::string seed_node_data;

                for (const auto& node : _config.seed_nodes)
                    seed_node_data += node.to_disk();
                
                auto hash_bytes = session::hash::hash(32, session::to_span(seed_node_data));
                cache_file_name = "snode_pool_devnet_" + oxenc::to_hex(hash_bytes);
                break;
        }

        _snode_cache_file_path = *_config.cache_directory / cache_file_name;
        _load_from_disk();
        _disk_write_thread = std::thread{&SnodePool::_disk_write_loop, this};
    }
}

SnodePool::~SnodePool() {
    if (_disk_write_thread.joinable()) {
        {
            std::unique_lock lock{_cache_mutex};
            _shut_down_disk_thread = true;
        }
        
        _disk_write_cv.notify_one();
        _disk_write_thread.join();
    }
}

// MARK: Disk I/O Functions

void SnodePool::_load_from_disk() {
    if (_snode_cache_file_path.empty()) {
        log::error(cat, "Tried to load cache from disk without a cache file path.");
        return;
    }
    
    // Load the cache if present
    try {
        if (!fs::exists(_snode_cache_file_path)) {
            log::info(cat, "No existing snode cache, will rebuild.");
            return;
        }

        auto ftime = fs::last_write_time(_snode_cache_file_path);
        _last_snode_cache_update =
                std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        ftime - fs::file_time_type::clock::now() +
                        std::chrono::system_clock::now());

        auto file = open_for_reading(_snode_cache_file_path);
        std::vector<service_node> loaded_cache;
        std::string line;
        auto invalid_entries = 0;

        while (std::getline(file, line)) {
            try {
                loaded_cache.push_back(service_node::from_disk(line));
            } catch (...) {
                ++invalid_entries;
            }
        }

        if (invalid_entries > 0)
            log::warning(cat, "Skipped {} invalid entries in snode cache.", invalid_entries);

        std::shuffle(loaded_cache.begin(), loaded_cache.end(), csrng);
        _snode_cache = loaded_cache;
        _all_swarms = swarm::generate_swarms(loaded_cache);

        log::info(cat, "Loaded cache of {} snodes, {} swarms.", _snode_cache.size(), _all_swarms.size());
    } catch (const std::exception& e) {
        log::error(cat, "Failed to load snode cache, will rebuild ({}).", e.what());

        if (fs::exists(_snode_cache_file_path))
            fs::remove_all(_snode_cache_file_path);
    }
}

void SnodePool::_disk_write_loop() {
    std::unique_lock lock{_cache_mutex};

    while (!_shut_down_disk_thread) {
        _disk_write_cv.wait(lock, [this] {
            return _need_write || _need_clear_cache || _shut_down_disk_thread;
        });

        // Shutdown if needed
        if (_shut_down_disk_thread)
            break;

        // Clear cache if needed
        if (_need_clear_cache) {
            _snode_cache = {};
            _all_swarms = {};
            _swarm_cache = {};

            auto path_to_clear = _snode_cache_file_path;
            lock.unlock();
            try {
                if (!path_to_clear.empty(); fs::exists(path_to_clear))
                    fs::remove_all(path_to_clear);
                log::info(cat, "Cleared snode cache from disk.");
            } catch (const std::exception& e) {
                log::error(cat, "Failed to clear snode cache file: {}", e.what());
            }
            lock.lock();
            _need_clear_cache = false;
        }

        if (_need_write) {
            // Just in case
            if (_snode_cache_file_path.empty()) {
                _need_write = false;
                continue;
            }

            // Make a local copy so that we can release the lock and not
            // worry about other threads wanting to change things
            auto path_to_write = _snode_cache_file_path;
            auto snode_cache_write = _snode_cache;

            lock.unlock();
            {
                try {
                    // Create the cache directories if needed
                    fs::create_directories(path_to_write.parent_path());

                    // Save the snode pool to disk
                    auto tmp_path = path_to_write;
                    tmp_path += u8"_new";

                    {
                        std::stringstream ss;
                        for (auto& snode : snode_cache_write)
                            ss << snode.to_disk() << '\n';

                        std::ofstream file(tmp_path, std::ios::binary);
                        file << ss.rdbuf();
                    }

                    fs::rename(tmp_path, path_to_write);
                    log::debug(cat, "Finished writing snode cache to disk.");
                } catch (const std::exception& e) {
                    log::error(cat, "Failed to write snode cache: {}", e.what());
                }
            }
            lock.lock();
            _need_write = false;
        }
    }
}

// MARK: Refresh Functions

void SnodePool::_launch_next_refresh_request(bool is_bootstrap_request) {
    if (!_current_snode_cache_refresh_id || _refresh_candidate_nodes.empty())
        return;
    
    const std::string request_id = *_current_snode_cache_refresh_id;
    const uint8_t total_required = (is_bootstrap_request ? 1 : _config.num_nodes_to_use_for_refresh);
    auto results_ptr = _snode_refresh_results;
    auto target_node = _refresh_candidate_nodes.back();
    _refresh_candidate_nodes.pop_back();
    log::trace(cat, "Launching {}refresh request to {} for master request ID {}", (is_bootstrap_request ? "bootstrap" : ""), target_node.to_string(), request_id);

    _network_fetcher(target_node, [this, request_id, results_ptr, is_bootstrap_request, total_required](std::vector<service_node> nodes, std::optional<std::string> error) {
        // This callback runs on the network loop so acquire a lock
        std::unique_lock lock{_cache_mutex};

        // If the refresh was cancelled or completed while we were in-flight, do nothing.
        if (!_current_snode_cache_refresh_id || *_current_snode_cache_refresh_id != request_id) {
            log::debug(cat, "Ignoring stale refresh response for request ID {}", request_id);
            return;
        }

        // A request failed, so try to launch a replacement from our candidate pool.
        if (error) {
            log::warning(cat, "Failed to refresh snode cache from one node: {}. Trying another.", *error);
            _launch_next_refresh_request(is_bootstrap_request);
            return;
        }

        log::info(
            cat,
            "Received refresh result {}/{} with {} nodes cache for request ID {}.",
            results_ptr->size(),
            total_required,
            nodes.size(),
            request_id);
        results_ptr->push_back(std::move(nodes));

        // If we've received all the results then we need to process them and complete the refresh
        if (results_ptr->size() >= _config.num_nodes_to_use_for_refresh)
            _process_and_complete_refresh();
    });
}

void SnodePool::_process_and_complete_refresh() {
    if (!_current_snode_cache_refresh_id)
        return;
    
    log::info(cat, "Have {} successful responses, processing and finalizing snode cache refresh for request ID {}.", _snode_refresh_results->size(), *_current_snode_cache_refresh_id);

    // Sort the vectors (so make it easier to find the intersection)
    auto compare_service_nodes = [](const service_node& a, const service_node& b) {
        if (auto cmp = quic::Address(a) <=> quic::Address(b); cmp != 0)
            return cmp < 0;

        return std::tie(a.get_remote_key(), a.swarm_id, a.storage_server_version) < std::tie(b.get_remote_key(), b.swarm_id, b.storage_server_version);
    };

    for (auto& nodes : *_snode_refresh_results)
        std::stable_sort(nodes.begin(), nodes.end(), compare_service_nodes);

    auto nodes = (*_snode_refresh_results)[0];

    // If we triggered multiple requests then get the intersection of all vectors
    for (size_t i = 1; i < _snode_refresh_results->size(); ++i) {
        std::vector<service_node> intersection;
        std::set_intersection(
                nodes.begin(),
                nodes.end(),
                (*_snode_refresh_results)[i].begin(),
                (*_snode_refresh_results)[i].end(),
                std::back_inserter(intersection),
                compare_service_nodes);
        nodes = std::move(intersection);
    }

    log::info(
            cat,
            "Refreshing snode cache completed with {} nodes for request ID {}.",
            nodes.size(),
            *_current_snode_cache_refresh_id);
    _on_refresh_complete(std::move(nodes));
}

void SnodePool::_refresh_snode_cache(std::optional<std::string> request_id_opt) {
    std::unique_lock lock{_cache_mutex};

    const auto request_id = request_id_opt.value_or("RSC-" + random::random_base32(4));

    // Only allow a single cache refresh at a time
    if (_current_snode_cache_refresh_id) {
        log::debug(cat, "Ignoring request {} to refresh snode cache; a refresh is already in progress ({}).", request_id, *_current_snode_cache_refresh_id);
        return;
    }

    log::info(cat, "Starting snode cache refresh with request ID {}", request_id);
    _current_snode_cache_refresh_id = request_id;
    _snode_refresh_results = std::make_shared<std::vector<std::vector<service_node>>>();
    _refresh_candidate_nodes.clear();

    // If the cache is empty, cache refreshing is disabled, or it's smaller than `num_nodes_to_use_for_refresh` then we need to refresh from seed nodes (when fetching from seed nodes we only need to fetch from a single node so only kick off a single refresh request)
    if (_snode_cache.empty() || _config.num_nodes_to_use_for_refresh == 0 || _snode_cache.size() < _config.num_nodes_to_use_for_refresh) {
        log::debug(cat, "Snode cache is insufficient, bootstrapping from seed nodes for refresh {}", request_id);
        _refresh_candidate_nodes = _config.seed_nodes;
        std::shuffle(_refresh_candidate_nodes.begin(), _refresh_candidate_nodes.end(), csrng);

        // If we (somehow) have no candidate nodes then error and reset the state so we can try again later
        if (_refresh_candidate_nodes.empty()) {
            log::critical(cat, "Cannot bootstrap snode cache: no seed nodes are configured!");
            _current_snode_cache_refresh_id.reset();
            return;
        }

        _launch_next_refresh_request(true /* is_bootstrap_request */);
        return;
    }

    // Otherwise we want to try to refresh using nodes from the existing cache
    log::debug(cat, "Performing standard snode cache refresh using {} nodes for request ID {}", _config.num_nodes_to_use_for_refresh, request_id);
    _refresh_candidate_nodes = _snode_cache;
    std::shuffle(_refresh_candidate_nodes.begin(), _refresh_candidate_nodes.end(), csrng);

    // Kick off the concurrent requests
    for (uint8_t i = 0; i < _config.num_nodes_to_use_for_refresh; ++i)
        _launch_next_refresh_request(false /* is_bootstrap_request */);
}

void SnodePool::_on_refresh_complete(std::vector<service_node> new_nodes) {
    std::vector<std::function<void()>> after_refresh;
    
    {
        std::unique_lock lock{_cache_mutex};
        log::info(cat, "Snode cache refresh complete with {} nodes for request ID {}", new_nodes.size(), _current_snode_cache_refresh_id.value_or("NULL"));

        // Shuffle the nodes so we don't have a specific order
        std::shuffle(new_nodes.begin(), new_nodes.end(), csrng);

        // Update the in-memory caches and, since the swarm cache could now be invalid, clear it and re-generate `_all_swarms`
        _snode_cache = std::move(new_nodes);
        _all_swarms = swarm::generate_swarms(_snode_cache);
        _swarm_cache.clear();
        _last_snode_cache_update = std::chrono::system_clock::now();

        // Reset all failure and refresh-in-progress state
        _snode_failure_counts.clear();
        _current_snode_cache_refresh_id.reset();
        _snode_refresh_results.reset();
        _refresh_candidate_nodes.clear();
        _snode_cache_refresh_failure_count = 0;

        // Move any callbacks (so they can be called after the lock is freed)
        after_refresh = std::move(_after_snode_cache_refresh);

        // Flag that we need to write the updated cache to disk
        _need_write = true;
    }

    // Trigger any callbacks
    if (!after_refresh.empty()) {
        log::debug(cat, "Executing {} post-refresh callbacks.", after_refresh.size());

        for (const auto& cb : after_refresh) {
            try {
                cb();
            } catch (const std::exception& e) {
                log::error(cat, "Exception thrown in a post-refresh callback: {}", e.what());
            }
        }
    }
}

// MARK: Public Functions

size_t SnodePool::size() {
    std::lock_guard lock{_cache_mutex};
    return _snode_cache.size();
}

void SnodePool::clear_cache() {
    {
        std::lock_guard lock{_cache_mutex};
        _need_clear_cache = true;
        _disk_write_cv.notify_one();
    }
}

void SnodePool::record_node_failure(const service_node& node) {
    std::lock_guard lock{_cache_mutex};
    auto key = ed25519_pubkey::from_bytes(node.view_remote_key());
    _snode_failure_counts[key]++;
    log::trace(cat, "Recorded failure for node {}, total failures: {}", key.hex(), _snode_failure_counts[key]);
}

void SnodePool::refresh_if_needed(std::function<void()> on_refresh_complete) {
    bool needs_to_start_refresh = false;
    bool already_running = false;
    {
        std::lock_guard lock{_cache_mutex};
        
        // Don't bother if we are alread doing a refresh
        if (_current_snode_cache_refresh_id)
            already_running = true;
        else {
            auto cache_lifetime = std::chrono::system_clock::now() - _last_snode_cache_update;
            needs_to_start_refresh = (_snode_cache.empty() || cache_lifetime > _config.cache_expiration);
        }
        
        // If a refresh is needed or already running, queue the callback
        if ((needs_to_start_refresh || already_running) && on_refresh_complete)
            _after_snode_cache_refresh.push_back(std::move(on_refresh_complete));
    }
    
    // Kick off a refresh if needed (if none was needed then we should trigger the on_refresh_complete callback immediately)
    if (needs_to_start_refresh)
        _refresh_snode_cache();
    else if (on_refresh_complete)
        on_refresh_complete();
}

std::vector<service_node> SnodePool::get_unused_nodes(size_t count, const std::vector<service_node>& exclude_nodes) {
    // Kick of a cache refresh in the background if needed
    refresh_if_needed();

    // Then try to get the desired number of nodes from the current cache
    std::vector<service_node> result;
    result.reserve(count);

    std::unordered_set<ed25519_pubkey> exclusion_keys;
    exclusion_keys.reserve(exclude_nodes.size());
    for (const auto& node : exclude_nodes)
        exclusion_keys.insert(ed25519_pubkey::from_bytes(node.view_remote_key()));

    std::unordered_set<oxen::quic::ipv4> used_subnets;
    if (_config.enforce_subnet_diversity)
        for (const auto& node : exclude_nodes)
            used_subnets.insert(node.to_ipv4().to_base(24));

    std::lock_guard lock{_cache_mutex};

    if (_snode_cache.empty()) {
        log::warning(cat, "Cannot get unused nodes: snode cache is empty.");
        return result;
    }

    // Pick a random starting index to start checking for unused nodes
    size_t start_index = random::get_uniform_distribution<size_t>(0, _snode_cache.size() - 1);

    for (size_t i = 0; i < _snode_cache.size(); ++i) {
        if (result.size() >= count)
            break;
        
        const size_t current_index = (start_index + i) % _snode_cache.size();
        const auto& node = _snode_cache[current_index];
        auto current_key = ed25519_pubkey::from_bytes(node.view_remote_key());

        // Skip nodes explicitly excluded (needed in case subnet diversity is disabled)
        if (exclusion_keys.count(current_key))
            continue;

        // Skip nodes with too many failures
        auto it = _snode_failure_counts.find(current_key);
        if (it != _snode_failure_counts.end() && it->second >= _config.node_failure_threshold)
            continue;

        // Skip nodes whos IP addresses are in the exclusion list
        if (_config.enforce_subnet_diversity) {
            auto subnet = node.to_ipv4().to_base(24);
            if (used_subnets.count(subnet))
                continue;
        }

        result.push_back(node);

        if (_config.enforce_subnet_diversity)
            used_subnets.insert(node.to_ipv4().to_base(24));
    }

    if (result.size() < count)
        log::warning(cat, "Could only find {}/{} suitable unused nodes.", result.size(), count);

    return result;
}

void SnodePool::get_swarm(
        session::network::x25519_pubkey swarm_pubkey,
        std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, swarm_pubkey.hex());

    std::unique_lock lock{_cache_mutex};

    // Check the in-memory swarm cache first
    if (auto it = _swarm_cache.find(swarm_pubkey); it != _swarm_cache.end())
        return callback(it->second.first, it->second.second);

    // If we have no snode cache or no swarms then we need to rebuild the cache (which will also
    // rebuild the swarms) and run this request again
    if (_snode_cache.empty() || _all_swarms.empty()) {
        log::debug(cat, "Snode cache is empty, deferring get_swarm until refresh is complete.");
        
        // Queue this entire function call to be re-run after the refresh.
        _after_snode_cache_refresh.push_back([this, swarm_pubkey, cb = std::move(callback)]() {
            this->get_swarm(swarm_pubkey, std::move(cb));
        });

        // Check if a refresh is already running. If not, we need to start one.
        bool needs_to_start_refresh = !_current_snode_cache_refresh_id;
        
        // We MUST unlock before calling '_refresh_snode_cache' as it acquires a lock itself
        lock.unlock();

        // Start the refresh if we're the ones who decided it was needed
        if (needs_to_start_refresh)
            _refresh_snode_cache();
        
        return;
    }

    // Copy the required data and release the lock so we don't hold it during calculation
    auto all_swarms_copy = _all_swarms;
    lock.unlock();

    // Trigger a non-blocking background refresh if the data is stale
    refresh_if_needed();

    // Perform the swarm calculation using our local copy of the data
    auto swarm = swarm::get_swarm(swarm_pubkey, all_swarms_copy);
    log::info(
            cat,
            "Found swarm with {} nodes for {}, adding to cache.",
            swarm.second.size(),
            swarm_pubkey.hex());

    // Update our in-memory cache (need to re-acquire the lock to do so)
    {
        std::lock_guard write_lock{_cache_mutex};
        _swarm_cache[swarm_pubkey] = swarm;
    }

    // Trigger the callback with the swarm we found
    callback(swarm.first, swarm.second);
}

} // namespace session::network