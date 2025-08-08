#include "session/network/snode_pool.hpp"

#include <fmt/ranges.h>
#include <fstream>
#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/utils.hpp>
#include <fmt/ranges.h>

#include "session/file.hpp"
#include "session/hash.hpp"
#include "session/random.hpp"

using namespace oxen;
using namespace std::literals;
using namespace oxen::log::literals;

namespace std {

template <>
struct hash<oxen::quic::ipv4> {
    size_t operator()(const oxen::quic::ipv4& ip) const noexcept {
        return std::hash<uint32_t>{}(ip.addr);
    }
};

} // namespace std

namespace session::network {

namespace fs = std::filesystem;

namespace {
    inline auto cat = log::Cat("snode_pool");
}  // namespace

SnodePool::SnodePool(config::SnodePoolConfig config, std::shared_ptr<oxen::quic::Loop> loop, network_fetcher_t bootstrap_fetcher) : _config{config}, _loop{loop}, _bootstrap_fetcher{std::move(bootstrap_fetcher)} {
    if (_config.cache_directory) {
        std::string cache_file_name;

        switch (_config.netid) {
            case opt::netid::Target::mainnet: cache_file_name = "snode_pool"; break;
            case opt::netid::Target::testnet: cache_file_name = "snode_pool_testnet"; break;
            case opt::netid::Target::devnet:
                std::string seed_node_data;

                for (const auto& node : _config.seed_nodes)
                    node.to_disk(std::back_inserter(seed_node_data));
                
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

        std::vector<std::byte> loaded_cache_data = read_whole_file(_snode_cache_file_path);
        std::vector<service_node> loaded_cache; 
        auto invalid_entries = 0;

        std::string_view data_view(reinterpret_cast<const char*>(loaded_cache_data.data()), loaded_cache_data.size());
        loaded_cache.reserve((data_view.size() / service_node_disk_format::MAX_LINE_SIZE) + 1); // +1 for safety

        size_t start = 0;
        while (start < data_view.size()) {
            // Find either \n or \r
            size_t end = data_view.find_first_of("\n\r", start);
            if (end == std::string_view::npos) end = data_view.size();

            if (end > start) { // Skip empty lines
                std::string_view line = data_view.substr(start, end - start);

                try {
                    loaded_cache.push_back(service_node::from_disk(line));
                } catch (...) {
                    ++invalid_entries;
                }
            }

            // Skip past any line ending characters (\n, \r, or both in any order)
            start = end;
            while (start < data_view.size() && (data_view[start] == '\n' || data_view[start] == '\r')) {
                ++start;
            }
        }

        if (loaded_cache_data.size() > 0 && loaded_cache.size() == 0 && invalid_entries == 0)
            throw std::runtime_error{"Snode cache has invalid format."};

        if (invalid_entries > 0)
            log::warning(cat, "Skipped {} invalid entries in snode cache.", invalid_entries);

        std::shuffle(loaded_cache.begin(), loaded_cache.end(), csrng);
        _snode_cache = std::move(loaded_cache);
        _all_swarms = swarm::generate_swarms(_snode_cache);

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
                if (!path_to_clear.empty() && fs::exists(path_to_clear))
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
                    if (snode_cache_write.empty())
                        throw std::runtime_error{"cache was empty."};
                        
                    // Create the cache directories if needed
                    fs::create_directories(path_to_write.parent_path());

                    // Save the snode pool to disk
                    auto tmp_path = path_to_write;
                    tmp_path += u8"_new";

                    {
                        std::string output_buffer;
                        output_buffer.reserve(snode_cache_write.size() * service_node_disk_format::MAX_LINE_SIZE);

                        for (const auto& snode : snode_cache_write)
                            snode.to_disk(std::back_inserter(output_buffer));

                        std::ofstream file(tmp_path, std::ios::binary);
                        file.write(output_buffer.data(), output_buffer.size());
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

void SnodePool::_refresh_snode_cache(std::optional<std::string> request_id_opt) {
    const auto request_id = request_id_opt.value_or("RSC-" + random::random_base32(4));
    bool is_bootstrap = false;
    uint8_t num_nodes_for_refresh = 0;

    {
        std::unique_lock lock{_cache_mutex};

        // Only allow a single cache refresh at a time
        if (_current_snode_cache_refresh_id) {
            log::debug(cat, "Ignoring request {} to refresh snode cache; a refresh is already in progress ({}).", request_id, *_current_snode_cache_refresh_id);
            return;
        }

        log::info(cat, "Starting cache refresh with request ID {}", request_id);
        _current_snode_cache_refresh_id = request_id;
        _snode_refresh_results.clear();
        _refresh_candidate_nodes.clear();

        // If we have no `_standard_fetcher`, cache refreshing is disabled, or the cache is smaller than `cache_num_nodes_to_use_for_refresh` then we need to refresh from seed nodes (when fetching from seed nodes we only need to fetch from a single node so only kick off a single refresh request)
        auto bootstrap_mode = (_config.cache_num_nodes_to_use_for_refresh == 0 || _snode_cache.size() < _config.cache_num_nodes_to_use_for_refresh);
        is_bootstrap = (!_standard_fetcher || bootstrap_mode);
        num_nodes_for_refresh = (is_bootstrap ? 1 : _config.cache_num_nodes_to_use_for_refresh);
        _refresh_candidate_nodes = (is_bootstrap ? _config.seed_nodes : _snode_cache);
        std::shuffle(_refresh_candidate_nodes.begin(), _refresh_candidate_nodes.end(), csrng);

        if (is_bootstrap && !bootstrap_mode)
            log::warning(cat, "No standard fetcher set, using bootstrap fetcher to fetch from seed nodes for cache refresh {}", request_id);
        else if (is_bootstrap)
            log::debug(cat, "Cache is insufficient, bootstrapping from seed nodes for refresh {}", request_id);
        else
            log::debug(cat, "Performing cache refresh via standard fetcher using {} nodes for request ID {}", _config.cache_num_nodes_to_use_for_refresh, request_id);

        // If we (somehow) have no candidate nodes then error and reset the state so we can try again later
        if (_refresh_candidate_nodes.empty()) {
            log::critical(cat, "Cannot bootstrap cache: no seed nodes are configured!");
            _current_snode_cache_refresh_id.reset();
            return;
        }
    }

    // Kick off the concurrent requests (if there are any)
    for (uint8_t i = 0; i < num_nodes_for_refresh; ++i)
        _launch_next_refresh_request(request_id, is_bootstrap);
}

void SnodePool::_launch_next_refresh_request(const std::string& request_id, bool is_bootstrap_request) {
    service_node target_node;
    bool cache_refresh_using_legacy_endpoint = false;
    session::network::SnodePool::network_fetcher_t fetcher_to_use;

    {
        std::unique_lock lock{_cache_mutex};
        
        if (!_current_snode_cache_refresh_id)
            return;
        
        if (_refresh_candidate_nodes.empty()) {
            log::warning(cat, "No more candidate nodes, aborting refresh for request ID {}.", request_id);
            std::unique_lock lock{_cache_mutex};
            _current_snode_cache_refresh_id.reset();
            _refresh_candidate_nodes.clear();
            return;
        }

        target_node = _refresh_candidate_nodes.back();
        _refresh_candidate_nodes.pop_back();
        cache_refresh_using_legacy_endpoint = _config.cache_refresh_using_legacy_endpoint;
        fetcher_to_use = (is_bootstrap_request ? _bootstrap_fetcher : *_standard_fetcher);
    }

    // If we somehow got into '_launch_next_refresh_request' for a standard request then we need to make sure '_standard_fetcher' was set before we try to use it
    if (!fetcher_to_use) {
        log::critical(cat, "No fetcher available, aborting refresh for request ID {}.", request_id);
        std::unique_lock lock{_cache_mutex};
        _current_snode_cache_refresh_id.reset();
        _refresh_candidate_nodes.clear();
        return;
    }

    log::debug(cat, "Launching {}refresh request to {} for master request ID {}", (is_bootstrap_request ? "bootstrap " : ""), target_node.to_string(), request_id);
    const Request request = [this, &request_id, &target_node, is_bootstrap_request, cache_refresh_using_legacy_endpoint]() {
        // A mandatory service node upgrade needs to go out to support calling `active_nodes_bin` via onion requests so if it's not a bootstrap request and the `cache_refresh_using_legacy_endpoint` setting is set then we should use the legacy endpoint to refresh the cache
        if (!is_bootstrap_request && cache_refresh_using_legacy_endpoint) {
            nlohmann::json body{
                {"endpoint", "get_service_nodes"},
                {"params", {
                    {"active_only", true},
                    {"fields", {
                        {"pubkey_ed25519", true},
                        {"public_ip", true},
                        {"storage_port", true},
                        {"storage_lmq_port", true},
                        {"storage_server_version", true},
                        {"swarm_id", true}
                    }}
                }},
            };
            
            return Request{
                request_id,
                network_destination{target_node},
                std::string{"oxend_request"},
                to_vector(body.dump()),
                RequestCategory::standard,
                10s,
                std::nullopt,   // overall_timeout
                true            // ephemeral_connection
            };
        }
        
        return Request{
            request_id,
            network_destination{target_node},
            std::string{"active_nodes_bin"},
            std::nullopt,
            RequestCategory::standard,
            10s,
            std::nullopt,   // overall_timeout
            true            // ephemeral_connection
        };
    }();

    fetcher_to_use(request, [this, request_id, is_bootstrap_request, cache_refresh_using_legacy_endpoint](bool success, bool timeout, int16_t status_code, std::vector<std::pair<std::string, std::string>> headers, std::optional<std::string> response) {
        // This callback runs on the network loop so acquire a lock
        std::unique_lock lock{_cache_mutex};

        // If the refresh was cancelled or completed while we were in-flight, do nothing
        if (!_current_snode_cache_refresh_id || *_current_snode_cache_refresh_id != request_id) {
            log::debug(cat, "Ignoring stale refresh response for request ID {}", request_id);
            return;
        }

        std::vector<std::byte> result;
        
        try {
            if (!success || timeout || !response)
                throw std::runtime_error{response.value_or("Unknown error.")};

            if (status_code < 200 || status_code > 299)
                throw status_code_exception{status_code, {content_type_plain_text}, "Request failed with status code: {}, error: {}"_format(status_code, response.value_or("Unknown error."))};

            result.assign(
                        reinterpret_cast<const std::byte*>(response->data()),
                        reinterpret_cast<const std::byte*>(response->data() + response->length()));
        } catch (const std::exception& e) {
            _snode_cache_refresh_failure_count++;
            auto delay = _config.retry_delay.exponential(_snode_cache_refresh_failure_count);

            log::warning(cat, "Failed to refresh cache from one node: {}. Trying another in {}ms.", e.what(), delay.count());
            _loop->call_later(delay, [this, request_id, is_bootstrap_request] {
                _retry_refresh_request(request_id, is_bootstrap_request);
            });
            return;
        }

        const uint8_t total_required = (is_bootstrap_request ? 1 : _config.cache_num_nodes_to_use_for_refresh);
        _snode_refresh_results.push_back(std::move(result));
        log::info(
            cat,
            "Received refresh result {}/{} for request ID {}.",
            _snode_refresh_results.size(),
            total_required,
            request_id);

        // If we've received all the results then we need to process them and complete the refresh
        if (is_bootstrap_request || _snode_refresh_results.size() >= _config.cache_num_nodes_to_use_for_refresh) {
            auto final_results = std::move(_snode_refresh_results);
            auto refresh_id = *_current_snode_cache_refresh_id;
            lock.unlock();  // Unlock so `_on_refresh_complete` can get it's own lock
            _on_refresh_complete(refresh_id, final_results, is_bootstrap_request, cache_refresh_using_legacy_endpoint);
        }
    });
}

void SnodePool::_retry_refresh_request(const std::string& request_id, bool is_bootstrap_request) {
    std::unique_lock lock{_cache_mutex};
    _launch_next_refresh_request(request_id, is_bootstrap_request);
}

void SnodePool::_on_refresh_complete(std::string refresh_id, std::vector<std::vector<std::byte>> raw_results, bool is_bootstrap_request, bool cache_refresh_using_legacy_endpoint) {
    log::info(cat, "Have {} successful responses, processing and finalizing cache refresh for request ID {}.", raw_results.size(), refresh_id);

    // Sort the vectors (so make it easier to find the intersection)
    std::vector<std::vector<service_node>> processed_nodes;
    processed_nodes.reserve(raw_results.size());
    for (size_t i = 0; i < raw_results.size(); ++i) {
        try {
            auto& nodes_bin = raw_results[i];
            std::pair<std::vector<service_node>, int> result;
            auto& [nodes, invalid_count] = result;

            // Due to how onion requests work they need to return JSON data which means the data could be base64-encoded, so handle that case if needed
            if (!is_bootstrap_request && cache_refresh_using_legacy_endpoint) {
                nlohmann::json response_json = nlohmann::json::parse(to_string_view(nodes_bin));

                if (!response_json.contains("result") || !response_json["result"].is_object())
                    throw std::runtime_error{"JSON missing result field."};

                nlohmann::json result_json = response_json["result"];
                if (!result_json.contains("service_node_states") || !result_json["service_node_states"].is_array())
                    throw std::runtime_error{"JSON missing service_node_states field."};

                for (auto& snode : result_json["service_node_states"])
                    try {
                        nodes.emplace_back(service_node::legacy_from_json(snode));
                    } catch (...) {
                        invalid_count++;
                    }
            } else if (!is_bootstrap_request && oxenc::is_base64(nodes_bin)) {
                std::vector<std::byte> converted_nodes;
                oxenc::from_base64(nodes_bin.begin(), nodes_bin.end(), std::back_inserter(converted_nodes));
                result = service_node::process_snode_cache_bin(converted_nodes);
            } else
                result = service_node::process_snode_cache_bin(nodes_bin);

            log::info(cat, "Refresh request {} included {} nodes, {} invalid for request ID {}.", i, nodes.size(), invalid_count, refresh_id);
            std::stable_sort(nodes.begin(), nodes.end());
            processed_nodes.emplace_back(std::move(nodes));
        } catch (const std::exception& e) {
            log::error(cat, "Refresh request {} was invalid for request ID {} with error: {}.", i, refresh_id, e.what());
            std::chrono::milliseconds delay;
            uint8_t num_nodes_for_refresh;

            {
                std::unique_lock lock{_cache_mutex};
                _snode_refresh_results.clear();
                _snode_cache_refresh_failure_count++;

                // We don't want to retry indefinitely so limit the number of attempts
                if (_snode_cache_refresh_failure_count > _config.cache_refresh_retry_limit) {
                    log::warning(cat, "Refresh for request {} cancelled due to too many failures.", refresh_id);
                    _current_snode_cache_refresh_id.reset();
                    _refresh_candidate_nodes.clear();
                    return;
                }

                delay = _config.retry_delay.exponential(_snode_cache_refresh_failure_count);
                num_nodes_for_refresh = (is_bootstrap_request ? 1 : _config.cache_num_nodes_to_use_for_refresh);
            }

            _loop->call_later(delay, [this, num_nodes_for_refresh, refresh_id, is_bootstrap_request] {
                for (uint8_t i = 0; i < num_nodes_for_refresh; ++i)
                    _launch_next_refresh_request(refresh_id, is_bootstrap_request);
            });
            return;
        }
    }

    auto nodes = processed_nodes[0];

    // If we triggered multiple requests then get the intersection of all vectors
    for (size_t i = 1; i < processed_nodes.size(); ++i) {
        std::vector<service_node> intersection;
        std::set_intersection(
                nodes.begin(),
                nodes.end(),
                processed_nodes[i].begin(),
                processed_nodes[i].end(),
                std::back_inserter(intersection));
        nodes = std::move(intersection);
    }

    // Shuffle the nodes so we don't have a specific order
    std::shuffle(nodes.begin(), nodes.end(), csrng);
    log::info(cat, "Cache refresh complete with {} nodes for request ID {}.", nodes.size(), refresh_id);

    std::vector<std::function<void()>> after_refresh;

    {
        std::unique_lock lock{_cache_mutex};
    
        // Update the in-memory caches and, since the swarm cache could now be invalid, clear it and re-generate `_all_swarms`
        _snode_cache = std::move(nodes);
        _all_swarms = swarm::generate_swarms(_snode_cache);
        _swarm_cache.clear();
        _last_snode_cache_update = std::chrono::system_clock::now();

        // Reset all failure and refresh-in-progress state
        _snode_failure_counts.clear();
        _current_snode_cache_refresh_id.reset();
        _snode_refresh_results.clear();
        _refresh_candidate_nodes.clear();
        _snode_cache_refresh_failure_count = 0;

        // Move any callbacks (so they can be called after the lock is freed)
        after_refresh = std::move(_after_snode_cache_refresh);

        // Flag that we need to write the updated cache to disk
        _need_write = true;
    }

    _disk_write_cv.notify_one();

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

void SnodePool::set_standard_fetcher(network_fetcher_t standard_fetcher) {
    std::unique_lock lock{_cache_mutex};
    _standard_fetcher = std::move(standard_fetcher);
}

size_t SnodePool::size() {
    std::lock_guard lock{_cache_mutex};
    return _snode_cache.size();
}

void SnodePool::clear_cache() {
    {
        std::lock_guard lock{_cache_mutex};
        _need_clear_cache = true;
    }
    _disk_write_cv.notify_one();
}

void SnodePool::record_node_failure(const service_node& node) {
    std::lock_guard lock{_cache_mutex};
    auto key = ed25519_pubkey::from_bytes(node.view_remote_key());
    _snode_failure_counts[key]++;
    log::trace(cat, "Recorded failure for node {}, total failures: {}", key.hex(), _snode_failure_counts[key]);
}

void SnodePool::refresh_if_needed(const std::vector<service_node>& in_use_nodes, std::function<void()> on_refresh_complete) {
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

            // Also need to refresh if there are not enough non-failed nodes in the cache
            if (!needs_to_start_refresh) {
                size_t usable_nodes_count = 0;

                std::unordered_set<ed25519_pubkey> in_use_keys;
                for (const auto& node : in_use_nodes)
                    in_use_keys.insert(ed25519_pubkey::from_bytes(node.view_remote_key()));
                
                for (const auto& node : _snode_cache) {
                    auto pubkey = ed25519_pubkey::from_bytes(node.view_remote_key());
                    auto it = _snode_failure_counts.find(pubkey);
                    if (it != _snode_failure_counts.end() && it->second >= _config.cache_node_failure_threshold)
                        continue;
                    
                    // If the caller considers the node as already in use then it wouldn't be considered usable so ignore it for the purpose of determining whether we have enough nodes to avoid a refresh
                    if (in_use_keys.count(pubkey))
                        continue;

                    usable_nodes_count++;

                    if (usable_nodes_count >= _config.cache_min_size)
                        break;
                }
                
                if (usable_nodes_count < _config.cache_min_size)
                    needs_to_start_refresh = true;
            }
        }
        
        // If a refresh is needed or already running, queue the callback
        if ((needs_to_start_refresh || already_running) && on_refresh_complete)
            _after_snode_cache_refresh.push_back(std::move(on_refresh_complete));
    }
    
    // Kick off a refresh if needed (if none was needed then we should trigger the on_refresh_complete callback immediately)
    if (needs_to_start_refresh)
        _refresh_snode_cache();
    else if (!already_running && on_refresh_complete)
        on_refresh_complete();
}

std::vector<service_node> SnodePool::get_unused_nodes(size_t count, const std::vector<service_node>& exclude_nodes) {
    // Kick of a cache refresh in the background if needed (call_soon to ensure it is scheduled after whatever called `get_unused_nodes` which may be something trying to make it's own request that we would want to run first)
    _loop->call_soon([this, exclude_nodes] {
        refresh_if_needed(exclude_nodes);
    });

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
            used_subnets.insert(node.ip.to_base(24));

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
        if (it != _snode_failure_counts.end() && it->second >= _config.cache_node_failure_threshold)
            continue;

        // Skip nodes whos IP addresses are in the exclusion list
        if (_config.enforce_subnet_diversity) {
            auto subnet = node.ip.to_base(24);
            if (used_subnets.count(subnet))
                continue;
        }

        result.push_back(node);

        if (_config.enforce_subnet_diversity)
            used_subnets.insert(node.ip.to_base(24));
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
        log::debug(cat, "Cache is empty, deferring get_swarm until refresh is complete.");
        
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
    _loop->call_soon([this] {
        refresh_if_needed({});
    });

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