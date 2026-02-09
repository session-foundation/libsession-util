#include "session/network/snode_pool.hpp"

#include <fmt/ranges.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <fstream>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/utils.hpp>

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

}  // namespace std

namespace session::network {

namespace fs = std::filesystem;

namespace {
    inline auto cat = log::Cat("snode_pool");

    const std::chrono::seconds STRIKE_EXPIRY = 48h;
    const std::chrono::seconds SAVE_THROTTLE = 5min;
}  // namespace

SnodePool::SnodePool(
        config::SnodePoolConfig config,
        std::shared_ptr<oxen::quic::Loop> loop,
        network_fetcher_t direct_fetcher) :
        _config{config}, _loop{loop}, _direct_fetcher{std::move(direct_fetcher)} {
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
        _strikes_file_path = *_config.cache_directory / (cache_file_name + "_strikes");
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

        std::string_view data_view(
                reinterpret_cast<const char*>(loaded_cache_data.data()), loaded_cache_data.size());
        loaded_cache.reserve(
                (data_view.size() / service_node_disk_format::MAX_LINE_SIZE) + 1);  // +1 for safety

        size_t start = 0;
        while (start < data_view.size()) {
            // Find either \n or \r
            size_t end = data_view.find_first_of("\n\r", start);
            if (end == std::string_view::npos)
                end = data_view.size();

            if (end > start) {  // Skip empty lines
                std::string_view line = data_view.substr(start, end - start);

                try {
                    loaded_cache.push_back(service_node::from_disk(line));
                } catch (...) {
                    ++invalid_entries;
                }
            }

            // Skip past any line ending characters (\n, \r, or both in any order)
            start = end;
            while (start < data_view.size() &&
                   (data_view[start] == '\n' || data_view[start] == '\r')) {
                ++start;
            }
        }

        if (loaded_cache_data.size() > 0 && loaded_cache.size() == 0)
            throw std::runtime_error{"Snode cache has invalid format"};

        if (invalid_entries > 0)
            log::warning(cat, "Skipped {} invalid entries in snode cache.", invalid_entries);

        std::shuffle(loaded_cache.begin(), loaded_cache.end(), csrng);
        _snode_cache = std::move(loaded_cache);
        _all_swarms = swarm::generate_swarms(_snode_cache);

        log::info(
                cat,
                "Loaded cache of {} snodes, {} swarms.",
                _snode_cache.size(),
                _all_swarms.size());
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
            return _need_write || _strikes_dirty || _need_clear_cache || _shut_down_disk_thread;
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
                        output_buffer.reserve(
                                snode_cache_write.size() * service_node_disk_format::MAX_LINE_SIZE);

                        for (const auto& snode : snode_cache_write)
                            snode.to_disk(std::back_inserter(output_buffer));

                        std::ofstream file(tmp_path, std::ios::binary);
                        file.write(output_buffer.data(), output_buffer.size());
                        file.close();
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

        if (_strikes_dirty) {
            // Just in case
            if (_strikes_file_path.empty()) {
                _strikes_dirty = false;
                continue;
            }

            auto strikes_copy = _snode_strikes;
            auto strikes_path = _strikes_file_path;

            lock.unlock();

            try {
                uint64_t expiry_threshold = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch() - STRIKE_EXPIRY).count();
                std::vector<char> buffer;
                
                // Simple binary format: [Count(4)][Key(32)][NumStamps(2)][Stamp(8)]...
                uint32_t entry_count = 0;
                buffer.resize(sizeof(uint32_t)); 

                for (auto& [key, timestamps] : strikes_copy) {
                    std::vector<uint64_t> valid_stamps;
                    for(auto t : timestamps)
                        if (t > expiry_threshold)
                            valid_stamps.push_back(t);

                    // Drop node if no active strikes
                    if (valid_stamps.empty())
                        continue;

                    entry_count++;

                    // Write Key (32 bytes)
                    auto key_bytes = reinterpret_cast<const char*>(key.data());
                    buffer.insert(buffer.end(), key_bytes, key_bytes + key.size());

                    // Write Timestamp Count (2 bytes)
                    uint16_t t_count = static_cast<uint16_t>(valid_stamps.size());
                    const char* t_count_ptr = reinterpret_cast<const char*>(&t_count);
                    buffer.insert(buffer.end(), t_count_ptr, t_count_ptr + sizeof(uint16_t));

                    // Write Timestamps (8 bytes each)
                    const char* stamps_ptr = reinterpret_cast<const char*>(valid_stamps.data());
                    buffer.insert(buffer.end(), stamps_ptr, stamps_ptr + (valid_stamps.size() * sizeof(uint64_t)));
                }

                // Patch total count at the beginning
                std::memcpy(buffer.data(), &entry_count, sizeof(uint32_t));

                // Save the strikes to disk
                auto tmp_path = strikes_path;
                tmp_path += u8"_new";

                {
                    std::ofstream file(tmp_path, std::ios::binary);
                    file.write(buffer.data(), buffer.size());
                }

                fs::rename(tmp_path, strikes_path);
                log::debug(cat, "Saved {} strike entries to disk.", entry_count);

            } catch (const std::exception& e) {
                log::error(cat, "Failed to write strikes: {}", e.what());
            }
            lock.lock();
            _strikes_dirty = false;
        }
    }
}

// MARK: Refresh Functions

void SnodePool::_refresh_snode_cache(std::optional<std::string> request_id_opt) {
    const auto request_id = request_id_opt.value_or("RSC-" + random::random_base32(4));
    bool use_routed_fetcher = true;
    uint8_t num_nodes_for_refresh = 0;

    {
        std::unique_lock lock{_cache_mutex};

        if (_suspended) {
            log::info(cat, "Ignoring refresh as pool is suspended.");
            return;
        }

        // Only allow a single cache refresh at a time
        if (_current_snode_cache_refresh_id) {
            log::debug(
                    cat,
                    "[Request {}] Ignoring refresh snode cache attempt; a refresh is already in "
                    "progress ({}).",
                    request_id,
                    *_current_snode_cache_refresh_id);
            return;
        }

        log::info(cat, "[Request {}] Starting cache refresh.", request_id);
        _current_snode_cache_refresh_id = request_id;
        _snode_refresh_results.clear();
        _refresh_candidate_nodes.clear();

        // We should only use the routed_fetcher if it exists, passes a connectivity check, and
        // there are enough cached nodes
        const auto cache_insufficient =
                (_config.cache_num_nodes_to_use_for_refresh > 0 &&
                 _snode_cache.size() < _config.cache_num_nodes_to_use_for_refresh);
        use_routed_fetcher =
                (cache_insufficient && _routed_fetcher && _routed_fetcher_connectivity_check &&
                 (*_routed_fetcher_connectivity_check)());

        // We should only refresh using seed nodes if using cached nodes is disabled, or there
        // aren't enough cached nodes to refresh from
        const auto use_seed_nodes =
                (_config.cache_num_nodes_to_use_for_refresh == 0 || cache_insufficient);

        // Seed nodes are trusted so we only need to use a single node when refreshing from them
        num_nodes_for_refresh = (use_seed_nodes ? 1 : _config.cache_num_nodes_to_use_for_refresh);
        _refresh_candidate_nodes = (use_seed_nodes ? _config.seed_nodes : _snode_cache);
        std::shuffle(_refresh_candidate_nodes.begin(), _refresh_candidate_nodes.end(), csrng);

        if (!use_routed_fetcher && use_seed_nodes)
            log::debug(
                    cat,
                    "[Request {}] Refreshing using seed nodes{}.",
                    request_id,
                    (cache_insufficient ? " (cache is insufficient)" : ""));
        else if (!use_routed_fetcher && !use_seed_nodes)
            log::warning(
                    cat,
                    "[Request {}] {}, using direct fetcher to fetch from {} nodes for cache "
                    "refresh.",
                    request_id,
                    (!_routed_fetcher ? "No routed fetcher set" : "Routed fetcher not ready"),
                    num_nodes_for_refresh);
        else if (use_routed_fetcher && use_seed_nodes)
            log::debug(
                    cat,
                    "[Request {}] Refreshing using seed nodes (cache is insufficient).",
                    request_id);
        else
            log::debug(
                    cat,
                    "[Request {}] Refrshing via routed fetcher using {} nodes.",
                    request_id,
                    num_nodes_for_refresh);

        // If we (somehow) have no candidate nodes then error and reset the state so we can try
        // again later
        if (_refresh_candidate_nodes.empty()) {
            log::critical(
                    cat,
                    "Cannot refresh cache: {}",
                    (use_seed_nodes ? "No seed nodes are configured!"
                                    : "Found no nodes and decided not to use seed nodes!"));
            _current_snode_cache_refresh_id.reset();
            return;
        }
    }

    // Kick off the concurrent requests (if there are any)
    for (uint8_t i = 0; i < num_nodes_for_refresh; ++i)
        _launch_next_refresh_request(request_id, !use_routed_fetcher, num_nodes_for_refresh);
}

void SnodePool::_launch_next_refresh_request(
        const std::string& request_id,
        const bool use_direct_fetcher,
        const uint8_t total_requests) {
    service_node target_node;
    session::network::SnodePool::network_fetcher_t fetcher_to_use;
    bool use_legacy_endpoint = false;

    {
        std::unique_lock lock{_cache_mutex};

        if (!_current_snode_cache_refresh_id)
            return;

        if (_refresh_candidate_nodes.empty()) {
            // If we run out of candidate nodes then we should fail this refresh request and start a
            // new one with a new id (the `_refresh_snode_cache` will decide which nodes and fetcher
            // should be used)
            _snode_cache_refresh_failure_count++;
            auto delay = _config.retry_delay.exponential(_snode_cache_refresh_failure_count);
            log::warning(
                    cat,
                    "[Request {}] Ran out of nodes for refresh, discarding partial results and "
                    "trying again in {}ms.",
                    request_id,
                    delay.count());
            _loop->call_later(delay, [weak_self = weak_from_this()] {
                // We need to wait until after the `call_later` to reset the `refresh_id` (and clear
                // previous results) as if we don't then additional refreshes could be triggered
                // during the delay
                auto self = weak_self.lock();
                if (!self)
                    return;

                {
                    std::unique_lock lock{self->_cache_mutex};
                    self->_current_snode_cache_refresh_id.reset();
                    self->_snode_refresh_results.clear();
                }

                self->_refresh_snode_cache();
            });
            return;
        }

        target_node = _refresh_candidate_nodes.back();
        _refresh_candidate_nodes.pop_back();
        fetcher_to_use = (use_direct_fetcher ? _direct_fetcher : *_routed_fetcher);
        use_legacy_endpoint = (!use_direct_fetcher && _config.cache_refresh_using_legacy_endpoint);
    }

    // If we somehow got into '_launch_next_refresh_request' for a routed request then we need to
    // make sure '_routed_fetcher' was set before we try to use it
    if (!fetcher_to_use) {
        log::critical(cat, "[Request {}] No fetcher available, aborting refresh.", request_id);
        std::unique_lock lock{_cache_mutex};
        _current_snode_cache_refresh_id.reset();
        _refresh_candidate_nodes.clear();
        return;
    }

    log::debug(
            cat,
            "[Request {}] Launching {} refresh request to {}",
            request_id,
            (use_direct_fetcher ? "direct" : "routed"),
            target_node.to_string());
    const Request request =
            [this, &request_id, &target_node, use_direct_fetcher, use_legacy_endpoint]() {
                // A mandatory service node upgrade needs to go out to support calling
                // `active_nodes_bin` via onion requests so if the `use_legacy_endpoint` setting is
                // set then we should use the legacy endpoint to refresh the cache
                if (use_legacy_endpoint) {
                    nlohmann::json body{
                            {"endpoint", "get_service_nodes"},
                            {"params",
                             {{"active_only", true},
                              {"fields",
                               {{"pubkey_ed25519", true},
                                {"public_ip", true},
                                {"storage_port", true},
                                {"storage_lmq_port", true},
                                {"storage_server_version", true},
                                {"swarm_id", true}}}}},
                    };

                    return Request{
                            request_id,
                            network_destination{target_node},
                            std::string{"oxend_request"},
                            to_vector(body.dump()),
                            RequestCategory::standard,
                            10s,
                            std::nullopt,      // overall_timeout
                            std::monostate{},  // details
                            true               // ephemeral_connection
                    };
                }

                return Request{
                        request_id,
                        network_destination{target_node},
                        std::string{"active_nodes_bin"},
                        std::nullopt,
                        RequestCategory::standard,
                        10s,
                        std::nullopt,      // overall_timeout
                        std::monostate{},  // details
                        true               // ephemeral_connection
                };
            }();

    fetcher_to_use(
            request,
            [this, request_id, use_direct_fetcher, total_requests, use_legacy_endpoint](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                // This callback runs on the network loop so acquire a lock
                std::unique_lock lock{_cache_mutex};

                // If the refresh was cancelled or completed while we were in-flight, do nothing
                if (!_current_snode_cache_refresh_id ||
                    *_current_snode_cache_refresh_id != request_id) {
                    log::debug(cat, "[Request {}] Ignoring stale refresh response.", request_id);
                    return;
                }

                std::vector<std::byte> result;

                try {
                    if (!success || timeout || !response)
                        throw std::runtime_error{response.value_or("Unknown error.")};

                    if (status_code < 200 || status_code > 299)
                        throw status_code_exception{
                                status_code,
                                {content_type_plain_text},
                                "Request failed with status code: {}, error: {}"_format(
                                        status_code, response.value_or("Unknown error."))};

                    result.assign(
                            reinterpret_cast<const std::byte*>(response->data()),
                            reinterpret_cast<const std::byte*>(
                                    response->data() + response->length()));
                } catch (const std::exception& e) {
                    _snode_cache_refresh_failure_count++;
                    auto delay =
                            _config.retry_delay.exponential(_snode_cache_refresh_failure_count);

                    log::warning(
                            cat,
                            "Failed to refresh cache from one node: {}. Trying another in {}ms.",
                            e.what(),
                            delay.count());
                    _loop->call_later(
                            delay,
                            [weak_self = weak_from_this(),
                             request_id,
                             use_direct_fetcher,
                             total_requests] {
                                if (auto self = weak_self.lock())
                                    self->_retry_refresh_request(
                                            request_id, use_direct_fetcher, total_requests);
                            });
                    return;
                }

                _snode_refresh_results.push_back(std::move(result));
                log::info(
                        cat,
                        "[Request {}] Received refresh response {}/{}.",
                        request_id,
                        _snode_refresh_results.size(),
                        total_requests);

                // If we've received all the results then we need to process them and complete the
                // refresh
                if (_snode_refresh_results.size() >= total_requests) {
                    auto final_results = std::move(_snode_refresh_results);
                    auto refresh_id = *_current_snode_cache_refresh_id;
                    lock.unlock();  // Unlock so `_on_refresh_complete` can get it's own lock
                    _on_refresh_complete(
                            refresh_id,
                            final_results,
                            use_direct_fetcher,
                            total_requests,
                            use_legacy_endpoint);
                }
            });
}

void SnodePool::_retry_refresh_request(
        const std::string& request_id,
        const bool use_direct_fetcher,
        const uint8_t total_requests) {
    _launch_next_refresh_request(request_id, use_direct_fetcher, total_requests);
}

void SnodePool::_on_refresh_complete(
        std::string refresh_id,
        std::vector<std::vector<std::byte>> raw_results,
        const bool use_direct_fetcher,
        const uint8_t total_requests,
        const bool from_legacy_endpoint) {
    log::info(
            cat,
            "[Request {}] Have {} responses, processing and finalizing cache refresh.",
            refresh_id,
            raw_results.size());

    // Sort the vectors (so make it easier to find the intersection)
    std::vector<std::vector<service_node>> processed_nodes;
    processed_nodes.reserve(raw_results.size());
    for (size_t i = 0; i < raw_results.size(); ++i) {
        try {
            auto& nodes_bin = raw_results[i];
            std::pair<std::vector<service_node>, int> result;
            auto& [nodes, invalid_count] = result;

            // Due to how onion requests work they need to return JSON data which means the data
            // could be base64-encoded, so handle that case if needed
            if (from_legacy_endpoint) {
                nlohmann::json response_json = nlohmann::json::parse(to_string_view(nodes_bin));

                if (!response_json.contains("result") || !response_json["result"].is_object())
                    throw std::runtime_error{"JSON missing result field."};

                nlohmann::json result_json = response_json["result"];
                if (!result_json.contains("service_node_states") ||
                    !result_json["service_node_states"].is_array())
                    throw std::runtime_error{"JSON missing service_node_states field."};

                for (auto& snode : result_json["service_node_states"])
                    try {
                        nodes.emplace_back(service_node::legacy_from_json(snode));
                    } catch (...) {
                        invalid_count++;
                    }
            } else if (!use_direct_fetcher && oxenc::is_base64(nodes_bin)) {
                std::vector<std::byte> converted_nodes;
                oxenc::from_base64(
                        nodes_bin.begin(), nodes_bin.end(), std::back_inserter(converted_nodes));
                result = service_node::process_snode_cache_bin(converted_nodes);
            } else
                result = service_node::process_snode_cache_bin(nodes_bin);

            log::info(
                    cat,
                    "[Request {}] Refresh response #{} included {} nodes, {} invalid.",
                    refresh_id,
                    (i + 1),
                    nodes.size(),
                    invalid_count);
            std::stable_sort(nodes.begin(), nodes.end());
            processed_nodes.emplace_back(std::move(nodes));
        } catch (const std::exception& e) {
            std::chrono::milliseconds delay;

            {
                std::unique_lock lock{_cache_mutex};
                _snode_refresh_results.clear();
                _snode_cache_refresh_failure_count++;
                delay = _config.retry_delay.exponential(_snode_cache_refresh_failure_count);
            }

            log::error(
                    cat,
                    "[Request {}] Discarding responses and retrying after {}ms due to invalid "
                    "response #{}: {}.",
                    refresh_id,
                    delay.count(),
                    (i + 1),
                    e.what());
            _loop->call_later(
                    delay,
                    [weak_self = weak_from_this(), refresh_id, use_direct_fetcher, total_requests] {
                        if (auto self = weak_self.lock())
                            for (uint8_t i = 0; i < total_requests; ++i)
                                self->_launch_next_refresh_request(
                                        refresh_id, use_direct_fetcher, total_requests);
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
    log::info(cat, "[Request {}] Cache refresh complete with {} nodes.", refresh_id, nodes.size());

    std::vector<std::function<void()>> after_refresh;

    {
        std::unique_lock lock{_cache_mutex};

        // Update the in-memory caches and, since the swarm cache could now be invalid, clear it and
        // re-generate `_all_swarms`
        _snode_cache = std::move(nodes);
        _all_swarms = swarm::generate_swarms(_snode_cache);
        _swarm_cache.clear();
        _last_snode_cache_update = std::chrono::system_clock::now();

        // Reset all failure and refresh-in-progress state
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

void SnodePool::suspend() {
    std::unique_lock lock{_cache_mutex};
    _suspended = true;

    // Force a write immediately if we have dirty data
    if (_strikes_dirty) {
        _need_write = true;
        _disk_write_cv.notify_one();
    }

    log::info(cat, "Suspended.");
}

void SnodePool::resume() {
    std::unique_lock lock{_cache_mutex};
    if (!_suspended)
        return;

    _suspended = false;
    log::info(cat, "Resumed.");
}

void SnodePool::set_routed_fetcher(
        network_fetcher_t routed_fetcher, fetcher_connectivity_check_t connectivity_check) {
    std::unique_lock lock{_cache_mutex};
    _routed_fetcher = std::move(routed_fetcher);
    _routed_fetcher_connectivity_check = std::move(connectivity_check);
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

void SnodePool::record_node_failure(const service_node& node, bool permanent) {
    record_node_failure(ed25519_pubkey::from_bytes(node.view_remote_key()), permanent);
}

void SnodePool::record_node_failure(const ed25519_pubkey& key, bool permanent) {
    std::lock_guard lock{_cache_mutex};

    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (permanent) {
        for (int i = 0; i < _config.cache_node_failure_threshold; ++i) {
             _snode_strikes[key].push_back(now);
        }
    } else {
        _snode_strikes[key].push_back(now);
    }

    _strikes_dirty = true;
    log::trace(
            cat,
            "Recorded strike for node {}, total: {}",
            key.hex(),
            _snode_strikes[key].size());

    // Throttle persisting the strikes to disk to at most every X minutes
    if (!_strikes_flush_scheduled && !_shut_down_disk_thread) {
        _strikes_flush_scheduled = true;
        
        _loop->call_later(SAVE_THROTTLE, [weak_self = weak_from_this()] {
            if (auto self = weak_self.lock()) {
                std::lock_guard lock{self->_cache_mutex};
                
                if (self->_strikes_dirty) {
                    self->_disk_write_cv.notify_one();
                }
                self->_strikes_flush_scheduled = false;
            }
        });
    }
}

uint16_t SnodePool::node_failure_count(const service_node& node) {
    return node_failure_count(ed25519_pubkey::from_bytes(node.view_remote_key()));
}

uint16_t SnodePool::node_failure_count(const ed25519_pubkey& key) {
    std::lock_guard lock{_cache_mutex};
    if (!_snode_strikes.contains(key))
        return 0;
    
    const auto& stamps = _snode_strikes.at(key);

    uint64_t threshold = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch() - STRIKE_EXPIRY).count();

    uint16_t count = 0;
    for (auto t : stamps)
        if (t > threshold)
            count++;
    
    return count;
}

void SnodePool::clear_node_strikes() {
    std::lock_guard lock{_cache_mutex};
    _snode_strikes.clear();

    // Immediately write to disk after clearing the snode strikes
    _strikes_dirty = true;
    _disk_write_cv.notify_one();
    _strikes_flush_scheduled = false;
}

void SnodePool::refresh_if_needed(
        const std::vector<service_node>& in_use_nodes, std::function<void()> on_refresh_complete) {
    bool needs_to_start_refresh = false;
    bool already_running = false;
    std::optional<std::chrono::milliseconds> delay;

    {
        std::lock_guard lock{_cache_mutex};

        if (_suspended) {
            log::info(cat, "Ignoring refresh as pool is suspended.");
            return;
        }

        // Don't bother if we are alread doing a refresh
        if (_current_snode_cache_refresh_id)
            already_running = true;
        else {
            auto cache_lifetime = std::chrono::system_clock::now() - _last_snode_cache_update;
            needs_to_start_refresh =
                    (_snode_cache.empty() || cache_lifetime > _config.cache_expiration);

            // Also need to refresh if there are not enough non-failed nodes in the cache
            if (!needs_to_start_refresh) {
                size_t usable_nodes_count = 0;

                std::unordered_set<ed25519_pubkey> in_use_keys;
                for (const auto& node : in_use_nodes)
                    in_use_keys.insert(ed25519_pubkey::from_bytes(node.view_remote_key()));

                for (const auto& node : _snode_cache) {
                    auto pubkey = ed25519_pubkey::from_bytes(node.view_remote_key());
                    auto it = _snode_strikes.find(pubkey);
                    if (it != _snode_strikes.end() &&
                        it->second.size() >= _config.cache_node_failure_threshold)
                        continue;

                    // If the caller considers the node as already in use then it wouldn't be
                    // considered usable so ignore it for the purpose of determining whether we have
                    // enough nodes to avoid a refresh
                    if (in_use_keys.count(pubkey))
                        continue;

                    usable_nodes_count++;

                    if (usable_nodes_count >= _config.cache_min_size)
                        break;
                }

                if (usable_nodes_count < _config.cache_min_size)
                    needs_to_start_refresh = true;
            }

            if (needs_to_start_refresh && cache_lifetime < _config.cache_min_lifetime)
                delay.emplace(std::chrono::duration_cast<std::chrono::milliseconds>(
                        _config.cache_min_lifetime - cache_lifetime));
        }

        // If a refresh is needed or already running, queue the callback
        if ((needs_to_start_refresh || already_running) && on_refresh_complete)
            _after_snode_cache_refresh.push_back(std::move(on_refresh_complete));
    }

    // Kick off a refresh if needed (if none was needed then we should trigger the
    // on_refresh_complete callback immediately)
    if (needs_to_start_refresh)
        if (delay) {
            _loop->call_later(*delay, [weak_self = weak_from_this()] {
                if (auto self = weak_self.lock())
                    self->_refresh_snode_cache();
            });
        } else
            _refresh_snode_cache();
    else if (!already_running && on_refresh_complete)
        on_refresh_complete();
}

std::vector<service_node> SnodePool::get_unused_nodes(
        size_t count, const std::vector<service_node>& exclude_nodes) {
    // Kick of a cache refresh in the background if needed (call_soon to ensure it is scheduled
    // after whatever called `get_unused_nodes` which may be something trying to make it's own
    // request that we would want to run first)
    _loop->call_soon([weak_self = weak_from_this(), exclude_nodes] {
        if (auto self = weak_self.lock())
            self->refresh_if_needed(exclude_nodes);
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
        auto it = _snode_strikes.find(current_key);
        if (it != _snode_strikes.end() && it->second.size() >= _config.cache_node_failure_threshold)
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
    _loop->call_soon([weak_self = weak_from_this()] {
        if (auto self = weak_self.lock())
            self->refresh_if_needed({});
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

}  // namespace session::network
