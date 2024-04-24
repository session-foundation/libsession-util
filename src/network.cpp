#include "session/network.hpp"

#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>
#include <spdlog/sinks/callback_sink.h>

#include <fstream>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/opt.hpp>
#include <oxen/quic/utils.hpp>
#include <string>
#include <string_view>
#include <thread>

#include "session/ed25519.hpp"
#include "session/export.h"
#include "session/network.h"
#include "session/network_service_node.h"
#include "session/network_service_node.hpp"
#include "session/onionreq/builder.h"
#include "session/onionreq/builder.hpp"
#include "session/onionreq/key_types.hpp"
#include "session/onionreq/response_parser.hpp"
#include "session/util.hpp"

using namespace session;
using namespace session::onionreq;
using namespace session::network;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {

    inline auto log_cat = oxen::log::Cat("network");

    class status_code_exception : public std::runtime_error {
      public:
        int16_t status_code;

        status_code_exception(int16_t status_code, std::string message) :
                std::runtime_error(message), status_code{status_code} {}
    };

    // The amount of time the snode cache can be used before it needs to be refreshed
    const std::chrono::seconds snode_cache_expiration_duration = 2h;

    // The smallest size the snode pool can get to before we need to fetch more.
    const uint16_t min_snode_pool_count = 12;

    // The number of paths we want to maintain.
    const uint8_t target_path_count = 2;

    // The number of snodes (including the guard snode) in a path.
    const uint8_t path_size = 3;

    // The number of times a path can fail before it's replaced.
    const uint16_t path_failure_threshold = 3;

    // The number of times a snode can fail before it's replaced.
    const uint16_t snode_failure_threshold = 3;

    // File names
    const auto file_testnet = "/testnet"s;
    const auto file_snode_pool = "/snode_pool"s;
    const auto file_snode_pool_updated = "/snode_pool_updated"s;
    const auto swarm_dir = "/swarm"s;

    constexpr auto node_not_found_prefix = "Next node not found: "sv;
    constexpr auto ALPN = "oxenstorage"sv;
    const ustring uALPN{reinterpret_cast<const unsigned char*>(ALPN.data()), ALPN.size()};

    const std::vector<service_node> seed_nodes_testnet{
            service_node{"144.76.164.202|35400|"
                         "80adaead94db3b0402a6057869bdbe63204a28e93589fd95a035480ed6c03b45|"
                         "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"sv}};
    const std::vector<service_node> seed_nodes_mainnet{
            service_node{"144.76.164.202|20200|"
                         "be83fe1221fdd85e4d9d2b62e2a34ba82eaf73da45700185d25aff4575ec6018|"
                         "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef"sv},
            service_node{"88.99.102.229|20201|"
                         "05c8c236cf6c4013b8ca930a343fdc62c413ba038a16bb12e75632e0179d404a|"
                         "1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef7f971e88ab144c1a7ce"sv},
            service_node{"195.16.73.17|20202|"
                         "22ced8efd4e5faf15531e9b9244b2c1de299342892b97d19268c4db69ab6350f|"
                         "1f202f00f4d2d4acc01e20773999a291cf3e3136c325474d159814e06199919f"sv},
            service_node{"104.194.11.120|20203|"
                         "330ad0d67b58f39a6f46fbeaf5c3622860dfa584e9d787f70c3702031712767a|"
                         "1f303f1d7523c46fa5398826740d13282d26b5de90fbae5749442f66afb6d78b"sv},
            service_node{"104.194.8.115|20204|"
                         "929c5fc60efa1834a2d4a77a4a33387c1c3d5afc2b192c2ba0e040b29388b216|"
                         "1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad15a35e16b50c28db7b0"sv}};

    /// rng type that uses llarp::randint(), which is cryptographically secure
    struct CSRNG {
        using result_type = uint64_t;

        static constexpr uint64_t min() { return std::numeric_limits<uint64_t>::min(); };

        static constexpr uint64_t max() { return std::numeric_limits<uint64_t>::max(); };

        uint64_t operator()() {
            uint64_t i;
            randombytes((uint8_t*)&i, sizeof(i));
            return i;
        };
    };

    /// Converts a string such as "1.2.3" to a vector of ints {1,2,3}.  Throws if something
    /// in/around
    /// the .'s isn't parseable as an integer.
    std::vector<int> parse_version(std::string_view vers, bool trim_trailing_zero = true) {
        auto v_s = session::split(vers, ".");
        std::vector<int> result;
        for (const auto& piece : v_s)
            if (!oxen::quic::parse_int(piece, result.emplace_back()))
                throw std::invalid_argument{"Invalid version"};

        // Remove any trailing `0` values (but ensure we at least end up with a "0" version)
        if (trim_trailing_zero)
            while (result.size() > 1 && result.back() == 0)
                result.pop_back();

        return result;
    }

    std::optional<session::network::service_node> node_for_destination(
            network_destination destination) {
        if (auto* dest = std::get_if<SnodeDestination>(&destination))
            return dest->node;

        return std::nullopt;
    }

    std::optional<std::string> swarm_pubkey_for_destination(network_destination destination) {
        if (auto* dest = std::get_if<SnodeDestination>(&destination))
            return dest->swarm_pubkey;

        return std::nullopt;
    }
}  // namespace

// MARK: Initialization

Network::Network(std::optional<std::string> cache_path, bool use_testnet, bool pre_build_paths) :
        use_testnet{use_testnet},
        should_cache_to_disk{cache_path},
        cache_path{cache_path.value_or("")} {
    get_snode_pool_loop = std::make_shared<oxen::quic::Loop>();
    build_paths_loop = std::make_shared<oxen::quic::Loop>();
    endpoint = net.endpoint(oxen::quic::Address{"0.0.0.0", 0}, oxen::quic::opt::alpns{{uALPN}});

    // Load the cache from disk and start the disk write thread
    if (should_cache_to_disk) {
        load_cache_from_disk();
        std::thread disk_write_thread(&Network::start_disk_write_thread, this);
        disk_write_thread.detach();
    }

    // Kick off a separate thread to build paths (may as well kick this off early)
    if (pre_build_paths) {
        std::thread build_paths_thread(
                &Network::build_paths_if_needed,
                this,
                std::nullopt,
                [](std::optional<std::vector<onion_path>>) {});
        build_paths_thread.detach();
    }
}

Network::~Network() {
    {
        std::lock_guard lock{snode_cache_mutex};
        shut_down_disk_thread = true;
    }
    snode_cache_cv.notify_one();
}

// MARK: Cache Management

void Network::load_cache_from_disk() {
    // If the cache is for the wrong network then delete everything
    auto cache_is_for_testnet = std::filesystem::exists(cache_path + file_testnet);
    if ((!use_testnet && cache_is_for_testnet) || (use_testnet && !cache_is_for_testnet))
        std::filesystem::remove_all(cache_path);

    // Create the cache directory if needed
    std::filesystem::create_directories(cache_path);
    std::filesystem::create_directories(cache_path + swarm_dir);

    // If we are using testnet then create a file to indicate that
    if (use_testnet)
        std::ofstream{cache_path + file_testnet};

    // Load the last time the snode pool was updated
    //
    // Note: We aren't just reading the write time of the file because Apple consider
    // accessing file timestamps a method that can be used to track the user (and we
    // want to avoid being flagged as using such)
    if (std::filesystem::exists(cache_path + file_snode_pool_updated)) {
        std::ifstream file{cache_path + file_snode_pool_updated};
        std::time_t timestamp;
        file >> timestamp;
        last_snode_pool_update = std::chrono::system_clock::from_time_t(timestamp);
    }

    // Load the snode pool
    if (std::filesystem::exists(cache_path + file_snode_pool)) {
        std::ifstream file{cache_path + file_snode_pool};
        std::vector<service_node> loaded_pool;
        std::string line;

        while (std::getline(file, line)) {
            try {
                loaded_pool.push_back(std::string_view(line));
            } catch (...) {
                oxen::log::warning(log_cat, "Skipping invalid entry in snode pool cache.");
            }
        }

        snode_pool = loaded_pool;
    }

    // Load the swarm cache
    auto swarm_path = (cache_path + swarm_dir);
    std::unordered_map<std::string, std::vector<service_node>> loaded_cache;

    for (auto& entry : std::filesystem::directory_iterator(swarm_path)) {
        std::ifstream file{entry.path()};
        std::vector<service_node> nodes;
        std::string line;

        while (std::getline(file, line)) {
            try {
                nodes.push_back(std::string_view(line));
            } catch (...) {
                oxen::log::warning(log_cat, "Skipping invalid entry in snode pool cache.");
            }
        }

        loaded_cache[entry.path().filename()] = nodes;
    }

    swarm_cache = loaded_cache;

    oxen::log::info(
            log_cat,
            "Loaded cache of {} snodes, {} swarms.",
            snode_pool.size(),
            swarm_cache.size());
}
void Network::start_disk_write_thread() {
    std::unique_lock lock{snode_cache_mutex};
    while (true) {
        snode_cache_cv.wait(lock, [this] { return need_write || shut_down_disk_thread; });

        if (need_write) {
            // Make local copies so that we can release the lock and not
            // worry about other threads wanting to change things:
            auto snode_pool_write = snode_pool;
            auto last_pool_update_write = last_snode_pool_update;
            auto swarm_cache_write = swarm_cache;

            lock.unlock();
            {
                // Create the cache directories if needed
                std::filesystem::create_directories(cache_path);
                std::filesystem::create_directories(cache_path + swarm_dir);

                // Save the snode pool to disk
                if (need_pool_write) {
                    auto pool_path = cache_path + file_snode_pool;
                    std::filesystem::remove(pool_path + "_new");
                    std::ofstream file{pool_path + "_new"};
                    for (auto& snode : snode_pool_write)
                        file << snode.serialise() << '\n';

                    std::filesystem::remove(pool_path);
                    std::filesystem::rename(pool_path + "_new", pool_path);

                    // Write the last update timestamp to disk
                    std::filesystem::remove(cache_path + file_snode_pool_updated);
                    std::ofstream timestamp_file{cache_path + file_snode_pool_updated};
                    timestamp_file << std::chrono::system_clock::to_time_t(last_pool_update_write);
                    oxen::log::debug(log_cat, "Finished writing snode pool cache to disk.");
                }

                // Write the swarm cache to disk
                if (need_swarm_write) {
                    for (auto& [key, swarm] : swarm_cache_write) {
                        auto swarm_path = cache_path + swarm_dir + "/" + key;
                        std::filesystem::remove(swarm_path + "_new");
                        std::ofstream swarm_file{swarm_path + "_new"};
                        for (auto& snode : swarm)
                            swarm_file << snode.serialise() << '\n';

                        std::filesystem::remove(cache_path + swarm_dir + "/" + key);
                        std::filesystem::rename(swarm_path + "_new", swarm_path);
                    }
                    oxen::log::debug(log_cat, "Finished writing swarm cache to disk.");
                }

                need_pool_write = false;
                need_swarm_write = false;
                need_write = false;
            }
            lock.lock();
        }
        if (need_clear_cache) {
            snode_pool = {};
            last_snode_pool_update = {};
            swarm_cache = {};

            lock.unlock();
            { std::filesystem::remove_all(cache_path); }
            lock.lock();
            need_clear_cache = false;
        }
        if (shut_down_disk_thread)
            return;
    }
}

void Network::clear_cache() {
    net.call([this]() mutable {
        {
            std::lock_guard lock{snode_cache_mutex};
            need_clear_cache = true;
        }
        snode_cache_cv.notify_one();
    });
}

// MARK: Logging

void Network::add_logger(
        std::function<void(oxen::log::Level lvl, const std::string& name, const std::string& msg)>
                callback) {
    auto sink = std::make_shared<spdlog::sinks::callback_sink_mt>(
            [this, cb = std::move(callback)](const spdlog::details::log_msg& msg) {
                spdlog::memory_buf_t buf;
                formatter.format(msg, buf);
                cb(msg.level, to_string(msg.logger_name), to_string(buf));
            });
    oxen::log::add_sink(sink);
}

// MARK: Connection

void Network::update_status(ConnectionStatus updated_status) {
    // Ignore updates which don't change the status
    if (status == updated_status)
        return;

    // If we are already 'connected' then ignore 'connecting' status changes (if we drop one path
    // and build another in the background this can happen)
    if (status == ConnectionStatus::connected && updated_status == ConnectionStatus::connecting)
        return;

    // Store the updated status
    status = updated_status;

    if (!status_changed)
        return;

    status_changed(updated_status);
}

connection_info Network::get_connection_info(
        service_node target,
        std::optional<oxen::quic::connection_established_callback> conn_established_cb) {
    auto connection_key_pair = ed25519::ed25519_key_pair();
    auto creds = oxen::quic::GNUTLSCreds::make_from_ed_seckey(
            std::string(connection_key_pair.second.begin(), connection_key_pair.second.end()));

    auto c = endpoint->connect(
            target,
            creds,
            oxen::quic::opt::keep_alive{10s},
            conn_established_cb,
            [this, target](oxen::quic::connection_interface& conn, uint64_t) {
                // When the connection is closed, update the path and connection status
                auto target_path =
                        std::find_if(paths.begin(), paths.end(), [&target](const auto& path) {
                            return !path.nodes.empty() && target == path.nodes.front();
                        });

                if (target_path != paths.end() && target_path->conn_info.conn &&
                    conn.reference_id() == target_path->conn_info.conn->reference_id()) {
                    target_path->conn_info.conn.reset();
                    target_path->conn_info.stream.reset();
                    handle_errors(
                            {target, "", std::nullopt, std::nullopt, *target_path, 0ms, false},
                            std::nullopt,
                            std::nullopt,
                            std::nullopt);
                }
            });

    return {target, c, c->open_stream<oxen::quic::BTRequestStream>()};
}

// MARK: Snode Pool and Onion Path

void Network::with_snode_pool(std::function<void(std::vector<service_node> pool)> callback) {
    get_snode_pool_loop->call([this, cb = std::move(callback)]() mutable {
        auto current_pool_info = net.call_get(
                [this]() -> std::pair<
                                 std::vector<service_node>,
                                 std::chrono::system_clock::time_point> {
                    return {snode_pool, last_snode_pool_update};
                });

        // Check if the cache is too old or if the updated timestamp is invalid
        auto cache_duration = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now() - current_pool_info.second);
        auto cache_has_expired =
                (cache_duration <= 0s && cache_duration > snode_cache_expiration_duration);

        // If the cache has enough snodes and it hasn't expired then return it
        if (current_pool_info.first.size() >= min_snode_pool_count && !cache_has_expired)
            return cb(current_pool_info.first);

        // Update the network status
        net.call([this]() mutable { update_status(ConnectionStatus::connecting); });

        // Define the response handler to avoid code duplication
        auto handle_nodes_response = [](std::promise<std::vector<service_node>>& prom) {
            return [&prom](std::vector<service_node> nodes, std::optional<std::string> error) {
                try {
                    if (nodes.empty())
                        throw std::runtime_error{error.value_or("No nodes received.")};
                    prom.set_value(nodes);
                } catch (...) {
                    prom.set_exception(std::current_exception());
                }
            };
        };

        try {
            CSRNG rng;
            std::vector<service_node> target_pool;

            // If we don't have enough nodes in the current cached pool then we need to fetch from
            // the seed nodes
            if (current_pool_info.first.size() < min_snode_pool_count) {
                oxen::log::info(log_cat, "Fetching from seed nodes.");
                target_pool = (use_testnet ? seed_nodes_testnet : seed_nodes_mainnet);

                // Just in case, make sure the seed nodes are have values
                if (target_pool.empty())
                    throw std::runtime_error{"Insufficient seed nodes."};

                std::shuffle(target_pool.begin(), target_pool.end(), rng);
                std::promise<std::vector<service_node>> prom;

                get_service_nodes(target_pool.front(), 256, handle_nodes_response(prom));

                // We want to block the `get_snode_pool_loop` until we have retrieved the snode pool
                // so we don't double up on requests
                auto nodes = prom.get_future().get();

                // Update the cache
                net.call([this, nodes]() mutable {
                    {
                        std::lock_guard lock{snode_cache_mutex};
                        snode_pool = nodes;
                        last_snode_pool_update = std::chrono::system_clock::now();
                        need_pool_write = true;
                        need_write = true;
                    }
                    snode_cache_cv.notify_one();
                });

                oxen::log::info(log_cat, "Updated snode pool from seed node.");
                return cb(nodes);
            }

            // Pick ~9 random snodes from the current cache to fetch nodes from (we want to
            // fetch from 3 snodes and retry up to 3 times if needed)
            target_pool = current_pool_info.first;
            std::shuffle(target_pool.begin(), target_pool.end(), rng);
            size_t num_retries = std::min(target_pool.size() / 3, static_cast<size_t>(3));

            oxen::log::info(log_cat, "Fetching from random expired cache nodes.");
            std::vector<service_node> first_nodes(
                    target_pool.begin(), target_pool.begin() + num_retries);
            std::vector<service_node> second_nodes(
                    target_pool.begin() + num_retries, target_pool.begin() + (num_retries * 2));
            std::vector<service_node> third_nodes(
                    target_pool.begin() + (num_retries * 2),
                    target_pool.begin() + (num_retries * 3));
            std::promise<std::vector<service_node>> prom1;
            std::promise<std::vector<service_node>> prom2;
            std::promise<std::vector<service_node>> prom3;

            // Kick off 3 concurrent requests
            get_service_nodes_recursive(first_nodes, std::nullopt, handle_nodes_response(prom1));
            get_service_nodes_recursive(second_nodes, std::nullopt, handle_nodes_response(prom2));
            get_service_nodes_recursive(third_nodes, std::nullopt, handle_nodes_response(prom3));

            // We want to block the `get_snode_pool_loop` until we have retrieved the snode pool
            // so we don't double up on requests
            auto first_result_nodes = prom1.get_future().get();
            auto second_result_nodes = prom2.get_future().get();
            auto third_result_nodes = prom3.get_future().get();

            auto compare_nodes = [](const auto& a, const auto& b) {
                if (a.host() == b.host()) {
                    return a.port() < b.port();
                }
                return a.host() < b.host();
            };

            // Sort the vectors (so make it easier to find the
            // intersection)
            std::stable_sort(first_result_nodes.begin(), first_result_nodes.end(), compare_nodes);
            std::stable_sort(second_result_nodes.begin(), second_result_nodes.end(), compare_nodes);
            std::stable_sort(third_result_nodes.begin(), third_result_nodes.end(), compare_nodes);

            // Get the intersection of the vectors
            std::vector<service_node> first_second_intersection;
            std::vector<service_node> intersection;

            std::set_intersection(
                    first_result_nodes.begin(),
                    first_result_nodes.end(),
                    second_result_nodes.begin(),
                    second_result_nodes.end(),
                    std::back_inserter(first_second_intersection),
                    [](const auto& a, const auto& b) { return a == b; });
            std::set_intersection(
                    first_second_intersection.begin(),
                    first_second_intersection.end(),
                    third_result_nodes.begin(),
                    third_result_nodes.end(),
                    std::back_inserter(intersection),
                    [](const auto& a, const auto& b) { return a == b; });

            // Since we sorted it we now need to shuffle it again
            std::shuffle(intersection.begin(), intersection.end(), rng);

            // Update the cache to be the first 256 nodes from
            // the intersection
            auto size = std::min(256, static_cast<int>(intersection.size()));
            std::vector<service_node> updated_pool(
                    intersection.begin(), intersection.begin() + size);
            net.call([this, updated_pool]() mutable {
                {
                    std::lock_guard lock{snode_cache_mutex};
                    snode_pool = updated_pool;
                    last_snode_pool_update = std::chrono::system_clock::now();
                    need_pool_write = true;
                    need_write = true;
                }
                snode_cache_cv.notify_one();
            });

            oxen::log::info(log_cat, "Updated snode pool.");
            cb(updated_pool);
        } catch (const std::exception& e) {
            oxen::log::info(log_cat, "Failed to get snode pool: {}", e.what());
            cb({});
        }
    });
}

void Network::with_path(
        std::optional<service_node> excluded_node,
        std::function<void(std::optional<onion_path> path)> callback) {
    auto current_paths = net.call_get([this]() -> std::vector<onion_path> { return paths; });

    // Retrieve a random path that doesn't contain the excluded node
    auto select_valid_path = [](std::optional<service_node> excluded_node,
                                std::vector<onion_path> paths) -> std::optional<onion_path> {
        if (paths.empty())
            return std::nullopt;

        std::vector<onion_path> possible_paths;
        std::copy_if(
                paths.begin(),
                paths.end(),
                std::back_inserter(possible_paths),
                [&excluded_node](const auto& path) {
                    return !path.nodes.empty() &&
                           (!excluded_node ||
                            std::find(path.nodes.begin(), path.nodes.end(), excluded_node) ==
                                    path.nodes.end());
                });

        if (possible_paths.empty())
            return std::nullopt;

        CSRNG rng;
        std::shuffle(possible_paths.begin(), possible_paths.end(), rng);

        return possible_paths.front();
    };

    // If we found a path then return it (also build additional paths in the background if needed)
    if (auto target_path = select_valid_path(excluded_node, current_paths)) {
        // Build additional paths in the background if we don't have enough
        if (current_paths.size() < target_path_count) {
            std::thread build_paths_thread(
                    &Network::build_paths_if_needed,
                    this,
                    std::nullopt,
                    [](std::optional<std::vector<onion_path>>) {});
            build_paths_thread.detach();
        }

        // If the stream had been closed then try to open a new one
        if (!target_path->conn_info.is_valid())
            target_path->conn_info = get_connection_info(
                    target_path->nodes[0], [this](oxen::quic::connection_interface&) {
                        // If the connection is re-established update the network status back to
                        // connected
                        update_status(ConnectionStatus::connected);
                    });

        return callback(*target_path);
    }

    // If we don't have any paths then build them
    build_paths_if_needed(
            std::nullopt,
            [excluded_node, select_path = std::move(select_valid_path), cb = std::move(callback)](
                    std::vector<onion_path> updated_paths) {
                cb(select_path(excluded_node, updated_paths));
            });
}

void Network::build_paths_if_needed(
        std::optional<service_node> excluded_node,
        std::function<void(std::vector<onion_path> updated_paths)> callback) {
    with_snode_pool([this, excluded_node, cb = std::move(callback)](
                            std::vector<service_node> pool) {
        if (pool.empty())
            return cb({});

        build_paths_loop->call([this, excluded_node, pool, cb = std::move(cb)]() mutable {
            auto current_paths =
                    net.call_get([this]() -> std::vector<onion_path> { return paths; });

            // No need to do anything if we already have enough paths
            if (current_paths.size() >= target_path_count)
                return cb(current_paths);

            // Update the network status
            net.call([this]() mutable { update_status(ConnectionStatus::connecting); });

            // Get the possible guard nodes
            oxen::log::info(log_cat, "Building paths.");
            std::vector<service_node> nodes_to_exclude;
            std::vector<service_node> possible_guard_nodes;

            if (excluded_node)
                nodes_to_exclude.push_back(*excluded_node);

            for (auto& path : paths)
                nodes_to_exclude.insert(
                        nodes_to_exclude.end(), path.nodes.begin(), path.nodes.end());

            if (nodes_to_exclude.empty())
                possible_guard_nodes = pool;
            else
                std::copy_if(
                        pool.begin(),
                        pool.end(),
                        std::back_inserter(possible_guard_nodes),
                        [&nodes_to_exclude](const auto& node) {
                            return std::find(
                                           nodes_to_exclude.begin(),
                                           nodes_to_exclude.end(),
                                           node) == nodes_to_exclude.end();
                        });

            if (possible_guard_nodes.empty()) {
                oxen::log::info(
                        log_cat, "Unable to build paths due to lack of possible guard nodes.");
                return cb({});
            }

            // Now that we have a list of possible guard nodes we need to build the paths, first off
            // we need to find valid guard nodes for the paths
            CSRNG rng;
            std::shuffle(possible_guard_nodes.begin(), possible_guard_nodes.end(), rng);

            // Split the possible nodes list into a list of lists (one list could run out before the
            // other but in most cases this should work fine)
            size_t required_paths = (target_path_count - current_paths.size());
            size_t chunk_size = (possible_guard_nodes.size() / required_paths);
            std::vector<std::vector<service_node>> nodes_to_test;
            auto start = 0;

            for (size_t i = 0; i < required_paths; ++i) {
                auto end = std::min(start + chunk_size, possible_guard_nodes.size());

                if (i == required_paths - 1)
                    end = possible_guard_nodes.size();

                nodes_to_test.emplace_back(
                        possible_guard_nodes.begin() + start, possible_guard_nodes.begin() + end);
                start = end;
            }

            // Start testing guard nodes based on the number of paths we want to build
            std::vector<std::promise<std::pair<connection_info, std::vector<service_node>>>>
                    promises(required_paths);

            for (size_t i = 0; i < required_paths; ++i) {
                find_valid_guard_node_recursive(
                        nodes_to_test[i],
                        [&prom = promises[i]](
                                std::optional<connection_info> valid_guard_node,
                                std::vector<service_node> unused_nodes) {
                            try {
                                if (!valid_guard_node)
                                    std::runtime_error{"Failed to find valid guard node."};
                                prom.set_value({*valid_guard_node, unused_nodes});
                            } catch (...) {
                                prom.set_exception(std::current_exception());
                            }
                        });
            }

            // Combine the results (we want to block the `build_paths_loop` until we have retrieved
            // the valid guard nodes so we don't double up on requests
            try {
                std::vector<connection_info> valid_nodes;
                std::vector<service_node> unused_nodes;

                for (auto& prom : promises) {
                    auto result = prom.get_future().get();
                    valid_nodes.emplace_back(result.first);
                    unused_nodes.insert(
                            unused_nodes.begin(), result.second.begin(), result.second.end());
                }

                // Make sure we ended up getting enough valid nodes
                auto have_enough_guard_nodes =
                        (current_paths.size() + valid_nodes.size() >= target_path_count);
                auto have_enough_unused_nodes =
                        (unused_nodes.size() >= ((path_size - 1) * target_path_count));

                if (!have_enough_guard_nodes || !have_enough_unused_nodes)
                    throw std::runtime_error{"Not enough remaining nodes."};

                // Build the paths
                auto updated_paths = current_paths;

                for (auto& info : valid_nodes) {
                    std::vector<service_node> path{info.node};

                    for (auto i = 0; i < path_size - 1; i++) {
                        auto node = unused_nodes.back();
                        unused_nodes.pop_back();
                        path.push_back(node);
                    }

                    updated_paths.emplace_back(onion_path{std::move(info), path, 0});

                    // Log that a path was built
                    std::vector<std::string> node_descriptions;
                    std::transform(
                            path.begin(),
                            path.end(),
                            std::back_inserter(node_descriptions),
                            [](service_node& node) { return node.to_string(); });
                    auto path_description = "{}"_format(fmt::join(node_descriptions, ", "));
                    oxen::log::info(
                            log_cat, "Built new onion request path: [{}]", path_description);
                }

                // Paths were successfully built, update the connection status
                update_status(ConnectionStatus::connected);

                // Store the updated paths and update the connection status
                std::vector<std::vector<service_node>> raw_paths;
                for (auto& path : updated_paths)
                    raw_paths.emplace_back(path.nodes);

                net.call([this, updated_paths, raw_paths]() mutable {
                    paths = updated_paths;

                    if (paths_changed)
                        paths_changed(raw_paths);
                });

                // Trigger the callback with the updated paths
                cb(updated_paths);
            } catch (const std::exception& e) {
                oxen::log::info(log_cat, "Unable to build paths due to error: {}", e.what());
                cb({});
            }
        });
    });
}

// MARK: Multi-request logic

void Network::get_service_nodes_recursive(
        std::vector<service_node> target_nodes,
        std::optional<int> limit,
        std::function<void(std::vector<service_node> nodes, std::optional<std::string> error)>
                callback) {
    if (target_nodes.empty())
        return callback({}, "No nodes to fetch from provided.");

    auto target_node = target_nodes.front();
    get_service_nodes(
            target_node,
            limit,
            [this, limit, target_nodes, cb = std::move(callback)](
                    std::vector<service_node> nodes, std::optional<std::string> error) {
                // If we got nodes then stop looping and return them
                if (!nodes.empty())
                    return cb(nodes, error);

                // Loop if we didn't get any nodes
                std::vector<service_node> remaining_nodes(
                        target_nodes.begin() + 1, target_nodes.end());
                get_service_nodes_recursive(remaining_nodes, limit, cb);
            });
}

void Network::find_valid_guard_node_recursive(
        std::vector<service_node> target_nodes,
        std::function<
                void(std::optional<connection_info> valid_guard_node,
                     std::vector<service_node> unused_nodes)> callback) {
    if (target_nodes.empty())
        return callback(std::nullopt, {});

    auto target_node = target_nodes.front();
    oxen::log::info(log_cat, "Testing guard snode: {}", target_node.to_string());

    get_version(
            target_node,
            3s,
            [this, target_node, target_nodes, cb = std::move(callback)](
                    std::vector<int> version,
                    connection_info info,
                    std::optional<std::string> error) {
                std::vector<service_node> remaining_nodes(
                        target_nodes.begin() + 1, target_nodes.end());

                try {
                    if (error)
                        throw std::runtime_error{*error};

                    // Ensure the node meets the minimum version requirements after a slight
                    // delay (don't want to drain the pool if the network goes down)
                    std::vector<int> min_version = parse_version("2.0.7");
                    if (version < min_version)
                        throw std::runtime_error{
                                "Outdated node version ({})"_format(fmt::join(version, "."))};

                    oxen::log::info(log_cat, "Guard snode {} valid.", target_node.to_string());
                    cb(info, remaining_nodes);
                } catch (const std::exception& e) {
                    // Log the error and loop after a slight delay (don't want to drain the pool
                    // too quickly if the network goes down)
                    oxen::log::info(
                            log_cat,
                            "Testing {} failed with error: {}",
                            target_node.to_string(),
                            e.what());
                    std::thread retry_thread([this, remaining_nodes, cb = std::move(cb)] {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        find_valid_guard_node_recursive(remaining_nodes, cb);
                    });
                    retry_thread.detach();
                }
            });
}

// MARK: Pre-Defined Requests

void Network::get_service_nodes(
        service_node node,
        std::optional<int> limit,
        std::function<void(std::vector<service_node> nodes, std::optional<std::string> error)>
                callback) {
    auto info = get_connection_info(node, std::nullopt);

    if (!info.is_valid())
        return callback({}, "Network is unreachable.");

    nlohmann::json params{
            {"active_only", true},
            {"fields",
             {{"public_ip", true},
              {"pubkey_ed25519", true},
              {"pubkey_x25519", true},
              {"storage_lmq_port", true}}}};

    if (limit)
        params["limit"] = *limit;

    oxenc::bt_dict_producer payload;
    payload.append("endpoint", "get_service_nodes");
    payload.append("params", params.dump());

    info.stream->command(
            "oxend_request",
            payload.view(),
            [this, cb = std::move(callback)](oxen::quic::message resp) {
                try {
                    auto [status_code, body] = validate_response(resp, true);

                    oxenc::bt_list_consumer result_bencode{body};
                    result_bencode.skip_value();  // Skip the status code (already validated)
                    auto response_dict = result_bencode.consume_dict_consumer();
                    response_dict.skip_until("result");

                    auto result_dict = response_dict.consume_dict_consumer();
                    result_dict.skip_until("service_node_states");

                    // Process the node list
                    std::vector<service_node> result;
                    auto node = result_dict.consume_list_consumer();

                    while (!node.is_finished())
                        result.emplace_back(node.consume_dict_consumer());

                    // Output the result
                    cb(result, std::nullopt);
                } catch (const std::exception& e) {
                    cb({}, e.what());
                }
            });
}

void Network::get_version(
        service_node node,
        std::optional<std::chrono::milliseconds> timeout,
        std::function<void(
                std::vector<int> version, connection_info info, std::optional<std::string> error)>
                callback) {
    auto info = get_connection_info(node, std::nullopt);

    if (!info.is_valid())
        return callback({}, info, "Network is unreachable.");

    oxenc::bt_dict_producer payload;
    info.stream->command(
            "info",
            payload.view(),
            timeout,
            [this, info, cb = std::move(callback)](oxen::quic::message resp) {
                try {
                    auto [status_code, body] = validate_response(resp, true);

                    oxenc::bt_list_consumer result_bencode{body};
                    result_bencode.skip_value();  // Skip the status code (already validated)
                    auto response_dict = result_bencode.consume_dict_consumer();
                    response_dict.skip_until("result");

                    std::vector<int> version;
                    response_dict.skip_until("version");
                    auto version_list = response_dict.consume_list_consumer();

                    while (!version_list.is_finished())
                        version.emplace_back(version_list.consume_integer<int>());

                    cb(version, info, std::nullopt);
                } catch (const std::exception& e) {
                    return cb({}, info, e.what());
                }
            });
}

void Network::get_swarm(
        std::string swarm_pubkey_hex,
        std::function<void(std::vector<service_node> swarm)> callback) {
    auto cached_swarm =
            net.call_get([this, swarm_pubkey_hex]() -> std::optional<std::vector<service_node>> {
                if (!swarm_cache.contains(swarm_pubkey_hex))
                    return std::nullopt;
                return swarm_cache[swarm_pubkey_hex];
            });

    // If we have a cached swarm then return it
    if (cached_swarm)
        return callback(*cached_swarm);

    // Pick a random node from the snode pool to fetch the swarm from
    with_snode_pool([this, swarm_pubkey_hex, cb = std::move(callback)](
                            std::vector<service_node> pool) {
        if (pool.empty())
            return cb({});

        auto updated_pool = pool;
        CSRNG rng;
        std::shuffle(updated_pool.begin(), updated_pool.end(), rng);
        auto node = updated_pool.front();

        nlohmann::json params{{"pubkey", swarm_pubkey_hex}};
        nlohmann::json payload{
                {"method", "get_swarm"},
                {"params", params},
        };

        send_onion_request(
                SnodeDestination{node, swarm_pubkey_hex},
                ustring{oxen::quic::to_usv(payload.dump())},
                oxen::quic::DEFAULT_TIMEOUT,
                false,
                [this, swarm_pubkey_hex, cb = std::move(cb)](
                        bool success, bool timeout, int16_t, std::optional<std::string> response) {
                    if (!success || timeout || !response)
                        return cb({});

                    std::vector<service_node> swarm;

                    try {
                        nlohmann::json response_json = nlohmann::json::parse(*response);

                        if (!response_json.contains("snodes") ||
                            !response_json["snodes"].is_array())
                            throw std::runtime_error{"JSON missing swarm field."};

                        for (auto& snode : response_json["snodes"])
                            swarm.emplace_back(snode);
                    } catch (...) {
                        return cb({});
                    }

                    // Update the cache
                    net.call([this, swarm_pubkey_hex, swarm]() mutable {
                        {
                            std::lock_guard lock{snode_cache_mutex};
                            swarm_cache[swarm_pubkey_hex] = swarm;
                            need_swarm_write = true;
                            need_write = true;
                        }
                        snode_cache_cv.notify_one();
                    });

                    cb(swarm);
                });
    });
}

void Network::get_random_nodes(
        uint16_t count, std::function<void(std::vector<service_node> nodes)> callback) {
    with_snode_pool([count, cb = std::move(callback)](std::vector<service_node> pool) {
        if (pool.size() < count)
            return cb({});

        auto random_pool = pool;
        CSRNG rng;
        std::shuffle(random_pool.begin(), random_pool.end(), rng);

        std::vector<service_node> result(random_pool.begin(), random_pool.begin() + count);
        cb(result);
    });
}

// MARK: Request Handling

void Network::send_request(
        request_info info, connection_info conn_info, network_response_callback_t handle_response) {
    if (!conn_info.is_valid())
        return handle_response(false, false, -1, "Network is unreachable.");

    oxen::quic::bstring_view payload{};

    if (info.body)
        payload = oxen::quic::bstring_view{
                reinterpret_cast<const std::byte*>(info.body->data()), info.body->size()};

    conn_info.stream->command(
            info.endpoint,
            payload,
            info.timeout,
            [this, info, cb = std::move(handle_response)](oxen::quic::message resp) {
                try {
                    auto [status_code, body] = validate_response(resp, false);
                    cb(true, false, status_code, body);
                } catch (const status_code_exception& e) {
                    handle_errors(info, e.status_code, e.what(), cb);
                } catch (const std::exception& e) {
                    cb(false, resp.timed_out, -1, e.what());
                }
            });
}

void Network::send_onion_request(
        network_destination destination,
        std::optional<ustring> body,
        std::chrono::milliseconds timeout,
        bool is_retry,
        network_response_callback_t handle_response) {
    with_path(
            node_for_destination(destination),
            [this, destination, body, timeout, is_retry, cb = std::move(handle_response)](
                    std::optional<onion_path> path) {
                if (!path)
                    return cb(false, false, -1, "No valid onion paths.");

                try {
                    // Construct the onion request
                    auto builder = Builder();
                    builder.set_destination(destination);

                    for (auto& node : path->nodes)
                        builder.add_hop(
                                {ed25519_pubkey::from_bytes(node.view_remote_key()),
                                 node.x25519_pubkey});

                    auto payload = builder.generate_payload(body);
                    auto onion_req_payload = builder.build(payload);

                    request_info info{
                            path->nodes[0],
                            "onion_req",
                            onion_req_payload,
                            swarm_pubkey_for_destination(destination),
                            *path,
                            timeout,
                            is_retry};

                    send_request(
                            info,
                            path->conn_info,
                            [this,
                             builder = std::move(builder),
                             info,
                             destination = std::move(destination),
                             cb = std::move(cb)](
                                    bool success,
                                    bool timeout,
                                    int16_t status_code,
                                    std::optional<std::string> response) {
                                if (!success || timeout ||
                                    !ResponseParser::response_long_enough(
                                            builder.enc_type, response->size()))
                                    return handle_errors(info, status_code, response, cb);

                                if (std::holds_alternative<SnodeDestination>(destination))
                                    process_snode_response(builder, *response, info, cb);
                                else if (std::holds_alternative<ServerDestination>(destination))
                                    process_server_response(builder, *response, info, cb);
                            });
                } catch (const std::exception& e) {
                    cb(false, false, -1, e.what());
                }
            });
}

// MARK: Response Handling

// The SnodeDestination runs via V3 onion requests
void Network::process_snode_response(
        Builder builder,
        std::string response,
        request_info info,
        network_response_callback_t handle_response) {
    try {
        std::string base64_iv_and_ciphertext;

        try {
            nlohmann::json response_json = nlohmann::json::parse(response);

            if (!response_json.contains("result") || !response_json["result"].is_string())
                throw std::runtime_error{"JSON missing result field."};

            base64_iv_and_ciphertext = response_json["result"].get<std::string>();
        } catch (...) {
            base64_iv_and_ciphertext = response;
        }

        if (!oxenc::is_base64(base64_iv_and_ciphertext))
            throw std::runtime_error{"Invalid base64 encoded IV and ciphertext."};

        ustring iv_and_ciphertext;
        oxenc::from_base64(
                base64_iv_and_ciphertext.begin(),
                base64_iv_and_ciphertext.end(),
                std::back_inserter(iv_and_ciphertext));
        auto parser = ResponseParser(builder);
        auto result = parser.decrypt(iv_and_ciphertext);
        auto result_json = nlohmann::json::parse(result);
        int16_t status_code;
        std::string body;

        if (result_json.contains("status_code") && result_json["status_code"].is_number())
            status_code = result_json["status_code"].get<int16_t>();
        else if (result_json.contains("status") && result_json["status"].is_number())
            status_code = result_json["status"].get<int16_t>();
        else
            throw std::runtime_error{"Invalid JSON response, missing required status_code field."};

        if (result_json.contains("body") && result_json["body"].is_string())
            body = result_json["body"].get<std::string>();
        else
            body = result_json.dump();

        // If we got a non 2xx status code, return the error
        if (status_code < 200 || status_code > 299)
            return handle_errors(info, status_code, body, handle_response);

        handle_response(true, false, status_code, body);
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what());
    }
}

// The ServerDestination runs via V4 onion requests
void Network::process_server_response(
        Builder builder,
        std::string response,
        request_info info,
        network_response_callback_t handle_response) {
    try {
        ustring response_data{to_unsigned(response.data()), response.size()};
        auto parser = ResponseParser(builder);
        auto result = parser.decrypt(response_data);

        // Process the bencoded response
        oxenc::bt_list_consumer result_bencode{result};

        if (result_bencode.is_finished() || !result_bencode.is_string())
            throw std::runtime_error{"Invalid bencoded response"};

        auto response_info_string = result_bencode.consume_string();
        int16_t status_code;
        nlohmann::json response_info_json = nlohmann::json::parse(response_info_string);

        if (response_info_json.contains("code") && response_info_json["code"].is_number())
            status_code = response_info_json["code"].get<int16_t>();
        else
            throw std::runtime_error{"Invalid JSON response, missing required status_code field."};

        // If we have a status code that is not in the 2xx range, return the error
        if (status_code < 200 || status_code > 299) {
            if (result_bencode.is_finished())
                return handle_errors(info, status_code, std::nullopt, handle_response);

            return handle_errors(
                    info, status_code, result_bencode.consume_string(), handle_response);
        }

        // If there is no body just return the success status
        if (result_bencode.is_finished())
            return handle_response(true, false, status_code, std::nullopt);

        // Otherwise return the result
        handle_response(true, false, status_code, result_bencode.consume_string());
    } catch (const std::exception& e) {
        handle_response(false, false, -1, e.what());
    }
}

// MARK: Error Handling

std::pair<uint16_t, std::string> Network::validate_response(
        oxen::quic::message resp, bool is_bencoded) {
    std::string body = resp.body_str();

    if (resp.timed_out)
        throw std::runtime_error{"Timed out"};
    if (resp.is_error())
        throw std::runtime_error{body.empty() ? "Unknown error" : body};

    if (is_bencoded) {
        // Process the bencoded response
        oxenc::bt_list_consumer result_bencode{body};

        if (result_bencode.is_finished() || !result_bencode.is_integer())
            throw std::runtime_error{"Invalid bencoded response"};

        // If we have a status code that is not in the 2xx range, return the error
        auto status_code = result_bencode.consume_integer<int16_t>();

        if (status_code < 200 || status_code > 299) {
            if (result_bencode.is_finished() || !result_bencode.is_string())
                throw status_code_exception{
                        status_code,
                        "Request failed with status code: " + std::to_string(status_code)};

            throw status_code_exception{status_code, result_bencode.consume_string()};
        }

        // Can't convert the data to a string so just return the response body itself
        return {status_code, body};
    }

    // Default to a 200 success if the response is empty but didn't timeout or error
    int16_t status_code = 200;
    std::string response_string;

    try {
        nlohmann::json response_json = nlohmann::json::parse(body);

        if (response_json.is_array() && response_json.size() == 2) {
            status_code = response_json[0].get<int16_t>();
            response_string = response_json[1].dump();
        } else
            response_string = body;
    } catch (...) {
        response_string = body;
    }

    if (status_code < 200 || status_code > 299)
        throw status_code_exception{status_code, response_string};

    return {status_code, response_string};
}

void Network::handle_errors(
        request_info info,
        std::optional<int16_t> status_code_,
        std::optional<std::string> response,
        std::optional<network_response_callback_t> handle_response) {
    auto status_code = status_code_.value_or(-1);

    switch (status_code) {
        // A 404 or a 400 is likely due to a bad/missing SOGS or file so
        // shouldn't mark a path or snode as invalid
        case 400:
        case 404:
            if (handle_response)
                return (*handle_response)(false, false, status_code, response);
            return;

        // The user's clock is out of sync with the service node network (a
        // snode will return 406, but V4 onion requests returns a 425)
        case 406:
        case 425:
            if (handle_response)
                return (*handle_response)(false, false, status_code, response);
            return;

        // The snode is reporting that it isn't associated with the given public key anymore. If
        // this is the first 421 then we want to try another node in the swarm (just in case it
        // was reported incorrectly). If this is the second occurrence of the 421 then the
        // client needs to update the swarm (if the response contains updated swarm data), or
        // increment the path failure count.
        case 421:
            try {
                // If there is no response handler or no swarm information was provided then we
                // should just replace the swarm
                if (!handle_response || !info.swarm_pubkey)
                    throw std::invalid_argument{"Unable to handle redirect."};

                auto cached_swarm = net.call_get(
                        [this, swarm_pubkey = *info.swarm_pubkey]() -> std::vector<service_node> {
                            return swarm_cache[swarm_pubkey];
                        });

                if (cached_swarm.empty())
                    throw std::invalid_argument{"Unable to handle redirect."};

                // If this was the first 421 then we want to retry using another node in the
                // swarm to get confirmation that we should switch to a different swarm
                if (!info.is_retry) {
                    CSRNG rng;
                    std::vector<session::network::service_node> swarm_copy = cached_swarm;
                    std::shuffle(swarm_copy.begin(), swarm_copy.end(), rng);

                    std::optional<session::network::service_node> random_node;

                    for (auto& node : swarm_copy) {
                        if (node == info.target)
                            continue;

                        random_node = node;
                        break;
                    }

                    if (!random_node)
                        throw std::invalid_argument{"No other nodes in the swarm."};

                    return send_onion_request(
                            SnodeDestination{*random_node, info.swarm_pubkey},
                            info.body,
                            info.timeout,
                            true,
                            (*handle_response));
                }

                if (!response)
                    throw std::invalid_argument{"No response data."};

                auto response_json = nlohmann::json::parse(*response);
                auto snodes = response_json["snodes"];

                if (!snodes.is_array())
                    throw std::invalid_argument{"Invalid JSON response."};

                std::vector<session::network::service_node> swarm;

                for (auto snode : snodes)
                    swarm.emplace_back(snode);

                if (swarm.empty())
                    throw std::invalid_argument{"No snodes in the response."};

                // Update the cache
                net.call([this, swarm_pubkey = *info.swarm_pubkey, swarm]() mutable {
                    {
                        std::lock_guard lock{snode_cache_mutex};
                        swarm_cache[swarm_pubkey] = swarm;
                        need_swarm_write = true;
                        need_write = true;
                    }
                    snode_cache_cv.notify_one();
                });

                return (*handle_response)(false, false, status_code, response);
            } catch (...) {
            }

            // If we weren't able to retry or redirect the swarm then handle this like any other
            // error
            break;

        default: break;
    }

    // Check if we got an error specifying the specific node that failed
    auto updated_path = info.path;
    bool found_invalid_node = false;

    if (response && response->starts_with(node_not_found_prefix)) {
        std::string_view ed25519PublicKey{response->data() + node_not_found_prefix.size()};

        if (ed25519PublicKey.size() == 64 && oxenc::is_hex(ed25519PublicKey)) {
            session::onionreq::ed25519_pubkey edpk =
                    session::onionreq::ed25519_pubkey::from_hex(ed25519PublicKey);
            auto edpk_view = to_unsigned_sv(edpk.view());

            auto snode_it = std::find_if(
                    updated_path.nodes.begin(),
                    updated_path.nodes.end(),
                    [&edpk_view](const auto& node) { return node.view_remote_key() == edpk_view; });

            // Increment the failure count for the snode
            if (snode_it != updated_path.nodes.end()) {
                snode_it->failure_count += 1;
                found_invalid_node = true;

                if (snode_it->failure_count >= snode_failure_threshold)
                    snode_it->invalid = true;
            }
        }
    }

    // If we didn't find the specific node or the paths connection was closed then increment the
    // path failure count
    if (!found_invalid_node || !updated_path.conn_info.is_valid()) {
        // Increment the path failure count
        updated_path.failure_count += 1;

        // If the path has failed too many times we want to drop the guard snode
        // (marking it as invalid) and increment the failure count of each node in the
        // path
        if (updated_path.failure_count >= path_failure_threshold) {
            updated_path.nodes[0].invalid = true;

            for (auto& it : updated_path.nodes) {
                it.failure_count += 1;

                if (it.failure_count >= snode_failure_threshold)
                    it.invalid = true;
            }
        }
    }

    // Update the cache
    net.call([this,
              swarm_pubkey = info.swarm_pubkey,
              old_path = info.path,
              updated_path]() mutable {
        // Drop the path if it's guard node is invalid
        if (updated_path.nodes[0].invalid) {
            oxen::log::info(log_cat, "Dropping path.");
            paths.erase(std::remove(paths.begin(), paths.end(), old_path), paths.end());
        } else
            std::replace(paths.begin(), paths.end(), old_path, updated_path);

        // Update the network status if we've removed all paths
        if (paths.empty())
            update_status(ConnectionStatus::disconnected);

        {
            std::lock_guard lock{snode_cache_mutex};

            for (size_t i = 0; i < updated_path.nodes.size(); ++i)
                if (updated_path.nodes[i].invalid) {
                    snode_pool.erase(
                            std::remove(snode_pool.begin(), snode_pool.end(), old_path.nodes[i]),
                            snode_pool.end());

                    if (swarm_pubkey)
                        if (swarm_cache.contains(*swarm_pubkey)) {
                            auto updated_swarm = swarm_cache[*swarm_pubkey];
                            updated_swarm.erase(
                                    std::remove(
                                            updated_swarm.begin(),
                                            updated_swarm.end(),
                                            old_path.nodes[i]),
                                    updated_swarm.end());
                            swarm_cache[*swarm_pubkey] = updated_swarm;
                        }
                } else
                    std::replace(
                            snode_pool.begin(),
                            snode_pool.end(),
                            old_path.nodes[i],
                            updated_path.nodes[i]);

            need_pool_write = true;
            need_swarm_write = (swarm_pubkey && swarm_cache.contains(*swarm_pubkey));
            need_write = true;
        }
        snode_cache_cv.notify_one();
    });

    if (handle_response)
        (*handle_response)(false, false, status_code, response);
}

std::vector<network_service_node> convert_service_nodes(
        std::vector<session::network::service_node> nodes) {
    std::vector<network_service_node> converted_nodes;
    for (auto& node : nodes) {
        auto ed25519_pubkey_hex = oxenc::to_hex(node.view_remote_key());
        network_service_node converted_node;
        std::memcpy(converted_node.ip, node.host().data(), sizeof(converted_node.ip));
        strncpy(converted_node.x25519_pubkey_hex, node.x25519_pubkey.hex().c_str(), 64);
        strncpy(converted_node.ed25519_pubkey_hex, ed25519_pubkey_hex.c_str(), 64);
        converted_node.x25519_pubkey_hex[64] = '\0';   // Ensure null termination
        converted_node.ed25519_pubkey_hex[64] = '\0';  // Ensure null termination
        converted_node.quic_port = node.port();
        converted_node.failure_count = node.failure_count;
        converted_node.invalid = node.invalid;
        converted_nodes.push_back(converted_node);
    }

    return converted_nodes;
}

}  // namespace session::network

// MARK: C API

namespace {

inline session::network::Network& unbox(network_object* network_) {
    assert(network_ && network_->internals);
    return *static_cast<session::network::Network*>(network_->internals);
}

inline bool set_error(char* error, const std::exception& e) {
    if (!error)
        return false;

    std::string msg = e.what();
    if (msg.size() > 255)
        msg.resize(255);
    std::memcpy(error, msg.c_str(), msg.size() + 1);
    return false;
}

}  // namespace

extern "C" {

using namespace session::network;

LIBSESSION_C_API bool network_init(
        network_object** network,
        const char* cache_path_,
        bool use_testnet,
        bool pre_build_paths,
        char* error) {
    try {
        std::optional<std::string> cache_path;
        if (cache_path_)
            cache_path = cache_path_;

        auto n = std::make_unique<session::network::Network>(
                cache_path, use_testnet, pre_build_paths);
        auto n_object = std::make_unique<network_object>();

        n_object->internals = n.release();
        *network = n_object.release();
        return true;
    } catch (const std::exception& e) {
        return set_error(error, e);
    }
}

LIBSESSION_C_API void network_free(network_object* network) {
    delete network;
}

LIBSESSION_C_API void network_add_logger(
        network_object* network,
        void (*callback)(
                LOG_LEVEL lvl, const char* name, size_t namelen, const char* msg, size_t msglen)) {
    assert(callback);
    unbox(network).add_logger(
            [cb = std::move(callback)](
                    oxen::log::Level lvl, const std::string& name, const std::string& msg) {
                cb(static_cast<LOG_LEVEL>(lvl), name.c_str(), name.size(), msg.c_str(), msg.size());
            });
}

LIBSESSION_C_API void network_clear_cache(network_object* network) {
    unbox(network).clear_cache();
}

LIBSESSION_C_API void network_set_status_changed_callback(
        network_object* network, void (*callback)(CONNECTION_STATUS status, void* ctx), void* ctx) {
    if (!callback)
        unbox(network).status_changed = nullptr;
    else
        unbox(network).status_changed = [cb = std::move(callback), ctx](ConnectionStatus status) {
            cb(static_cast<CONNECTION_STATUS>(status), ctx);
        };
}

LIBSESSION_C_API void network_set_paths_changed_callback(
        network_object* network,
        void (*callback)(onion_request_path* paths, size_t paths_len, void* ctx),
        void* ctx) {
    if (!callback)
        unbox(network).paths_changed = nullptr;
    else
        unbox(network).paths_changed = [cb = std::move(callback),
                                        ctx](std::vector<std::vector<service_node>> paths) {
            std::vector<onion_request_path> c_paths;
            c_paths.reserve(paths.size());

            for (auto& nodes : paths) {
                auto c_nodes = session::network::convert_service_nodes(nodes);

                // Allocate memory that persists outside the loop
                network_service_node* c_nodes_array = new network_service_node[c_nodes.size()];
                std::copy(c_nodes.begin(), c_nodes.end(), c_nodes_array);

                onion_request_path c_path{c_nodes_array, c_nodes.size()};
                c_paths.emplace_back(c_path);
            }

            cb(c_paths.data(), c_paths.size(), ctx);

            // Free the allocated memory after cb is called
            for (auto& c_path : c_paths)
                delete[] c_path.nodes;
        };
}

LIBSESSION_C_API void network_get_swarm(
        network_object* network,
        const char* swarm_pubkey_hex,
        void (*callback)(network_service_node* nodes, size_t nodes_len, void*),
        void* ctx) {
    assert(swarm_pubkey_hex && callback);
    unbox(network).get_swarm(
            swarm_pubkey_hex, [cb = std::move(callback), ctx](std::vector<service_node> nodes) {
                auto c_nodes = session::network::convert_service_nodes(nodes);
                cb(c_nodes.data(), c_nodes.size(), ctx);
            });
}

LIBSESSION_C_API void network_get_random_nodes(
        network_object* network,
        uint16_t count,
        void (*callback)(network_service_node*, size_t, void*),
        void* ctx) {
    assert(callback);
    unbox(network).get_random_nodes(
            count, [cb = std::move(callback), ctx](std::vector<service_node> nodes) {
                auto c_nodes = session::network::convert_service_nodes(nodes);
                cb(c_nodes.data(), c_nodes.size(), ctx);
            });
}

LIBSESSION_C_API void network_send_onion_request_to_snode_destination(
        network_object* network,
        const network_service_node node,
        const unsigned char* body_,
        size_t body_size,
        const char* swarm_pubkey_hex,
        int64_t timeout_ms,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                void*),
        void* ctx) {
    assert(callback);

    try {
        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        std::optional<std::string> swarm_pubkey;
        if (swarm_pubkey_hex)
            swarm_pubkey = std::string(swarm_pubkey_hex);

        std::array<uint8_t, 4> ip;
        std::memcpy(ip.data(), node.ip, ip.size());

        unbox(network).send_onion_request(
                SnodeDestination{
                        {{node.ed25519_pubkey_hex, 64},
                         {node.x25519_pubkey_hex, 64},
                         "{}"_format(fmt::join(ip, ".")),
                         node.quic_port,
                         node.failure_count},
                        swarm_pubkey},
                body,
                std::chrono::milliseconds{timeout_ms},
                false,
                [callback, ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response) {
                    callback(
                            success, timeout, status_code, response->data(), response->size(), ctx);
                });
    } catch (const std::exception& e) {
        callback(false, false, -1, e.what(), std::strlen(e.what()), ctx);
    }
}

LIBSESSION_C_API void network_send_onion_request_to_server_destination(
        network_object* network,
        const network_server_destination server,
        const unsigned char* body_,
        size_t body_size,
        int64_t timeout_ms,
        void (*callback)(
                bool success,
                bool timeout,
                int16_t status_code,
                const char* response,
                size_t response_size,
                void*),
        void* ctx) {
    assert(callback);

    try {
        std::optional<std::vector<std::pair<std::string, std::string>>> headers;
        if (server.headers_size > 0) {
            headers = std::vector<std::pair<std::string, std::string>>{};

            for (size_t i = 0; i < server.headers_size; i++)
                headers->emplace_back(server.headers[i], server.header_values[i]);
        }

        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        unbox(network).send_onion_request(
                ServerDestination{
                        server.protocol,
                        server.host,
                        server.endpoint,
                        x25519_pubkey::from_hex({server.x25519_pubkey, 64}),
                        server.port,
                        headers,
                        server.method},
                body,
                std::chrono::milliseconds{timeout_ms},
                false,
                [callback, ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::optional<std::string> response) {
                    callback(
                            success, timeout, status_code, response->data(), response->size(), ctx);
                });
    } catch (const std::exception& e) {
        callback(false, false, -1, e.what(), std::strlen(e.what()), ctx);
    }
}

}  // extern "C"