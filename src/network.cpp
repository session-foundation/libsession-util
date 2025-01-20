#include "session/network.hpp"

#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>

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

#include "session/blinding.hpp"
#include "session/ed25519.hpp"
#include "session/export.h"
#include "session/file.hpp"
#include "session/network.h"
#include "session/onionreq/builder.h"
#include "session/onionreq/builder.hpp"
#include "session/onionreq/key_types.hpp"
#include "session/onionreq/response_parser.hpp"
#include "session/util.hpp"

using namespace oxen;
using namespace session::onionreq;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {

    inline auto cat = log::Cat("network");

    class load_cache_exception : public std::runtime_error {
      public:
        load_cache_exception(std::string message) : std::runtime_error(message) {}
    };
    class status_code_exception : public std::runtime_error {
      public:
        int16_t status_code;
        std::vector<std::pair<std::string, std::string>> headers;

        status_code_exception(
                int16_t status_code,
                std::vector<std::pair<std::string, std::string>> headers,
                std::string message) :
                std::runtime_error(message), status_code{status_code}, headers{headers} {}
    };

    constexpr int16_t error_network_suspended = -10001;
    constexpr int16_t error_building_onion_request = -10002;
    constexpr int16_t error_path_build_timeout = -10003;

    const std::pair<std::string, std::string> content_type_plain_text = {
            "Content-Type", "text/plain; charset=UTF-8"};
    const std::pair<std::string, std::string> content_type_json = {
            "Content-Type", "application/json"};

    // The amount of time the snode cache can be used before it needs to be refreshed/
    constexpr auto snode_cache_expiration_duration = 2h;

    // The smallest size the snode cache can get to before we need to fetch more.
    constexpr size_t min_snode_cache_count = 12;

    // The number of snodes to use to refresh the cache.
    constexpr int num_snodes_to_refresh_cache_from = 3;

    // The number of snodes (including the guard snode) in a path.
    constexpr uint8_t path_size = 3;

    // The number of times a path can fail before it's replaced.
    constexpr uint16_t path_failure_threshold = 3;

    // The number of times a snode can fail before it's replaced.
    constexpr uint16_t snode_failure_threshold = 3;

    // The frequency to check if queued requests have timed out due to a pending path build
    constexpr auto queued_request_path_build_timeout_frequency = 250ms;

    const fs::path default_cache_path{u8"."}, file_testnet{u8"testnet"},
            file_snode_pool{u8"snode_pool"};
    const std::vector<fs::path> legacy_files{
            u8"snode_pool_updated", u8"swarm", u8"snode_failure_counts"};

    constexpr auto node_not_found_prefix = "502 Bad Gateway\n\nNext node not found: "sv;
    constexpr auto node_not_found_prefix_no_status = "Next node not found: "sv;
    constexpr auto ALPN = "oxenstorage"sv;
    constexpr auto ONION = "onion_req";

    enum class PathSelectionBehaviour {
        random,
        new_or_least_busy,
    };

    std::string path_type_name(PathType path_type, bool single_path_mode) {
        if (single_path_mode)
            return "single_path";

        switch (path_type) {
            case PathType::standard: return "standard";
            case PathType::upload: return "upload";
            case PathType::download: return "download";
        }
        return "standard";  // Default
    }

    // The mininum number of paths we want to maintain
    uint8_t min_path_count(PathType path_type, bool single_path_mode) {
        if (single_path_mode)
            return 1;

        switch (path_type) {
            case PathType::standard: return 2;
            case PathType::upload: return 2;
            case PathType::download: return 2;
        }
        return 2;  // Default
    }

    PathSelectionBehaviour path_selection_behaviour(PathType path_type) {
        switch (path_type) {
            case PathType::standard: return PathSelectionBehaviour::random;
            case PathType::upload: return PathSelectionBehaviour::new_or_least_busy;
            case PathType::download: return PathSelectionBehaviour::new_or_least_busy;
        }
        return PathSelectionBehaviour::random;  // Default
    }

    /// Converts a string such as "1.2.3" to a vector of ints {1,2,3}.  Throws if something
    /// in/around the .'s isn't parseable as an integer.
    std::vector<int> parse_version(std::string_view vers, bool trim_trailing_zero = true) {
        auto v_s = session::split(vers, ".");
        std::vector<int> result;
        for (const auto& piece : v_s)
            if (!quic::parse_int(piece, result.emplace_back()))
                throw std::invalid_argument{"Invalid version"};

        // Remove any trailing `0` values (but ensure we at least end up with a "0" version)
        if (trim_trailing_zero)
            while (result.size() > 1 && result.back() == 0)
                result.pop_back();

        return result;
    }

    service_node node_from_json(nlohmann::json json) {
        auto pk_ed = json["pubkey_ed25519"].get<std::string_view>();
        if (pk_ed.size() != 64 || !oxenc::is_hex(pk_ed))
            throw std::invalid_argument{
                    "Invalid service node json: pubkey_ed25519 is not a valid, hex pubkey"};

        // When parsing a node from JSON it'll generally be from the 'get_swarm` endpoint or a 421
        // error neither of which contain the `storage_server_version` - luckily we don't need the
        // version for these two cases so can just default it to `0`
        std::vector<int> storage_server_version = {0};
        if (json.contains("storage_server_version")) {
            if (json["storage_server_version"].is_array()) {
                if (json["storage_server_version"].size() > 0) {
                    // Convert the version to a string and parse it back into a version code to
                    // ensure the version formats remain consistent throughout
                    storage_server_version = json["storage_server_version"].get<std::vector<int>>();
                    storage_server_version =
                            parse_version("{}"_format(fmt::join(storage_server_version, ".")));
                }
            } else
                storage_server_version =
                        parse_version(json["storage_server_version"].get<std::string>());
        }

        std::string ip;
        if (json.contains("public_ip"))
            ip = json["public_ip"].get<std::string>();
        else
            ip = json["ip"].get<std::string>();

        uint16_t port;
        if (json.contains("storage_lmq_port"))
            port = json["storage_lmq_port"].get<uint16_t>();
        else
            port = json["port_omq"].get<uint16_t>();

        swarm_id_t swarm_id = INVALID_SWARM_ID;
        if (json.contains("swarm_id"))
            swarm_id = json["swarm_id"].get<swarm_id_t>();

        return {oxenc::from_hex(pk_ed), storage_server_version, swarm_id, ip, port};
    }

    service_node node_from_disk(std::string_view str, bool can_ignore_version = false) {
        // Format is "{ip}|{port}|{version}|{ed_pubkey}|{swarm_id}"
        auto parts = split(str, "|");
        if (parts.size() != 5)
            throw std::invalid_argument("Invalid service node serialisation: {}"_format(str));
        if (parts[3].size() != 64 || !oxenc::is_hex(parts[3]))
            throw std::invalid_argument{
                    "Invalid service node serialisation: pubkey is not hex or has wrong size"};

        uint16_t port;
        if (!quic::parse_int(parts[1], port))
            throw std::invalid_argument{"Invalid service node serialization: invalid port"};

        std::vector<int> storage_server_version = parse_version(parts[2]);
        if (!can_ignore_version && storage_server_version == std::vector<int>{0})
            throw std::invalid_argument{"Invalid service node serialization: invalid version"};

        swarm_id_t swarm_id = INVALID_SWARM_ID;
        quic::parse_int(parts[4], swarm_id);

        return {
                oxenc::from_hex(parts[3]),  // ed25519_pubkey
                storage_server_version,     // storage_server_version
                swarm_id,                   // swarm_id
                std::string(parts[0]),      // ip
                port,                       // port
        };
    }

    const std::vector<service_node> seed_nodes_testnet{
            node_from_disk("144.76.164.202|35400|2.8.0|"
                           "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9|"sv)};
    const std::vector<service_node> seed_nodes_mainnet{
            node_from_disk("144.76.164.202|20200|2.8.0|"
                           "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef|"sv),
            node_from_disk("88.99.102.229|20201|2.8.0|"
                           "1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef7f971e88ab144c1a7ce|"sv),
            node_from_disk("195.16.73.17|20202|2.8.0|"
                           "1f202f00f4d2d4acc01e20773999a291cf3e3136c325474d159814e06199919f|"sv),
            node_from_disk("104.194.11.120|20203|2.8.0|"
                           "1f303f1d7523c46fa5398826740d13282d26b5de90fbae5749442f66afb6d78b|"sv),
            node_from_disk("104.194.8.115|20204|2.8.0|"
                           "1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad15a35e16b50c28db7b0|"sv)};
    constexpr auto file_server = "filev2.getsession.org"sv;
    constexpr auto file_server_pubkey =
            "da21e1d886c6fbaea313f75298bd64aab03a97ce985b46bb2dad9f2089c8ee59"sv;

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

    std::string node_to_disk(service_node node) {
        // Format is "{ip}|{port}|{version}|{ed_pubkey}|{swarm_id}"
        auto ed25519_pubkey_hex = oxenc::to_hex(node.view_remote_key());

        return fmt::format(
                "{}|{}|{}|{}|{}",
                node.host(),
                node.port(),
                "{}"_format(fmt::join(node.storage_server_version, ".")),
                ed25519_pubkey_hex,
                node.swarm_id);
    }

    session::onionreq::x25519_pubkey compute_xpk(ustring_view ed25519_pk) {
        std::array<unsigned char, 32> xpk;
        if (0 != crypto_sign_ed25519_pk_to_curve25519(xpk.data(), ed25519_pk.data()))
            throw std::runtime_error{
                    "An error occured while attempting to convert Ed25519 pubkey to X25519; "
                    "is the pubkey valid?"};
        return session::onionreq::x25519_pubkey::from_bytes({xpk.data(), 32});
    }

    std::string consume_string(oxenc::bt_dict_consumer dict, std::string_view key) {
        if (!dict.skip_until(key))
            throw std::invalid_argument{
                    "Unable to find entry in dict for key '" + std::string(key) + "'"};
        return dict.consume_string();
    }

    template <typename IntType>
    auto consume_integer(oxenc::bt_dict_consumer dict, std::string_view key) {
        if (!dict.skip_until(key))
            throw std::invalid_argument{
                    "Unable to find entry in dict for key '" + std::string(key) + "'"};
        return dict.next_integer<IntType>().second;
    }
}  // namespace

namespace detail {
    swarm_id_t pubkey_to_swarm_space(const session::onionreq::x25519_pubkey& pk) {
        swarm_id_t res = 0;
        for (size_t i = 0; i < 4; i++) {
            swarm_id_t buf;
            std::memcpy(&buf, pk.data() + i * 8, 8);
            res ^= buf;
        }
        oxenc::big_to_host_inplace(res);

        return res;
    }

    std::vector<std::pair<swarm_id_t, std::vector<service_node>>> generate_swarms(
            std::vector<service_node> nodes) {
        std::vector<std::pair<swarm_id_t, std::vector<service_node>>> result;
        std::unordered_map<uint64_t, std::vector<service_node>> _grouped_nodes;

        for (const auto& node : nodes)
            _grouped_nodes[node.swarm_id].push_back(node);

        for (auto& [swarm_id, nodes] : _grouped_nodes)
            result.emplace_back(swarm_id, std::move(nodes));

        std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
            return a.first < b.first;
        });
        return result;
    }

    std::optional<service_node> node_for_destination(network_destination destination) {
        if (auto* dest = std::get_if<service_node>(&destination))
            return *dest;

        return std::nullopt;
    }

    session::onionreq::x25519_pubkey pubkey_for_destination(network_destination destination) {
        if (auto* dest = std::get_if<service_node>(&destination))
            return compute_xpk(dest->view_remote_key());

        if (auto* dest = std::get_if<ServerDestination>(&destination))
            return dest->x25519_pubkey;

        throw std::runtime_error{"Invalid destination."};
    }

    nlohmann::json get_service_nodes_params(std::optional<int> limit) {
        nlohmann::json params{
                {"active_only", true},
                {"fields",
                 {{"public_ip", true},
                  {"pubkey_ed25519", true},
                  {"storage_lmq_port", true},
                  {"storage_server_version", true},
                  {"swarm_id", true}}}};

        if (limit)
            params["limit"] = *limit;

        return params;
    }

    std::vector<service_node> process_get_service_nodes_response(
            oxenc::bt_list_consumer result_bencode) {
        std::vector<service_node> result;
        result_bencode.skip_value();  // Skip the status code (already validated)
        auto response_dict = result_bencode.consume_dict_consumer();
        response_dict.skip_until("result");

        auto result_dict = response_dict.consume_dict_consumer();
        result_dict.skip_until("service_node_states");

        // Process the node list
        auto node = result_dict.consume_list_consumer();

        while (!node.is_finished()) {
            auto node_consumer = node.consume_dict_consumer();
            auto pubkey_ed25519 = oxenc::from_hex(consume_string(node_consumer, "pubkey_ed25519"));
            auto public_ip = consume_string(node_consumer, "public_ip");
            auto storage_lmq_port = consume_integer<uint16_t>(node_consumer, "storage_lmq_port");

            std::vector<int> storage_server_version;
            node_consumer.skip_until("storage_server_version");
            auto version_consumer = node_consumer.consume_list_consumer();
            auto swarm_id = consume_integer<uint64_t>(node_consumer, "swarm_id");

            while (!version_consumer.is_finished()) {
                storage_server_version.emplace_back(version_consumer.consume_integer<int>());
            }

            result.emplace_back(
                    pubkey_ed25519, storage_server_version, swarm_id, public_ip, storage_lmq_port);
        }

        return result;
    }

    std::vector<service_node> process_get_service_nodes_response(nlohmann::json response_json) {
        if (!response_json.contains("result") || !response_json["result"].is_object())
            throw std::runtime_error{"JSON missing result field."};

        nlohmann::json result_json = response_json["result"];
        if (!result_json.contains("service_node_states") ||
            !result_json["service_node_states"].is_array())
            throw std::runtime_error{"JSON missing service_node_states field."};

        std::vector<service_node> result;
        for (auto& snode : result_json["service_node_states"])
            result.emplace_back(node_from_json(snode));

        return result;
    }

    void log_retry_result_if_needed(request_info info, bool single_path_mode) {
        if (!info.retry_reason)
            return;

        // For debugging purposes if the error was a redirect retry then
        // we want to log that the retry was successful as this will
        // help identify how often we are receiving incorrect errors
        auto reason = "unknown retry";

        switch (*info.retry_reason) {
            case request_info::RetryReason::none: reason = "unknown retry"; break;
            case request_info::RetryReason::redirect: reason = "421 retry"; break;
            case request_info::RetryReason::decryption_failure: reason = "decryption error"; break;
            case request_info::RetryReason::redirect_swarm_refresh:
                reason = "421 swarm refresh retry";
                break;
        }

        log::info(
                cat,
                "Received valid response after {} in request {} for {}.",
                reason,
                info.request_id,
                path_type_name(info.path_type, single_path_mode));
    }

    std::vector<network_service_node> convert_service_nodes(
            std::vector<session::network::service_node> nodes) {
        std::vector<network_service_node> converted_nodes;
        for (auto& node : nodes) {
            auto ed25519_pubkey_hex = oxenc::to_hex(node.view_remote_key());
            auto ipv4 = node.to_ipv4();
            network_service_node converted_node;
            converted_node.ip[0] = (ipv4.addr >> 24) & 0xFF;
            converted_node.ip[1] = (ipv4.addr >> 16) & 0xFF;
            converted_node.ip[2] = (ipv4.addr >> 8) & 0xFF;
            converted_node.ip[3] = ipv4.addr & 0xFF;
            strncpy(converted_node.ed25519_pubkey_hex, ed25519_pubkey_hex.c_str(), 64);
            converted_node.ed25519_pubkey_hex[64] = '\0';  // Ensure null termination
            converted_node.quic_port = node.port();
            converted_nodes.push_back(converted_node);
        }

        return converted_nodes;
    }

    ServerDestination convert_server_destination(const network_server_destination server) {
        std::optional<std::vector<std::pair<std::string, std::string>>> headers;
        if (server.headers_size > 0) {
            headers = std::vector<std::pair<std::string, std::string>>{};

            for (size_t i = 0; i < server.headers_size; i++)
                headers->emplace_back(server.headers[i], server.header_values[i]);
        }

        return ServerDestination{
                server.protocol,
                server.host,
                server.endpoint,
                x25519_pubkey::from_hex({server.x25519_pubkey, 64}),
                server.port,
                headers,
                server.method};
    }
}  // namespace detail

request_info request_info::make(
        onionreq::network_destination _dest,
        std::optional<ustring> _original_body,
        std::optional<session::onionreq::x25519_pubkey> _swarm_pk,
        std::chrono::milliseconds _request_timeout,
        std::optional<std::chrono::milliseconds> _request_and_path_build_timeout,
        PathType _type,
        std::optional<std::string> _req_id,
        std::optional<std::string> _ep,
        std::optional<ustring> _body) {
    return request_info{
            _req_id.value_or("R-{}"_format(random::random_base32(4))),
            std::move(_dest),
            _ep.value_or(ONION),
            std::move(_body),
            std::move(_original_body),
            std::move(_swarm_pk),
            _type,
            _request_timeout,
            _request_and_path_build_timeout};
}

std::string onion_path::to_string() const {
    std::vector<std::string> node_descriptions;
    std::transform(
            nodes.begin(),
            nodes.end(),
            std::back_inserter(node_descriptions),
            [](const service_node& node) { return node.to_string(); });

    return "{}"_format(fmt::join(node_descriptions, ", "));
}

// MARK: Initialization

Network::Network(
        std::optional<fs::path> cache_path,
        bool use_testnet,
        bool single_path_mode,
        bool pre_build_paths) :
        use_testnet{use_testnet},
        should_cache_to_disk{cache_path},
        single_path_mode{single_path_mode},
        cache_path{cache_path.value_or(default_cache_path)} {
    // Load the cache from disk and start the disk write thread
    if (should_cache_to_disk) {
        load_cache_from_disk();
        disk_write_thread = std::thread{&Network::disk_write_thread_loop, this};
    }

    // Kick off a separate thread to build paths (may as well kick this off early)
    if (pre_build_paths)
        for (int i = 0; i < min_path_count(PathType::standard, single_path_mode); ++i) {
            auto path_id = "P-{}"_format(random::random_base32(4));
            in_progress_path_builds[path_id] = PathType::standard;
            net.call_soon([this, path_id] { build_path(path_id, PathType::standard); });
        }
}

Network::~Network() {
    // We need to explicitly close the connections at the start of the destructor to prevent ban
    // memory errors due to complex logic with the quic::Network instance
    destroyed = true;
    _close_connections();

    {
        std::lock_guard lock{snode_cache_mutex};
        shut_down_disk_thread = true;
    }
    update_disk_cache_throttled(true);
    if (disk_write_thread.joinable())
        disk_write_thread.join();
}

// MARK: Cache Management

void Network::load_cache_from_disk() {
    try {
        // If the cache is for the wrong network then delete everything
        auto testnet_stub = cache_path / file_testnet;
        if (use_testnet != fs::exists(testnet_stub) && fs::exists(testnet_stub))
            fs::remove_all(cache_path);

        // Remove any legacy files (don't want to leave old data around)
        for (const auto& path : legacy_files) {
            auto path_to_remove = cache_path / path;
            fs::remove_all(path_to_remove);
        }

        // If we are using testnet then create a file to indicate that
        if (use_testnet)
            write_whole_file(testnet_stub);

        // Load the snode pool
        if (auto pool_path = cache_path / file_snode_pool; fs::exists(pool_path)) {
            auto ftime = fs::last_write_time(pool_path);
            last_snode_cache_update =
                    std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                            ftime - fs::file_time_type::clock::now() +
                            std::chrono::system_clock::now());

            auto file = open_for_reading(pool_path);
            std::vector<service_node> loaded_cache;
            std::string line;
            auto invalid_entries = 0;

            while (std::getline(file, line)) {
                try {
                    loaded_cache.push_back(node_from_disk(line));
                } catch (...) {
                    ++invalid_entries;
                }
            }

            if (invalid_entries > 0)
                log::warning(cat, "Skipped {} invalid entries in snode cache.", invalid_entries);

            snode_cache = loaded_cache;
            all_swarms = detail::generate_swarms(loaded_cache);
        }

        log::info(
                cat,
                "Loaded cache of {} snodes, {} swarms.",
                snode_cache.size(),
                all_swarms.size());
    } catch (const std::exception& e) {
        log::error(cat, "Failed to load snode cache, will rebuild ({}).", e.what());

        if (fs::exists(cache_path))
            fs::remove_all(cache_path);
    }
}

void Network::update_disk_cache_throttled(bool force_immediate_write) {
    // If we are forcing an immediate write then just notify the disk write thread and reset the
    // pending write flag
    if (force_immediate_write) {
        snode_cache_cv.notify_one();
        has_pending_disk_write = false;
        return;
    }

    if (has_pending_disk_write)
        return;

    has_pending_disk_write = true;
    net.call_later(1s, [this]() {
        snode_cache_cv.notify_one();
        has_pending_disk_write = false;
    });
}

void Network::disk_write_thread_loop() {
    std::unique_lock lock{snode_cache_mutex};
    while (true) {
        snode_cache_cv.wait(
                lock, [this] { return need_write || need_clear_cache || shut_down_disk_thread; });

        if (need_write) {
            // Make a local copy so that we can release the lock and not
            // worry about other threads wanting to change things
            auto snode_cache_write = snode_cache;

            lock.unlock();
            {
                try {
                    // Create the cache directories if needed
                    fs::create_directories(cache_path);

                    // If we are using testnet then create a file to indicate that
                    if (use_testnet) {
                        auto testnet_stub = cache_path / file_testnet;
                        write_whole_file(testnet_stub);
                    }

                    // Save the snode pool to disk
                    auto pool_path = cache_path / file_snode_pool, pool_tmp = pool_path;
                    pool_tmp += u8"_new";

                    {
                        std::stringstream ss;
                        for (auto& snode : snode_cache_write)
                            ss << node_to_disk(snode) << '\n';

                        std::ofstream file(pool_tmp, std::ios::binary);
                        file << ss.rdbuf();
                    }

                    fs::rename(pool_tmp, pool_path);
                    need_write = false;

                    log::debug(cat, "Finished writing snode cache to disk.");
                } catch (const std::exception& e) {
                    log::error(cat, "Failed to write snode cache: {}", e.what());
                }
            }
            lock.lock();
        }
        if (need_clear_cache) {
            snode_cache = {};

            lock.unlock();
            if (fs::exists(cache_path))
                fs::remove_all(cache_path);
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
        update_disk_cache_throttled(true);
    });
}

size_t Network::snode_cache_size() {
    return net.call_get([this]() -> size_t { return snode_cache.size(); });
}

// MARK: Connection

void Network::suspend() {
    net.call([this]() mutable {
        suspended = true;
        close_connections();
        log::info(cat, "Suspended.");
    });
}

void Network::resume() {
    net.call([this]() mutable {
        suspended = false;
        log::info(cat, "Resumed.");
    });
}

void Network::close_connections() {
    net.call([this]() mutable { _close_connections(); });
}

void Network::_close_connections() {
    // Explicitly reset the endpoint to close all connections
    endpoint.reset();

    // Cancel any pending requests (they can't succeed once the connection is closed)
    for (const auto& [path_type, path_type_requests] : request_queue)
        for (const auto& [info, callback] : path_type_requests)
            callback(
                    false,
                    false,
                    error_network_suspended,
                    {content_type_plain_text},
                    "Network is suspended.");

    // Clear all storage of requests, paths and connections so that we are in a fresh state on
    // relaunch
    request_queue.clear();
    paths.clear();
    path_build_queue.clear();
    paths_pending_drop.clear();
    unused_connections.clear();
    in_progress_connections.clear();
    snode_refresh_results.reset();
    current_snode_cache_refresh_request_id = std::nullopt;

    update_status(ConnectionStatus::disconnected);
    log::info(cat, "Closed all connections.");
}

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

std::chrono::milliseconds Network::retry_delay(
        int num_failures, std::chrono::milliseconds max_delay) {
    return std::chrono::milliseconds(std::min(
            max_delay.count(),
            static_cast<typename std::chrono::milliseconds::rep>(100 * std::pow(2, num_failures))));
}

std::shared_ptr<quic::Endpoint> Network::get_endpoint() {
    return net.call_get([this]() mutable {
        if (!endpoint)
            endpoint = net.endpoint(quic::Address{"0.0.0.0", 0}, quic::opt::alpns{ALPN});

        return endpoint;
    });
}

// MARK: Request Queues and Path Building

size_t Network::min_snode_cache_size() const {
    if (!seed_node_cache_size)
        return min_snode_cache_count;

    // If the seed node cache size is somehow smaller than `min_snode_cache_count` (ie. Testnet
    // having issues) then the minimum size should be the full cache size (minus enough to build a
    // path) or at least the size of a path
    auto min_path_size = static_cast<size_t>(path_size);
    return std::min(
            std::max(min_path_size, *seed_node_cache_size - min_path_size), min_snode_cache_count);
}

std::vector<service_node> Network::get_unused_nodes() {
    if (snode_cache.size() < min_snode_cache_size())
        return {};

    // Exclude any IPs that are already in use from existing paths
    std::vector<quic::ipv4> node_ips_to_exlude = all_path_ips();

    // Exclude unused connections
    for (const auto& conn_info : unused_connections)
        node_ips_to_exlude.emplace_back(conn_info.node.to_ipv4());

    // Exclude in progress connections
    for (const auto& [request_id, node] : in_progress_connections)
        node_ips_to_exlude.emplace_back(node.to_ipv4());

    // Exclude pending requests
    for (const auto& [path_type, path_type_requests] : request_queue)
        for (const auto& [info, callback] : path_type_requests)
            if (auto* dest = std::get_if<service_node>(&info.destination))
                node_ips_to_exlude.emplace_back(dest->to_ipv4());

    // Exclude any nodes which have surpassed the failure threshold
    for (const auto& [node_string, failure_count] : snode_failure_counts)
        if (failure_count >= snode_failure_threshold) {
            size_t colon_pos = node_string.find(':');

            if (colon_pos != std::string::npos)
                node_ips_to_exlude.emplace_back(quic::ipv4{node_string.substr(0, colon_pos)});
            else
                node_ips_to_exlude.emplace_back(quic::ipv4{node_string});
        }

    // Populate the unused nodes with any nodes in the cache which shouldn't be excluded
    std::vector<service_node> result;

    if (node_ips_to_exlude.empty())
        result = snode_cache;
    else
        std::copy_if(
                snode_cache.begin(),
                snode_cache.end(),
                std::back_inserter(result),
                [&node_ips_to_exlude](const auto& node) {
                    return std::find(
                                   node_ips_to_exlude.begin(),
                                   node_ips_to_exlude.end(),
                                   node.to_ipv4()) == node_ips_to_exlude.end();
                });

    // Shuffle the `result` so anything that uses it would get random nodes
    CSRNG rng;
    std::shuffle(result.begin(), result.end(), rng);

    return result;
}

void Network::establish_connection(
        std::string id,
        service_node target,
        std::optional<std::chrono::milliseconds> timeout,
        std::function<void(connection_info info, std::optional<std::string> error)> callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, id);
    auto currently_suspended = net.call_get([this]() -> bool { return suspended; });

    // If the network is currently suspended then don't try to open a connection
    if (currently_suspended)
        return callback(
                {target, std::make_shared<size_t>(0), nullptr, nullptr}, "Network is suspended.");

    auto conn_key_pair = ed25519::ed25519_key_pair();
    auto creds = quic::GNUTLSCreds::make_from_ed_seckey(from_unsigned_sv(conn_key_pair.second));
    auto cb_called = std::make_shared<std::once_flag>();
    auto cb = std::make_shared<std::function<void(connection_info, std::optional<std::string>)>>(
            std::move(callback));
    auto conn_promise = std::promise<std::shared_ptr<oxen::quic::connection_interface>>();
    auto conn_future = conn_promise.get_future().share();
    auto handshake_timeout =
            timeout ? std::optional{quic::opt::handshake_timeout{
                              std::chrono::duration_cast<std::chrono::nanoseconds>(*timeout)}}
                    : std::nullopt;

    auto c = get_endpoint()->connect(
            target,
            creds,
            quic::opt::keep_alive{10s},
            handshake_timeout,
            [this, id, target, cb, cb_called, conn_future](quic::connection_interface&) mutable {
                log::trace(cat, "Connection established for {}.", id);

                // Just in case, call it within a `net.call`
                net.call([&] {
                    std::call_once(*cb_called, [&]() {
                        if (cb) {
                            auto conn = conn_future.get();
                            (*cb)({target,
                                   std::make_shared<size_t>(0),
                                   conn,
                                   conn->open_stream<quic::BTRequestStream>()},
                                  std::nullopt);
                            cb.reset();
                        }
                    });
                });
            },
            [this, target, id, cb, cb_called, conn_future](
                    quic::connection_interface& conn, uint64_t error_code) mutable {
                if (error_code == static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT))
                    log::info(
                            cat,
                            "Unable to establish connection to {} for {}.",
                            target.to_string(),
                            id);
                else
                    log::info(cat, "Connection to {} closed for {}.", target.to_string(), id);

                // Just in case, call it within a `net.call`
                net.call([&] {
                    // Trigger the callback first before updating the paths in case this was
                    // triggered when try to establish a connection
                    std::call_once(*cb_called, [&]() {
                        if (cb) {
                            (*cb)({target, std::make_shared<size_t>(0), nullptr, nullptr},
                                  std::nullopt);
                            cb.reset();
                        }
                    });

                    // If the Network instance has been `destroyed` (ie. it's destructor has been
                    // called) then don't do any of the following logic as it'll likely result in
                    // undefined behaviours and crashes
                    if (destroyed)
                        return;

                    // Remove the connection from `unused_connection` if present
                    std::erase_if(unused_connections, [&conn, &target](auto& unused_conn) {
                        return (unused_conn.node == target && unused_conn.conn &&
                                unused_conn.conn->reference_id() == conn.reference_id());
                    });

                    // If this connection is being used in an existing path then we should drop it
                    // (as the path is no longer valid)
                    for (const auto& [path_type, paths_for_type] : paths) {
                        for (const auto& path : paths_for_type) {
                            if (!path.nodes.empty() && path.nodes.front() == target &&
                                path.conn_info.conn &&
                                conn.reference_id() == path.conn_info.conn->reference_id()) {
                                drop_path_when_empty(id, path_type, path);
                                break;
                            }
                        }
                    }

                    // Since a connection was closed we should also clear any pending path drops
                    // in case this connection was one of those
                    clear_empty_pending_path_drops();

                    // If the connection failed with a handshake timeout then the node is
                    // unreachable, either due to a device network issue or because the node
                    // is down so set the failure count to the failure threshold so it won't
                    // be used for subsequent requests
                    if (error_code == static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT))
                        snode_failure_counts[target.to_string()] = snode_failure_threshold;
                });
            });

    conn_promise.set_value(c);
}

void Network::establish_and_store_connection(std::string path_id) {
    // If we are suspended then don't try to establish a new connection
    if (suspended)
        return;

    // If we haven't set a connection status yet then do so now
    if (status == ConnectionStatus::unknown)
        update_status(ConnectionStatus::connecting);

    // Re-populate the unused nodes if it ends up being empty
    if (unused_nodes.empty())
        unused_nodes = get_unused_nodes();

    // If there aren't enough unused nodes then trigger a cache refresh
    if (unused_nodes.size() < min_snode_cache_size()) {
        log::trace(
                cat,
                "Unable to establish new connection due to lack of unused nodes, refreshing snode "
                "cache ({}).",
                path_id);
        return net.call_soon([this, path_id]() { refresh_snode_cache(path_id); });
    }

    // Otherwise check if it's been too long since the last cache update and, if so, trigger a
    // refresh
    auto cache_lifetime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - last_snode_cache_update);

    if (cache_lifetime < 0s || cache_lifetime > snode_cache_expiration_duration)
        net.call_soon([this]() { refresh_snode_cache(); });

    // If there are no in progress connections then reset the failure count
    if (in_progress_connections.empty())
        connection_failures = 0;

    // Grab a node from the `unused_nodes` list to establish a connection to
    auto target_node = unused_nodes.back();
    unused_nodes.pop_back();

    // Try to establish a new connection to the target (this has a 3s handshake timeout as we
    // wouldn't want to use any nodes which take longer than that anyway)
    log::info(cat, "Establishing connection to {} for {}.", target_node.to_string(), path_id);
    in_progress_connections.emplace(path_id, target_node);

    establish_connection(
            path_id,
            target_node,
            3s,
            [this, target_node, path_id](connection_info info, std::optional<std::string>) {
                // If we failed to get a connection then try again after a delay (may as well try
                // indefinitely because there is no way to recover from this issue)
                if (!info.is_valid()) {
                    connection_failures++;
                    auto connection_retry_delay = retry_delay(connection_failures);
                    log::error(
                            cat,
                            "Failed to connect to {}, will try another after {}ms.",
                            target_node.to_string(),
                            connection_retry_delay.count());
                    return net.call_later(connection_retry_delay, [this, path_id]() {
                        establish_and_store_connection(path_id);
                    });
                }

                // We were able to connect to the node so add it to the unused_connections queue
                log::info(cat, "Connection to {} valid for {}.", target_node.to_string(), path_id);
                unused_connections.emplace_back(info);

                // Kick off the next pending path build since we now have a valid connection
                if (!path_build_queue.empty()) {
                    in_progress_path_builds[path_id] = path_build_queue.front();
                    net.call_soon([this, path_type = path_build_queue.front(), path_id]() {
                        build_path(path_id, path_type);
                    });
                    path_build_queue.pop_front();
                }

                // If there are still pending path builds but no in progress connections then kick
                // off enough additional connections for remaining builds (this shouldn't happen but
                // better to be safe and avoid a situation where a path build gets orphaned)
                if (!path_build_queue.empty() && in_progress_connections.empty())
                    for ([[maybe_unused]] const auto& _ : path_build_queue)
                        net.call_soon([this]() {
                            auto conn_id = "EC-{}"_format(random::random_base32(4));
                            establish_and_store_connection(conn_id);
                        });
            });
}

void Network::refresh_snode_cache_complete(std::vector<service_node> nodes) {
    // Shuffle the nodes so we don't have a specific order
    CSRNG rng;
    std::shuffle(nodes.begin(), nodes.end(), rng);

    // Update the disk cache if the snode pool was updated
    {
        std::lock_guard lock{snode_cache_mutex};
        snode_cache = nodes;
        last_snode_cache_update = std::chrono::system_clock::now();
        need_write = true;
    }
    update_disk_cache_throttled();

    // Reset the cache refresh state
    current_snode_cache_refresh_request_id = std::nullopt;
    snode_cache_refresh_failure_count = 0;
    in_progress_snode_cache_refresh_count = 0;
    unused_snode_refresh_nodes = std::nullopt;
    snode_refresh_results.reset();

    // Reset the snode failure counts (assume if the snode refresh includes
    // nodes then they are valid)
    snode_failure_counts.clear();

    // Since we've updated the snode cache the swarm cache could be invalid
    // so we need to regenerate it (the resulting `all_swarms` needs to be
    // stored in ascending order as it is required for the logic to find the
    // appropriate swarm for a given pubkey)
    all_swarms.clear();
    swarm_cache.clear();
    all_swarms = detail::generate_swarms(nodes);

    // Run any post-refresh processes
    for (const auto& callback : after_snode_cache_refresh)
        net.call_soon([cb = std::move(callback)]() { cb(); });
    after_snode_cache_refresh.clear();

    // Resume any queued path builds
    for (const auto& path_type : path_build_queue) {
        auto path_id = "P-{}"_format(random::random_base32(4));
        in_progress_path_builds[path_id] = path_type;
        net.call_soon([this, path_type, path_id]() { build_path(path_id, path_type); });
    }
    path_build_queue.clear();
}

void Network::refresh_snode_cache_from_seed_nodes(std::string request_id, bool reset_unused_nodes) {
    if (suspended) {
        log::info(cat, "Ignoring snode cache refresh as network is suspended ({}).", request_id);
        return;
    }

    // Only allow a single cache refresh at a time (this gets cleared in `_close_connections` so if
    // it happens to loop after going to, and returning from, the background a subsequent refresh
    // won't be blocked)
    if (current_snode_cache_refresh_request_id &&
        current_snode_cache_refresh_request_id != request_id) {
        log::info(
                cat,
                "Snode cache refresh from seed node {} ignored as it doesn't match the current "
                "refresh id ({}).",
                request_id,
                current_snode_cache_refresh_request_id.value_or("NULL"));
        return;
    }

    // If the unused nodes is empty then reset it (if we are refreshing from seed nodes it means the
    // local cache is not usable so we are just going to have to call this endlessly until it works)
    if (reset_unused_nodes || !unused_snode_refresh_nodes || unused_snode_refresh_nodes->empty()) {
        log::info(
                cat,
                "Existing cache is insufficient, refreshing from seed nodes ({}).",
                request_id);

        // Shuffle to ensure we pick random nodes to fetch from
        CSRNG rng;
        unused_snode_refresh_nodes = (use_testnet ? seed_nodes_testnet : seed_nodes_mainnet);
        std::shuffle(unused_snode_refresh_nodes->begin(), unused_snode_refresh_nodes->end(), rng);
    }

    auto target_node = unused_snode_refresh_nodes->back();
    unused_snode_refresh_nodes->pop_back();

    establish_connection(
            request_id,
            target_node,
            3s,
            [this, request_id](connection_info info, std::optional<std::string>) {
                // If we failed to get a connection then try again after a delay (may as well try
                // indefinitely because there is no way to recover from this issue)
                if (!info.is_valid()) {
                    snode_cache_refresh_failure_count++;
                    auto cache_refresh_retry_delay = retry_delay(snode_cache_refresh_failure_count);
                    log::error(
                            cat,
                            "Failed to connect to seed node to refresh snode cache, will retry "
                            "after {}ms ({}).",
                            cache_refresh_retry_delay.count(),
                            request_id);
                    return net.call_later(cache_refresh_retry_delay, [this, request_id]() {
                        refresh_snode_cache_from_seed_nodes(request_id, false);
                    });
                }

                get_service_nodes(
                        request_id,
                        info,
                        std::nullopt,
                        [this, request_id](
                                std::vector<service_node> nodes, std::optional<std::string> error) {
                            // If we got no nodes then we will need to try again
                            if (nodes.empty()) {
                                snode_cache_refresh_failure_count++;
                                auto cache_refresh_retry_delay =
                                        retry_delay(snode_cache_refresh_failure_count);
                                log::error(
                                        cat,
                                        "Failed to retrieve nodes from seed node to refresh cache "
                                        "due to error: {}, will retry after {}ms ({}).",
                                        error.value_or("Unknown Error"),
                                        cache_refresh_retry_delay.count(),
                                        request_id);
                                return net.call_later(
                                        cache_refresh_retry_delay, [this, request_id]() {
                                            refresh_snode_cache_from_seed_nodes(request_id, false);
                                        });
                            }

                            log::info(
                                    cat,
                                    "Refreshing snode cache from seed nodes completed with {} "
                                    "nodes ({}).",
                                    nodes.size(),
                                    request_id);
                            seed_node_cache_size = nodes.size();
                            refresh_snode_cache_complete(nodes);
                        });
            });
}

void Network::refresh_snode_cache(std::optional<std::string> existing_request_id) {
    auto request_id = existing_request_id.value_or("RSC-{}"_format(random::random_base32(4)));

    if (suspended) {
        log::info(cat, "Ignoring snode cache refresh as network is suspended ({}).", request_id);
        return;
    }

    // Only allow a single cache refresh at a time (this gets cleared in `_close_connections` so if
    // it happens to loop after going to, and returning from, the background a subsequent refresh
    // won't be blocked)
    if (current_snode_cache_refresh_request_id &&
        current_snode_cache_refresh_request_id != request_id) {
        log::info(
                cat,
                "Snode cache refresh {} ignored due to in progress refresh ({}).",
                request_id,
                current_snode_cache_refresh_request_id.value_or("NULL"));
        return;
    }

    // We are starting a new cache refresh so store an identifier for it (we also initialise
    // `snode_refresh_results` so we can use it to track the results from the different requests)
    if (!current_snode_cache_refresh_request_id) {
        log::info(cat, "Refreshing snode cache ({}).", request_id);
        current_snode_cache_refresh_request_id = request_id;
        snode_refresh_results = std::make_shared<std::vector<std::vector<service_node>>>();
    }

    // If we don't have enough nodes in the unused nodes then refresh it
    if (unused_nodes.size() < min_snode_cache_size())
        unused_nodes = get_unused_nodes();

    // If we still don't have enough nodes in the unused nodes it likely means we didn't
    // have enough nodes in the cache so instead just fetch from the seed nodes (which is
    // a trusted source so we can update the cache from a single response)
    if (unused_nodes.size() < min_snode_cache_size())
        return refresh_snode_cache_from_seed_nodes(request_id, true);

    // Target an unused node and increment the in progress refresh counter
    auto target_node = unused_nodes.back();
    unused_nodes.pop_back();
    in_progress_snode_cache_refresh_count++;

    // If there are still more concurrent refresh_snode_cache requests we want to trigger then
    // trigger the next one to run in the next run loop
    if (in_progress_snode_cache_refresh_count < num_snodes_to_refresh_cache_from)
        net.call_soon([this, request_id]() { refresh_snode_cache(request_id); });

    // Prepare and send the request to retrieve service nodes
    nlohmann::json payload{
            {"method", "oxend_request"},
            {"params",
             {{"endpoint", "get_service_nodes"},
              {"params", detail::get_service_nodes_params(std::nullopt)}}},
    };
    auto info = request_info::make(
            target_node,
            ustring{quic::to_usv(payload.dump())},
            std::nullopt,
            quic::DEFAULT_TIMEOUT,
            std::nullopt,
            PathType::standard,
            request_id);
    _send_onion_request(
            info,
            [this, request_id](
                    bool success,
                    bool timeout,
                    int16_t,
                    std::vector<std::pair<std::string, std::string>>,
                    std::optional<std::string> response) {
                // If the 'snode_refresh_results' value doesn't exist it means we have already
                // completed/cancelled this snode cache refresh and have somehow gotten into an
                // invalid state, so just ignore this request
                if (!snode_refresh_results) {
                    log::warning(
                            cat,
                            "Ignoring snode cache response after cache update already completed "
                            "({}).",
                            request_id);
                    return;
                }

                try {
                    if (!success || timeout || !response)
                        throw std::runtime_error{response.value_or("Unknown error.")};

                    nlohmann::json response_json = nlohmann::json::parse(*response);
                    std::vector<service_node> result =
                            detail::process_get_service_nodes_response(response_json);
                    snode_refresh_results->emplace_back(result);

                    // Update the in progress request count
                    in_progress_snode_cache_refresh_count--;
                } catch (const std::exception& e) {
                    // The request failed so increment the failure counter and retry after a short
                    // delay
                    snode_cache_refresh_failure_count++;

                    auto cache_refresh_retry_delay = retry_delay(snode_cache_refresh_failure_count);
                    log::error(
                            cat,
                            "Failed to retrieve nodes from one target when refreshing cache due to "
                            "error: {} Will try another target after {}ms ({}).",
                            e.what(),
                            cache_refresh_retry_delay.count(),
                            request_id);
                    return net.call_later(cache_refresh_retry_delay, [this, request_id]() {
                        refresh_snode_cache(request_id);
                    });
                }

                // If we haven't received all results then do nothing
                if (snode_refresh_results->size() != num_snodes_to_refresh_cache_from) {
                    log::info(
                            cat,
                            "Received snode cache refresh result {}/{} ({}).",
                            snode_refresh_results->size(),
                            num_snodes_to_refresh_cache_from,
                            request_id);
                    return;
                }

                auto any_nodes_request_failed = std::any_of(
                        snode_refresh_results->begin(),
                        snode_refresh_results->end(),
                        [](const auto& n) { return n.empty(); });

                // If the current cache is still usable just send a warning and don't bother
                // retrying
                if (any_nodes_request_failed) {
                    log::warning(cat, "Failed to refresh snode cache ({}).", request_id);
                    current_snode_cache_refresh_request_id = std::nullopt;
                    snode_cache_refresh_failure_count = 0;
                    in_progress_snode_cache_refresh_count = 0;
                    snode_refresh_results.reset();
                    return;
                }

                // Sort the vectors (so make it easier to find the intersection)
                for (auto& nodes : *snode_refresh_results)
                    std::stable_sort(nodes.begin(), nodes.end());

                auto nodes = (*snode_refresh_results)[0];

                // If we triggered multiple requests then get the intersection of all vectors
                if (snode_refresh_results->size() > 1) {
                    for (size_t i = 1; i < snode_refresh_results->size(); ++i) {
                        std::vector<service_node> temp;
                        std::set_intersection(
                                nodes.begin(),
                                nodes.end(),
                                (*snode_refresh_results)[i].begin(),
                                (*snode_refresh_results)[i].end(),
                                std::back_inserter(temp),
                                [](const auto& a, const auto& b) { return a == b; });
                        nodes = std::move(temp);
                    }
                }

                log::info(
                        cat,
                        "Refreshing snode cache completed with {} nodes ({}).",
                        nodes.size(),
                        request_id);
                refresh_snode_cache_complete(nodes);
            });
}

void Network::build_path(std::string path_id, PathType path_type) {
    if (suspended) {
        log::info(cat, "Ignoring build_path call as network is suspended.");
        return;
    }

    auto path_name = path_type_name(path_type, single_path_mode);

    // If we don't have an unused connection for the first hop then enqueue the path build and
    // establish a new connection
    if (unused_connections.empty()) {
        log::info(
                cat,
                "No unused connections available to build {} path, creating new connection for {}.",
                path_name,
                path_id);
        path_build_queue.emplace_back(path_type);
        in_progress_path_builds.erase(path_id);
        return net.call_soon([this, path_id]() { establish_and_store_connection(path_id); });
    }

    // Reset the unused nodes list if it's too small
    if (unused_nodes.size() < path_size)
        unused_nodes = get_unused_nodes();

    // If we still don't have enough unused nodes then we need to refresh the cache
    if (unused_nodes.size() < path_size) {
        log::info(
                cat, "Re-queing {} path build due to insufficient nodes ({}).", path_name, path_id);
        path_build_failures = 0;
        path_build_queue.emplace_back(path_type);
        in_progress_path_builds.erase(path_id);
        return net.call_soon([this]() { refresh_snode_cache(); });
    }

    // Build the path
    log::info(cat, "Building {} path ({}).", path_name, path_id);
    in_progress_path_builds[path_id] = path_type;

    auto conn_info = std::move(unused_connections.front());
    unused_connections.pop_front();
    std::vector<service_node> path_nodes = {conn_info.node};

    while (path_nodes.size() < path_size) {
        if (unused_nodes.empty()) {
            // Log the error and try build again after a slight delay
            log::info(
                    cat,
                    "Unable to build {} path due to lack of suitable unused nodes ({}).",
                    path_name,
                    path_id);

            // Delay the next path build attempt based on the error we received
            path_build_failures++;
            unused_connections.push_front(std::move(conn_info));
            auto delay = retry_delay(path_build_failures);
            net.call_later(delay, [this, path_id, path_type]() { build_path(path_id, path_type); });
            return;
        }

        // Grab the next unused node to continue building the path
        auto node = unused_nodes.back();
        unused_nodes.pop_back();

        // Ensure we don't put two nodes with the same IP into the same path
        auto snode_with_ip_it = std::find_if(
                path_nodes.begin(), path_nodes.end(), [&node](const auto& existing_node) {
                    return existing_node.to_ipv4() == node.to_ipv4();
                });

        if (snode_with_ip_it == path_nodes.end())
            path_nodes.push_back(node);
    }

    // Store the new path
    auto path = onion_path{path_id, std::move(conn_info), path_nodes, 0};
    paths[path_type].emplace_back(path);
    in_progress_path_builds.erase(path_id);

    // Log that a path was built
    log::info(
            cat,
            "Built new onion request path [{}], now have {} {} path(s) ({}).",
            path.to_string(),
            paths[path_type].size(),
            path_name,
            path_id);

    // If the connection info is valid and it's a standard path then update the
    // connection status to connected
    if (path_type == PathType::standard) {
        update_status(ConnectionStatus::connected);

        // If a paths_changed callback was provided then call it
        if (paths_changed) {
            std::vector<std::vector<service_node>> raw_paths;
            for (const auto& path : paths[path_type])
                raw_paths.emplace_back(path.nodes);

            paths_changed(raw_paths);
        }
    }

    // Remove the nodes from unused_nodes which have the same IPs as nodes in
    // the final path
    std::vector<oxen::quic::ipv4> path_ips;
    for (const auto& node : path_nodes)
        path_ips.emplace_back(node.to_ipv4());

    std::erase_if(unused_nodes, [&path_ips](const auto& node) {
        return std::find(path_ips.begin(), path_ips.end(), node.to_ipv4()) != path_ips.end();
    });

    // If there are pending requests which this path is valid for then resume them
    std::erase_if(request_queue[path_type], [this, &path](const auto& request) {
        if (!find_valid_path(request.first, {path}))
            return false;

        net.call_soon([this, info = request.first, cb = std::move(request.second)]() {
            _send_onion_request(std::move(info), std::move(cb));
        });
        return true;
    });

    // If there are still pending requests and there are no pending path builds for them then kick
    // off a subsequent path build in an effort to resume the remaining requests
    if (!request_queue[path_type].empty()) {
        auto additional_path_id = "P-{}"_format(random::random_base32(4));
        in_progress_path_builds[additional_path_id] = path_type;
        net.call_soon([this, path_type, additional_path_id] {
            build_path(additional_path_id, path_type);
        });
    } else
        request_queue.erase(path_type);
}

std::optional<onion_path> Network::find_valid_path(
        const request_info info, const std::vector<onion_path> paths) {
    if (paths.empty())
        return std::nullopt;

    // Only include paths with valid connections as options
    std::vector<onion_path> possible_paths;
    std::copy_if(
            paths.begin(), paths.end(), std::back_inserter(possible_paths), [&](const auto& path) {
                return path.is_valid();
            });

    // If the request destination is a node then only select a path that doesn't include the IP of
    // the destination
    if (auto target = detail::node_for_destination(info.destination)) {
        std::vector<onion_path> ip_excluded_paths;
        std::copy_if(
                possible_paths.begin(),
                possible_paths.end(),
                std::back_inserter(ip_excluded_paths),
                [excluded_ip = target->to_ipv4()](const auto& path) {
                    return std::none_of(
                            path.nodes.begin(), path.nodes.end(), [&excluded_ip](const auto& node) {
                                return node.to_ipv4() == excluded_ip;
                            });
                });

        if (single_path_mode && ip_excluded_paths.empty())
            log::warning(
                    cat,
                    "Path should have been excluded due to matching IP for {} but network is in "
                    "single path mode.",
                    info.request_id);
        else
            possible_paths = ip_excluded_paths;
    }

    if (possible_paths.empty())
        return std::nullopt;

    // Randomise the possible paths (if all paths are equal for the PathSelectionBehaviour then we
    // want a random one to be selected)
    CSRNG rng;
    std::shuffle(possible_paths.begin(), possible_paths.end(), rng);

    // Select from the possible paths based on the desired behaviour
    auto behaviour = path_selection_behaviour(info.path_type);
    switch (behaviour) {
        case PathSelectionBehaviour::new_or_least_busy: {
            auto min_num_paths = min_path_count(info.path_type, single_path_mode);
            std::sort(
                    possible_paths.begin(), possible_paths.end(), [](const auto& a, const auto& b) {
                        return a.num_pending_requests() < b.num_pending_requests();
                    });

            // If we have already have the min number of paths for this path type, or there is
            // a path with no pending requests then return the first path
            if (paths.size() >= min_num_paths || possible_paths.front().num_pending_requests() == 0)
                return possible_paths.front();

            // Otherwise we want to build a new path (for this PathSelectionBehaviour the assuption
            // is that it'd be faster to build a new path and send the request along that rather
            // than use an existing path)
            return std::nullopt;
        }

        // Random is the default behaviour
        case PathSelectionBehaviour::random: return possible_paths.front();
        default: return possible_paths.front();
    }
};

void Network::build_path_if_needed(PathType path_type, bool found_path) {
    const auto current_paths = paths[path_type];

    // In `single_path_mode` we never build additional paths
    if (current_paths.size() > 0 && single_path_mode)
        return;

    // We only want to enqueue a new path build if:
    // - We don't have the minimum number of paths for the specified type
    // - We don't have any pending builds
    // - The current paths are unsuitable for the request
    auto min_paths = min_path_count(path_type, single_path_mode);

    // If we have enough existing paths and found a valid path then no need to build more paths
    if (found_path && current_paths.size() >= min_paths)
        return;

    // Get the number pending paths
    auto queued = std::count(path_build_queue.begin(), path_build_queue.end(), path_type);
    auto in_progress = std::count_if(
            in_progress_path_builds.begin(),
            in_progress_path_builds.end(),
            [&path_type](const auto& build) { return build.second == path_type; });
    auto pending_paths = (queued + in_progress);

    // If we don't have enough current + pending paths, or the request couldn't be sent then
    // kick off a new path build
    if ((current_paths.size() + pending_paths) < min_paths || (!found_path && pending_paths == 0)) {
        auto path_id = "P-{}"_format(random::random_base32(4));
        build_path(path_id, path_type);
    }
}

// MARK: Direct Requests

void Network::get_service_nodes(
        std::string request_id,
        connection_info conn_info,
        std::optional<int> limit,
        std::function<void(std::vector<service_node> nodes, std::optional<std::string> error)>
                callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);

    if (!conn_info.is_valid())
        return callback({}, "Connection is not valid.");

    oxenc::bt_dict_producer payload;
    payload.append("endpoint", "get_service_nodes");
    payload.append("params", detail::get_service_nodes_params(limit).dump());

    conn_info.add_pending_request();
    conn_info.stream->command(
            "oxend_request",
            payload.view(),
            [this, request_id, conn_info, cb = std::move(callback)](quic::message resp) {
                log::trace(cat, "{} got response for {}.", __PRETTY_FUNCTION__, request_id);
                std::vector<service_node> result;
                conn_info.remove_pending_request();

                try {
                    auto [status_code, body] = validate_response(resp, true);
                    oxenc::bt_list_consumer result_bencode{body};
                    result = detail::process_get_service_nodes_response(result_bencode);
                } catch (const std::exception& e) {
                    return cb({}, e.what());
                }

                // Output the result
                cb(result, std::nullopt);

                // After completing a request we should try to clear any pending path drops (just in
                // case this request was the final one on a pending path drop)
                if (!conn_info.has_pending_requests())
                    clear_empty_pending_path_drops();
            });
}

// MARK: Swarm Management

void Network::get_swarm(
        session::onionreq::x25519_pubkey swarm_pubkey,
        std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, swarm_pubkey.hex());

    net.call([this, swarm_pubkey, cb = std::move(callback)]() {
        // If we have a cached swarm then return it
        auto cached_swarm = swarm_cache[swarm_pubkey.hex()];
        if (!cached_swarm.second.empty())
            return cb(cached_swarm.first, cached_swarm.second);

        // If we have no snode cache or no swarms then we need to rebuild the cache (which will also
        // rebuild the swarms) and run this request again
        if (snode_cache.empty() || all_swarms.empty()) {
            after_snode_cache_refresh.emplace_back([this, swarm_pubkey, cb = std::move(cb)]() {
                get_swarm(swarm_pubkey, std::move(cb));
            });
            return net.call_soon([this]() { refresh_snode_cache(); });
        }

        // If there is only a single swarm then return it
        if (all_swarms.size() == 1)
            return cb(all_swarms.front().first, all_swarms.front().second);

        // Generate a swarm_id for the pubkey
        const swarm_id_t swarm_id = detail::pubkey_to_swarm_space(swarm_pubkey);

        // Find the right boundary, i.e. first swarm with swarm_id >= res
        auto right_it = std::lower_bound(
                all_swarms.begin(), all_swarms.end(), swarm_id, [](const auto& s, uint64_t v) {
                    return s.first < v;
                });

        if (right_it == all_swarms.end())
            // res is > the top swarm_id, meaning it is big and in the wrapping space between last
            // and first elements.
            right_it = all_swarms.begin();

        // Our "left" is the one just before that (with wraparound, if right is the first swarm)
        auto left_it = std::prev(right_it == all_swarms.begin() ? all_swarms.end() : right_it);

        uint64_t dright = right_it->first - swarm_id;
        uint64_t dleft = swarm_id - left_it->first;
        auto swarm = &*(dright < dleft ? right_it : left_it);

        // Update the cache with the result
        log::info(
                cat,
                "Found swarm with {} nodes for {}, adding to cache.",
                swarm->second.size(),
                swarm_pubkey.hex());
        swarm_cache[swarm_pubkey.hex()] = *swarm;
        cb(swarm->first, swarm->second);
    });
}

// MARK: Node Retrieval

void Network::get_random_nodes(
        uint16_t count, std::function<void(std::vector<service_node> nodes)> callback) {
    auto request_id = "R-{}"_format(random::random_base32(4));
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, request_id);

    net.call([this, request_id, count, cb = std::move(callback)]() mutable {
        // If we don't have sufficient unused nodes then regenerate it
        if (unused_nodes.size() < count)
            unused_nodes = get_unused_nodes();

        // If we still don't have sufficient nodes then we need to refresh the snode cache
        if (unused_nodes.size() < count) {
            after_snode_cache_refresh.emplace_back(
                    [this, count, cb = std::move(cb)]() { get_random_nodes(count, cb); });
            return net.call_soon([this]() { refresh_snode_cache(); });
        }

        // Otherwise callback with the requested random number of nodes
        auto random_nodes =
                std::vector<service_node>(unused_nodes.begin(), unused_nodes.begin() + count);
        unused_nodes.erase(unused_nodes.begin(), unused_nodes.begin() + count);
        cb(random_nodes);
    });
}

// MARK: Request Handling

void Network::check_request_queue_timeouts(std::optional<std::string> request_timeout_id_) {
    // If the network is suspended (or destroyed) then don't bother checking for timeouts
    if (suspended || destroyed)
        return;

    // If there is an existing timeout checking loop then we don't want to start a second
    if (request_timeout_id != request_timeout_id_)
        return;

    // If there wasn't an existing loop id then set it here
    if (!request_timeout_id)
        request_timeout_id = "RT-{}"_format(random::random_base32(4));

    // Timeout and remove any pending requests which should timeout based on path build time
    auto has_remaining_timeout_requests = false;
    auto time_now = std::chrono::system_clock::now();

    for (auto& [path_type, requests_for_path] : request_queue)
        std::erase_if(
                requests_for_path,
                [&has_remaining_timeout_requests, &time_now](const auto& request) {
                    // If the request doesn't have a path build timeout then ignore it
                    if (!request.first.request_and_path_build_timeout)
                        return false;

                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            time_now - request.first.creation_time);

                    if (duration > *request.first.request_and_path_build_timeout) {
                        request.second(
                                false,
                                true,
                                error_path_build_timeout,
                                {content_type_plain_text},
                                "Timed out waiting for path build.");
                        return true;
                    }

                    has_remaining_timeout_requests = true;
                    return false;
                });

    // If there are no more timeout requests then stop looping here
    if (!has_remaining_timeout_requests) {
        request_timeout_id = std::nullopt;
        return;
    }

    // Otherwise schedule the next check
    net.call_later(queued_request_path_build_timeout_frequency, [this]() {
        check_request_queue_timeouts(request_timeout_id);
    });
}

void Network::send_request(
        request_info info, connection_info conn_info, network_response_callback_t handle_response) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, info.request_id);

    if (!conn_info.is_valid())
        return handle_response(
                false, false, -1, {content_type_plain_text}, "Network is unreachable.");

    quic::bstring_view payload{};

    if (info.body)
        payload = convert_sv<std::byte>(*info.body);

    // Calculate the remaining timeout
    std::chrono::milliseconds timeout = info.request_timeout;

    if (info.request_and_path_build_timeout) {
        auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now() - info.creation_time);

        timeout = *info.request_and_path_build_timeout - elapsed_time;

        // If the timeout was somehow negative then just fail the request (no point continuing if
        // we have already timed out)
        if (timeout < std::chrono::milliseconds(0))
            return handle_response(
                    false,
                    true,
                    error_path_build_timeout,
                    {content_type_plain_text},
                    "Path Build Timed Out.");
    }

    conn_info.add_pending_request();
    conn_info.stream->command(
            info.endpoint,
            payload,
            timeout,
            [this, info, conn_info, cb = std::move(handle_response)](quic::message resp) {
                log::trace(cat, "{} got response for {}.", __PRETTY_FUNCTION__, info.request_id);

                std::pair<uint16_t, std::string> result;
                auto& [status_code, body] = result;
                conn_info.remove_pending_request();

                try {
                    result = validate_response(resp, false);
                } catch (const status_code_exception& e) {
                    return handle_errors(
                            info,
                            conn_info,
                            resp.timed_out,
                            e.status_code,
                            e.headers,
                            e.what(),
                            cb);
                } catch (const std::exception& e) {
                    return handle_errors(
                            info,
                            conn_info,
                            resp.timed_out,
                            -1,
                            {content_type_plain_text},
                            e.what(),
                            cb);
                }

                cb(true, false, status_code, {}, body);

                // After completing a request we should try to clear any pending path drops (just in
                // case this request was the final one on a pending path drop)
                if (!conn_info.has_pending_requests())
                    clear_empty_pending_path_drops();
            });
}

void Network::send_onion_request(
        onionreq::network_destination destination,
        std::optional<ustring> body,
        std::optional<session::onionreq::x25519_pubkey> swarm_pubkey,
        network_response_callback_t handle_response,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> request_and_path_build_timeout,
        PathType type) {
    _send_onion_request(
            request_info::make(
                    std::move(destination),
                    std::move(body),
                    std::move(swarm_pubkey),
                    request_timeout,
                    request_and_path_build_timeout,
                    type),
            std::move(handle_response));
}

void Network::_send_onion_request(request_info info, network_response_callback_t handle_response) {
    auto path_name = path_type_name(info.path_type, single_path_mode);
    log::trace(cat, "{} called for {} path ({}).", __PRETTY_FUNCTION__, path_name, info.request_id);

    // Try to retrieve a valid path for this request, if we can't get one then add the request to
    // the queue to be run once a path for it has successfully been built
    auto path = net.call_get([this, info]() {
        auto result = find_valid_path(info, paths[info.path_type]);
        net.call_soon([this, path_type = info.path_type, found_path = result.has_value()]() {
            build_path_if_needed(path_type, found_path);
        });
        return result;
    });

    if (!path) {
        return net.call([this, info = std::move(info), cb = std::move(handle_response)]() {
            // If the network is suspended then fail immediately
            if (suspended)
                return cb(
                        false,
                        false,
                        error_network_suspended,
                        {content_type_plain_text},
                        "Network is suspended.");

            request_queue[info.path_type].emplace_back(std::move(info), std::move(cb));

            // If the request has a path_build_timeout then start the timeout check loop
            if (info.request_and_path_build_timeout)
                net.call_later(queued_request_path_build_timeout_frequency, [this]() {
                    check_request_queue_timeouts();
                });
        });
    }

    log::trace(cat, "{} got {} path for {}.", __PRETTY_FUNCTION__, path_name, info.request_id);

    // Construct the onion request
    auto builder = Builder();
    try {
        builder.set_destination(info.destination);
        builder.set_destination_pubkey(detail::pubkey_for_destination(info.destination));

        for (auto& node : path->nodes)
            builder.add_hop(
                    {ed25519_pubkey::from_bytes(node.view_remote_key()),
                     compute_xpk(node.view_remote_key())});

        // Update the `request_info` to have the onion request payload
        auto payload = builder.generate_payload(info.original_body);
        info.body = builder.build(payload);
    } catch (const std::exception& e) {
        return handle_response(
                false, false, error_building_onion_request, {content_type_plain_text}, e.what());
    }

    // Actually send the request
    send_request(
            info,
            path->conn_info,
            [this,
             builder = std::move(builder),
             info,
             path = *path,
             cb = std::move(handle_response)](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                log::trace(cat, "{} got response for {}.", __PRETTY_FUNCTION__, info.request_id);

                // If the request was reported as a failure or a timeout then we
                // will have already handled the errors so just trigger the callback
                if (!success || timeout)
                    return cb(success, timeout, status_code, headers, response);

                try {
                    // Ensure the response is long enough to be processed, if not
                    // then handle it as an error
                    if (!ResponseParser::response_long_enough(builder.enc_type, response->size()))
                        throw status_code_exception{
                                status_code,
                                {content_type_plain_text},
                                "Response is too short to be an onion request response: " +
                                        *response};

                    // Otherwise, process the onion request response
                    std::tuple<
                            int16_t,
                            std::vector<std::pair<std::string, std::string>>,
                            std::optional<std::string>>
                            processed_response;

                    // The SnodeDestination runs via V3 onion requests and the
                    // ServerDestination runs via V4
                    if (std::holds_alternative<service_node>(info.destination))
                        processed_response = process_v3_onion_response(builder, *response);
                    else if (std::holds_alternative<ServerDestination>(info.destination))
                        processed_response = process_v4_onion_response(builder, *response);

                    // If we got a non 2xx status code, return the error
                    auto& [processed_status_code, processed_headers, processed_body] =
                            processed_response;
                    if (processed_status_code < 200 || processed_status_code > 299)
                        throw status_code_exception{
                                processed_status_code,
                                {content_type_plain_text},
                                processed_body.value_or("Request returned "
                                                        "non-success status "
                                                        "code.")};

                    // For debugging purposes we want to add a log if this was a successful request
                    // after we did an automatic retry
                    detail::log_retry_result_if_needed(info, single_path_mode);

                    // Try process the body in case it was a batch request which
                    // failed
                    std::optional<nlohmann::json> results;
                    if (processed_body) {
                        try {
                            auto processed_body_json = nlohmann::json::parse(*processed_body);

                            // If it wasn't a batch/sequence request then assume it
                            // was successful and return no error
                            if (processed_body_json.contains("results"))
                                results = processed_body_json["results"];
                        } catch (...) {
                        }
                    }

                    // If there was no 'results' array then it wasn't a batch
                    // request so we can stop here and return
                    if (!results)
                        return cb(
                                true,
                                false,
                                processed_status_code,
                                processed_headers,
                                processed_body);

                    // Otherwise we want to check if all of the results have the
                    // same status code and, if so, handle that failure case
                    // (default the 'error_body' to the 'processed_body' in case we
                    // don't get an explicit error)
                    int16_t single_status_code = -1;
                    std::vector<std::pair<std::string, std::string>> single_headers = {
                            content_type_plain_text};
                    std::optional<std::string> error_body = processed_body;
                    for (const auto& result : results->items()) {
                        if (result.value().contains("code") && result.value()["code"].is_number() &&
                            (single_status_code == -1 ||
                             result.value()["code"].get<int16_t>() != single_status_code))
                            single_status_code = result.value()["code"].get<int16_t>();
                        else {
                            // Either there was no code, or the code was different
                            // from a former code in which case there wasn't an
                            // individual detectable error (ie. it needs specific
                            // handling) so return no error
                            single_status_code = 200;
                            break;
                        }

                        if (result.value().contains("headers")) {
                            single_headers = {};
                            auto header_vals = result.value()["headers"];

                            for (auto it = header_vals.begin(); it != header_vals.end(); ++it)
                                single_headers.emplace_back(it.key(), it.value());
                        }

                        if (result.value().contains("body") && result.value()["body"].is_string())
                            error_body = result.value()["body"].get<std::string>();
                    }

                    // If all results contained the same error then handle it as a
                    // single error
                    if (single_status_code < 200 || single_status_code > 299)
                        throw status_code_exception{
                                single_status_code,
                                single_headers,
                                error_body.value_or("Sub-request returned "
                                                    "non-success status code.")};

                    // Otherwise some requests succeeded and others failed so
                    // succeed with the processed data
                    return cb(
                            true, false, processed_status_code, processed_headers, processed_body);
                } catch (const status_code_exception& e) {
                    handle_errors(
                            info, path.conn_info, false, e.status_code, e.headers, e.what(), cb);
                } catch (const std::exception& e) {
                    handle_errors(
                            info,
                            path.conn_info,
                            false,
                            -1,
                            {content_type_plain_text},
                            e.what(),
                            cb);
                }
            });
}

void Network::upload_file_to_server(
        ustring data,
        onionreq::ServerDestination server,
        std::optional<std::string> file_name,
        network_response_callback_t handle_response,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> request_and_path_build_timeout) {
    std::vector<std::pair<std::string, std::string>> headers;
    std::unordered_set<std::string> existing_keys;

    if (server.headers)
        for (auto& [key, value] : *server.headers) {
            headers.emplace_back(key, value);
            existing_keys.insert(key);
        }

    // Add the required headers if they weren't provided
    if (existing_keys.find("Content-Disposition") == existing_keys.end())
        headers.emplace_back(
                "Content-Disposition",
                (file_name ? "attachment; filename=\"{}\""_format(*file_name) : "attachment"));

    if (existing_keys.find("Content-Type") == existing_keys.end())
        headers.emplace_back("Content-Type", "application/octet-stream");

    send_onion_request(
            ServerDestination{
                    server.protocol,
                    server.host,
                    server.endpoint,
                    server.x25519_pubkey,
                    server.port,
                    headers,
                    server.method},
            data,
            std::nullopt,
            handle_response,
            request_timeout,
            request_and_path_build_timeout,
            PathType::upload);
}

void Network::download_file(
        std::string_view download_url,
        session::onionreq::x25519_pubkey x25519_pubkey,
        network_response_callback_t handle_response,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> request_and_path_build_timeout) {
    const auto& [proto, host, port, path] = parse_url(download_url);

    if (!path)
        throw std::invalid_argument{"Invalid URL provided: Missing path"};

    download_file(
            ServerDestination{proto, host, *path, x25519_pubkey, port, std::nullopt, "GET"},
            handle_response,
            request_timeout,
            request_and_path_build_timeout);
}

void Network::download_file(
        onionreq::ServerDestination server,
        network_response_callback_t handle_response,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> request_and_path_build_timeout) {
    send_onion_request(
            server,
            std::nullopt,
            std::nullopt,
            handle_response,
            request_timeout,
            request_and_path_build_timeout,
            PathType::download);
}

void Network::get_client_version(
        Platform platform,
        onionreq::ed25519_seckey seckey,
        network_response_callback_t handle_response,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> request_and_path_build_timeout) {
    std::string endpoint;

    switch (platform) {
        case Platform::android: endpoint = "/session_version?platform=android"; break;
        case Platform::desktop: endpoint = "/session_version?platform=desktop"; break;
        case Platform::ios: endpoint = "/session_version?platform=ios"; break;
    }

    // Generate the auth signature
    auto blinded_keys = blind_version_key_pair(to_unsigned_sv(seckey.view()));
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                             (std::chrono::system_clock::now()).time_since_epoch())
                             .count();
    auto signature = blind_version_sign(to_unsigned_sv(seckey.view()), platform, timestamp);
    auto pubkey = x25519_pubkey::from_hex(file_server_pubkey);
    std::string blinded_pk_hex;
    blinded_pk_hex.reserve(66);
    blinded_pk_hex += "07";
    oxenc::to_hex(
            blinded_keys.first.begin(),
            blinded_keys.first.end(),
            std::back_inserter(blinded_pk_hex));

    auto headers = std::vector<std::pair<std::string, std::string>>{};
    headers.emplace_back("X-FS-Pubkey", blinded_pk_hex);
    headers.emplace_back("X-FS-Timestamp", "{}"_format(timestamp));
    headers.emplace_back("X-FS-Signature", oxenc::to_base64(signature));

    send_onion_request(
            ServerDestination{
                    "http", std::string(file_server), endpoint, pubkey, 80, headers, "GET"},
            std::nullopt,
            pubkey,
            handle_response,
            request_timeout,
            request_and_path_build_timeout,
            PathType::standard);
}

// MARK: Response Handling

std::tuple<int16_t, std::vector<std::pair<std::string, std::string>>, std::optional<std::string>>
Network::process_v3_onion_response(Builder builder, std::string response) {
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
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;

    if (result_json.contains("status_code") && result_json["status_code"].is_number())
        status_code = result_json["status_code"].get<int16_t>();
    else if (result_json.contains("status") && result_json["status"].is_number())
        status_code = result_json["status"].get<int16_t>();
    else
        throw std::runtime_error{"Invalid JSON response, missing required status_code field."};

    if (result_json.contains("headers")) {
        auto header_vals = result_json["headers"];

        for (auto it = header_vals.begin(); it != header_vals.end(); ++it)
            headers.emplace_back(it.key(), it.value());
    }

    if (result_json.contains("body") && result_json["body"].is_string())
        body = result_json["body"].get<std::string>();
    else
        body = result_json.dump();

    return {status_code, headers, body};
}

std::tuple<int16_t, std::vector<std::pair<std::string, std::string>>, std::optional<std::string>>
Network::process_v4_onion_response(Builder builder, std::string response) {
    ustring response_data{to_unsigned(response.data()), response.size()};
    auto parser = ResponseParser(builder);
    auto result = parser.decrypt(response_data);

    // Process the bencoded response
    oxenc::bt_list_consumer result_bencode{result};

    if (result_bencode.is_finished() || !result_bencode.is_string())
        throw std::runtime_error{"Invalid bencoded response"};

    auto response_info_string = result_bencode.consume_string();
    int16_t status_code;
    std::vector<std::pair<std::string, std::string>> headers;
    nlohmann::json response_info_json = nlohmann::json::parse(response_info_string);

    if (response_info_json.contains("code") && response_info_json["code"].is_number())
        status_code = response_info_json["code"].get<int16_t>();
    else
        throw std::runtime_error{"Invalid JSON response, missing required code field."};

    if (response_info_json.contains("headers")) {
        auto header_vals = response_info_json["headers"];

        for (auto it = header_vals.begin(); it != header_vals.end(); ++it)
            headers.emplace_back(it.key(), it.value());
    }

    if (result_bencode.is_finished())
        return {status_code, headers, std::nullopt};

    return {status_code, headers, result_bencode.consume_string()};
}

// MARK: Error Handling

std::pair<uint16_t, std::string> Network::validate_response(quic::message resp, bool is_bencoded) {
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
                        {content_type_plain_text},
                        "Request failed with status code: " + std::to_string(status_code)};

            throw status_code_exception{
                    status_code, {content_type_plain_text}, result_bencode.consume_string()};
        }

        // Can't convert the data to a string so just return the response body itself
        return {status_code, body};
    }

    // Default to a 200 success if the response is empty but didn't timeout or error
    int16_t status_code = 200;
    std::pair<std::string, std::string> content_type;
    std::string response_string;

    try {
        nlohmann::json response_json = nlohmann::json::parse(body);
        content_type = content_type_json;

        if (response_json.is_array() && response_json.size() == 2) {
            status_code = response_json[0].get<int16_t>();
            response_string = response_json[1].dump();
        } else
            response_string = body;
    } catch (...) {
        response_string = body;
        content_type = content_type_plain_text;
    }

    if (status_code < 200 || status_code > 299)
        throw status_code_exception{status_code, {content_type}, response_string};

    return {status_code, response_string};
}

void Network::drop_path_when_empty(std::string id, PathType path_type, onion_path path) {
    paths_pending_drop.emplace_back(path, path_type);
    paths[path_type].erase(
            std::remove(paths[path_type].begin(), paths[path_type].end(), path),
            paths[path_type].end());

    std::string reason;
    if (id == path.id)
        reason = "connection being closed";
    else
        reason = "failure threshold passed with {} failure"_format(id);

    log::info(
            cat,
            "Flagging path {} [{}] to be dropped due to {}, now have {} {} paths(s).",
            path.id,
            path.to_string(),
            reason,
            paths[path_type].size(),
            path_type_name(path_type, single_path_mode));

    // Clear any paths which are waiting to be dropped
    clear_empty_pending_path_drops();
}

void Network::clear_empty_pending_path_drops() {
    auto remaining_standard_paths = 0;
    std::erase_if(paths_pending_drop, [this, &remaining_standard_paths](const auto& path_info) {
        // If the path is no longer valid then we can drop it
        if (!path_info.first.has_pending_requests()) {
            log::info(
                    cat,
                    "Removing flagged {} path {} that {}: [{}].",
                    path_type_name(path_info.second, single_path_mode),
                    path_info.first.id,
                    (path_info.first.is_valid() ? "has no remaining requests"
                                                : "is no longer valid"),
                    path_info.first.to_string());
            return true;
        }
        remaining_standard_paths++;
        return false;
    });

    // Update the network status if we've removed all standard paths
    if (remaining_standard_paths == 0 && paths[PathType::standard].empty())
        update_status(ConnectionStatus::disconnected);
}

void Network::handle_errors(
        request_info info,
        connection_info conn_info,
        bool timeout_,
        int16_t status_code_,
        std::vector<std::pair<std::string, std::string>> headers_,
        std::optional<std::string> response,
        std::optional<network_response_callback_t> handle_response) {
    bool timeout = timeout_;
    auto status_code = status_code_;
    auto headers = headers_;
    auto path_name = path_type_name(info.path_type, single_path_mode);

    // There is an issue which can occur where we get invalid data back and are unable to decrypt
    // it, if we do see this behaviour then we want to retry the request on the off chance it
    // resolves itself
    //
    // When testing this case the retry always resulted in a 421 error, if that occurs we want to go
    // through the standard 421 behaviour (which, in this case, would involve a 3rd retry against
    // another node in the swarm to confirm the redirect)
    if (!info.retry_reason && response && *response == session::onionreq::decryption_failed_error) {
        log::info(
                cat,
                "Received decryption failure in request {} on {} path, retrying.",
                info.request_id,
                path_name);
        auto updated_info = info;
        updated_info.retry_reason = request_info::RetryReason::decryption_failure;
        return net.call_soon([this, updated_info, cb = std::move(*handle_response)]() {
            _send_onion_request(updated_info, std::move(cb));
        });
    }

    // A number of server errors can return HTML data but no status code, we want to extract those
    // cases so they can be handled properly below
    if (status_code == -1 && response) {
        const std::unordered_map<std::string, std::pair<int16_t, bool>> response_map = {
                {"400 Bad Request", {400, false}},
                {"403 Forbidden", {403, false}},
                {"500 Internal Server Error", {500, false}},
                {"502 Bad Gateway", {502, false}},
                {"503 Service Unavailable", {503, false}},
                {"504 Gateway Timeout", {504, true}},
        };

        for (const auto& [prefix, result] : response_map) {
            if (response->starts_with(prefix)) {
                status_code = result.first;
                timeout = (timeout || result.second);
            }
        }
    }

    // In trace mode log all error info
    log::trace(
            cat,
            "Received network error in request {} on {} path, status_code: {}, timeout: {}, "
            "response: {}",
            info.request_id,
            path_name,
            status_code,
            timeout,
            response.value_or("(No Response)"));

    // A timeout could be caused because the destination is unreachable rather than the the path
    // (eg. if a user has an old SOGS which is no longer running on their device they will get a
    // timeout) so if we timed out while sending a proxied request we assume something is wrong on
    // the server side and don't update the path/snode state
    if (!info.node_destination && timeout) {
        if (handle_response)
            return (*handle_response)(false, true, status_code, headers, response);
        return;
    }

    switch (status_code) {
        // A 404 or a 400 is likely due to a bad/missing SOGS or file so
        // shouldn't mark a path or snode as invalid
        case 400:
        case 404:
            if (handle_response)
                return (*handle_response)(false, false, status_code, headers, response);
            return;

        // The user's clock is out of sync with the service node network (a
        // snode will return 406, but V4 onion requests returns a 425)
        case 406:
        case 425:
            if (handle_response)
                return (*handle_response)(false, false, status_code, headers, response);
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
                auto target = detail::node_for_destination(info.destination);

                if (!handle_response || !info.swarm_pubkey || !target)
                    throw std::invalid_argument{"Unable to handle redirect."};

                switch (info.retry_reason.value_or(request_info::RetryReason::none)) {
                    // If this was the first 421 then we want to retry using another node in the
                    // swarm to get confirmation that we should switch to a different swarm
                    case request_info::RetryReason::none:
                    case request_info::RetryReason::decryption_failure: {
                        auto cached_swarm = swarm_cache[info.swarm_pubkey->hex()];

                        if (cached_swarm.second.empty())
                            throw std::invalid_argument{
                                    "Unable to handle redirect due to lack of swarm."};

                        CSRNG rng;
                        std::vector<service_node> swarm_copy;
                        std::copy_if(
                                cached_swarm.second.begin(),
                                cached_swarm.second.end(),
                                std::back_inserter(swarm_copy),
                                [&target = *target](const auto& node) { return node != target; });
                        std::shuffle(swarm_copy.begin(), swarm_copy.end(), rng);

                        if (swarm_copy.empty())
                            throw std::invalid_argument{"No other nodes in the swarm."};

                        log::info(
                                cat,
                                "Received 421 error in request {} on {} path, retrying once before "
                                "updating swarm.",
                                info.request_id,
                                path_name);
                        auto updated_info = info;
                        updated_info.destination = swarm_copy.front();
                        updated_info.retry_reason = request_info::RetryReason::redirect;
                        return net.call_soon(
                                [this, updated_info, cb = std::move(*handle_response)]() {
                                    _send_onion_request(updated_info, std::move(cb));
                                });
                    }

                    // If we got a second 421 then it's likely that our cached swarm is out of date
                    // so we need to refresh our snode cache, regenerate our swarm and try one more
                    // time
                    case request_info::RetryReason::redirect:
                        log::info(
                                cat,
                                "Received second 421 error in request {} on {} path, refreshing "
                                "snode cache before trying one final time.",
                                info.request_id,
                                path_name);
                        after_snode_cache_refresh.emplace_back([this,
                                                                swarm_pubkey = info.swarm_pubkey,
                                                                info,
                                                                status_code,
                                                                headers,
                                                                response,
                                                                cb = std::move(
                                                                        *handle_response)]() {
                            get_swarm(
                                    *swarm_pubkey,
                                    [this,
                                     info,
                                     status_code,
                                     headers,
                                     response,
                                     cb = std::move(cb)](
                                            swarm_id_t, std::vector<service_node> swarm) {
                                        auto target =
                                                detail::node_for_destination(info.destination);

                                        CSRNG rng;
                                        std::vector<service_node> swarm_copy;
                                        std::copy_if(
                                                swarm.begin(),
                                                swarm.end(),
                                                std::back_inserter(swarm_copy),
                                                [&target = *target](const auto& node) {
                                                    return node != target;
                                                });
                                        std::shuffle(swarm_copy.begin(), swarm_copy.end(), rng);

                                        // If there are no nodes in the swarm then don't bother
                                        // trying again
                                        if (swarm_copy.empty()) {
                                            log::info(
                                                    cat,
                                                    "Second 421 retry for request {} resulted in "
                                                    "another 421 and had no other nodes in the "
                                                    "swarm.",
                                                    info.request_id);
                                            return cb(false, false, status_code, headers, response);
                                        }

                                        auto updated_info = info;
                                        updated_info.retry_reason =
                                                request_info::RetryReason::redirect_swarm_refresh;
                                        updated_info.destination = swarm_copy.front();
                                        net.call_soon([this, updated_info, cb = std::move(cb)]() {
                                            _send_onion_request(updated_info, std::move(cb));
                                        });
                                    });
                        });
                        return net.call_soon([this, request_id = info.request_id]() {
                            refresh_snode_cache(request_id);
                        });

                    // If we got a 421 after refreshing the swarm then there is some bigger issue
                    // (ie. our local swarm generation logic differs from the server or we are
                    // getting invalid swarm ids back when updating our cache) so the best we can
                    // do is handle this like any other error
                    case request_info::RetryReason::redirect_swarm_refresh:
                        log::info(
                                cat,
                                "Received another 421 for request {} after refreshing the snode "
                                "cache, failing request.",
                                info.request_id);
                        break;

                    default: break;  // Unhandled case should just behave like any other error
                }
            } catch (...) {
            }

            // If we weren't able to retry or redirect the swarm then handle this like any other
            // error
            break;

        case 500:
        case 504:
            // If we are making a proxied request to a server then assume 500 errors are occurring
            // on the server rather than in the service node network and don't update the path/snode
            // state
            if (!info.node_destination) {
                if (handle_response)
                    return (*handle_response)(false, timeout, status_code, headers, response);
                return;
            }
            break;

        default: break;
    }

    // Retrieve the path for the connection_info (no paths share the same guard node so we can use
    // that to find it)
    std::optional<onion_path> path;
    auto is_active_path = true;

    auto path_it = std::find_if(
            paths[info.path_type].begin(),
            paths[info.path_type].end(),
            [guard_node = conn_info.node](const auto& path) {
                return !path.nodes.empty() && path.nodes.front() == guard_node;
            });

    // Try to retrieve the path this request was on, if it's not in an active or pending drop path
    // then log a warning (as this shouldn't be possible) and call the callback
    if (path_it != paths[info.path_type].end())
        path = *path_it;
    else {
        auto path_pending_drop_it = std::find_if(
                paths_pending_drop.begin(),
                paths_pending_drop.end(),
                [guard_node = conn_info.node](const auto& path_info) {
                    return !path_info.first.nodes.empty() &&
                           path_info.first.nodes.front() == guard_node;
                });

        if (path_pending_drop_it == paths_pending_drop.end()) {
            log::warning(
                    cat,
                    "Request {} failed but {} path with guard {} already dropped.",
                    info.request_id,
                    path_name,
                    conn_info.node.to_string());

            if (handle_response)
                (*handle_response)(false, timeout, status_code, headers, response);
            return;
        }
        path = path_pending_drop_it->first;
        is_active_path = false;
    }

    // Update the failure counts and paths
    auto updated_path = *path;
    bool found_invalid_node = false;

    if (response) {
        std::optional<std::string_view> ed25519PublicKey;

        // Check if the response has one of the 'node_not_found' prefixes
        if (response->starts_with(node_not_found_prefix))
            ed25519PublicKey = {response->data() + node_not_found_prefix.size()};
        else if (response->starts_with(node_not_found_prefix_no_status))
            ed25519PublicKey = {response->data() + node_not_found_prefix_no_status.size()};

        // If we found a result then try to extract the pubkey and process it
        if (ed25519PublicKey && ed25519PublicKey->size() == 64 &&
            oxenc::is_hex(*ed25519PublicKey)) {
            session::onionreq::ed25519_pubkey edpk =
                    session::onionreq::ed25519_pubkey::from_hex(*ed25519PublicKey);
            auto edpk_view = to_unsigned_sv(edpk.view());

            auto snode_it = std::find_if(
                    updated_path.nodes.begin(),
                    updated_path.nodes.end(),
                    [&edpk_view](const auto& node) { return node.view_remote_key() == edpk_view; });

            if (snode_it != updated_path.nodes.end()) {
                found_invalid_node = true;

                // If we get an explicit node failure then we should just immediately drop it and
                // try to repair the existing path by replacing the bad node with another one
                snode_failure_counts[snode_it->to_string()] = snode_failure_threshold;

                try {
                    // If the node that's gone bad is the guard node then we just have to
                    // drop the path
                    if (snode_it == updated_path.nodes.begin())
                        throw std::runtime_error{"Cannot recover if guard node is bad"};

                    if (unused_nodes.empty())
                        throw std::runtime_error{"No remaining nodes"};

                    auto target_node = unused_nodes.back();
                    unused_nodes.pop_back();

                    std::replace(
                            updated_path.nodes.begin(),
                            updated_path.nodes.end(),
                            *snode_it,
                            target_node);
                    log::info(
                            cat,
                            "Found bad node ({}) in {} path, replacing node ({}).",
                            *ed25519PublicKey,
                            path_name,
                            updated_path.id);
                } catch (...) {
                    // There aren't enough unused nodes remaining so we need to drop the
                    // path
                    updated_path.failure_count = path_failure_threshold;
                    log::info(
                            cat,
                            "Unable to replace bad node ({}) in {} path ({}).",
                            *ed25519PublicKey,
                            path_name,
                            updated_path.id);
                }
            }
        }
    }

    // If we didn't find the specific node or the paths connection was closed then increment the
    // path failure count
    if (!found_invalid_node || !updated_path.conn_info.is_valid()) {
        updated_path.failure_count += 1;

        // If the path has failed too many times we want to drop the guard snode (marking it as
        // invalid) and increment the failure count of each node in the path)
        if (updated_path.failure_count >= path_failure_threshold) {
            for (auto& it : updated_path.nodes)
                ++snode_failure_counts[it.to_string()];

            // Set the failure count of the guard node to match the threshold so we don't use it
            // again until we refresh the cache
            snode_failure_counts[updated_path.nodes[0].to_string()] = snode_failure_threshold;
        } else if (updated_path.nodes.size() < path_size)
            // triggered when trying to establish a new path and, as such, we should increase
            // the failure count of the guard node since it is probably invalid
            ++snode_failure_counts[updated_path.nodes[0].to_string()];
    }

    // Drop the path if invalid (and currently an active path)
    if (is_active_path) {
        if (updated_path.failure_count >= path_failure_threshold)
            drop_path_when_empty(info.request_id, info.path_type, *path_it);
        else
            std::replace(
                    paths[info.path_type].begin(),
                    paths[info.path_type].end(),
                    *path_it,
                    updated_path);
    }

    if (handle_response)
        (*handle_response)(false, timeout, status_code, headers, response);
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

using namespace session;
using namespace session::network;

LIBSESSION_C_API bool network_init(
        network_object** network,
        const char* cache_path_,
        bool use_testnet,
        bool single_path_mode,
        bool pre_build_paths,
        char* error) {
    try {
        std::optional<std::string> cache_path;
        if (cache_path_)
            cache_path = cache_path_;

        auto n = std::make_unique<session::network::Network>(
                cache_path, use_testnet, single_path_mode, pre_build_paths);
        auto n_object = std::make_unique<network_object>();

        n_object->internals = n.release();
        *network = n_object.release();
        return true;
    } catch (const std::exception& e) {
        return set_error(error, e);
    }
}

LIBSESSION_C_API void network_free(network_object* network) {
    delete static_cast<session::network::Network*>(network->internals);
    delete network;
}

LIBSESSION_C_API void network_suspend(network_object* network) {
    unbox(network).suspend();
}

LIBSESSION_C_API void network_resume(network_object* network) {
    unbox(network).resume();
}

LIBSESSION_C_API void network_close_connections(network_object* network) {
    unbox(network).close_connections();
}

LIBSESSION_C_API void network_clear_cache(network_object* network) {
    unbox(network).clear_cache();
}

LIBSESSION_C_API size_t network_get_snode_cache_size(network_object* network) {
    return unbox(network).snode_cache_size();
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
            size_t paths_mem_size = 0;
            for (auto& nodes : paths)
                paths_mem_size +=
                        sizeof(onion_request_path) + (sizeof(network_service_node) * nodes.size());

            // Allocate the memory for the onion_request_paths* array
            auto* c_paths_array = static_cast<onion_request_path*>(std::malloc(paths_mem_size));
            for (size_t i = 0; i < paths.size(); ++i) {
                auto c_nodes = network::detail::convert_service_nodes(paths[i]);

                // Allocate memory that persists outside the loop
                size_t node_array_size = sizeof(network_service_node) * c_nodes.size();
                auto* c_nodes_array =
                        static_cast<network_service_node*>(std::malloc(node_array_size));
                std::copy(c_nodes.begin(), c_nodes.end(), c_nodes_array);
                new (c_paths_array + i) onion_request_path{c_nodes_array, c_nodes.size()};
            }

            cb(c_paths_array, paths.size(), ctx);
        };
}

LIBSESSION_C_API void network_get_swarm(
        network_object* network,
        const char* swarm_pubkey_hex,
        void (*callback)(network_service_node* nodes, size_t nodes_len, void*),
        void* ctx) {
    assert(swarm_pubkey_hex && callback);
    unbox(network).get_swarm(
            x25519_pubkey::from_hex({swarm_pubkey_hex, 64}),
            [cb = std::move(callback), ctx](swarm_id_t, std::vector<service_node> nodes) {
                auto c_nodes = network::detail::convert_service_nodes(nodes);
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
                auto c_nodes = network::detail::convert_service_nodes(nodes);
                cb(c_nodes.data(), c_nodes.size(), ctx);
            });
}

LIBSESSION_C_API void network_send_onion_request_to_snode_destination(
        network_object* network,
        const network_service_node node,
        const unsigned char* body_,
        size_t body_size,
        const char* swarm_pubkey_hex,
        int64_t request_timeout_ms,
        int64_t request_and_path_build_timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx) {
    assert(callback);

    try {
        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        std::optional<x25519_pubkey> swarm_pubkey;
        if (swarm_pubkey_hex)
            swarm_pubkey = x25519_pubkey::from_hex({swarm_pubkey_hex, 64});

        std::optional<std::chrono::milliseconds> request_and_path_build_timeout;
        if (request_and_path_build_timeout_ms > 0)
            request_and_path_build_timeout =
                    std::chrono::milliseconds{request_and_path_build_timeout_ms};

        std::array<uint8_t, 4> ip;
        std::memcpy(ip.data(), node.ip, ip.size());

        unbox(network).send_onion_request(
                service_node{
                        oxenc::from_hex({node.ed25519_pubkey_hex, 64}),
                        {0},
                        INVALID_SWARM_ID,
                        "{}"_format(fmt::join(ip, ".")),
                        node.quic_port},
                body,
                swarm_pubkey,
                [cb = std::move(callback), ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::vector<std::pair<std::string, std::string>> headers,
                        std::optional<std::string> response) {
                    std::vector<const char*> cHeaders;
                    std::vector<const char*> cHeaderValues;
                    cHeaders.reserve(headers.size());
                    cHeaderValues.reserve(headers.size());

                    for (const auto& [header, value] : headers) {
                        cHeaders.push_back(header.c_str());
                        cHeaderValues.push_back(value.c_str());
                    }

                    if (response)
                        cb(success,
                           timeout,
                           status_code,
                           cHeaders.data(),
                           cHeaderValues.data(),
                           headers.size(),
                           (*response).c_str(),
                           (*response).size(),
                           ctx);
                    else
                        cb(success,
                           timeout,
                           status_code,
                           cHeaders.data(),
                           cHeaderValues.data(),
                           headers.size(),
                           nullptr,
                           0,
                           ctx);
                },
                std::chrono::milliseconds{request_timeout_ms},
                request_and_path_build_timeout);
    } catch (const std::exception& e) {
        callback(false, false, -1, nullptr, nullptr, 0, e.what(), std::strlen(e.what()), ctx);
    }
}

LIBSESSION_C_API void network_send_onion_request_to_server_destination(
        network_object* network,
        const network_server_destination server,
        const unsigned char* body_,
        size_t body_size,
        int64_t request_timeout_ms,
        int64_t request_and_path_build_timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx) {
    assert(server.method && server.protocol && server.host && server.endpoint &&
           server.x25519_pubkey && callback);

    try {
        std::optional<ustring> body;
        if (body_size > 0)
            body = {body_, body_size};

        std::optional<std::chrono::milliseconds> request_and_path_build_timeout;
        if (request_and_path_build_timeout_ms > 0)
            request_and_path_build_timeout =
                    std::chrono::milliseconds{request_and_path_build_timeout_ms};

        unbox(network).send_onion_request(
                network::detail::convert_server_destination(server),
                body,
                std::nullopt,
                [cb = std::move(callback), ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::vector<std::pair<std::string, std::string>> headers,
                        std::optional<std::string> response) {
                    std::vector<const char*> cHeaders;
                    std::vector<const char*> cHeaderValues;
                    cHeaders.reserve(headers.size());
                    cHeaderValues.reserve(headers.size());

                    for (const auto& [header, value] : headers) {
                        cHeaders.push_back(header.c_str());
                        cHeaderValues.push_back(value.c_str());
                    }

                    if (response)
                        cb(success,
                           timeout,
                           status_code,
                           cHeaders.data(),
                           cHeaderValues.data(),
                           headers.size(),
                           (*response).c_str(),
                           (*response).size(),
                           ctx);
                    else
                        cb(success,
                           timeout,
                           status_code,
                           cHeaders.data(),
                           cHeaderValues.data(),
                           headers.size(),
                           nullptr,
                           0,
                           ctx);
                },
                std::chrono::milliseconds{request_timeout_ms},
                request_and_path_build_timeout);
    } catch (const std::exception& e) {
        callback(false, false, -1, nullptr, nullptr, 0, e.what(), std::strlen(e.what()), ctx);
    }
}

LIBSESSION_C_API void network_upload_to_server(
        network_object* network,
        const network_server_destination server,
        const unsigned char* data,
        size_t data_len,
        const char* file_name_,
        int64_t request_timeout_ms,
        int64_t request_and_path_build_timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx) {
    assert(data && server.method && server.protocol && server.host && server.endpoint &&
           server.x25519_pubkey && callback);

    try {
        std::optional<std::string> file_name;
        if (file_name_)
            file_name = file_name_;

        std::optional<std::chrono::milliseconds> request_and_path_build_timeout;
        if (request_and_path_build_timeout_ms > 0)
            request_and_path_build_timeout =
                    std::chrono::milliseconds{request_and_path_build_timeout_ms};

        unbox(network).upload_file_to_server(
                {data, data_len},
                network::detail::convert_server_destination(server),
                file_name,
                [cb = std::move(callback), ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::vector<std::pair<std::string, std::string>> headers,
                        std::optional<std::string> response) {
                    std::vector<const char*> cHeaders;
                    std::vector<const char*> cHeaderValues;
                    cHeaders.reserve(headers.size());
                    cHeaderValues.reserve(headers.size());

                    for (const auto& [header, value] : headers) {
                        cHeaders.push_back(header.c_str());
                        cHeaderValues.push_back(value.c_str());
                    }

                    if (response)
                        cb(success,
                           timeout,
                           status_code,
                           cHeaders.data(),
                           cHeaderValues.data(),
                           headers.size(),
                           (*response).c_str(),
                           (*response).size(),
                           ctx);
                    else
                        cb(success,
                           timeout,
                           status_code,
                           cHeaders.data(),
                           cHeaderValues.data(),
                           headers.size(),
                           nullptr,
                           0,
                           ctx);
                },
                std::chrono::milliseconds{request_timeout_ms},
                request_and_path_build_timeout);
    } catch (const std::exception& e) {
        callback(false, false, -1, nullptr, nullptr, 0, e.what(), std::strlen(e.what()), ctx);
    }
}

LIBSESSION_C_API void network_download_from_server(
        network_object* network,
        const network_server_destination server,
        int64_t request_timeout_ms,
        int64_t request_and_path_build_timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx) {
    assert(server.method && server.protocol && server.host && server.endpoint &&
           server.x25519_pubkey && callback);

    try {
        std::optional<std::chrono::milliseconds> request_and_path_build_timeout;
        if (request_and_path_build_timeout_ms > 0)
            request_and_path_build_timeout =
                    std::chrono::milliseconds{request_and_path_build_timeout_ms};

        unbox(network).download_file(
                network::detail::convert_server_destination(server),
                [cb = std::move(callback), ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::vector<std::pair<std::string, std::string>> headers,
                        std::optional<std::string> response) {
                    std::vector<const char*> cHeaders;
                    std::vector<const char*> cHeaderValues;
                    cHeaders.reserve(headers.size());
                    cHeaderValues.reserve(headers.size());

                    for (const auto& [header, value] : headers) {
                        cHeaders.push_back(header.c_str());
                        cHeaderValues.push_back(value.c_str());
                    }

                    if (response)
                        cb(success,
                           timeout,
                           status_code,
                           cHeaders.data(),
                           cHeaderValues.data(),
                           headers.size(),
                           (*response).c_str(),
                           (*response).size(),
                           ctx);
                    else
                        cb(success,
                           timeout,
                           status_code,
                           cHeaders.data(),
                           cHeaderValues.data(),
                           headers.size(),
                           nullptr,
                           0,
                           ctx);
                },
                std::chrono::milliseconds{request_timeout_ms},
                request_and_path_build_timeout);
    } catch (const std::exception& e) {
        callback(false, false, -1, nullptr, nullptr, 0, e.what(), std::strlen(e.what()), ctx);
    }
}

LIBSESSION_C_API void network_get_client_version(
        network_object* network,
        CLIENT_PLATFORM platform,
        const unsigned char* ed25519_secret,
        int64_t request_timeout_ms,
        int64_t request_and_path_build_timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx) {
    assert(platform && callback);

    try {
        std::optional<std::chrono::milliseconds> request_and_path_build_timeout;
        if (request_and_path_build_timeout_ms > 0)
            request_and_path_build_timeout =
                    std::chrono::milliseconds{request_and_path_build_timeout_ms};

        unbox(network).get_client_version(
                static_cast<Platform>(platform),
                onionreq::ed25519_seckey::from_bytes({ed25519_secret, 64}),
                [cb = std::move(callback), ctx](
                        bool success,
                        bool timeout,
                        int status_code,
                        std::vector<std::pair<std::string, std::string>> headers,
                        std::optional<std::string> response) {
                    std::vector<const char*> cHeaders;
                    std::vector<const char*> cHeaderValues;
                    cHeaders.reserve(headers.size());
                    cHeaderValues.reserve(headers.size());

                    for (const auto& [header, value] : headers) {
                        cHeaders.push_back(header.c_str());
                        cHeaderValues.push_back(value.c_str());
                    }

                    if (response)
                        cb(success,
                           timeout,
                           status_code,
                           cHeaders.data(),
                           cHeaderValues.data(),
                           headers.size(),
                           (*response).c_str(),
                           (*response).size(),
                           ctx);
                    else
                        cb(success,
                           timeout,
                           status_code,
                           cHeaders.data(),
                           cHeaderValues.data(),
                           headers.size(),
                           nullptr,
                           0,
                           ctx);
                },
                std::chrono::milliseconds{request_timeout_ms},
                request_and_path_build_timeout);
    } catch (const std::exception& e) {
        callback(false, false, -1, nullptr, nullptr, 0, e.what(), std::strlen(e.what()), ctx);
    }
}

}  // extern "C"
