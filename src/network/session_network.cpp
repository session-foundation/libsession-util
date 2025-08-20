#include "session/network/session_network.hpp"

#include <oxenc/base64.h>

#include <any>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <vector>

#include "session/blinding.hpp"
#include "session/network/network_config.hpp"
#include "session/network/network_opt.hpp"
#include "session/network/routing/lokinet_router.hpp"
#include "session/network/routing/onion_request_router.hpp"
#include "session/network/session_network.h"
#include "session/network/session_network_types.hpp"
#include "session/network/transport/quic_transport.hpp"
#include "session/random.hpp"

using namespace oxen;
using namespace session::network;
using namespace session::network::config;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {

    inline auto cat = log::Cat("network");

    constexpr auto file_server = "filev2.getsession.org"sv;
    constexpr auto file_server_pubkey =
            "da21e1d886c6fbaea313f75298bd64aab03a97ce985b46bb2dad9f2089c8ee59"sv;

    config::SnodePoolConfig build_snode_pool_config(const config::Config& main_config) {
        return {main_config.cache_directory,
                main_config.cache_expiration,
                main_config.cache_refresh_retry_limit,
                main_config.enforce_subnet_diversity,
                main_config.retry_delay,
                main_config.netid,
                main_config.seed_nodes,
                main_config.cache_min_size,
                main_config.cache_num_nodes_to_use_for_refresh,
                main_config.cache_node_failure_threshold,
                main_config.cache_refresh_using_legacy_endpoint};
    }

    config::QuicTransportConfig build_quic_transport_config(const config::Config& main_config) {
        return {main_config.quic_handshake_timeout,
                main_config.quic_keep_alive,
                main_config.quic_disable_mtu_discovery};
    }

    config::LokinetRouterConfig build_lokinet_router_config(const config::Config& main_config) {
        if (!main_config.cache_directory)
            throw std::invalid_argument{"Lokinet requires a cache_directory to be configured."};

        if (main_config.netid == opt::netid::Target::devnet)
            throw std::invalid_argument{"Lokinet does not support devnet."};

        return {main_config.netid,
                *main_config.cache_directory,
                main_config.request_timeout_check_frequency,
                main_config.path_length};
    }

    config::OnionRequestRouterConfig build_onion_request_router_config(
            const config::Config& main_config) {
        return {main_config.retry_delay,
                main_config.request_timeout_check_frequency,
                main_config.path_length,
                main_config.onionreq_path_failure_threshold,
                main_config.onionreq_path_build_retry_limit,
                main_config.onionreq_disable_pre_build_paths,
                main_config.onionreq_single_path_mode,
                main_config.onionreq_min_path_counts};
    }

}  // namespace

namespace detail {

    std::vector<network_service_node> convert_service_nodes(
            std::vector<session::network::service_node> nodes) {
        std::vector<network_service_node> converted_nodes;
        for (auto& node : nodes) {
            network_service_node converted_node;
            node.into(converted_node);
            converted_nodes.push_back(converted_node);
        }

        return converted_nodes;
    }

}  // namespace detail

Network_v2::Network_v2(config::Config config) : config{config} {
    // Start by validating the configuration
    switch (config.transport) {
        case opt::transport::Type::quic: break;
        case opt::transport::Type::callbacks:
            break;
            if (!config.callbacks_callback)
                throw std::invalid_argument{"Callbacks requires a callback to be provided."};
            break;
    }

    // Now we can properly do any setup needed
    _loop = std::make_shared<quic::Loop>();

    // Setup the transport layer
    switch (config.transport) {
        case opt::transport::Type::quic:
            _transport = std::make_shared<QuicTransport>(
                    std::move(build_quic_transport_config(config)), _loop);
            break;

        case opt::transport::Type::callbacks:
            // _transport = std::make_shared<LokinetTransport>(_config, *_snode_pool, _loop);
            break;
    }

    // The SnodePool is needed regardless of the transport layer as it includes swarm information
    // which is needed by the clients in order to send requests
    auto bootstrap_fetcher = [bt = std::weak_ptr{_transport}](
                                     Request req, network_response_callback_t on_complete) {
        if (auto transport = bt.lock())
            transport->send_request(std::move(req), std::move(on_complete));
        else
            log::error(
                    cat,
                    "Transport provided to the SnodePool bootstrap fetcher has been destroyed.");
    };
    _snode_pool = std::make_shared<SnodePool>(
            std::move(build_snode_pool_config(config)), _loop, bootstrap_fetcher);

    // Additional transport configuration
    _transport->set_node_failure_reporter(
            [pool = _snode_pool.get()](const ed25519_pubkey& pubkey, bool permanent) {
                if (pool)
                    pool->record_node_failure(pubkey, permanent);
            });

    // Setup the router
    switch (config.router) {
        case opt::router::Type::onion_requests:
            _router = std::make_unique<OnionRequestRouter>(
                    std::move(build_onion_request_router_config(config)),
                    _loop,
                    _snode_pool,
                    _transport);
            break;

        case opt::router::Type::lokinet:
            _router = std::make_unique<LokinetRouter>(
                    std::move(build_lokinet_router_config(config)), _loop, _snode_pool, _transport);
            break;

        case opt::router::Type::direct:
            // _router = std::make_unique<DirectTransport>(_config, *_snode_pool, _loop);
            break;
    }

    // Now that we have our router setup we need to setup the `standard_fetcher` on the `SnodePool`
    _snode_pool->set_standard_fetcher([r = std::weak_ptr{_router}, loop = _loop](
                                              Request req,
                                              network_response_callback_t on_complete) {
        loop->call([r, req = std::move(req), on_complete = std::move(on_complete)] {
            if (auto router = r.lock())
                router->send_request(std::move(req), std::move(on_complete));
            else
                log::error(
                        cat,
                        "Router provided to the SnodePool standard fetcher has been destroyed.");
        });
    });

    // Add hooks to update the connection status
    _router->on_status_changed = [this] { _recalculate_status(); };
    _transport->on_status_changed = [this] { _recalculate_status(); };
}

Network_v2::~Network_v2() {
    _update_status(ConnectionStatus::disconnected);
    log::debug(cat, "[Network] Destroyed.");
}

std::vector<PathInfo> Network_v2::get_active_paths() {
    if (_router)
        return _router->get_active_paths();
    
    return {};
}

void Network_v2::get_swarm(
        session::network::x25519_pubkey swarm_pubkey,
        std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback) {
    _snode_pool->get_swarm(std::move(swarm_pubkey), std::move(callback));
}

void Network_v2::get_random_nodes(
        uint16_t count, std::function<void(std::vector<service_node> nodes)> callback) {
    _loop->call([this, count, cb = std::move(callback)] {
        auto unused_nodes = _snode_pool->get_unused_nodes(count);

        // If we don't have sufficient nodes then we need to refresh the snode cache
        if (unused_nodes.size() < count) {
            std::vector<service_node> nodes_to_exclude = _router->get_all_used_nodes();

            return _snode_pool->refresh_if_needed(
                    nodes_to_exclude,
                    [this, count, cb = std::move(cb)] { get_random_nodes(count, cb); });
        }
        cb(unused_nodes);
    });
}

void Network_v2::send_request(Request request, network_response_callback_t callback) {
    if (!_transport)
        return callback(
                false, false, -1, {content_type_plain_text}, "No transport layer configured");
    if (!_router)
        return callback(false, false, -1, {content_type_plain_text}, "No router configured");

    try {
        auto processed_request = _preprocess_request(std::move(request));
        auto router_callback =
                [this, original_req = processed_request, cb = std::move(callback)](
                        bool success, bool timeout, int16_t status_code, auto headers, auto body) {
                    if (success && body)
                        _update_network_state(*body);

                    int16_t final_status_code = status_code;

                    if (body.has_value();
                        auto uniform_error = Response::find_uniform_batch_error(*body))
                        final_status_code = *uniform_error;

                    // If we got a 421 then our swarm info is out of data so we need to refresh our
                    // cache, the original request might succeed after this refresh so we should
                    // just automatically retry
                    if (final_status_code == 421) {
                        _handle_421_retry(std::move(original_req), std::move(cb));
                        return;
                    }

                    // For debugging purposes we want to add a log if this was a successful request
                    // after we did an automatic retry
                    if (original_req.retry_count > 0)
                        log::info(
                                cat,
                                "[Request {}] Received valid response after 421 retry.",
                                original_req.request_id);

                    auto final_success =
                            (success && final_status_code >= 200 && final_status_code <= 299);
                    cb(final_success, timeout, status_code, std::move(headers), std::move(body));
                };

        _router->send_request(std::move(processed_request), std::move(router_callback));
    } catch (const std::exception& e) {
        return callback(false, false, -1, {content_type_plain_text}, e.what());
    }
}

// MARK: Internal Logic

void Network_v2::_recalculate_status() {
    _loop->call([this] {
        if (!_transport || !_router)
            return _update_status(ConnectionStatus::disconnected);

        auto transport_status = _transport->get_status();
        auto router_status = _router->get_status();

        // If both layers report being fully connected then we are connected
        if (transport_status == ConnectionStatus::connected &&
            router_status == ConnectionStatus::connected)
            _update_status(ConnectionStatus::connected);
        // If either layer is disconnected, the whole system is disconnected
        else if (
                transport_status == ConnectionStatus::disconnected ||
                router_status == ConnectionStatus::disconnected)
            _update_status(ConnectionStatus::disconnected);
        // If either layer is trying to connect, the whole system is connecting
        else if (
                transport_status == ConnectionStatus::connecting ||
                router_status == ConnectionStatus::connecting)
            _update_status(ConnectionStatus::connecting);
        // Otherwise, we are in an unknown state
        else
            _update_status(ConnectionStatus::unknown);
    });
}

void Network_v2::_update_status(ConnectionStatus new_status) {
    if (_status == new_status)
        return;

    _status = new_status;

    if (on_status_changed)
        on_status_changed(new_status);
}

Request Network_v2::_preprocess_request(Request request) {
    std::visit(
            [&](auto&& details) {
                using T = std::decay_t<decltype(details)>;

                if constexpr (std::is_same_v<T, UploadInfo>) {
                    if (!request.body)
                        throw std::invalid_argument("Upload request must have a body.");

                    if (request.category != RequestCategory::upload) {
                        log::warning(
                                cat,
                                "Request {} has UploadInfo but category is not 'upload', forcing "
                                "to 'upload'.",
                                request.request_id);
                        request.category = RequestCategory::upload;
                    }

                    // Add the required headers if they weren't provided
                    if (auto* dest = std::get_if<ServerDestination>(&request.destination)) {
                        if (!dest->headers)
                            dest->headers.emplace();

                        std::unordered_set<std::string> existing_keys;
                        if (dest->headers)
                            for (const auto& [key, val] : *dest->headers)
                                existing_keys.insert(key);

                        if (existing_keys.find("Content-Type") == existing_keys.end())
                            dest->headers->emplace_back("Content-Type", "application/octet-stream");

                        if (existing_keys.find("Content-Disposition") == existing_keys.end()) {
                            if (details.file_name)
                                dest->headers->emplace_back(
                                        "Content-Disposition",
                                        fmt::format(
                                                "attachment; filename=\"{}\"", *details.file_name));
                            else
                                dest->headers->emplace_back("Content-Disposition", "attachment");
                        }
                    }
                } else if constexpr (std::is_same_v<T, std::monostate>) { /* No special handling */
                }
            },
            request.details);

    return request;
}

void Network_v2::_update_network_state(const std::string& body) {
    try {
        auto json = nlohmann::json::parse(body);
        const nlohmann::json* target_json = &json;

        // If it was a batch/sequence request then take the one with the highest "t" value as that
        // would have been the one which was returned last
        if (json.contains("results") && json["results"].is_array()) {
            log::trace(cat, "Parsing batch response for latest network state.");

            int64_t max_t = -1;
            const nlohmann::json* latest_body = nullptr;

            for (const auto& result : json["results"]) {
                if (!result.is_object() || !result.contains("body") || !result["body"].is_object())
                    continue;

                const auto& result_body = result["body"];

                if (result_body.contains("t") && result_body["t"].is_number()) {
                    int64_t current_t = result_body["t"].get<int64_t>();

                    if (current_t > max_t) {
                        max_t = current_t;
                        latest_body = &result_body;
                    }
                }
            }

            if (latest_body)
                target_json = latest_body;
        }

        // Update time offset
        if (target_json->contains("t") && (*target_json)["t"].is_number()) {
            auto server_time = std::chrono::seconds{(*target_json)["t"].get<int64_t>()};
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch());
            _network_time_offset = server_time - now;
            log::trace(cat, "Network offset set to: {}", (server_time - now).count());
        }

        // Update hardfork/softfork versions
        if (target_json->contains("hf") && (*target_json)["hf"].is_array() &&
            (*target_json)["hf"].size() >= 2) {
            std::pair<int, int> new_versions = {
                    (*target_json)["hf"][0].get<int>(), (*target_json)["hf"][1].get<int>()};

            auto current_versions = _fork_versions.load();
            auto desired_next_versions = current_versions;

            if (new_versions.first > desired_next_versions.hardfork)
                desired_next_versions = {new_versions.first, new_versions.second};
            else if (
                    new_versions.first == desired_next_versions.hardfork &&
                    new_versions.second > desired_next_versions.softfork)
                desired_next_versions.softfork = new_versions.second;

            if (current_versions != desired_next_versions)
                _fork_versions.compare_exchange_weak(current_versions, desired_next_versions);
            log::trace(
                    cat,
                    "Fork version set to: {}.{}",
                    desired_next_versions.hardfork,
                    desired_next_versions.softfork);
        }
    } catch (const std::exception& e) {
        log::warning(cat, "Failed to parse network state from response: {}", e.what());
    }
}

void Network_v2::_handle_421_retry(
        Request original_request, network_response_callback_t final_callback) {
    if (original_request.retry_count >= config.redirect_retry_count) {
        log::error(
                cat,
                "Request {} received 421 but exceeded max retry count.",
                original_request.request_id);
        return final_callback(
                false, false, 421, {content_type_plain_text}, "Exceeded retry limit for 421 error");
    }

    // Shouldn't automatically retry if the destination isn't a node (we on'y want to auto-retry due
    // to a node being in the wrong swarm)
    auto* original_dest_node = std::get_if<service_node>(&original_request.destination);
    if (!original_dest_node)
        return final_callback(
                false,
                false,
                421,
                {content_type_plain_text},
                "Received 421 from a non-service-node destination");

    // If we got a 421 it means our snode cache is outdated (because the swarm the destination node
    // belongs to doesn't match our cache anymore)
    log::info(
            cat,
            "Request {} received 421 from node {}, refreshing swarm.",
            original_request.request_id,
            original_dest_node->to_string());

    auto failed_node_copy = *original_dest_node;
    std::vector<service_node> nodes_to_exclude = _router->get_all_used_nodes();
    _snode_pool->refresh_if_needed(
            std::move(nodes_to_exclude),
            [this,
             req_to_retry = std::move(original_request),
             cb = std::move(final_callback),
             failed_node = failed_node_copy] {
                auto swarm_pubkey = failed_node.swarm_pubkey();

                _snode_pool->get_swarm(
                        swarm_pubkey,
                        [this,
                         req_to_retry = std::move(req_to_retry),
                         cb = std::move(cb),
                         failed_node](swarm::swarm_id_t, std::vector<service_node> swarm_nodes) {
                            std::optional<service_node> new_target;
                            std::shuffle(swarm_nodes.begin(), swarm_nodes.end(), csrng);

                            for (const auto& node : swarm_nodes) {
                                if (node != failed_node) {
                                    new_target = node;
                                    break;
                                }
                            }

                            if (!new_target)
                                return cb(
                                        false,
                                        false,
                                        421,
                                        {content_type_plain_text},
                                        "421 Misdirected Request, but no other nodes in swarm to "
                                        "retry");

                            log::info(
                                    cat,
                                    "Request {} retrying 421 error on new node {}.",
                                    req_to_retry.request_id,
                                    new_target->to_string());
                            auto final_request = req_to_retry;
                            final_request.retry_count++;
                            final_request.destination = *new_target;
                            this->send_request(std::move(final_request), std::move(cb));
                        });
            });
}

}  // namespace session::network

// MARK: C API

struct session_response_handle_cpp_t {
    session::network::network_response_callback_t cpp_callback;
};

namespace {

inline session::network::Network_v2& unbox(network_object_v2* network_) {
    assert(network_ && network_->internals);
    return *static_cast<session::network::Network_v2*>(network_->internals);
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

LIBSESSION_C_API session_network_config session_network_config_default() {
    Config cpp_defaults{};
    session_network_config config = {};

    switch (cpp_defaults.netid) {
        case opt::netid::Target::mainnet: config.netid = SESSION_NETWORK_MAINNET;
        case opt::netid::Target::testnet: config.netid = SESSION_NETWORK_TESTNET;
        case opt::netid::Target::devnet: config.netid = SESSION_NETWORK_DEVNET;
        default: config.netid = SESSION_NETWORK_MAINNET;
    }

    switch (cpp_defaults.router) {
        case opt::router::Type::onion_requests:
            config.router = SESSION_NETWORK_ROUTER_ONION_REQUESTS;
        case opt::router::Type::lokinet: config.router = SESSION_NETWORK_ROUTER_LOKINET;
        case opt::router::Type::direct: config.router = SESSION_NETWORK_ROUTER_DIRECT;
        default: config.router = SESSION_NETWORK_ROUTER_ONION_REQUESTS;
    }

    switch (cpp_defaults.transport) {
        case opt::transport::Type::quic: config.transport = SESSION_NETWORK_TRANSPORT_QUIC;
        case opt::transport::Type::callbacks:
            config.transport = SESSION_NETWORK_TRANSPORT_CALLBACKS;
        default: config.transport = SESSION_NETWORK_TRANSPORT_QUIC;
    }

    config.path_length = cpp_defaults.path_length;
    config.enforce_subnet_diversity = cpp_defaults.enforce_subnet_diversity;
    config.redirect_retry_count = cpp_defaults.redirect_retry_count;
    config.min_retry_delay_ms = cpp_defaults.retry_delay.base_delay.count();
    config.max_retry_delay_ms = cpp_defaults.retry_delay.max_delay.count();
    config.request_timeout_check_frequency_ms =
            cpp_defaults.request_timeout_check_frequency.count();

    config.devnet_seed_nodes = nullptr;
    config.devnet_seed_nodes_size = 0;

    config.cache_dir = nullptr;
    config.cache_expiration_minutes =
            std::chrono::duration_cast<std::chrono::minutes>(cpp_defaults.cache_expiration).count();
    config.cache_refresh_retry_limit = cpp_defaults.cache_refresh_retry_limit;
    config.cache_min_size = cpp_defaults.cache_min_size;
    config.cache_num_nodes_to_use_for_refresh = cpp_defaults.cache_num_nodes_to_use_for_refresh;
    config.cache_node_failure_threshold = cpp_defaults.cache_node_failure_threshold;
    config.cache_refresh_using_legacy_endpoint = cpp_defaults.cache_refresh_using_legacy_endpoint;

    config.onionreq_path_failure_threshold = cpp_defaults.onionreq_path_failure_threshold;
    config.onionreq_path_build_retry_limit = cpp_defaults.onionreq_path_build_retry_limit;
    config.onionreq_min_path_count_standard =
            cpp_defaults.onionreq_min_path_counts[RequestCategory::standard];
    config.onionreq_min_path_count_upload =
            cpp_defaults.onionreq_min_path_counts[RequestCategory::upload];
    config.onionreq_min_path_count_download =
            cpp_defaults.onionreq_min_path_counts[RequestCategory::download];
    config.onionreq_single_path_mode = cpp_defaults.onionreq_single_path_mode;
    config.onionreq_disable_pre_build_paths = cpp_defaults.onionreq_disable_pre_build_paths;

    config.quic_handshake_timeout_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(cpp_defaults.quic_handshake_timeout)
                    .count();
    config.quic_keep_alive_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(cpp_defaults.quic_keep_alive).count();
    config.quic_disable_mtu_discovery = cpp_defaults.quic_disable_mtu_discovery;

    config.transport_callback = nullptr;
    config.transport_callback_ctx = nullptr;

    return config;
}

LIBSESSION_C_API bool session_network_init(
        network_object_v2** network, const session_network_config* config, char* error) {
    if (!network || !config)
        return set_error(error, std::invalid_argument{"network or config were null."});

    try {
        // Build the configuration options (ordered this way for the debug logs to make the most
        // sense)
        std::vector<std::any> cpp_opts;

        // Network ID
        switch (config->netid) {
            case SESSION_NETWORK_MAINNET: cpp_opts.emplace_back(opt::netid::mainnet()); break;
            case SESSION_NETWORK_TESTNET: cpp_opts.emplace_back(opt::netid::testnet()); break;
            case SESSION_NETWORK_DEVNET:
                if (!config->devnet_seed_nodes || config->devnet_seed_nodes_size == 0)
                    throw std::runtime_error(
                            "SESSION_NETWORK_DEVNET requires at least one seed node.");

                std::vector<service_node> seed_nodes;
                seed_nodes.reserve(config->devnet_seed_nodes_size);

                for (size_t i = 0; i < config->devnet_seed_nodes_size; ++i)
                    seed_nodes.push_back(service_node::from(config->devnet_seed_nodes[i]));

                cpp_opts.emplace_back(opt::netid::devnet(std::move(seed_nodes)));
                break;
        }

        // Router
        switch (config->router) {
            case SESSION_NETWORK_ROUTER_ONION_REQUESTS:
                cpp_opts.emplace_back(opt::router::onion_requests());
                break;
            case SESSION_NETWORK_ROUTER_LOKINET:
                cpp_opts.emplace_back(opt::router::lokinet());
                break;
            case SESSION_NETWORK_ROUTER_DIRECT: cpp_opts.emplace_back(opt::router::direct()); break;
        }

        // Transport
        switch (config->transport) {
            case SESSION_NETWORK_TRANSPORT_QUIC:
                cpp_opts.emplace_back(opt::transport::quic());
                break;

            case SESSION_NETWORK_TRANSPORT_CALLBACKS:
                if (!config->transport_callback)
                    throw std::runtime_error(
                            "transport_callback must be set when using the CALLBACKS for sending "
                            "requests.");

                auto c_callback_ptr = config->transport_callback;
                auto ctx = config->transport_callback_ctx;

                opt::transport::network_callback_t cpp_callback =
                        [c_callback_ptr, ctx](
                                std::string url,
                                std::string body,
                                session::network::network_response_callback_t handle_response) {
                            auto* c_response_handle =
                                    new session_response_handle_t{std::move(handle_response)};

                            c_callback_ptr(
                                    url.c_str(), body.data(), body.size(), c_response_handle, ctx);
                        };

                cpp_opts.emplace_back(opt::transport::callbacks(std::move(cpp_callback)));
                break;
        }

        if (!config->enforce_subnet_diversity)
            cpp_opts.emplace_back(opt::disable_subnet_diversity{});

        if (config->min_retry_delay_ms > 0 || config->max_retry_delay_ms > 0)
            cpp_opts.emplace_back(opt::retry_delay{
                    std::chrono::milliseconds{config->min_retry_delay_ms},
                    std::chrono::milliseconds{config->max_retry_delay_ms}});

        // A `0` value is valid for this option
        cpp_opts.emplace_back(opt::redirect_retry_count{config->redirect_retry_count});

        if (config->request_timeout_check_frequency_ms > 0)
            cpp_opts.emplace_back(opt::request_timeout_check_frequency{
                    std::chrono::milliseconds{config->request_timeout_check_frequency_ms}});

        // Snode cache
        if (config->cache_dir)
            cpp_opts.emplace_back(opt::cache_directory{std::filesystem::path{config->cache_dir}});

        if (config->cache_expiration_minutes > 0)
            cpp_opts.emplace_back(
                    opt::cache_expiration{std::chrono::minutes{config->cache_expiration_minutes}});

        if (config->cache_refresh_retry_limit > 0)
            cpp_opts.emplace_back(
                    opt::cache_refresh_retry_limit{config->cache_refresh_retry_limit});

        if (config->cache_min_size > 0)
            cpp_opts.emplace_back(opt::cache_min_size{config->cache_min_size});

        // A `0` value is valid for this option
        cpp_opts.emplace_back(opt::cache_num_nodes_to_use_for_refresh{
                config->cache_num_nodes_to_use_for_refresh});

        if (config->cache_node_failure_threshold > 0)
            cpp_opts.emplace_back(
                    opt::cache_node_failure_threshold{config->cache_node_failure_threshold});

        if (config->cache_refresh_using_legacy_endpoint)
            cpp_opts.emplace_back(opt::cache_refresh_using_legacy_endpoint{});

        // Router-specific settings
        switch (config->router) {
            case SESSION_NETWORK_ROUTER_ONION_REQUESTS:
                // Process the Onion Request options since we are using them
                if (config->path_length > 0)
                    cpp_opts.emplace_back(opt::path_length{config->path_length});

                if (config->onionreq_path_failure_threshold > 0)
                    cpp_opts.emplace_back(opt::onionreq_path_failure_threshold{
                            config->onionreq_path_failure_threshold});

                if (config->onionreq_path_build_retry_limit > 0)
                    cpp_opts.emplace_back(opt::onionreq_path_build_retry_limit{
                            config->onionreq_path_build_retry_limit});

                if (config->onionreq_min_path_count_standard > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{
                            RequestCategory::standard, config->onionreq_min_path_count_standard});

                if (config->onionreq_min_path_count_upload > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{
                            RequestCategory::upload, config->onionreq_min_path_count_upload});

                if (config->onionreq_min_path_count_download > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{
                            RequestCategory::download, config->onionreq_min_path_count_download});

                if (config->onionreq_single_path_mode)
                    cpp_opts.emplace_back(opt::onionreq_single_path_mode{});

                if (config->onionreq_disable_pre_build_paths)
                    cpp_opts.emplace_back(opt::onionreq_disable_pre_build_paths{});
                break;

            case SESSION_NETWORK_ROUTER_LOKINET:
                // Process the Lokinet options since we are using them
                if (config->path_length > 0)
                    cpp_opts.emplace_back(opt::path_length{config->path_length});
                break;

            case SESSION_NETWORK_ROUTER_DIRECT: break;
        }

        // Transport-specific settings
        switch (config->transport) {
            case SESSION_NETWORK_TRANSPORT_QUIC:
                if (config->quic_handshake_timeout_seconds > 0)
                    cpp_opts.emplace_back(opt::quic_handshake_timeout{
                            std::chrono::seconds{config->quic_handshake_timeout_seconds}});

                if (config->quic_keep_alive_seconds > 0)
                    cpp_opts.emplace_back(opt::quic_keep_alive{
                            std::chrono::seconds{config->quic_keep_alive_seconds}});

                if (config->quic_disable_mtu_discovery)
                    cpp_opts.emplace_back(opt::quic_disable_mtu_discovery{});

                break;

            case SESSION_NETWORK_TRANSPORT_CALLBACKS: break;
        }

        // Construct the Network instance
        Config final_config(cpp_opts);
        auto n = std::make_unique<Network_v2>(std::move(final_config));
        auto n_object = std::make_unique<network_object_v2>();
        n_object->internals = n.release();
        *network = n_object.release();
        return true;
    } catch (const std::exception& e) {
        return set_error(error, e);
    }
}

LIBSESSION_C_API void network_free_v2(network_object_v2* network) {
    delete static_cast<session::network::Network_v2*>(network->internals);
    delete network;
}

LIBSESSION_C_API void session_request_params_free(session_request_params* params) {
    if (params)
        std::free(params);
}

LIBSESSION_C_API uint64_t session_network_time_offset(network_object_v2* network) {
    return unbox(network).network_time_offset().count();
}

LIBSESSION_C_API int session_network_hardfork(network_object_v2* network) {
    return unbox(network).hardfork();
}

LIBSESSION_C_API int session_network_softfork(network_object_v2* network) {
    return unbox(network).softfork();
}

LIBSESSION_C_API void session_network_set_status_changed_callback(
        network_object_v2* network, void (*callback)(CONNECTION_STATUS status, void* ctx), void* ctx) {
    if (!callback)
        unbox(network).on_status_changed = nullptr;
    else
        unbox(network).on_status_changed = [cb = std::move(callback), ctx](ConnectionStatus status) {
            cb(static_cast<CONNECTION_STATUS>(status), ctx);
        };
}

LIBSESSION_C_API void session_network_callbacks_respond(
        network_object_v2* network,
        session_response_handle_t* response_handle,
        bool success,
        bool timeout,
        int16_t status_code,
        const char* const* headers_,
        const char* const* header_values,
        size_t headers_size,
        const char* body_,
        size_t body_len) {
    if (!response_handle)
        return;

    std::unique_ptr<session_response_handle_cpp_t> handle_guard(response_handle);
    std::vector<std::pair<std::string, std::string>> headers;
    headers.reserve(headers_size);

    if (headers_size > 0)
        for (size_t i = 0; i < headers_size; i++)
            headers.emplace_back(headers_[i], header_values[i]);

    std::optional<std::string> body;
    if (body_len > 0)
        body.emplace(body_, body_len);

    handle_guard->cpp_callback(success, timeout, status_code, std::move(headers), std::move(body));
}

LIBSESSION_C_API void session_network_get_active_paths(
    network_object_v2* network,
    session_path_info** out_paths,
    size_t* out_paths_len) {
    if (!network || !out_paths || !out_paths_len)
        return;

    *out_paths = nullptr;
    *out_paths_len = 0;

    try {
        std::vector<PathInfo> cpp_paths = unbox(network).get_active_paths();
        if (cpp_paths.empty())
            return;

        // Calculate the size of the data
        size_t total_size = cpp_paths.size() * sizeof(session_path_info);
        size_t total_nodes = 0;
        for (const auto& path : cpp_paths)
            total_nodes += path.nodes.size();
        total_size += total_nodes * sizeof(network_service_node);
        
        size_t total_metadata_size = 0;
        for (const auto& p : cpp_paths) {
            std::visit([&](auto&& md) {
                using T = std::decay_t<decltype(md)>;
                if constexpr (std::is_same_v<T, OnionPathMetadata>)
                    total_metadata_size += sizeof(session_onion_path_metadata);
                else if constexpr (std::is_same_v<T, LokinetTunnelMetadata>)
                    total_metadata_size += sizeof(session_lokinet_tunnel_metadata);
            }, p.metadata);
        }
        total_size += total_metadata_size;

        // Allocate and assign the memory
        unsigned char* buffer = static_cast<unsigned char*>(std::malloc(total_size));
        if (!buffer)
            return;

        auto* c_paths_array = reinterpret_cast<session_path_info*>(buffer);
        auto* current_node_ptr = reinterpret_cast<network_service_node*>(c_paths_array + cpp_paths.size());
        unsigned char* current_metadata_ptr = reinterpret_cast<unsigned char*>(current_node_ptr + total_nodes);

        for (size_t i = 0; i < cpp_paths.size(); ++i) {
            const auto& cpp_path = cpp_paths[i];
            auto& c_path = c_paths_array[i];
            
            new (&c_path) session_path_info{};
            
            c_path.nodes = current_node_ptr;
            c_path.nodes_count = cpp_path.nodes.size();
            for (const auto& cpp_node : cpp_path.nodes) {
                new (current_node_ptr) network_service_node{};
                cpp_node.into(*current_node_ptr);
                current_node_ptr++;
            }
            
            // Copy metadata
            std::visit([&](auto&& m) {
                using T = std::decay_t<decltype(m)>;

                if constexpr (std::is_same_v<T, OnionPathMetadata>) {
                    auto* meta = reinterpret_cast<session_onion_path_metadata*>(current_metadata_ptr);
                    new (meta) session_onion_path_metadata{};
                    meta->category = static_cast<SESSION_NETWORK_REQUEST_CATEGORY>(m.category);
                    c_path.onion_metadata = meta;
                    current_metadata_ptr += sizeof(session_onion_path_metadata);
                } else if constexpr (std::is_same_v<T, LokinetTunnelMetadata>) {
                    auto* meta = reinterpret_cast<session_lokinet_tunnel_metadata*>(current_metadata_ptr);
                    new (meta) session_lokinet_tunnel_metadata{};
                    strncpy(meta->destination_pubkey, m.destination_pubkey.c_str(), sizeof(meta->destination_pubkey) - 1);
                    meta->destination_pubkey[sizeof(meta->destination_pubkey) - 1] = '\0';
                    strncpy(meta->destination_snode_address, m.destination_snode_address.c_str(), sizeof(meta->destination_snode_address) - 1);
                    meta->destination_snode_address[sizeof(meta->destination_snode_address) - 1] = '\0';
                    c_path.lokinet_metadata = meta;
                    current_metadata_ptr += sizeof(session_lokinet_tunnel_metadata);
                }
            }, cpp_path.metadata);
        }
        
        *out_paths = c_paths_array;
        *out_paths_len = cpp_paths.size();
    } catch (...) {
        *out_paths = nullptr;
        *out_paths_len = 0;
    }
}

LIBSESSION_C_API void session_network_paths_free(session_path_info* paths) {
    if (paths)
        std::free(paths);
}

LIBSESSION_C_API void session_network_get_swarm(
        network_object_v2* network,
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

LIBSESSION_C_API void session_network_get_random_nodes(
        network_object_v2* network,
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

LIBSESSION_C_API void session_network_send_request(
        network_object_v2* network,
        const session_request_params* params,
        session_network_response_t callback,
        void* ctx) {
    assert(callback);

    try {
        if (!network)
            throw std::invalid_argument("Invalid request: 'network' cannot be null.");
        if (!params)
            throw std::invalid_argument("Invalid request: 'params' cannot be null.");

        network_destination dest;

        if (params->snode_dest && params->server_dest)
            throw std::invalid_argument(
                    "Invalid request: Cannot have both 'snode_dest' and 'server_dest' set.");

        if (params->snode_dest) {
            dest = service_node::from(*params->snode_dest);
        } else if (params->server_dest) {
            const auto& c_server = *params->server_dest;

            std::optional<std::vector<std::pair<std::string, std::string>>> headers;
            if (c_server.headers_kv_pairs && c_server.headers_kv_pairs_len > 0) {
                if (c_server.headers_kv_pairs_len % 2 != 0)
                    throw std::invalid_argument(
                            "Invalid request: Header must have an even number of key-value "
                            "strings.");

                headers.emplace();
                headers->reserve(c_server.headers_kv_pairs_len / 2);
                for (int i = 0; i < c_server.headers_kv_pairs_len; i += 2) {
                    const char* key = c_server.headers_kv_pairs[i];
                    const char* val = c_server.headers_kv_pairs[i + 1];

                    if (!key || !val)
                        throw std::invalid_argument(
                                "Invalid request: Header list contains a null key or value.");

                    headers->emplace_back(key, val);
                }
            }

            dest = ServerDestination{
                    c_server.protocol,
                    c_server.host,
                    x25519_pubkey::from_hex(c_server.x25519_pubkey_hex),
                    (c_server.port > 0 ? std::optional{c_server.port} : std::nullopt),
                    headers,
                    c_server.method};
        } else
            throw std::invalid_argument(
                    "Invalid request: Must have either 'snode_dest' or 'server_dest' set.");

        std::optional<std::vector<unsigned char>> body;
        if (params->body && params->body_size > 0)
            body.emplace(params->body, params->body + params->body_size);

        std::optional<std::string> request_id;
        if (params->request_id)
            request_id = params->request_id;

        auto request = Request{
                dest,
                std::string{params->endpoint},
                body,
                static_cast<RequestCategory>(params->category),
                std::chrono::milliseconds{params->request_timeout_ms},
                (params->overall_timeout_ms > 0
                         ? std::optional{std::chrono::milliseconds{params->overall_timeout_ms}}
                         : std::nullopt),
                request_id};
        auto cpp_callback = [c_cb = callback, c_ctx = ctx](
                                    bool success,
                                    bool timeout,
                                    int16_t status_code,
                                    std::vector<std::pair<std::string, std::string>> headers,
                                    std::optional<std::string> body) {
            std::vector<const char*> c_headers;
            c_headers.reserve(headers.size() * 2 + 1);
            for (const auto& [key, val] : headers) {
                c_headers.push_back(key.c_str());
                c_headers.push_back(val.c_str());
            }
            c_headers.push_back(nullptr);  // NULL terminator

            c_cb(success,
                 timeout,
                 status_code,
                 c_headers.data(),
                 (headers.size() * 2),
                 body ? reinterpret_cast<const unsigned char*>(body->data()) : nullptr,
                 body ? body->size() : 0,
                 c_ctx);
        };

        unbox(network).send_request(std::move(request), std::move(cpp_callback));
    } catch (const std::exception& e) {
        callback(
                false,
                false,
                -1,
                nullptr,
                0,
                reinterpret_cast<const unsigned char*>(e.what()),
                strlen(e.what()),
                ctx);
    }
}

}  // extern "C"
