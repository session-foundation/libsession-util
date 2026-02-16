#include "session/network/session_network.hpp"

#include <oxenc/base64.h>

#include <any>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <vector>

#include "session/blinding.hpp"
#include "session/network/network_config.hpp"
#include "session/network/network_opt.hpp"
#include "session/network/request_queue.hpp"
#include "session/network/routing/direct_router.hpp"
#include "session/network/routing/onion_request_router.hpp"
#include "session/network/routing/session_router_router.hpp"
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
    constexpr auto clock_out_of_sync_error = "Clock out of sync";

    config::SnodePoolConfig build_snode_pool_config(const config::Config& main_config) {
        return {main_config.cache_directory,
                main_config.cache_expiration,
                main_config.cache_min_lifetime,
                main_config.enforce_subnet_diversity,
                main_config.retry_delay,
                main_config.netid,
                main_config.seed_nodes,
                main_config.cache_min_size,
                main_config.cache_min_swarm_size,
                main_config.cache_num_nodes_to_use_for_refresh,
                main_config.cache_min_num_refresh_presence_to_include_node,
                main_config.cache_node_strike_threshold,
                main_config.cache_refresh_using_legacy_endpoint};
    }

    config::QuicTransportConfig build_quic_transport_config(const config::Config& main_config) {
        return {main_config.quic_handshake_timeout,
                main_config.quic_keep_alive,
                main_config.quic_disable_mtu_discovery,
                main_config.quic_max_streams};
    }

    config::SessionRouterConfig build_session_router_config(const config::Config& main_config) {
        if (!main_config.cache_directory)
            throw std::invalid_argument{
                    "Session Router requires a cache_directory to be configured."};

        if (main_config.netid == opt::netid::Target::devnet)
            throw std::invalid_argument{"Session Router does not support devnet."};

        return {main_config.netid, *main_config.cache_directory, main_config.path_length};
    }

    config::OnionRequestRouterConfig build_onion_request_router_config(
            const config::Config& main_config) {
        return {main_config.cache_directory,
                main_config.onionreq_edge_node_cache_duration,
                main_config.netid,
                main_config.seed_nodes,
                main_config.retry_delay,
                main_config.path_length,
                main_config.onionreq_path_strike_threshold,
                main_config.onionreq_path_build_retry_limit,
                main_config.onionreq_path_rotation_frequency,
                main_config.cache_node_strike_threshold,
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

Network::Network(config::Config config) : config{config} {
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
    _disk_manager = std::make_shared<DiskManager>();

    // Setup the transport layer
    switch (config.transport) {
        case opt::transport::Type::quic:
            _transport = std::make_shared<QuicTransport>(
                    std::move(build_quic_transport_config(config)), _loop);
            break;

        case opt::transport::Type::callbacks:
            // _transport = std::make_shared<SessionRouterTransport>(_config, *_snode_pool, _loop);
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
            std::move(build_snode_pool_config(config)), _loop, _disk_manager, bootstrap_fetcher);

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
                    _disk_manager,
                    _snode_pool,
                    _transport);
            break;

        case opt::router::Type::session_router:
            _router = std::make_unique<SessionRouter>(
                    std::move(build_session_router_config(config)), _loop, _snode_pool, _transport);
            break;

        case opt::router::Type::direct:
            _router = std::make_unique<DirectRouter>(_loop, _transport);
            break;
    }

    // Now that we have our router setup we need to setup the `standard_fetcher` on the `SnodePool`
    auto routed_fetcher = [r = std::weak_ptr{_router}, loop = _loop](
                                  Request req, network_response_callback_t on_complete) {
        loop->call([r, req = std::move(req), on_complete = std::move(on_complete)] {
            if (auto router = r.lock())
                router->send_request(std::move(req), std::move(on_complete));
            else
                log::error(
                        cat, "Router provided to the SnodePool routed_fetcher has been destroyed.");
        });
    };
    auto routed_fetcher_connected = [r = std::weak_ptr{_router}, loop = _loop]() -> bool {
        return loop->call_get([r] {
            if (auto router = r.lock())
                return router->get_status() == ConnectionStatus::connected;

            return false;
        });
    };
    _snode_pool->set_routed_fetcher(std::move(routed_fetcher), std::move(routed_fetcher_connected));

    // Add hooks to update the connection status
    _router->on_status_changed = [this] { _recalculate_status(); };
    _transport->on_status_changed = [this] { _recalculate_status(); };

    // Perform a clock resync
    _loop->call_soon([this] { _resync_clock(std::nullopt, std::nullopt); });
}

Network::~Network() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        // Need to ensure the destruction of the router and transport objects don't trigger
        // `_recalculate_status` since that accesses both values which could result in a crash due
        // to accessing deallocated memory
        if (_router)
            _router->on_status_changed = nullptr;
        if (_transport)
            _transport->on_status_changed = nullptr;

        _update_status(ConnectionStatus::disconnected);
    });
    log::debug(cat, "Destroyed.");
}

void Network::clear_cache() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        if (_snode_pool)
            _snode_pool->clear_cache();
        if (_router)
            _router->clear_cache();
    });
}

// MARK: Connection

void Network::suspend() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        _suspended = true;

        if (_snode_pool)
            _snode_pool->suspend();
        if (_transport)
            _transport->suspend();
        if (_router)
            _router->suspend();

        _close_connections();
        log::info(cat, "Suspended.");
    });
}

void Network::resume(bool automatically_reconnect) {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this, automatically_reconnect] {
        if (!_suspended)
            return;

        if (_snode_pool)
            _snode_pool->resume();
        if (_transport)
            _transport->resume(automatically_reconnect);
        if (_router)
            _router->resume(automatically_reconnect);

        // When resuming we may need to resync the clock but don't want to do so if the last resync
        // was too recent (eg. if a user backgrounds and foregrounds the app frequently)
        auto time_since_last_resync =
                std::chrono::steady_clock::now() - _last_successful_clock_resync;

        if (time_since_last_resync >= config.min_resume_clock_resync_interval) {
            _loop->call_soon([this] {
                log::info(
                        cat,
                        "Performing clock resync as enough time has passed since the last resync.");
                _resync_clock(std::nullopt, std::nullopt);
            });
        }

        _suspended = false;
        log::info(cat, "Resumed.");
    });
}

void Network::close_connections() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] { _close_connections(); });
}

// MARK: Interface

ConnectionStatus Network::get_status() {
    return _status.load();
}

std::vector<PathInfo> Network::get_active_paths() {
    if (_router)
        return _router->get_active_paths();

    return {};
}

void Network::get_swarm(
        session::network::x25519_pubkey swarm_pubkey,
        bool ignore_strike_count,
        std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback) {
    _loop->call([this,
                 pubkey = std::move(swarm_pubkey),
                 ignore_strike_count,
                 cb = std::move(callback)] {
        if (!_snode_pool) {
            log::warning(
                    cat,
                    "Attempted to get swarm for {} but SnodePool has been destroyed.",
                    pubkey.hex());
            return cb(INVALID_SWARM_ID, {});
        }

        _snode_pool->get_swarm(std::move(pubkey), ignore_strike_count, std::move(cb));
    });
}

void Network::get_random_nodes(
        uint16_t count, std::function<void(std::vector<service_node> nodes)> callback) {
    _loop->call([this, count, cb = std::move(callback)] {
        if (!_snode_pool) {
            log::warning(
                    cat,
                    "Attempted to get {} random nodes(s) but SnodePool has been destroyed.",
                    count);
            return cb({});
        }

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

void Network::send_request(Request request, network_response_callback_t callback) {
    if (_suspended) {
        callback(
                false,
                false,
                ERROR_NETWORK_SUSPENDED,
                {content_type_plain_text},
                "Network is suspended.");
        return;
    }
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
                    const auto dest_is_snode =
                            std::holds_alternative<service_node>(original_req.destination);

                    // If we got a successful response (with a body) and the request was sent to a
                    // service node then we should update the network state based on the response
                    // (Note: we don't want to do this for server requests because they could
                    // include values in different formats, eg. the "Session Network" API returns
                    // `t` in seconds)
                    if (success && body && dest_is_snode)
                        _update_network_state(*body);

                    int16_t final_status_code = status_code;

                    if (body)
                        if (auto uniform_error = Response::find_uniform_batch_error(*body))
                            final_status_code = *uniform_error;

                    // If we got a 406 from a snode, or a 425 from a server, then the device clock
                    // is out of sync so we need to kick off a clock resync request
                    if ((final_status_code == 406 && dest_is_snode) ||
                        (final_status_code == 425 && !dest_is_snode)) {
                        _resync_clock(std::move(original_req), std::move(cb));
                        return;
                    }

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

void Network::_close_connections() {
    if (_transport)
        _transport->close_connections();
    if (_router)
        _router->close_connections();

    _recalculate_status();
    log::info(cat, "Closed all connections.");
}

void Network::_recalculate_status() {
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

void Network::_update_status(ConnectionStatus new_status) {
    if (_status == new_status)
        return;

    _status = new_status;

    if (on_status_changed)
        on_status_changed(new_status);
}

Request Network::_preprocess_request(Request request) {
    std::visit(
            [&](auto&& details) {
                using T = std::decay_t<decltype(details)>;

                if constexpr (std::is_same_v<T, UploadInfo>) {
                    if (!request.body)
                        throw std::invalid_argument("Upload request must have a body.");

                    if (request.category != RequestCategory::file) {
                        log::warning(
                                cat,
                                "Request {} has UploadInfo but category is not 'file', forcing "
                                "to 'file'.",
                                request.request_id);
                        request.category = RequestCategory::file;
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

void Network::_update_network_state(const std::string& body) {
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

        // Update hardfork/softfork versions
        auto old_versions = _fork_versions.load();

        if (target_json->contains("hf") && (*target_json)["hf"].is_array() &&
            (*target_json)["hf"].size() >= 2) {
            std::pair<uint16_t, uint16_t> new_versions = {
                    (*target_json)["hf"][0].get<uint16_t>(),
                    (*target_json)["hf"][1].get<uint16_t>()};

            auto current_versions = old_versions;
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

        // If the network info changed then call the callback
        if (on_network_info_changed) {
            auto new_versions = _fork_versions.load();

            if (new_versions != old_versions)
                on_network_info_changed(
                        _network_time_offset.load(), new_versions.hardfork, new_versions.softfork);
        }
    } catch (const std::exception& e) {
        log::warning(cat, "Failed to parse network state from response: {}", e.what());
    }
}

// MARK: Specific Error Handling

void Network::_handle_421_retry(
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
            "Request {} received 421 from node {}, refreshing swarm if stale.",
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
                        false,
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

void Network::_resync_clock(
        std::optional<Request> original_request,
        std::optional<network_response_callback_t> request_callback) {
    if (_suspended) {
        log::info(cat, "Ignoring clock resync attempt as network is suspended.");
        if (request_callback)
            (*request_callback)(
                    false,
                    false,
                    ERROR_NETWORK_SUSPENDED,
                    {content_type_plain_text},
                    "Network is suspended.");
        return;
    }

    // Add the request to the request queue, we do this so we can trigger it's callback after the
    // resync completes as it would likely fail with another clock out of sync error if it gets
    // retried immediately
    if (original_request && request_callback) {
        // If we don't have a resync request queue then create one
        if (!_clock_resync_request_queue)
            _clock_resync_request_queue = std::make_shared<detail::RequestQueue>(_loop);

        _clock_resync_request_queue->add(
                std::move(*original_request), std::move(*request_callback));
    }

    // Only allow a single clock resync at a time
    if (_current_clock_resync_id) {
        log::debug(
                cat,
                "A resync is already in progress ({}), adding request to be processed after "
                "result.",
                *_current_clock_resync_id);
        return;
    }

    const auto request_id = "CoS-" + random::random_base32(4);
    log::info(cat, "[Request {}] Starting clock resync.", request_id);
    _current_clock_resync_id = request_id;
    _clock_resync_results.clear();

    // Pick the random nodes we want to use for retrying (these won't change for this resync
    // attempt)
    auto resync_nodes = _snode_pool->get_unused_nodes(config.num_nodes_to_check_for_network_offset);

    for (uint8_t i = 0; i < resync_nodes.size(); ++i)
        _launch_next_clock_out_of_sync_request(
                request_id, i, resync_nodes[i], config.num_nodes_to_check_for_network_offset);
}

void Network::_launch_next_clock_out_of_sync_request(
        const std::string& request_id,
        const uint8_t index,
        const service_node& node,
        const uint8_t total_requests) {
    if (!_current_clock_resync_id)
        return;

    const auto target_request_id = "{}-{}"_format(request_id, index);
    log::info(
            cat,
            "[Request {}] Launching clock resync request to {}",
            target_request_id,
            node.to_string());
    const Request request = Request{
            target_request_id,
            network_destination{node},
            std::string{"info"},
            std::nullopt,
            RequestCategory::standard,
            10s,
            std::nullopt,      // overall_timeout
            std::monostate{},  // details
            false              // ephemeral_connection
    };

    auto start = std::chrono::steady_clock::now();
    send_request(
            std::move(request),
            [this, request_id, target_request_id, total_requests, start](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                auto end_steady = std::chrono::steady_clock::now();
                auto end_system = std::chrono::system_clock::now();

                // If the resync was cancelled or completed while we were in-flight, do nothing
                if (!_current_clock_resync_id || *_current_clock_resync_id != request_id) {
                    log::info(
                            cat,
                            "[Request {}] Ignoring stale clock resync response.",
                            target_request_id);
                    return;
                }

                try {
                    if (!success || timeout || !response)
                        throw std::runtime_error{response.value_or("Unknown error.")};

                    if (status_code < 200 || status_code > 299)
                        throw status_code_exception{
                                status_code,
                                {content_type_plain_text},
                                "Request failed with status code: {}, error: {}"_format(
                                        status_code, response.value_or("Unknown error."))};

                    auto json = nlohmann::json::parse(*response);

                    if (!json.contains("t") || !json["t"].is_number())
                        throw std::runtime_error{"Response didn't contain a 't' value"};

                    auto server_timestamp_ms = json["t"].get<int64_t>();
                    auto server_time = std::chrono::time_point<std::chrono::system_clock>(
                            std::chrono::milliseconds{server_timestamp_ms});
                    auto latency = ((end_steady - start) / 2);
                    auto tmp = latency.count();
                    auto offset = std::chrono::duration_cast<std::chrono::milliseconds>(
                            (server_time - end_system) - latency);
                    _clock_resync_results.push_back(std::move(offset));

                    log::info(
                            cat,
                            "[Request {}] Received clock resync response {}/{} with offset: {}ms.",
                            target_request_id,
                            _clock_resync_results.size(),
                            total_requests,
                            offset.count());
                } catch (const std::exception& e) {
                    // If one of the requests fails then don't worry about it (we still get the
                    // median, and if this happens to result in subsequent clock out of sync errors
                    // then we will trigger another resync)
                    _clock_resync_results.push_back(std::nullopt);

                    log::warning(
                            cat,
                            "[Request {}] Clock resync attempt {}/{} failed: {}.",
                            target_request_id,
                            _clock_resync_results.size(),
                            total_requests,
                            e.what());
                }

                // If we've received all the results then we need to process them and complete the
                // resync
                if (_clock_resync_results.size() >= total_requests) {
                    auto final_results = std::move(_clock_resync_results);
                    auto refresh_id = *_current_clock_resync_id;
                    _on_clock_resync_complete(refresh_id, final_results, total_requests);
                }
            });
}

void Network::_on_clock_resync_complete(
        std::string refresh_id,
        std::vector<std::optional<std::chrono::milliseconds>> raw_results,
        const uint8_t total_requests) {
    log::info(
            cat,
            "[Request {}] Have {} responses, processing and finalizing clock resync.",
            refresh_id,
            raw_results.size());

    // Filter and sort the offsets and find the median
    std::vector<std::chrono::milliseconds> result;

    for (const auto& opt : raw_results)
        if (opt)
            result.push_back(*opt);

    const auto count = result.size();

    // If we got a successful response then we should update the network offset
    if (count > 0) {
        std::chrono::milliseconds median_offset;
        std::sort(result.begin(), result.end());

        if (count % 2 == 1)
            median_offset = result[count / 2];
        else {
            auto mid_index = (count / 2);
            auto middle_values_sum = (result[mid_index - 1] + result[mid_index]);
            median_offset = (middle_values_sum / 2);
        }

        _network_time_offset = median_offset;
        _last_successful_clock_resync = std::chrono::steady_clock::now();
        log::info(
                cat, "[Request {}] Network offset set to: {}ms", refresh_id, median_offset.count());

        // Trigger the network info changed callback to update the client
        if (on_network_info_changed) {
            auto versions = _fork_versions.load();

            on_network_info_changed(median_offset, versions.hardfork, versions.softfork);
        }
    }

    // Now that the clock resync is complete (regardless of whether it was successful or not) we can
    // fail any requests which received clock out of sync errors while waiting for the resync to
    // complete (we can't automatically retry as libSession can't currently reconstruct the requests
    // with updated timestamps)
    if (_clock_resync_request_queue && !_clock_resync_request_queue->is_empty()) {
        auto pending = _clock_resync_request_queue->pop_all();
        log::debug(cat, "Failing {} requests queued during clock resync.", pending.size());

        for (auto& [req, cb] : pending) {
            const auto dest_is_snode = std::holds_alternative<service_node>(req.destination);
            cb(false,
               false,
               (dest_is_snode ? 406 : 425),
               {content_type_plain_text},
               clock_out_of_sync_error);
        }
    }
}

}  // namespace session::network

// MARK: C API

struct session_response_handle_cpp_t {
    session::network::network_response_callback_t cpp_callback;
};

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
        case opt::router::Type::session_router:
            config.router = SESSION_NETWORK_ROUTER_SESSION_ROUTER;
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
    config.num_nodes_to_check_for_network_offset =
            cpp_defaults.num_nodes_to_check_for_network_offset;
    config.min_resume_clock_resync_interval_minutes =
            std::chrono::duration_cast<std::chrono::minutes>(
                    cpp_defaults.min_resume_clock_resync_interval)
                    .count();

    config.devnet_seed_nodes = nullptr;
    config.devnet_seed_nodes_size = 0;

    config.cache_dir = nullptr;
    config.cache_expiration_minutes =
            std::chrono::duration_cast<std::chrono::minutes>(cpp_defaults.cache_expiration).count();
    config.cache_min_lifetime_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(cpp_defaults.cache_min_lifetime)
                    .count();

    config.cache_min_size = cpp_defaults.cache_min_size;
    config.cache_min_swarm_size = cpp_defaults.cache_min_swarm_size;
    config.cache_num_nodes_to_use_for_refresh = cpp_defaults.cache_num_nodes_to_use_for_refresh;
    config.cache_min_num_refresh_presence_to_include_node =
            cpp_defaults.cache_min_num_refresh_presence_to_include_node;
    config.cache_node_strike_threshold = cpp_defaults.cache_node_strike_threshold;
    config.cache_refresh_using_legacy_endpoint = cpp_defaults.cache_refresh_using_legacy_endpoint;

    config.onionreq_path_strike_threshold = cpp_defaults.onionreq_path_strike_threshold;
    config.onionreq_path_build_retry_limit = cpp_defaults.onionreq_path_build_retry_limit;
    config.onionreq_min_path_count_standard =
            cpp_defaults.onionreq_min_path_counts[PathCategory::standard];
    config.onionreq_min_path_count_file = cpp_defaults.onionreq_min_path_counts[PathCategory::file];
    config.onionreq_single_path_mode = cpp_defaults.onionreq_single_path_mode;
    config.onionreq_disable_pre_build_paths = cpp_defaults.onionreq_disable_pre_build_paths;
    config.onionreq_path_rotation_frequency_minutes =
            cpp_defaults.onionreq_path_rotation_frequency.count();
    config.onionreq_edge_node_cache_duration_days =
            cpp_defaults.onionreq_edge_node_cache_duration.count();

    config.quic_handshake_timeout_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(cpp_defaults.quic_handshake_timeout)
                    .count();
    config.quic_keep_alive_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(cpp_defaults.quic_keep_alive).count();
    config.quic_disable_mtu_discovery = cpp_defaults.quic_disable_mtu_discovery;
    config.quic_max_general_streams = cpp_defaults.quic_max_streams[RequestCategory::standard];
    config.quic_max_file_streams = cpp_defaults.quic_max_streams[RequestCategory::file];

    config.transport_callback = nullptr;
    config.transport_callback_ctx = nullptr;

    return config;
}

LIBSESSION_C_API bool session_network_init(
        network_object** network, const session_network_config* config, char* error) {
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
            case SESSION_NETWORK_ROUTER_SESSION_ROUTER:
                cpp_opts.emplace_back(opt::router::session_router());
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

        if (config->num_nodes_to_check_for_network_offset > 0)
            cpp_opts.emplace_back(opt::num_nodes_to_check_for_network_offset{
                    config->num_nodes_to_check_for_network_offset});

        if (config->min_resume_clock_resync_interval_minutes > 0)
            cpp_opts.emplace_back(opt::min_resume_clock_resync_interval{
                    std::chrono::minutes{config->min_resume_clock_resync_interval_minutes}});

        // Snode cache
        if (config->cache_dir)
            cpp_opts.emplace_back(opt::cache_directory{std::filesystem::path{config->cache_dir}});

        if (config->cache_expiration_minutes > 0)
            cpp_opts.emplace_back(
                    opt::cache_expiration{std::chrono::minutes{config->cache_expiration_minutes}});

        if (config->cache_min_lifetime_ms > 0)
            cpp_opts.emplace_back(opt::cache_min_lifetime{
                    std::chrono::milliseconds{config->cache_min_lifetime_ms}});

        if (config->cache_min_size > 0)
            cpp_opts.emplace_back(opt::cache_min_size{config->cache_min_size});

        if (config->cache_min_swarm_size > 0)
            cpp_opts.emplace_back(opt::cache_min_swarm_size{config->cache_min_swarm_size});

        // A `0` value is valid for these options
        cpp_opts.emplace_back(opt::cache_num_nodes_to_use_for_refresh{
                config->cache_num_nodes_to_use_for_refresh});
        cpp_opts.emplace_back(opt::cache_min_num_refresh_presence_to_include_node{
                config->cache_min_num_refresh_presence_to_include_node});

        if (config->cache_node_strike_threshold > 0)
            cpp_opts.emplace_back(
                    opt::cache_node_strike_threshold{config->cache_node_strike_threshold});

        if (config->cache_refresh_using_legacy_endpoint)
            cpp_opts.emplace_back(opt::cache_refresh_using_legacy_endpoint{});

        // Router-specific settings
        switch (config->router) {
            case SESSION_NETWORK_ROUTER_ONION_REQUESTS:
                // Process the Onion Request options since we are using them
                if (config->path_length > 0)
                    cpp_opts.emplace_back(opt::path_length{config->path_length});

                if (config->onionreq_path_strike_threshold > 0)
                    cpp_opts.emplace_back(opt::onionreq_path_strike_threshold{
                            config->onionreq_path_strike_threshold});

                if (config->onionreq_path_build_retry_limit > 0)
                    cpp_opts.emplace_back(opt::onionreq_path_build_retry_limit{
                            config->onionreq_path_build_retry_limit});

                if (config->onionreq_min_path_count_standard > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{
                            PathCategory::standard, config->onionreq_min_path_count_standard});

                if (config->onionreq_min_path_count_file > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{
                            PathCategory::file, config->onionreq_min_path_count_file});

                if (config->onionreq_single_path_mode)
                    cpp_opts.emplace_back(opt::onionreq_single_path_mode{});

                if (config->onionreq_disable_pre_build_paths)
                    cpp_opts.emplace_back(opt::onionreq_disable_pre_build_paths{});

                if (config->onionreq_path_rotation_frequency_minutes > 0)
                    cpp_opts.emplace_back(
                            opt::onionreq_path_rotation_frequency{std::chrono::minutes{
                                    config->onionreq_path_rotation_frequency_minutes}});

                if (config->onionreq_edge_node_cache_duration_days > 0)
                    cpp_opts.emplace_back(opt::onionreq_edge_node_cache_duration{
                            std::chrono::days{config->onionreq_edge_node_cache_duration_days}});
                break;

            case SESSION_NETWORK_ROUTER_SESSION_ROUTER:
                // Process the Session Router options since we are using them
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

                if (config->quic_max_general_streams > 0)
                    cpp_opts.emplace_back(opt::quic_max_streams{
                            RequestCategory::standard, config->quic_max_general_streams});

                if (config->quic_max_file_streams > 0)
                    cpp_opts.emplace_back(opt::quic_max_streams{
                            RequestCategory::file, config->quic_max_file_streams});

                break;

            case SESSION_NETWORK_TRANSPORT_CALLBACKS: break;
        }

        // Construct the Network instance
        Config final_config(cpp_opts);
        auto n = std::make_unique<Network>(std::move(final_config));
        auto n_object = std::make_unique<network_object>();
        n_object->internals = n.release();
        *network = n_object.release();
        return true;
    } catch (const std::exception& e) {
        return set_error(error, e);
    }
}

LIBSESSION_C_API void session_network_free(network_object* network) {
    delete static_cast<session::network::Network*>(network->internals);
    delete network;
}

LIBSESSION_C_API void session_request_params_free(session_request_params* params) {
    if (params)
        std::free(params);
}

LIBSESSION_C_API void session_network_suspend(network_object* network) {
    unbox(network).suspend();
}

LIBSESSION_C_API void session_network_resume(
        network_object* network, bool automatically_reconnect) {
    unbox(network).resume(automatically_reconnect);
}

LIBSESSION_C_API void session_network_close_connections(network_object* network) {
    unbox(network).close_connections();
}

LIBSESSION_C_API void session_network_clear_cache(network_object* network) {
    unbox(network).clear_cache();
}

LIBSESSION_C_API int64_t session_network_time_offset(network_object* network) {
    return unbox(network).network_time_offset().count();
}

LIBSESSION_C_API uint16_t session_network_hardfork(network_object* network) {
    return unbox(network).hardfork();
}

LIBSESSION_C_API uint16_t session_network_softfork(network_object* network) {
    return unbox(network).softfork();
}

LIBSESSION_C_API void session_network_set_status_changed_callback(
        network_object* network, void (*callback)(CONNECTION_STATUS status, void* ctx), void* ctx) {
    if (!callback)
        unbox(network).on_status_changed = nullptr;
    else
        unbox(network).on_status_changed = [cb = std::move(callback),
                                            ctx](ConnectionStatus status) {
            cb(static_cast<CONNECTION_STATUS>(status), ctx);
        };
}

LIBSESSION_C_API void session_network_set_network_info_changed_callback(
        network_object* network,
        void (*callback)(
                int64_t network_time_offset, uint16_t hardfork, uint16_t softfork, void* ctx),
        void* ctx) {
    if (!callback)
        unbox(network).on_network_info_changed = nullptr;
    else
        unbox(network).on_network_info_changed =
                [cb = std::move(callback), ctx](
                        std::chrono::milliseconds network_time_offset,
                        uint16_t hardfork,
                        uint16_t softfork) {
                    cb(network_time_offset.count(), hardfork, softfork, ctx);
                };
}

LIBSESSION_C_API void session_network_callbacks_respond(
        network_object* network,
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

    std::unique_ptr<session_response_handle_cpp_t> handle_edge(response_handle);
    std::vector<std::pair<std::string, std::string>> headers;
    headers.reserve(headers_size);

    if (headers_size > 0)
        for (size_t i = 0; i < headers_size; i++)
            headers.emplace_back(headers_[i], header_values[i]);

    std::optional<std::string> body;
    if (body_len > 0)
        body.emplace(body_, body_len);

    handle_edge->cpp_callback(success, timeout, status_code, std::move(headers), std::move(body));
}

LIBSESSION_C_API CONNECTION_STATUS session_network_get_status(network_object* network) {
    if (!network)
        return CONNECTION_STATUS_UNKNOWN;

    return static_cast<CONNECTION_STATUS>(unbox(network).get_status());
}

LIBSESSION_C_API void session_network_get_active_paths(
        network_object* network, session_path_info** out_paths, size_t* out_paths_len) {
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
            std::visit(
                    [&]<typename T>(const T& md) {
                        if constexpr (std::is_same_v<T, OnionPathMetadata>)
                            total_metadata_size += sizeof(session_onion_path_metadata);
                        else {
                            static_assert(std::is_same_v<T, SessionRouterTunnelMetadata>);
                            total_metadata_size += sizeof(session_router_tunnel_metadata);
                        }
                    },
                    p.metadata);
        }
        total_size += total_metadata_size;

        // Allocate and assign the memory
        unsigned char* buffer = static_cast<unsigned char*>(std::malloc(total_size));
        if (!buffer)
            return;

        auto* c_paths_array = reinterpret_cast<session_path_info*>(buffer);
        auto* current_node_ptr =
                reinterpret_cast<network_service_node*>(c_paths_array + cpp_paths.size());
        unsigned char* current_metadata_ptr =
                reinterpret_cast<unsigned char*>(current_node_ptr + total_nodes);

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
            std::visit(
                    [&]<typename T>(const T& m) {
                        if constexpr (std::is_same_v<T, OnionPathMetadata>) {
                            auto* meta = reinterpret_cast<session_onion_path_metadata*>(
                                    current_metadata_ptr);
                            new (meta) session_onion_path_metadata{};
                            meta->category = static_cast<SESSION_NETWORK_PATH_CATEGORY>(m.category);
                            c_path.onion_metadata = meta;
                            current_metadata_ptr += sizeof(session_onion_path_metadata);
                        } else {
                            static_assert(std::is_same_v<T, SessionRouterTunnelMetadata>);
                            auto* meta = reinterpret_cast<session_router_tunnel_metadata*>(
                                    current_metadata_ptr);
                            new (meta) session_router_tunnel_metadata{};
                            strncpy(meta->destination_pubkey,
                                    m.destination_pubkey.c_str(),
                                    sizeof(meta->destination_pubkey) - 1);
                            meta->destination_pubkey[sizeof(meta->destination_pubkey) - 1] = '\0';
                            strncpy(meta->destination_snode_address,
                                    m.destination_snode_address.c_str(),
                                    sizeof(meta->destination_snode_address) - 1);
                            meta->destination_snode_address
                                    [sizeof(meta->destination_snode_address) - 1] = '\0';
                            c_path.session_router_metadata = meta;
                            current_metadata_ptr += sizeof(session_router_tunnel_metadata);
                        }
                    },
                    cpp_path.metadata);
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
        network_object* network,
        const char* swarm_pubkey_hex,
        bool ignore_strike_count,
        void (*callback)(network_service_node* nodes, size_t nodes_len, void*),
        void* ctx) {
    assert(swarm_pubkey_hex && callback);
    unbox(network).get_swarm(
            x25519_pubkey::from_hex({swarm_pubkey_hex, 64}),
            ignore_strike_count,
            [cb = std::move(callback), ctx](swarm_id_t, std::vector<service_node> nodes) {
                auto c_nodes = network::detail::convert_service_nodes(nodes);
                cb(c_nodes.data(), c_nodes.size(), ctx);
            });
}

LIBSESSION_C_API void session_network_get_random_nodes(
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

LIBSESSION_C_API void session_network_send_request(
        network_object* network,
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
