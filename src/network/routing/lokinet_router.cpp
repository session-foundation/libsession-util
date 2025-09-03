#include "session/network/routing/lokinet_router.hpp"

#include <fmt/ranges.h>
#include <oxenc/base64.h>

#include <llarp/contact/router_id.hpp>
#include <lokinet.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "session/network/network_opt.hpp"

using namespace oxen;
using namespace session;
using namespace session::network;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {
    auto cat = oxen::log::Cat("network");

    oxen::quic::RemoteAddress address_for_destination(
            const network_destination& dest, const std::string& request_id) {
        std::optional<oxen::quic::RemoteAddress> address;

        std::visit(
                [&address, &request_id](auto&& arg) {
                    using T = std::decay_t<decltype(arg)>;

                    if constexpr (std::is_same_v<T, oxen::quic::RemoteAddress>) {
                        log::trace(
                                cat,
                                "[LokinetRouter Request {}]: Using pre-resolved RemoteAddress.",
                                request_id);
                        address = arg;
                    } else if constexpr (std::is_same_v<T, service_node>) {
                        log::trace(
                                cat,
                                "[LokinetRouter Request {}]: Resolving service_node to "
                                "RemoteAddress.",
                                request_id);
                        address.emplace(arg.view_remote_key(), arg.host(), arg.omq_port);
                    }
                },
                dest);

        if (!address)
            throw std::runtime_error{"Invalid destination"};

        if (address->view_remote_key().size() != 32)
            throw std::runtime_error{"Invalid remote key"};

        return *address;
    }
}  // namespace

LokinetRouter::LokinetRouter(
        config::LokinetRouterConfig config,
        std::shared_ptr<oxen::quic::Loop> loop,
        std::weak_ptr<SnodePool> snode_pool,
        std::weak_ptr<ITransport> transport) :
        _config{std::move(config)}, _loop{loop}, _transport{transport} {
    log::trace(cat, "[LokinetRouter] Initializing.");

    auto test_ini = R"(
    [router]
    netid={}
    data-dir={}
    [logging]
    type=none
    level=*=debug,quic=info
    )"_format(opt::netid::to_string(_config.netid), _config.cache_directory);

    try {
        _update_status(ConnectionStatus::connecting);

        // TODO: Don't pass the loop for now.
        lokinet = std::make_shared<lokinet::Lokinet>(test_ini /*, loop*/);

        // TODO: Remove this hack to wait for lokinet to be ready before any requests get sent
        _loop->call_later(5000ms, [this] {
            if (auto snode_pool = _snode_pool.lock()) {
                if (snode_pool->size() == 0)
                    snode_pool->refresh_if_needed(
                            {}, [this] { _loop->call([this] { _finish_setup(); }); });
                else
                    _loop->call([this] { _finish_setup(); });
            } else
                log::critical(cat, "[LokinetRouter] SnodePool was destroyed, cannot setup router.");
        });
    } catch (const std::exception& e) {
        log::error(cat, "[LokinetRouter] Failed to start lokinet ({}).", e.what());
        _update_status(ConnectionStatus::disconnected);
        throw e;
    }
}

LokinetRouter::~LokinetRouter() {
    // Use 'call_get' to force this to be synchronous
    if (_loop)
        _loop->call_get([this] { _update_status(ConnectionStatus::disconnected); });
    log::debug(cat, "[LokinetRouter] Destroyed.");
}

// MARK: IRouter

void LokinetRouter::suspend() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        _suspended = true;
        _close_connections();
        log::info(cat, "[LokinetRouter] Suspended.");
    });
}

void LokinetRouter::resume(bool automatically_reconnect) {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        if (!_suspended)
            return;

        _suspended = false;
        log::info(cat, "[LokinetRouter] Resumed.");
    });
}

void LokinetRouter::close_connections() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] { _close_connections(); });
}

void LokinetRouter::clear_cache() {
    // TODO: Implement this
}

std::vector<PathInfo> LokinetRouter::get_active_paths() {
    // TODO: Implement this
    return {};
}

void LokinetRouter::send_request(Request request, network_response_callback_t callback) {
    _loop->call([this, req = std::move(request), cb = std::move(callback)] {
        _send_request_internal(std::move(req), std::move(cb));
    });
}

// MARK: Internal Logic

void LokinetRouter::_finish_setup() {
    // Start processing requests
    _ready = true;
    log::debug(cat, "[LokinetRouter] Finishing setup, router is now ready.");

    auto requests_to_process = std::move(_pending_requests);
    if (requests_to_process.empty())
        return;

    // Process any requests that were queued before we were ready
    log::debug(
            cat,
            "[LokinetRouter] Processing {} requests queued during initialization.",
            requests_to_process.size());

    for (auto& [address, requests] : requests_to_process) {
        if (!requests.empty()) {
            log::debug(
                    cat,
                    "[LokinetRouter] Processing {} queued requests for address {}.",
                    requests.size(),
                    address);

            for (auto&& [req, cb] : std::move(requests))
                _send_request_internal(std::move(req), std::move(cb));
        }
    }
}

void LokinetRouter::_close_connections() {
    // TODO: Need to close any active connections on the lokinet instance

    // Cancel any pending requests (they can't succeed once the connection is closed)
    for (const auto& [pubkey, pupkey_requests] : _pending_requests)
        for (const auto& [info, callback] : pupkey_requests)
            callback(
                    false,
                    false,
                    ERROR_NETWORK_SUSPENDED,
                    {content_type_plain_text},
                    "Network is suspended.");

    // Clear all storage of requests, paths and connections so that we are in a fresh state on
    // relaunch
    _active_tunnels.clear();
    _pending_requests.clear();
    _update_status(ConnectionStatus::disconnected);
    log::info(cat, "[LokinetRouter] Closed all connections.");
}

void LokinetRouter::_update_status(ConnectionStatus new_status) {
    ConnectionStatus old_status = _status.load();
    if (old_status == new_status)
        return;

    _status.store(new_status);

    if (on_status_changed)
        on_status_changed();
}

void LokinetRouter::_send_request_internal(Request request, network_response_callback_t callback) {
    // If we are suspended then fail immediately
    if (_suspended)
        return callback(
                false,
                false,
                ERROR_NETWORK_SUSPENDED,
                {content_type_plain_text},
                "LokinetRouter is suspended.");

    // If the request is being sent to a `ServerDestination` then we need to make a proxied request
    // instead
    if (std::holds_alternative<ServerDestination>(request.destination)) {
        log::critical(
                cat,
                "[LokinetRouter Request {}] Server request are currently unsupported!",
                request.request_id);
        return callback(
                false,
                false,
                -1,
                {content_type_plain_text},
                "Internal error: invalid destination for LokinetRouter");
    }
    //     log::debug(cat, "[LokinetRouter Request {}]: Destination is a server. Finding a proxy node.", request.request_id);

    //     auto snode_pool = _snode_pool.lock();
    //     if (!snode_pool) {
    //         return callback(false, false, -1, {}, "SnodePool was destroyed, cannot find proxy.", std::nullopt);
    //     }
        
    //     // Get a random, healthy node to act as our proxy.
    //     auto proxy_nodes = snode_pool->get_unused_nodes(1);
    //     if (proxy_nodes.empty()) {
    //         return callback(false, false, -1, {}, "No available service nodes to use as a proxy.", std::nullopt);
    //     }
    //     service_node proxy_node = proxy_nodes[0];
        
    //     log::debug(cat, "[LokinetRouter Request {}]: Selected {} as proxy.", request.request_id, proxy_node.to_string());
        
    //     // --- Create the new, wrapped request for the proxy ---
    //     Request proxy_request;
    //     proxy_request.request_id = request.request_id;
    //     proxy_request.destination = proxy_node; // The destination is now the proxy node
    //     proxy_request.endpoint = "onion_req";   // The endpoint is always "onion_req"
    //     proxy_request.body = create_proxy_request_body(request); // The body is the wrapper
    //     proxy_request.category = request.category;
    //     proxy_request.request_timeout = request.request_timeout;
    //     proxy_request.overall_timeout = request.overall_timeout;
    //     proxy_request.creation_time = request.creation_time;
        
    //     // Now, recursively call ourselves with this new, well-defined request.
    //     // This will now hit the "direct Lokinet destination" path at the top of the function.
    //     _send_request_internal(std::move(proxy_request), std::move(callback));
    //     return;
    // }

    auto address = address_for_destination(request.destination, request.request_id);
    const auto address_pubkey_hex = oxenc::to_hex(address.view_remote_key());

    if (!_ready) {
        log::debug(
                cat,
                "[LokinetRouter Request {}]: Router not ready, queueing request.",
                request.request_id);

        // Queue the request if not ready. We need the pubkey hex as the key.
        try {
            _pending_requests[address_pubkey_hex].emplace_back(
                    std::move(request), std::move(callback));
        } catch (const std::exception& e) {
            log::critical(
                    cat,
                    "[LokinetRouter Request {}]: Dropping after failure to queue due to error: {}.",
                    request.request_id,
                    e.what());
            return callback(false, false, -1, {content_type_plain_text}, e.what());
        }
        return;
    }

    if (auto it = _active_tunnels.find(address_pubkey_hex); it != _active_tunnels.end()) {
        log::trace(cat, "[LokinetRouter Request {}] Found active tunnel.", request.request_id);
        _send_via_tunnel(it->second, std::move(request), std::move(callback));
        return;
    }

    // If we should already be establishing a tunnel then we can just add this as a pending request
    // and it'll be picked up once the tunnel is made
    if (_pending_requests.count(address_pubkey_hex)) {
        log::debug(
                cat,
                "[LokinetRouter Request {}] Tunnel to {} is pending, queueing request.",
                request.request_id,
                address_pubkey_hex);
        _pending_requests[address_pubkey_hex].emplace_back(std::move(request), std::move(callback));
        return;
    }

    // No tunnel exists so we need to start a new one and queue the request
    log::info(
            cat,
            "[LokinetRouter Request {}] No tunnel to {}, initiating new tunnel.",
            request.request_id,
            address_pubkey_hex);
    std::string initiating_req_id = request.request_id;
    _pending_requests[address_pubkey_hex].emplace_back(std::move(request), std::move(callback));
    _establish_tunnel(address, initiating_req_id);
}

void LokinetRouter::_establish_tunnel(
        const oxen::quic::RemoteAddress& address, const std::string& initiating_req_id) {
    auto key = address.view_remote_key();
    auto address_pubkey_hex = oxenc::to_hex(key);

    if (address_pubkey_hex.size() != 32) {
        log::critical(
                cat,
                "[LokinetRouter] Destination had an invalid remote key, request {} is being "
                "dropped.",
                initiating_req_id);
        // Fail all the pending requests for this connection
        if (auto it = _pending_requests.find(address_pubkey_hex); it != _pending_requests.end()) {
            auto to_fail = std::move(it->second);
            _pending_requests.erase(it);
            log::error(
                    cat,
                    "[LokinetRouter] Failing {} pending request(s) due to connection failure.",
                    to_fail.size());

            for (auto& [req, cb] : to_fail)
                cb(false,
                   false,
                   -1,
                   {content_type_plain_text},
                   "Failed to establish tunnel to remote.");
        }
        return;
    }

    llarp::RouterID router_id{key.first<32>()};
    // auto snode_address = "34d9udo9ethfcrcaxcgdyxsi1w8gr79jzornsytcfgdw5rpmif8y.loki";//
    // address.to_network_address(true);
    //  auto snode_address = "55fxd8stjrt9g6rsbftx7eesy47pj4751xjghinr3k9ffxh4ieyo.snode";
    auto lokinet_address = router_id.to_network_address(true);
    auto test_port = address.port();  // 35519;

    log::debug(
            cat,
            "[LokinetRouter Request {}] Establishing new tunnel to {}.",
            initiating_req_id,
            address_pubkey_hex);
    lokinet->establish_udp(
            lokinet_address,
            test_port,
            [this, address_pubkey_hex, initiating_req_id](lokinet::tunnel_info info) mutable {
                log::info(
                        cat,
                        "[LokinetRouter Request {}] Tunnel to remote {} established.",
                        initiating_req_id,
                        address_pubkey_hex);

                auto requests_to_process = std::move(_pending_requests[address_pubkey_hex]);
                _pending_requests.erase(address_pubkey_hex);
                _active_tunnels.insert_or_assign(address_pubkey_hex, info);

                // We had a successful connection so update the status to connected
                _update_status(ConnectionStatus::connected);

                if (!requests_to_process.empty()) {
                    log::debug(
                            cat,
                            "[LokinetRouter] Processing {} pending requests on new tunnel to {}.",
                            requests_to_process.size(),
                            info.remote);

                    for (auto&& [req, cb] : std::move(requests_to_process))
                        _send_via_tunnel(info, std::move(req), std::move(cb));
                }
            },
            [this, address_pubkey_hex, initiating_req_id](std::string errmsg) mutable {
                log::info(
                        cat,
                        "[LokinetRouter Request {}] Unable to establish lokinet UDP connection to "
                        "{} due to error: {}.",
                        initiating_req_id,
                        address_pubkey_hex,
                        errmsg);

                _active_tunnels.erase(address_pubkey_hex);

                // Fail all the pending requests for this connection
                if (auto it = _pending_requests.find(address_pubkey_hex);
                    it != _pending_requests.end()) {
                    auto to_fail = std::move(it->second);
                    _pending_requests.erase(it);

                    log::error(
                            cat,
                            "[LokinetRouter] Failing {} pending requests due to UDP connection "
                            "failure.",
                            to_fail.size());

                    for (auto& [req, cb] : to_fail)
                        cb(false, false, -1, {content_type_plain_text}, errmsg);
                }

                // If we have no longer have any active connections then we are disconnected
                if (_active_tunnels.empty())
                    _update_status(ConnectionStatus::disconnected);
            });
}

    // TODO: Is there a way to check that the 'tunnel_info' still active?
    
void LokinetRouter::_send_via_tunnel(
        lokinet::tunnel_info tunnel, Request request, network_response_callback_t callback) {
    // If the request has already timedout at this point then just fail it immediately
    auto timeout = request.time_remaining();
    if (timeout <= std::chrono::milliseconds::zero())
        return callback(false, true, 408, {content_type_plain_text}, "Request already timed out");

    // We have a valid connection and stream so we can send the request
    log::debug(cat, "[LokinetRouter Request {}] Sending to {}.", request.request_id, tunnel.remote);

    oxen::quic::RemoteAddress address =
            address_for_destination(request.destination, request.request_id);
    auto key = address.view_remote_key();
    const auto address_pubkey_hex = oxenc::to_hex(key);
    auto test_key = key;
    // auto test_key =
    // oxenc::from_base64("1n+DAM9hKyJhtXSPR5L/HdemIKPiHs8dZsPn2kEQuMs="); auto test_key
    // = oxenc::from_base32z("55fxd8stjrt9g6rsbftx7eesy47pj4751xjghinr3k9ffxh4ieyo");
    auto loki_target = oxen::quic::RemoteAddress{test_key, "127.0.0.1", tunnel.local_port};

    // Construct the actual request to send
    std::optional<std::chrono::milliseconds> remaining_overall_timeout =
            (request.overall_timeout.has_value() ? std::optional{request.time_remaining()}
                                                 : std::nullopt);
    Request lokinet_request{
            request.request_id,
            network_destination{loki_target},  // Send to local lokinet address
            request.endpoint,                  // Send to onion request handling endpoint
            request.body,
            request.category,
            request.time_remaining(),
            remaining_overall_timeout};

    if (auto transport = _transport.lock())
        transport->send_request(std::move(lokinet_request), std::move(callback));
    else {
        log::critical(cat, "[LokinetRouter] Transport was destroyed, cannot send request.");
        return;
    }
}

}  // namespace session::network
