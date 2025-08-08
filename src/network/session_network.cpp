#include "session/network/session_network.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <any>
#include <vector>

#include "session/network/session_network.h"
#include "session/network/network_config.hpp"
#include "session/network/network_opt.hpp"
#include "session/network/session_network_types.hpp"
#include "session/network/transport/quic_transport.hpp"
#include "session/network/routing/onion_request_router.hpp"
#include "session/random.hpp"

using namespace oxen;
using namespace session::network;
using namespace session::network::config;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {

    inline auto cat = log::Cat("network");

config::SnodePoolConfig build_snode_pool_config(const config::Config& main_config) {
    return {
        main_config.cache_directory,
        main_config.cache_expiration,
        main_config.cache_refresh_retry_limit,
        main_config.enforce_subnet_diversity,
        main_config.retry_delay,
        main_config.netid,
        main_config.seed_nodes,
        main_config.cache_min_size,
        main_config.cache_num_nodes_to_use_for_refresh,
        main_config.cache_node_failure_threshold,
        main_config.cache_refresh_using_legacy_endpoint
    };
}

config::QuicTransportConfig build_quic_transport_config(const config::Config& main_config) {
    return {
        main_config.quic_handshake_timeout,
        main_config.quic_keep_alive,
        main_config.quic_disable_mtu_discovery
    };
}

config::OnionRequestRouterConfig build_onion_request_router_config(const config::Config& main_config) {
    return {
        main_config.retry_delay,
        main_config.request_timeout_check_frequency,
        main_config.path_length,
        main_config.onionreq_path_failure_threshold,
        main_config.onionreq_path_build_retry_limit,
        main_config.onionreq_disable_pre_build_paths,
        main_config.onionreq_single_path_mode,
        main_config.onionreq_min_path_counts
    };
}

} // namespace

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
    switch (config.router) {
        case opt::router::Type::lokinet:
            if (!config.cache_directory)
                throw std::invalid_argument{"Lokinet requires a cache_directory to be configured."};
            break;

        case opt::router::Type::onion_requests: break;
        case opt::router::Type::direct: break;
    }

    switch (config.transport) {
        case opt::transport::Type::quic: break;
        case opt::transport::Type::callbacks: break;
            if (!config.callbacks_callback)
                throw std::invalid_argument{"Callbacks requires a callback to be provided."};
            break;
    }

    // Now we can properly do any setup needed
    _loop = std::make_shared<quic::Loop>();

    // Setup the transport layer
    switch (config.transport) {
        case opt::transport::Type::quic:
            _transport = std::make_shared<QuicTransport>(std::move(build_quic_transport_config(config)), _loop);
            break;

        case opt::transport::Type::callbacks:
            // _transport = std::make_shared<LokinetTransport>(_config, *_snode_pool, _loop);
            break;
    }

    // The SnodePool is needed regardless of the transport layer as it includes swarm information which is needed by the clients in order to send requests
    auto bootstrap_fetcher = [bt = std::weak_ptr{_transport}](Request req, network_response_callback_t on_complete) {
        if (auto transport = bt.lock())
            transport->send_request(std::move(req), std::move(on_complete));
        else
            log::error(cat, "Transport provided to the SnodePool bootstrap fetcher has been destroyed.");
    };
    _snode_pool = std::make_shared<SnodePool>(std::move(build_snode_pool_config(config)), _loop, bootstrap_fetcher);

    // Setup the router
    switch (config.router) {
        case opt::router::Type::onion_requests:
            _router = std::make_unique<OnionRequestRouter>(std::move(build_onion_request_router_config(config)), _loop, _snode_pool, _transport);
            break;

        case opt::router::Type::lokinet:
            // _router = std::make_unique<LokinetTransport>(_config, *_snode_pool, _loop);
            break;

        case opt::router::Type::direct:
            // _router = std::make_unique<DirectTransport>(_config, *_snode_pool, _loop);
            break;
    }

    // Now that we have our router setup we need to setup the `standard_fetcher` on the `SnodePool`
    _snode_pool->set_standard_fetcher([r = std::weak_ptr{_router}, loop = _loop](Request req, network_response_callback_t on_complete) {
        loop->call([r, req = std::move(req), on_complete = std::move(on_complete)] {
            if (auto router = r.lock())
                router->send_request(std::move(req), std::move(on_complete));
            else
                log::error(cat, "Router provided to the SnodePool standard fetcher has been destroyed.");
        });
    });
}

Network_v2::~Network_v2() {
}

void Network_v2::get_swarm(
        session::network::x25519_pubkey swarm_pubkey,
        std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback) {
    _snode_pool->get_swarm(std::move(swarm_pubkey), std::move(callback));
}

void Network_v2::send_request(Request request, network_response_callback_t callback) {
    if (!_transport)
        return callback(false, false, -1, {content_type_plain_text}, "No transport layer configured");
    if (!_router)
        return callback(false, false, -1, {content_type_plain_text}, "No router configured");

    _router->send_request(std::move(request), std::move(callback));
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
        case opt::router::Type::onion_requests: config.router = SESSION_NETWORK_ROUTER_ONION_REQUESTS;
        case opt::router::Type::lokinet: config.router = SESSION_NETWORK_ROUTER_LOKINET;
        case opt::router::Type::direct: config.router = SESSION_NETWORK_ROUTER_DIRECT;
        default: config.router = SESSION_NETWORK_ROUTER_ONION_REQUESTS;
    }

    switch (cpp_defaults.transport) {
        case opt::transport::Type::quic: config.transport = SESSION_NETWORK_TRANSPORT_QUIC;
        case opt::transport::Type::callbacks: config.transport = SESSION_NETWORK_TRANSPORT_CALLBACKS;
        default: config.transport = SESSION_NETWORK_TRANSPORT_QUIC;
    }

    config.path_length = cpp_defaults.path_length;
    config.enforce_subnet_diversity = cpp_defaults.enforce_subnet_diversity;
    config.min_retry_delay_ms = cpp_defaults.retry_delay.base_delay.count();
    config.max_retry_delay_ms = cpp_defaults.retry_delay.max_delay.count();
    config.request_timeout_check_frequency_ms = cpp_defaults.request_timeout_check_frequency.count();

    config.devnet_seed_nodes = nullptr;
    config.devnet_seed_nodes_size = 0;

    config.cache_dir = nullptr;
    config.cache_expiration_minutes = std::chrono::duration_cast<std::chrono::minutes>(cpp_defaults.cache_expiration).count();
    config.cache_refresh_retry_limit = cpp_defaults.cache_refresh_retry_limit;
    config.cache_min_size = cpp_defaults.cache_min_size;
    config.cache_num_nodes_to_use_for_refresh = cpp_defaults.cache_num_nodes_to_use_for_refresh;
    config.cache_node_failure_threshold = cpp_defaults.cache_node_failure_threshold;
    config.cache_refresh_using_legacy_endpoint = cpp_defaults.cache_refresh_using_legacy_endpoint;
    
    config.onionreq_path_failure_threshold = cpp_defaults.onionreq_path_failure_threshold;
    config.onionreq_path_build_retry_limit = cpp_defaults.onionreq_path_build_retry_limit;
    config.onionreq_min_path_count_standard = cpp_defaults.onionreq_min_path_counts[RequestCategory::standard];
    config.onionreq_min_path_count_upload = cpp_defaults.onionreq_min_path_counts[RequestCategory::upload];
    config.onionreq_min_path_count_download = cpp_defaults.onionreq_min_path_counts[RequestCategory::download];
    config.onionreq_single_path_mode = cpp_defaults.onionreq_single_path_mode;
    config.onionreq_disable_pre_build_paths = cpp_defaults.onionreq_disable_pre_build_paths;

    config.quic_handshake_timeout_seconds = std::chrono::duration_cast<std::chrono::seconds>(cpp_defaults.quic_handshake_timeout).count();
    config.quic_keep_alive_seconds = std::chrono::duration_cast<std::chrono::seconds>(cpp_defaults.quic_keep_alive).count();
    config.quic_disable_mtu_discovery = cpp_defaults.quic_disable_mtu_discovery;

    config.transport_callback = nullptr;
    config.transport_callback_ctx = nullptr;

    return config;
}

LIBSESSION_C_API bool session_network_init(
    network_object_v2** network,
    const session_network_config* config,
    char* error
) {
    if (!network || !config)
        return set_error(error, std::invalid_argument{"network or config were null."});
    
    try {
        // Build the configuration options (ordered this way for the debug logs to make the most sense)
        std::vector<std::any> cpp_opts;

        // Network ID
        switch (config->netid) {
            case SESSION_NETWORK_MAINNET: cpp_opts.emplace_back(opt::netid::mainnet()); break;
            case SESSION_NETWORK_TESTNET: cpp_opts.emplace_back(opt::netid::testnet()); break;
            case SESSION_NETWORK_DEVNET:
                if (!config->devnet_seed_nodes || config->devnet_seed_nodes_size == 0)
                    throw std::runtime_error("SESSION_NETWORK_DEVNET requires at least one seed node.");

                std::vector<service_node> seed_nodes;
                seed_nodes.reserve(config->devnet_seed_nodes_size);

                for (size_t i = 0; i < config->devnet_seed_nodes_size; ++i)
                    seed_nodes.push_back(service_node::from(config->devnet_seed_nodes[i]));
                
                cpp_opts.emplace_back(opt::netid::devnet(std::move(seed_nodes)));
                break;
        }

        // Router
        switch (config->router) {
            case SESSION_NETWORK_ROUTER_ONION_REQUESTS: cpp_opts.emplace_back(opt::router::onion_requests()); break;
            case SESSION_NETWORK_ROUTER_LOKINET: cpp_opts.emplace_back(opt::router::lokinet()); break;
            case SESSION_NETWORK_ROUTER_DIRECT: cpp_opts.emplace_back(opt::router::direct()); break;
        }

        // Transport
        switch (config->transport) {
            case SESSION_NETWORK_TRANSPORT_QUIC:
                cpp_opts.emplace_back(opt::transport::quic());
                break;
            
            case SESSION_NETWORK_TRANSPORT_CALLBACKS:
                if (!config->transport_callback)
                    throw std::runtime_error("transport_callback must be set when using the CALLBACKS for sending requests.");

                auto c_callback_ptr = config->transport_callback;
                auto ctx = config->transport_callback_ctx;

                opt::transport::network_callback_t cpp_callback = [c_callback_ptr, ctx](
                    std::string url,
                    std::string body,
                    session::network::network_response_callback_t handle_response) {
                        auto* c_response_handle = new session_response_handle_t{
                            std::move(handle_response)
                        };

                        c_callback_ptr(
                            url.c_str(),
                            body.data(),
                            body.size(),
                            c_response_handle,
                            ctx
                        );
                };

                cpp_opts.emplace_back(opt::transport::callbacks(std::move(cpp_callback)));
                break;
        }

        if (!config->enforce_subnet_diversity)
            cpp_opts.emplace_back(opt::disable_subnet_diversity{});

        if (config->min_retry_delay_ms > 0 || config->max_retry_delay_ms > 0)
            cpp_opts.emplace_back(opt::retry_delay{std::chrono::milliseconds{config->min_retry_delay_ms}, std::chrono::milliseconds{config->max_retry_delay_ms}});
        
        if (config->request_timeout_check_frequency_ms > 0)
            cpp_opts.emplace_back(opt::request_timeout_check_frequency{std::chrono::milliseconds{config->request_timeout_check_frequency_ms}});
        
        // Snode cache
        if (config->cache_dir)
            cpp_opts.emplace_back(opt::cache_directory{std::filesystem::path{config->cache_dir}});
        
        if (config->cache_expiration_minutes > 0)
            cpp_opts.emplace_back(opt::cache_expiration{std::chrono::minutes{config->cache_expiration_minutes}});
        
        if (config->cache_refresh_retry_limit > 0)
            cpp_opts.emplace_back(opt::cache_refresh_retry_limit{config->cache_refresh_retry_limit});
        
        if (config->cache_min_size > 0)
            cpp_opts.emplace_back(opt::cache_min_size{config->cache_min_size});
        
        // A `0` value is valid for this case
        cpp_opts.emplace_back(opt::cache_num_nodes_to_use_for_refresh{config->cache_num_nodes_to_use_for_refresh});
        
        if (config->cache_node_failure_threshold > 0)
            cpp_opts.emplace_back(opt::cache_node_failure_threshold{config->cache_node_failure_threshold});

        if (config->cache_refresh_using_legacy_endpoint)
            cpp_opts.emplace_back(opt::cache_refresh_using_legacy_endpoint{});

        // Router-specific settings
        switch (config->router) {
            case SESSION_NETWORK_ROUTER_ONION_REQUESTS:
                // Process the Onion Request options since we are using them
                if (config->path_length > 0)
                    cpp_opts.emplace_back(opt::path_length{config->path_length});
                
                if (config->onionreq_path_failure_threshold > 0)
                    cpp_opts.emplace_back(opt::onionreq_path_failure_threshold{config->onionreq_path_failure_threshold});

                if (config->onionreq_path_build_retry_limit > 0)
                    cpp_opts.emplace_back(opt::onionreq_path_build_retry_limit{config->onionreq_path_build_retry_limit});
                
                if (config->onionreq_min_path_count_standard > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{RequestCategory::standard, config->onionreq_min_path_count_standard});

                if (config->onionreq_min_path_count_upload > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{RequestCategory::upload, config->onionreq_min_path_count_upload});

                if (config->onionreq_min_path_count_download > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{RequestCategory::download, config->onionreq_min_path_count_download});

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
                    cpp_opts.emplace_back(opt::quic_handshake_timeout{std::chrono::seconds{config->quic_handshake_timeout_seconds}});

                if (config->quic_keep_alive_seconds > 0)
                    cpp_opts.emplace_back(opt::quic_keep_alive{std::chrono::seconds{config->quic_keep_alive_seconds}});

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
    size_t body_len
) {
    if (!response_handle) return;

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

LIBSESSION_C_API void session_network_get_swarm(
    network_object_v2* network,
    const char* swarm_pubkey_hex,
    void (*callback)(network_service_node* nodes, size_t nodes_len, void*),
    void* ctx
) {
    assert(swarm_pubkey_hex && callback);
    unbox(network).get_swarm(
            x25519_pubkey::from_hex({swarm_pubkey_hex, 64}),
            [cb = std::move(callback), ctx](swarm_id_t, std::vector<service_node> nodes) {
                auto c_nodes = network::detail::convert_service_nodes(nodes);
                cb(c_nodes.data(), c_nodes.size(), ctx);
            });
}

LIBSESSION_C_API void session_network_send_request(
    network_object_v2* network,
    const session_request_params* params,
    session_network_response_t callback,
    void* ctx
) {
    assert(callback);

    try {
        if (!network)
            throw std::invalid_argument("Invalid request: 'network' cannot be null.");
        if (!params)
            throw std::invalid_argument("Invalid request: 'params' cannot be null.");
        
        network_destination dest;
        
        if (params->snode_dest && params->server_dest)
            throw std::invalid_argument("Invalid request: Cannot have both 'snode_dest' and 'server_dest' set.");
        
        if (params->snode_dest) {
            dest = service_node::from(*params->snode_dest);
        } else if (params->server_dest) {
            const auto& c_server = *params->server_dest;

            std::optional<std::vector<std::pair<std::string, std::string>>> headers;
            if (c_server.headers_kv_pairs && c_server.headers_kv_pairs_len > 0) {
                if (c_server.headers_kv_pairs_len % 2 != 0)
                   throw std::invalid_argument("Invalid request: Header must have an even number of key-value strings.");
                
                headers.emplace();
                headers->reserve(c_server.headers_kv_pairs_len / 2);
                for (int i = 0; i < c_server.headers_kv_pairs_len; i += 2) {
                    const char* key = c_server.headers_kv_pairs[i];
                    const char* val = c_server.headers_kv_pairs[i + 1];
                    
                    if (!key || !val)
                        throw std::invalid_argument("Invalid request: Header list contains a null key or value.");

                    headers->emplace_back(key, val);
                }
            }

            dest = ServerDestination{
                c_server.protocol,
                c_server.host,
                c_server.endpoint,  // TODO: Remove this (redundant duplication)
                x25519_pubkey::from_hex(c_server.x25519_pubkey_hex),
                (c_server.port > 0 ? std::optional{c_server.port} : std::nullopt),
                headers,
                c_server.method
            };
        } else
            throw std::invalid_argument("Invalid request: Must have either 'snode_dest' or 'server_dest' set.");

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
            static_cast<RequestCategory>(params->category),     // TODO: Need to assert that these values match between C and C++
            std::chrono::milliseconds{params->request_timeout_ms},
            (params->overall_timeout_ms > 0 ? std::optional{std::chrono::milliseconds{params->overall_timeout_ms}} : std::nullopt),
            request_id
        };
        auto cpp_callback = [c_cb = callback, c_ctx = ctx](bool success, bool timeout, int16_t status_code, std::vector<std::pair<std::string, std::string>> headers, std::optional<std::string> body) {            
            std::vector<const char*> c_headers;
            c_headers.reserve(headers.size() * 2 + 1);
            for (const auto& [key, val] : headers) {
                c_headers.push_back(key.c_str());
                c_headers.push_back(val.c_str());
            }
            c_headers.push_back(nullptr); // NULL terminator

            c_cb(
                success, timeout, status_code,
                c_headers.data(),
                (headers.size() * 2),
                body ? reinterpret_cast<const unsigned char*>(body->data()) : nullptr,
                body ? body->size() : 0,
                c_ctx
            );
        };
        
        unbox(network).send_request(std::move(request), std::move(cpp_callback));
    } catch (const std::exception& e) {
        callback(false, false, -1, nullptr, 0, reinterpret_cast<const unsigned char*>(e.what()), strlen(e.what()), ctx);
    }
}

}  // extern "C"
