#include "session/network/session_network.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <any>
#include <vector>

#include "session/network/session_network.h"
#include "session/network/session_network_config.hpp"
#include "session/network/session_network_opt.hpp"

using namespace oxen;
using namespace session::onionreq;
using namespace session::network;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

Network_v2::Network_v2(session::network::Config config) : config{config} {
    // Start by validating the configuration
    switch (config.router) {
        case opt::router::Type::onion_requests: break;
        case opt::router::Type::lokinet:
            if (!config.cache_directory)
                throw std::invalid_argument{"Lokinet requires a cache_directory to be configured."};
            break;

        case opt::router::Type::direct: break;
    }

    switch (config.transport) {
        case opt::transport::Type::quic: break;
        case opt::transport::Type::callbacks: break;
            if (!config.transport_callbacks_callback)
                throw std::invalid_argument{"Callbacks requires a callback to be provided."};
            break;
    }

    // Now we can properly do any setup needed
    loop = std::make_shared<quic::Loop>();
}

Network_v2::~Network_v2() {
}

}  // namespace session::network

// MARK: C API

struct session_response_handle_cpp_t {
    session::network::opt::transport::network_response_callback_t cpp_callback;
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
    
    config.cache_dir = nullptr;
    config.snode_cache_expiration_minutes = cpp_defaults.snode_cache_expiration.count();

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
    
    config.onionreq_min_snode_cache_size = cpp_defaults.onionreq_min_snode_cache_size;
    config.onionreq_num_cache_nodes_to_use_for_refresh = cpp_defaults.onionreq_num_cache_nodes_to_use_for_refresh;
    config.onionreq_path_size = cpp_defaults.onionreq_path_size;
    config.onionreq_path_failure_threshold = cpp_defaults.onionreq_path_failure_threshold;
    config.onionreq_node_failure_threshold = cpp_defaults.onionreq_node_failure_threshold;
    config.onionreq_min_path_count_standard = cpp_defaults.onionreq_min_path_counts[opt::onionreq_min_path_count::PathType::standard];
    config.onionreq_min_path_count_upload = cpp_defaults.onionreq_min_path_counts[opt::onionreq_min_path_count::PathType::upload];
    config.onionreq_min_path_count_download = cpp_defaults.onionreq_min_path_counts[opt::onionreq_min_path_count::PathType::download];
    config.onionreq_disable_pre_build_paths = cpp_defaults.onionreq_disable_pre_build_paths;

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
        // Build the configuration options
        std::vector<std::any> cpp_opts;
        
        // Cache directory
        if (config->cache_dir)
            cpp_opts.emplace_back(opt::cache_directory{std::filesystem::path{config->cache_dir}});
        
        // Snode cache expiration
        if (config->snode_cache_expiration_minutes > 0)
            cpp_opts.emplace_back(opt::snode_cache_expiration(std::chrono::minutes(config->snode_cache_expiration_minutes)));

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
            case SESSION_NETWORK_ROUTER_ONION_REQUESTS:
                cpp_opts.emplace_back(opt::router::onion_requests());

                // Process the Onion Request options since we are using them
                if (config->onionreq_min_snode_cache_size > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_snode_cache_size(config->onionreq_min_snode_cache_size));
                
                if (config->onionreq_num_cache_nodes_to_use_for_refresh > 0)
                    cpp_opts.emplace_back(opt::onionreq_num_cache_nodes_to_use_for_refresh(config->onionreq_num_cache_nodes_to_use_for_refresh));
                
                if (config->onionreq_path_size > 0)
                    cpp_opts.emplace_back(opt::onionreq_path_size(config->onionreq_path_size));
                
                if (config->onionreq_path_failure_threshold > 0)
                    cpp_opts.emplace_back(opt::onionreq_path_failure_threshold(config->onionreq_path_failure_threshold));
                
                if (config->onionreq_node_failure_threshold > 0)
                    cpp_opts.emplace_back(opt::onionreq_node_failure_threshold(config->onionreq_node_failure_threshold));
                
                if (config->onionreq_min_path_count_standard > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{
                        opt::onionreq_min_path_count::PathType::standard,
                        config->onionreq_min_path_count_standard
                    });

                if (config->onionreq_min_path_count_upload > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{
                        opt::onionreq_min_path_count::PathType::upload,
                        config->onionreq_min_path_count_upload
                    });

                if (config->onionreq_min_path_count_download > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{
                        opt::onionreq_min_path_count::PathType::download,
                        config->onionreq_min_path_count_download
                    });

                if (config->onionreq_disable_pre_build_paths)
                    cpp_opts.emplace_back(opt::onionreq_disable_pre_build_paths{});
                break;
            
            case SESSION_NETWORK_ROUTER_LOKINET: cpp_opts.emplace_back(opt::router::lokinet()); break;
            case SESSION_NETWORK_ROUTER_DIRECT: cpp_opts.emplace_back(opt::router::direct()); break;
        }
        
        // Transport
        switch (config->transport) {
            case SESSION_NETWORK_TRANSPORT_QUIC: cpp_opts.emplace_back(opt::transport::quic()); break;
            case SESSION_NETWORK_TRANSPORT_CALLBACKS:
                if (!config->transport_callback)
                    throw std::runtime_error("transport_callback must be set when using the CALLBACKS for sending requests.");

                auto c_callback_ptr = config->transport_callback;
                auto ctx = config->transport_callback_ctx;

                opt::transport::network_callback_t cpp_callback = [c_callback_ptr, ctx](
                    std::string url,
                    std::string body,
                    opt::transport::network_response_callback_t handle_response) {
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

}  // extern "C"
