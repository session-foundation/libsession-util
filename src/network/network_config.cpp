#include "session/network/network_config.hpp"

#include <any>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

using namespace oxen;
using namespace oxen::log::literals;

namespace session::network::config {

inline auto cat = oxen::log::Cat("network");

Config::Config(const std::vector<std::any>& opts) {
    for (const auto& opt_any : opts) {
        #define HANDLE_TYPE(T) \
            if (const auto* p = std::any_cast<T>(&opt_any)) { \
                handle_config_opt(*p); \
                continue; \
            }

        HANDLE_TYPE(opt::netid);
        HANDLE_TYPE(opt::router);
        HANDLE_TYPE(opt::transport);
        HANDLE_TYPE(opt::path_length);

        // Snode pool options
        HANDLE_TYPE(opt::cache_directory);
        HANDLE_TYPE(opt::cache_expiration);
        HANDLE_TYPE(opt::min_cache_size);
        HANDLE_TYPE(opt::num_nodes_to_use_for_refresh);
        HANDLE_TYPE(opt::node_failure_threshold);

        // Quic transport options
        HANDLE_TYPE(opt::quic_handshake_timeout);
        HANDLE_TYPE(opt::quic_keep_alive);

        // Onion request router options
        HANDLE_TYPE(opt::onionreq_path_failure_threshold);
        HANDLE_TYPE(opt::onionreq_min_path_count);
        HANDLE_TYPE(opt::onionreq_disable_pre_build_paths);
        
        log::warning(cat, "Ignoring unknown option type in Config constructor");
        #undef HANDLE_TYPE
    }

    _init();
}

void Config::_init() {
    log::debug(cat, "Network config created successfully");
}

void Config::handle_config_opt(opt::netid netid_) {
    netid = netid_.target;
    seed_nodes = std::move(netid_.seed_nodes);

    switch (netid_.target) {
        case opt::netid::Target::mainnet:
            log::debug(cat, "Network config set to mainnet with {} seed nodes", seed_nodes.size());
            break;
        case opt::netid::Target::testnet:
            log::debug(cat, "Network config set to testnet with {} seed nodes", seed_nodes.size());
            break;

        case opt::netid::Target::devnet:
            log::debug(cat, "Network config set to devnet with {} seed nodes", seed_nodes.size());
            break;
    }
}

void Config::handle_config_opt(opt::router router_) {
    router = router_.type;

    switch (router_.type) {
        case opt::router::Type::onion_requests:
            log::debug(cat, "Network config set to route requests using Onion Requests");
            break;

        case opt::router::Type::lokinet:
            log::debug(cat, "Network config set to route requests using Lokinet");
            break;

        case opt::router::Type::direct:
            log::debug(cat, "Network config set to route requests directly");
            break;
    }
}

void Config::handle_config_opt(opt::transport transport_) {
    transport = transport_.type;

    switch (transport_.type) {
        case opt::transport::Type::quic:
            log::debug(cat, "Network config set to send requests via QUIC");
            break;

        case opt::transport::Type::callbacks: {
            if (!transport_.callback)
                throw std::invalid_argument{
                        "Must provide callback when using the Callbacks to send requests"};

            callbacks_callback = std::move(transport_.callback);
            log::debug(cat, "Network config set to send requests via Callbacks");
        }
    }
}

void Config::handle_config_opt(opt::path_length pl) {
    path_length = pl.length;
    log::debug(cat, "Network config path length set to {}", pl.length);
}

// MARK: Snode Pool Options

void Config::handle_config_opt(opt::cache_directory dir) {
    cache_directory = std::move(dir.path);

    if (cache_directory)
        log::debug(cat, "Network config using cache dir {}", cache_directory->string());
}

void Config::handle_config_opt(opt::cache_expiration ce) {
    cache_expiration = ce.duration;
    log::debug(cat, "Network config snode pool cache expiration set to {} minutes", ce.duration.count());
}

void Config::handle_config_opt(opt::min_cache_size mcs) {
    min_cache_size = mcs.size;
    log::debug(cat, "Network config min snode pool cache size set to {}", mcs.size);
}

void Config::handle_config_opt(opt::num_nodes_to_use_for_refresh nnr) {
    num_nodes_to_use_for_refresh = nnr.count;
    log::debug(
            cat,
            "Network config number of cached nodes to be used for refreshing the snode pool cache set to {}{}",
            nnr.count,
            (nnr.count > 0 ? "" : ", refreshes will always use a random seed node"));
}

void Config::handle_config_opt(opt::node_failure_threshold nft) {
    node_failure_threshold = nft.count;
    log::debug(cat, "Network config snode pool node failure threshold set to {}", nft.count);
}

// MARK: Quic Transport Options

void Config::handle_config_opt(opt::quic_handshake_timeout qht) {
    quic_handshake_timeout = qht.duration;
    log::debug(cat, "Network config quic handshake timeout set to {}ms", qht.duration.count());
}

void Config::handle_config_opt(opt::quic_keep_alive qka) {
    quic_keep_alive = qka.duration;
    log::debug(cat, "Network config quic keep alive set to {}s", qka.duration.count());
}

void Config::handle_config_opt(opt::quic_disable_mtu_discovery qdmd) {
    quic_disable_mtu_discovery = true;
    log::debug(cat, "Network config disabled MTU discovery for Quic");
}

// MARK: Onion Request Router Options

void Config::handle_config_opt(opt::onionreq_path_failure_threshold pft) {
    onionreq_path_failure_threshold = pft.count;
    log::debug(cat, "Network config onion request path failure threshold set to {}", pft.count);
}

void Config::handle_config_opt(opt::onionreq_min_path_count mpc) {
    onionreq_min_path_counts.emplace(mpc.type, mpc.min_count);

    std::string path_type_name;
    switch (mpc.type) {
        case opt::onionreq_min_path_count::PathType::standard: path_type_name = "standard";
        case opt::onionreq_min_path_count::PathType::download: path_type_name = "download";
        case opt::onionreq_min_path_count::PathType::upload: path_type_name = "upload";
        default: path_type_name = "unknown";
    }
    log::debug(
            cat,
            "Network config min {} onion request path count set to {}",
            path_type_name,
            mpc.min_count);
}

void Config::handle_config_opt(opt::onionreq_disable_pre_build_paths dpbp) {
    onionreq_disable_pre_build_paths = true;
    log::debug(cat, "Network config disabled pre-building onion request paths");
}

}  // namespace session::network
