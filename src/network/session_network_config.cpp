#include "session/network/session_network_config.hpp"

#include <any>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

using namespace oxen;
using namespace oxen::log::literals;

namespace session::network {

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
        HANDLE_TYPE(opt::cache_directory);
        HANDLE_TYPE(opt::snode_cache_expiration);
        HANDLE_TYPE(opt::onionreq_min_snode_cache_size);
        HANDLE_TYPE(opt::onionreq_num_cache_nodes_to_use_for_refresh);
        HANDLE_TYPE(opt::onionreq_path_size);
        HANDLE_TYPE(opt::onionreq_path_failure_threshold);
        HANDLE_TYPE(opt::onionreq_node_failure_threshold);
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
            log::trace(cat, "Network config set to mainnet with {} seed nodes", seed_nodes.size());
            break;
        case opt::netid::Target::testnet:
            log::trace(cat, "Network config set to testnet with {} seed nodes", seed_nodes.size());
            break;

        case opt::netid::Target::devnet:
            log::trace(cat, "Network config set to devnet with {} seed nodes", seed_nodes.size());
            break;
    }
}

void Config::handle_config_opt(opt::router router_) {
    router = router_.type;

    switch (router_.type) {
        case opt::router::Type::onion_requests:
            log::trace(cat, "Network config set to route requests using Onion Requests");
            break;

        case opt::router::Type::lokinet:
            log::trace(cat, "Network config set to route requests using Lokinet");
            break;

        case opt::router::Type::direct:
            log::trace(cat, "Network config set to route requests directly");
            break;
    }
}

void Config::handle_config_opt(opt::transport transport_) {
    transport = transport_.type;

    switch (transport_.type) {
        case opt::transport::Type::quic:
            log::trace(cat, "Network config set to send requests via QUIC");
            break;

        case opt::transport::Type::callbacks: {
            if (!transport_.callback)
                throw std::invalid_argument{
                        "Must provide callback when using the Callbacks to send requests"};

            transport_callbacks_callback = std::move(transport_.callback);
            log::trace(cat, "Network config set to send requests via Callbacks");
        }
    }
}

void Config::handle_config_opt(opt::cache_directory dir) {
    cache_directory = std::move(dir.path);
    log::trace(cat, "Network config using cache dir {}", cache_directory);
}

void Config::handle_config_opt(opt::snode_cache_expiration sce) {
    snode_cache_expiration = sce.duration;
    log::trace(cat, "Network config onion request snode cache expiration set to {}", sce.duration);
}

void Config::handle_config_opt(opt::onionreq_min_snode_cache_size mscs) {
    onionreq_min_snode_cache_size = mscs.size;
    log::trace(cat, "Network config min onion request snode cache size set to {}", mscs.size);
}

void Config::handle_config_opt(opt::onionreq_num_cache_nodes_to_use_for_refresh ncn) {
    onionreq_num_cache_nodes_to_use_for_refresh = ncn.count;
    log::trace(
            cat,
            "Network config number of cached nodes to be used for refreshing the onion request snode cache set to {}{}",
            ncn.count,
            (ncn.count > 0 ? "" : ", refreshes will always use a random seed node"));
}

void Config::handle_config_opt(opt::onionreq_path_size ps) {
    onionreq_path_size = ps.size;
    log::trace(cat, "Network config onion request path size set to {}", ps.size);
}

void Config::handle_config_opt(opt::onionreq_path_failure_threshold pft) {
    onionreq_path_failure_threshold = pft.count;
    log::trace(cat, "Network config onion request path failure threshold set to {}", pft.count);
}

void Config::handle_config_opt(opt::onionreq_node_failure_threshold nft) {
    onionreq_node_failure_threshold = nft.count;
    log::trace(cat, "Network config onion request node failure threshold set to {}", nft.count);
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
    log::trace(
            cat,
            "Network config min {} onion request path count set to {}",
            path_type_name,
            mpc.min_count);
}

void Config::handle_config_opt(opt::onionreq_disable_pre_build_paths dpbp) {
    onionreq_disable_pre_build_paths = true;
    log::trace(cat, "Network config disabled pre-building onion request paths");
}

}  // namespace session::network
