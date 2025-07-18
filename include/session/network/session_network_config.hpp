#pragma once

#include <chrono>
#include <filesystem>
#include <limits>
#include <oxen/log.hpp>

#include "session/network/session_network_opt.hpp"
#include "session/types.hpp"

namespace session::network {

using namespace std::chrono_literals;
namespace fs = std::filesystem;

struct Config {
  public:
    opt::netid::Target netid = opt::netid::Target::mainnet;
    opt::router::Type router = opt::router::Type::onion_requests;
    opt::transport::Type transport = opt::transport::Type::quic;
    std::optional<fs::path> cache_directory;
    std::chrono::minutes snode_cache_expiration = 2h;

    // Netid Options
    std::vector<service_node> seed_nodes;

    // Onion Request Options
    size_t onionreq_min_snode_cache_size = 12;
    uint8_t onionreq_num_cache_nodes_to_use_for_refresh = 3;
    uint8_t onionreq_path_size = 3;
    uint8_t onionreq_path_failure_threshold = 3;
    uint8_t onionreq_node_failure_threshold = 3;
    std::unordered_map<opt::onionreq_min_path_count::PathType, uint8_t> onionreq_min_path_counts = {
            {opt::onionreq_min_path_count::PathType::standard, 2},
            {opt::onionreq_min_path_count::PathType::download, 2},
            {opt::onionreq_min_path_count::PathType::upload, 2}};
    bool onionreq_disable_pre_build_paths = false;

    // Callback Options
    std::optional<opt::transport::network_callback_t> transport_callbacks_callback;

    template <typename... Opt>
        requires(sizeof...(Opt) > 0 && std::conjunction_v<std::is_base_of<opt::base, std::decay_t<Opt>>...>)
    Config(Opt&&... opts) {
        // parse all options
        ((void)handle_config_opt(std::forward<Opt>(opts)), ...);
        _init();
    }
    explicit Config(const std::vector<std::any>& opts);

    Config() = default;
    Config(const Config&) = default;
    Config(Config&&) = default;
    Config& operator=(const Config&) = default;
    Config& operator=(Config&&) = default;
    ~Config() = default;

  private:
    void _init();

    void handle_config_opt(opt::netid netid);
    void handle_config_opt(opt::router router);
    void handle_config_opt(opt::transport transport);
    void handle_config_opt(opt::cache_directory dir);
    void handle_config_opt(opt::snode_cache_expiration sce);
    void handle_config_opt(opt::onionreq_min_snode_cache_size mscs);
    void handle_config_opt(opt::onionreq_num_cache_nodes_to_use_for_refresh ncn);
    void handle_config_opt(opt::onionreq_path_size ps);
    void handle_config_opt(opt::onionreq_path_failure_threshold pft);
    void handle_config_opt(opt::onionreq_node_failure_threshold nft);
    void handle_config_opt(opt::onionreq_min_path_count mpc);
    void handle_config_opt(opt::onionreq_disable_pre_build_paths dpbp);
};

}  // namespace session::network
