#pragma once

#include <chrono>
#include <filesystem>
#include <limits>
#include <oxen/log.hpp>

#include "session/network/network_opt.hpp"
#include "session/types.hpp"

namespace session::network::config {

using namespace std::chrono_literals;
namespace fs = std::filesystem;

struct Config {
  public:
    opt::netid::Target netid = opt::netid::Target::mainnet;
    opt::router::Type router = opt::router::Type::onion_requests;
    opt::transport::Type transport = opt::transport::Type::quic;
    uint8_t path_length = 3;

    // Netid Options
    std::vector<service_node> seed_nodes;
    
    // Snode Pool Options
    std::optional<fs::path> cache_directory;
    std::chrono::minutes cache_expiration = 2h;
    size_t min_cache_size = 12;
    uint8_t num_nodes_to_use_for_refresh = 3;
    uint8_t node_failure_threshold = 3;

    // Onion Request Router Options
    uint8_t onionreq_path_failure_threshold = 3;
    std::unordered_map<opt::onionreq_min_path_count::PathType, uint8_t> onionreq_min_path_counts = {
            {opt::onionreq_min_path_count::PathType::standard, 2},
            {opt::onionreq_min_path_count::PathType::download, 2},
            {opt::onionreq_min_path_count::PathType::upload, 2}};
    bool onionreq_disable_pre_build_paths = false;

    // Quic Transport Options
    std::chrono::milliseconds quic_handshake_timeout{3s};
    std::chrono::seconds quic_keep_alive{10s};
    bool quic_disable_mtu_discovery = false;

    // Callback Transport Options
    std::optional<opt::transport::network_callback_t> callbacks_callback;

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
    void handle_config_opt(opt::path_length pl);

    // Snode pool options
    void handle_config_opt(opt::cache_directory dir);
    void handle_config_opt(opt::cache_expiration ce);
    void handle_config_opt(opt::min_cache_size mcs);
    void handle_config_opt(opt::num_nodes_to_use_for_refresh nnr);
    void handle_config_opt(opt::node_failure_threshold nft);

    // Quic transport options
    void handle_config_opt(opt::quic_handshake_timeout qht);
    void handle_config_opt(opt::quic_keep_alive qka);
    void handle_config_opt(opt::quic_disable_mtu_discovery qdmd);

    // Onion request router options
    void handle_config_opt(opt::onionreq_path_failure_threshold pft);
    void handle_config_opt(opt::onionreq_min_path_count mpc);
    void handle_config_opt(opt::onionreq_disable_pre_build_paths dpbp);

    template <typename Opt>
    void handle_config_opt(std::optional<Opt> option)
    {
        if (option)
            handle_config_opt(std::move(*option));
    }
};

}  // namespace session::network
