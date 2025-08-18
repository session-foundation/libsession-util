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
    bool enforce_subnet_diversity = true;
    uint8_t redirect_retry_count = 1;
    opt::retry_delay retry_delay = opt::retry_delay(200ms, 5s);
    std::chrono::milliseconds request_timeout_check_frequency = 250ms;

    // Netid Options
    std::vector<service_node> seed_nodes;
    
    // Snode Pool Options
    std::optional<fs::path> cache_directory;
    std::chrono::minutes cache_expiration = 2h;
    uint8_t cache_refresh_retry_limit = 3;
    size_t cache_min_size = 12;
    uint8_t cache_num_nodes_to_use_for_refresh = 3;
    uint8_t cache_node_failure_threshold = 3;
    bool cache_refresh_using_legacy_endpoint = false;

    // Onion Request Router Options
    uint8_t onionreq_path_failure_threshold = 3;
    uint8_t onionreq_path_build_retry_limit = 10;
    std::unordered_map<RequestCategory, uint8_t> onionreq_min_path_counts = {
            {RequestCategory::standard, 2},
            {RequestCategory::download, 2},
            {RequestCategory::upload, 2}};
    bool onionreq_single_path_mode = false;
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
    void handle_config_opt(opt::disable_subnet_diversity dsd);
    void handle_config_opt(opt::redirect_retry_count rrc);
    void handle_config_opt(opt::retry_delay rd);
    void handle_config_opt(opt::request_timeout_check_frequency rtcf);

    // Snode pool options
    void handle_config_opt(opt::cache_directory dir);
    void handle_config_opt(opt::cache_expiration ce);
    void handle_config_opt(opt::cache_refresh_retry_limit crrl);
    void handle_config_opt(opt::cache_min_size mcs);
    void handle_config_opt(opt::cache_num_nodes_to_use_for_refresh nnr);
    void handle_config_opt(opt::cache_node_failure_threshold nft);
    void handle_config_opt(opt::cache_refresh_using_legacy_endpoint rule);

    // Quic transport options
    void handle_config_opt(opt::quic_handshake_timeout qht);
    void handle_config_opt(opt::quic_keep_alive qka);
    void handle_config_opt(opt::quic_disable_mtu_discovery qdmd);

    // Onion request router options
    void handle_config_opt(opt::onionreq_path_failure_threshold pft);
    void handle_config_opt(opt::onionreq_path_build_retry_limit pbrl);
    void handle_config_opt(opt::onionreq_min_path_count mpc);
    void handle_config_opt(opt::onionreq_single_path_mode spm);
    void handle_config_opt(opt::onionreq_disable_pre_build_paths dpbp);

    template <typename Opt>
    void handle_config_opt(std::optional<Opt> option)
    {
        if (option)
            handle_config_opt(std::move(*option));
    }
};

}  // namespace session::network
