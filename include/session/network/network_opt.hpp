#pragma once

#include <filesystem>

#include "session/network/service_node.hpp"
#include "session/network/session_network_types.hpp"
#include "session/types.hpp"

namespace session::network {
class Endpoint;
class Stream;

namespace opt {
    namespace fs = std::filesystem;
    using namespace std::chrono_literals;

    namespace {
        inline std::vector<unsigned char> from_hex(std::string_view s) {
            std::vector<unsigned char> out;
            out.reserve(s.size() / 2);
            oxenc::from_hex(s.begin(), s.end(), std::back_inserter(out));

            return out;
        }
    }  // namespace

    struct base {};

    /// Can be used to override the default (mainnet) netid that the network will populate it's
    /// internal caches from, 'devnet' allows for specifying a custom server.
    struct netid : base {
        enum class Target {
            mainnet,
            testnet,
            devnet,
        };

        Target target;
        std::vector<service_node> seed_nodes;

      private:
        explicit netid(Target t, std::vector<service_node> seed_nodes = {}) :
                target{t}, seed_nodes{std::move(seed_nodes)} {}

      public:
        netid() = delete;

        static netid mainnet() {
            auto seed_nodes = {
                    service_node{
                            from_hex("1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1"
                                     "fef"),
                            oxen::quic::ipv4{"95.216.33.113"},
                            uint16_t{22100},
                            uint16_t{20200},
                            {2, 11, 0},
                            swarm::INVALID_SWARM_ID},
                    service_node{
                            from_hex("1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef7f971e88ab144c1a"
                                     "7ce"),
                            oxen::quic::ipv4{"37.27.236.229"},
                            uint16_t{22101},
                            uint16_t{20201},
                            {2, 11, 0},
                            swarm::INVALID_SWARM_ID},
                    service_node{
                            from_hex("1f202f00f4d2d4acc01e20773999a291cf3e3136c325474d159814e061999"
                                     "19f"),
                            oxen::quic::ipv4{"172.96.140.124"},
                            uint16_t{22102},
                            uint16_t{20202},
                            {2, 11, 0},
                            swarm::INVALID_SWARM_ID},
                    service_node{
                            from_hex("1f303f1d7523c46fa5398826740d13282d26b5de90fbae5749442f66afb6d"
                                     "78b"),
                            oxen::quic::ipv4{"208.73.207.54"},
                            uint16_t{22103},
                            uint16_t{20203},
                            {2, 11, 0},
                            swarm::INVALID_SWARM_ID},
                    service_node{
                            from_hex("1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad15a35e16b50c28db"
                                     "7b0"),
                            oxen::quic::ipv4{"104.194.8.115"},
                            uint16_t{22104},
                            uint16_t{20204},
                            {2, 11, 0},
                            swarm::INVALID_SWARM_ID},
            };

            return netid(Target::mainnet, seed_nodes);
        }

        static netid testnet() {
            auto seed_nodes = {
                    // service_node{
                    //         from_hex("decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"),
                    //         oxen::quic::ipv4{"144.76.164.202"},
                    //         uint16_t{35500},
                    //         uint16_t{35400},
                    //         {2, 10, 0},
                    //         swarm::INVALID_SWARM_ID},  // This is the original one

                    service_node{
                            from_hex("decaf20025ca6389d8225bda6a32d7fc4ee5176d21e3b2e9e08c3505a48a8"
                                     "11a"),
                            oxen::quic::ipv4{"23.88.6.250"},
                            uint16_t{35520},
                            uint16_t{35420},
                            {2, 10, 0},
                            swarm::INVALID_SWARM_ID},  // lokinet one
            };

            return netid(Target::testnet, seed_nodes);
        }

        static netid devnet(std::vector<service_node> seed_nodes) {
            if (seed_nodes.empty())
                throw std::invalid_argument(
                        "devnet must be configured with at least one seed node.");

            return netid(Target::devnet, std::move(seed_nodes));
        }

        static std::string to_string(Target target) {
            switch (target) {
                case Target::mainnet: return "mainnet";
                case Target::testnet: return "testnet";
                case Target::devnet: return "devnet";
            }

            return "mainnet";  // Shouldn't happen
        }
    };

    /// Can be used to override the default (onion_requests) routing method for requests.
    struct router : base {
        enum class Type {
            onion_requests,
            lokinet,
            direct,
        };

        Type type;

      private:
        explicit router(Type t) : type{t} {}

      public:
        router() = delete;

        static router onion_requests() { return router(Type::onion_requests); }
        static router lokinet() { return router(Type::lokinet); }
        static router direct() { return router(Type::direct); }
    };

    /// Can be used to override the default (quic_onionreq) transport layer used to send requests.
    struct transport : base {
        enum class Type {
            quic,
            callbacks,
        };
// TODO: Add in "HTTP" as an option
        using network_callback_t = std::function<void(
                std::string url, std::string body, network_response_callback_t handle_response)>;

        Type type;
        std::optional<network_callback_t> callback;

      private:
        explicit transport(Type t, std::optional<network_callback_t> callback = std::nullopt) :
                type{t}, callback{std::move(callback)} {}

      public:
        transport() = delete;

        static transport quic() { return transport(Type::quic); }
        static transport callbacks(network_callback_t callback) {
            return transport(Type::callbacks, std::move(callback));
        }
    };

    /// Can be used to override the default (3) path length used when building onion request or
    /// lokinet paths.
    struct path_length : base {
        uint8_t length;

        explicit path_length(uint8_t length) : length{length} {}
    };

    /// Can be used to prevent the code from excluding nodes within the same `/24` subnet from being
    /// included in the same path when building onion request or lokinet paths.
    struct disable_subnet_diversity : base {};

    /// Can be used to override the default (1) number of request retries that will occur when
    /// receiving a 421 error.
    struct redirect_retry_count : base {
        uint8_t count;

        explicit redirect_retry_count(uint8_t count) : count{count} {}
    };

    struct retry_delay : base {
        std::chrono::milliseconds base_delay;
        std::chrono::milliseconds max_delay;

        explicit retry_delay(
                std::chrono::milliseconds base_delay, std::chrono::milliseconds max_delay) :
                base_delay{base_delay}, max_delay{max_delay} {}

        /// API: retry_delay/exponential
        ///
        /// A function which generates an exponential delay to wait before retrying a request/action
        /// based on the provided failure count.
        ///
        /// Inputs:
        /// - 'failure_count' - [in] the number of times the request has already failed.
        inline std::chrono::milliseconds exponential(int failure_count) {
            if (failure_count <= 0)
                return base_delay;

            double delay_ms = base_delay.count() * std::pow(2.0, failure_count - 1);
            auto final_delay = std::chrono::milliseconds(static_cast<long long>(delay_ms));

            return std::min(final_delay, max_delay);
        }
    };

    /// Can be used to override the default (250ms) fequency that is used to check if queued
    /// requests have timed out due to transport/router setup.
    struct request_timeout_check_frequency : base {
        std::chrono::milliseconds frequency;
        explicit request_timeout_check_frequency(std::chrono::milliseconds f) : frequency{f} {}
    };

    // MARK: Snode Pool Options

    /// Can be used to override the default ('.') path the network uses to cache files (eg. snode
    /// pool and lokinet bootstrap).
    struct cache_directory : base {
        fs::path path;
        explicit cache_directory(fs::path p) : path{p} {}
    };

    /// Can be used to override the default (2h) duration that the snode cache can be used for
    /// before it needs to be refreshed.
    struct cache_expiration : base {
        std::chrono::minutes duration;
        explicit cache_expiration(std::chrono::minutes duration) : duration{duration} {}
    };

    /// Can be used to override the default (2s) minimum duration that the snode cache should live
    /// for, if a refresh is triggered within this period it will be delayed until the minimum
    /// duration has passed to prevent excessive looping.
    struct cache_min_lifetime : base {
        std::chrono::milliseconds duration;
        explicit cache_min_lifetime(std::chrono::milliseconds duration) : duration{duration} {}
    };

    /// Can be used to override the default (12) minimum number of unused nodes before we trigger a
    /// snode cache refresh.
    ///
    /// Note: If the cache size is somehow smaller than this value (eg. Testnet is having issues)
    /// then the minimum size will be the full cache size (minus enough to build a path) or at least
    /// the size of a single path.
    struct cache_min_size : base {
        size_t size;
        explicit cache_min_size(size_t size) : size{size} {}
    };

    /// Can be used to override the default (3) number of cached nodes used to refresh the cache for
    /// any subsequent refreshes after populating from a seed node.
    ///
    /// Note: Providing a value of `0` will result in the cache _always_ being refreshed using a
    /// seed node.
    struct cache_num_nodes_to_use_for_refresh : base {
        uint8_t count;
        explicit cache_num_nodes_to_use_for_refresh(uint8_t count) : count{count} {}
    };

    /// Can be used to override the default (3) number of times a specific node in a path can
    /// receive an error before it is removed from the path and replaced by a new node (or the path
    /// is rebuilt if it happens to be the guard node).
    struct cache_node_failure_threshold : base {
        uint16_t count;
        explicit cache_node_failure_threshold(uint16_t count) : count{count} {}
    };

    /// Can be used to make the snode cache use the legacy endpoint when refreshing.
    struct cache_refresh_using_legacy_endpoint : base {
        explicit cache_refresh_using_legacy_endpoint() {}
    };

    // MARK: Quic Transport Options

    /// Can be used to override the default (10s) handshake timeout duration for Quic connections.
    struct quic_handshake_timeout : base {
        std::chrono::milliseconds duration;
        explicit quic_handshake_timeout(std::chrono::milliseconds duration) : duration{duration} {}
    };

    /// Can be used to override the default (0ms) keep alive duration for Quic connections.
    struct quic_keep_alive : base {
        std::chrono::seconds duration;
        explicit quic_keep_alive(std::chrono::seconds duration) : duration{duration} {}
    };

    /// Can be used to disable Quic MTU discovery.
    struct quic_disable_mtu_discovery : base {};

    // MARK: Onion Request Router Options

    /// Can be used to override the default (3) number of times a path can receive an error before
    /// it is dropped and replaced by a new path.
    struct onionreq_path_failure_threshold : base {
        uint16_t count;

        explicit onionreq_path_failure_threshold(uint16_t count) : count{count} {}
    };

    /// Can be used to override the default (3) number of times a path can receive an error before
    /// it is dropped and replaced by a new path.
    struct onionreq_path_build_retry_limit : base {
        uint16_t count;

        explicit onionreq_path_build_retry_limit(uint16_t count) : count{count} {}
    };

    /// Can be used to override the default (2) minimum number of paths that are maintained for each
    /// request category when using onion requests. If `onionreq_single_path_mode` is provided this
    /// will be ignored.
    struct onionreq_min_path_count : base {
        RequestCategory category;
        uint8_t min_count;

        explicit onionreq_min_path_count(RequestCategory category, uint8_t min_count) :
                category{category}, min_count{min_count} {}
    };

    /// Can be used to force the onion request router to only use a single path regardless of what
    /// category the requests sent have. When this option is provided `onionreq_min_path_count` will
    /// be ignored.
    struct onionreq_single_path_mode : base {};

    /// Can be used to prevent the network instance from building onion request paths when
    /// initialised, when this option is provided paths will be built when the first request it
    /// made.
    struct onionreq_disable_pre_build_paths : base {};

}  //  namespace opt
}  // namespace session::network
