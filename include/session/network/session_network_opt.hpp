#pragma once

#include <filesystem>
#include "session/network/service_node.hpp"
#include "session/types.hpp"

namespace session::network {
class Endpoint;
class Stream;

namespace opt {
    namespace fs = std::filesystem;
    using namespace std::chrono_literals;

    struct base {};

    /// Can be used to override the default ('.') path the network uses to cache files (eg. snode pool and lokinet bootstrap).
    struct cache_directory: base {
        fs::path path;
        explicit cache_directory(fs::path p) : path{p} {}
    };

    /// Can be used to override the default (2h) duration that the snode cache can be used for before it needs to be refreshed.
    struct snode_cache_expiration : base {
        std::chrono::minutes duration;
        explicit snode_cache_expiration(std::chrono::minutes duration) :
                duration{duration} {}
    };

    /// Can be used to override the default (mainnet) netid that the network will populate it's internal caches from, 'devnet' allows for specifying a custom server.
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
                            "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef",
                            {2, 10, 0},
                            swarm::INVALID_SWARM_ID,
                            "144.76.164.202",
                            uint16_t{20200}},
                    service_node{
                            "1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef7f971e88ab144c1a7ce",
                            {2, 10, 0},
                            swarm::INVALID_SWARM_ID,
                            "88.99.102.229",
                            uint16_t{20201}},
                    service_node{
                            "1f202f00f4d2d4acc01e20773999a291cf3e3136c325474d159814e06199919f",
                            {2, 10, 0},
                            swarm::INVALID_SWARM_ID,
                            "195.16.73.17",
                            uint16_t{20202}},
                    service_node{
                            "1f303f1d7523c46fa5398826740d13282d26b5de90fbae5749442f66afb6d78b",
                            {2, 10, 0},
                            swarm::INVALID_SWARM_ID,
                            "104.194.11.120",
                            uint16_t{20203}},
                    service_node{
                            "1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad15a35e16b50c28db7b0",
                            {2, 10, 0},
                            swarm::INVALID_SWARM_ID,
                            "104.194.8.115",
                            uint16_t{20204}},
            };

            return netid(Target::mainnet, seed_nodes);
        }

        static netid testnet() {
            auto seed_nodes = {
                    // service_node{
                    //         "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9",
                    //         {2, 10, 0},
                    //         swarm::INVALID_SWARM_ID,
                    //         "144.76.164.202",
                    //         uint16_t{35400}},  // This is the original one

                    service_node{
                            "decaf20025ca6389d8225bda6a32d7fc4ee5176d21e3b2e9e08c3505a48a811a",
                            {2, 10, 0},
                            swarm::INVALID_SWARM_ID,
                            "23.88.6.250",
                            uint16_t{35420}},  // lokinet one
            };

            return netid(Target::testnet, seed_nodes);
        }

        static netid devnet(std::vector<service_node> seed_nodes) {
            if (seed_nodes.empty())
                throw std::invalid_argument(
                        "devnet must be configured with at least one seed node.");

            return netid(Target::devnet, std::move(seed_nodes));
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

        using network_response_callback_t = std::function<void(
                bool success,
                bool timeout,
                int16_t status_code,
                std::vector<std::pair<std::string, std::string>> headers,
                std::optional<std::string> response)>;
        using network_callback_t = std::function<void(
                std::string url, std::string body, network_response_callback_t handle_response)>;

        Type type;
        std::optional<network_callback_t> callback;

      private:
        explicit transport(
                Type t, std::optional<network_callback_t> callback = std::nullopt) :
                type{t}, callback{std::move(callback)} {}

      public:
        transport() = delete;

        static transport quic() { return transport(Type::quic); }
        static transport callbacks(network_callback_t callback) {
            return transport(Type::callbacks, std::move(callback));
        }
    };

    /// Can be used to override the default (12) minimum number of unused nodes before we trigger a snode cache refresh.
    ///
    /// Note: If the cache size is somehow smaller than this value (eg. Testnet is having issues) then the minimum size will be the full cache size (minus enough to build a path) or at least the size of a single path.
    struct onionreq_min_snode_cache_size : base {
        size_t size;
        explicit onionreq_min_snode_cache_size(size_t size) : size{size} {}
    };

    /// Can be used to override the default (3) number of cached nodes used to refresh the cache for any subsequent refreshes after populating from a seed node.
    ///
    /// Note: Providing a value of `0` will result in the cache _always_ being refreshed using a seed node.
    struct onionreq_num_cache_nodes_to_use_for_refresh : base {
        uint8_t count;
        explicit onionreq_num_cache_nodes_to_use_for_refresh(uint8_t count) : count{count} {}
    };

    /// Can be used to override the default (3) path size used when building onion request paths.
    struct onionreq_path_size : base {
        uint8_t size;

        explicit onionreq_path_size(uint8_t size) : size{size} {}
    };

    /// Can be used to override the default (3) number of times a path can receive an error before it is dropped and replaced by a new path.
    struct onionreq_path_failure_threshold : base {
        uint16_t count;

        explicit onionreq_path_failure_threshold(uint16_t count) : count{count} {}
    };

    /// Can be used to override the default (3) number of times a specific node in a path can receive an error before it is removed from the path and replaced by a new node (or the path is rebuilt if it happens to be the guard node).
    struct onionreq_node_failure_threshold : base {
        uint16_t count;

        explicit onionreq_node_failure_threshold(uint16_t count) : count{count} {}
    };

    /// Can be used to override the default (2) minimum number of paths that are maintained for each type of request when using onion requests.
    struct onionreq_min_path_count : base {
        enum class PathType {
            standard,
            upload,
            download,
        };

        PathType type;
        uint8_t min_count;

        explicit onionreq_min_path_count(PathType type, uint8_t min_count) :
                type{type}, min_count{min_count} {}
    };

    /// Can be used to prevent the network instance from building onion request paths when initialised, when this option is provided paths will be built when the first request it made.
    struct onionreq_disable_pre_build_paths : base {};

}  //  namespace opt
}  // namespace session::network
