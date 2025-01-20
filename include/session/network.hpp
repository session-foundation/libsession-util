#pragma once

#include <limits>
#include <oxen/quic.hpp>

#include "onionreq/builder.hpp"
#include "onionreq/key_types.hpp"
#include "platform.hpp"
#include "session/random.hpp"
#include "types.hpp"

namespace session::network {

namespace fs = std::filesystem;

using network_response_callback_t = std::function<void(
        bool success,
        bool timeout,
        int16_t status_code,
        std::vector<std::pair<std::string, std::string>> headers,
        std::optional<std::string> response)>;

enum class ConnectionStatus {
    unknown,
    connecting,
    connected,
    disconnected,
};

enum class PathType {
    standard,
    upload,
    download,
};

using swarm_id_t = uint64_t;
constexpr swarm_id_t INVALID_SWARM_ID = std::numeric_limits<uint64_t>::max();

struct service_node : public oxen::quic::RemoteAddress {
  public:
    std::vector<int> storage_server_version;
    swarm_id_t swarm_id;

    service_node() = delete;

    template <typename... Opt>
    service_node(
            std::string_view remote_pk,
            std::vector<int> storage_server_version,
            swarm_id_t swarm_id,
            Opt&&... opts) :
            oxen::quic::RemoteAddress{remote_pk, std::forward<Opt>(opts)...},
            storage_server_version{storage_server_version},
            swarm_id{swarm_id} {}

    template <typename... Opt>
    service_node(
            ustring_view remote_pk,
            std::vector<int> storage_server_version,
            swarm_id_t swarm_id,
            Opt&&... opts) :
            oxen::quic::RemoteAddress{remote_pk, std::forward<Opt>(opts)...},
            storage_server_version{storage_server_version},
            swarm_id{swarm_id} {}

    service_node(const service_node& obj) :
            oxen::quic::RemoteAddress{obj},
            storage_server_version{obj.storage_server_version},
            swarm_id{obj.swarm_id} {}
    service_node& operator=(const service_node& obj) {
        storage_server_version = obj.storage_server_version;
        swarm_id = obj.swarm_id;
        oxen::quic::RemoteAddress::operator=(obj);
        _copy_internals(obj);
        return *this;
    }

    bool operator==(const service_node& other) const {
        return static_cast<const oxen::quic::RemoteAddress&>(*this) ==
                       static_cast<const oxen::quic::RemoteAddress&>(other) &&
               storage_server_version == other.storage_server_version && swarm_id == other.swarm_id;
    }
};

struct connection_info {
    service_node node;
    std::shared_ptr<size_t> pending_requests;
    std::shared_ptr<oxen::quic::connection_interface> conn;
    std::shared_ptr<oxen::quic::BTRequestStream> stream;

    bool is_valid() const { return conn && stream && !stream->is_closing(); };
    bool has_pending_requests() const { return (pending_requests && (*pending_requests) > 0); };

    void add_pending_request() {
        if (!pending_requests)
            pending_requests = std::make_shared<size_t>(0);
        (*pending_requests)++;
    };

    // This is weird but since we are modifying the shared_ptr we aren't mutating
    // the object so it can be a const function
    void remove_pending_request() const {
        if (!pending_requests)
            return;
        (*pending_requests)--;
    };
};

struct onion_path {
    std::string id;
    connection_info conn_info;
    std::vector<service_node> nodes;
    uint8_t failure_count;

    bool is_valid() const { return !nodes.empty() && conn_info.is_valid(); };
    bool has_pending_requests() const { return conn_info.has_pending_requests(); }
    size_t num_pending_requests() const {
        if (!conn_info.pending_requests)
            return 0;
        return (*conn_info.pending_requests);
    }

    std::string to_string() const;

    bool operator==(const onion_path& other) const {
        // The `conn_info` and failure/timeout counts can be reset for a path in a number
        // of situations so just use the nodes to determine if the paths match
        return nodes == other.nodes;
    }
};

namespace detail {
    swarm_id_t pubkey_to_swarm_space(const session::onionreq::x25519_pubkey& pk);
    std::vector<std::pair<swarm_id_t, std::vector<service_node>>> generate_swarms(
            std::vector<service_node> nodes);

    std::optional<service_node> node_for_destination(onionreq::network_destination destination);

    session::onionreq::x25519_pubkey pubkey_for_destination(
            onionreq::network_destination destination);

}  //  namespace detail

struct request_info {
    static request_info make(
            onionreq::network_destination _dest,
            std::optional<ustring> _original_body,
            std::optional<session::onionreq::x25519_pubkey> _swarm_pk,
            std::chrono::milliseconds _request_timeout,
            std::optional<std::chrono::milliseconds> _request_and_path_build_timeout = std::nullopt,
            PathType _type = PathType::standard,
            std::optional<std::string> _req_id = std::nullopt,
            std::optional<std::string> endpoint = "onion_req",
            std::optional<ustring> _body = std::nullopt);

    enum class RetryReason {
        none,
        decryption_failure,
        redirect,
        redirect_swarm_refresh,
    };

    std::string request_id;
    session::onionreq::network_destination destination;
    std::string endpoint;
    std::optional<ustring> body;
    std::optional<ustring> original_body;
    std::optional<session::onionreq::x25519_pubkey> swarm_pubkey;
    PathType path_type;
    std::chrono::milliseconds request_timeout;
    std::optional<std::chrono::milliseconds> request_and_path_build_timeout;
    std::chrono::system_clock::time_point creation_time = std::chrono::system_clock::now();

    /// The reason we are retrying the request (if it's a retry). Generally only used for internal
    /// purposes (like receiving a `421`) in order to prevent subsequent retries.
    std::optional<RetryReason> retry_reason{};

    bool node_destination{detail::node_for_destination(destination).has_value()};
};

class Network {
  private:
    const bool use_testnet;
    const bool should_cache_to_disk;
    const bool single_path_mode;
    const fs::path cache_path;

    // Disk thread state
    std::mutex snode_cache_mutex;  // This guards all the below:
    std::condition_variable snode_cache_cv;
    bool has_pending_disk_write = false;
    bool shut_down_disk_thread = false;
    bool need_write = false;
    bool need_clear_cache = false;

    // Values persisted to disk
    std::optional<size_t> seed_node_cache_size;
    std::vector<service_node> snode_cache;
    std::chrono::system_clock::time_point last_snode_cache_update{};

    std::thread disk_write_thread;

    // General values
    bool destroyed = false;
    bool suspended = false;
    ConnectionStatus status;
    oxen::quic::Network net;
    std::shared_ptr<oxen::quic::Endpoint> endpoint;
    std::unordered_map<PathType, std::vector<onion_path>> paths;
    std::vector<std::pair<onion_path, PathType>> paths_pending_drop;
    std::vector<service_node> unused_nodes;
    std::unordered_map<std::string, uint8_t> snode_failure_counts;
    std::vector<std::pair<swarm_id_t, std::vector<service_node>>> all_swarms;
    std::unordered_map<std::string, std::pair<swarm_id_t, std::vector<service_node>>> swarm_cache;

    // Snode refresh state
    int snode_cache_refresh_failure_count;
    int in_progress_snode_cache_refresh_count;
    std::optional<std::string> current_snode_cache_refresh_request_id;
    std::vector<std::function<void()>> after_snode_cache_refresh;
    std::optional<std::vector<service_node>> unused_snode_refresh_nodes;
    std::shared_ptr<std::vector<std::vector<service_node>>> snode_refresh_results;

    // First hop state
    int connection_failures = 0;
    std::deque<connection_info> unused_connections;
    std::unordered_map<std::string, service_node> in_progress_connections;

    // Path build state
    int path_build_failures = 0;
    std::deque<PathType> path_build_queue;
    std::unordered_map<std::string, PathType> in_progress_path_builds;

    // Request state
    bool has_scheduled_resume_queues = false;
    std::optional<std::string> request_timeout_id;
    std::chrono::system_clock::time_point last_resume_queues_timestamp{};
    std::unordered_map<PathType, std::vector<std::pair<request_info, network_response_callback_t>>>
            request_queue;

  public:
    friend class TestNetwork;
    friend class TestNetworkWrapper;

    // Hook to be notified whenever the network connection status changes.
    std::function<void(ConnectionStatus status)> status_changed;

    // Hook to be notified whenever the onion request paths are updated.
    std::function<void(std::vector<std::vector<service_node>> paths)> paths_changed;

    // Constructs a new network with the given cache path and a flag indicating whether it should
    // use testnet or mainnet, all requests should be made via a single Network instance.
    Network(std::optional<fs::path> cache_path,
            bool use_testnet,
            bool single_path_mode,
            bool pre_build_paths);
    virtual ~Network();

    /// API: network/suspend
    ///
    /// Suspends the network preventing any further requests from creating new connections and
    /// paths.  This function also calls the `close_connections` function.
    void suspend();

    /// API: network/resume
    ///
    /// Resumes the network allowing new requests to creating new connections and paths.
    void resume();

    /// API: network/close_connections
    ///
    /// Closes any currently active connections.
    void close_connections();

    /// API: network/clear_cache
    ///
    /// Clears the cached from memory and from disk (if a cache path was provided during
    /// initialization).
    void clear_cache();

    /// API: network/snode_cache_size
    ///
    /// Retrieves the current size of the snode cache from memory (if a cache doesn't exist or
    /// hasn't been loaded then this will return 0).
    size_t snode_cache_size();

    /// API: network/get_swarm
    ///
    /// Retrieves the swarm for the given pubkey.  If there is already an entry in the cache for the
    /// swarm then that will be returned, otherwise a network request will be made to retrieve the
    /// swarm and save it to the cache.
    ///
    /// Inputs:
    /// - 'swarm_pubkey' - [in] public key for the swarm.
    /// - 'callback' - [in] callback to be called with the retrieved swarm (in the case of an error
    /// the callback will be called with an empty list).
    void get_swarm(
            session::onionreq::x25519_pubkey swarm_pubkey,
            std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback);

    /// API: network/get_random_nodes
    ///
    /// Retrieves a number of random nodes from the snode pool.  If the are no nodes in the pool a
    /// new pool will be populated and the nodes will be retrieved from that.
    ///
    /// Inputs:
    /// - 'count' - [in] the number of nodes to retrieve.
    /// - 'callback' - [in] callback to be called with the retrieved nodes (in the case of an error
    /// the callback will be called with an empty list).
    void get_random_nodes(
            uint16_t count, std::function<void(std::vector<service_node> nodes)> callback);

    /// API: network/send_onion_request
    ///
    /// Sends a request via onion routing to the provided service node or server destination.
    ///
    /// Inputs:
    /// - `destination` -- [in] service node or server destination information.
    /// - `body` -- [in] data to send to the specified destination.
    /// - `swarm_pubkey` -- [in, optional] pubkey for the swarm the request is associated with.
    /// Should be NULL if the request is not associated with a swarm.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    /// - `request_timeout` -- [in] timeout in milliseconds to use for the request.  This won't take
    /// the path build into account so if the path build takes forever then this request will never
    /// timeout.
    /// - `request_and_path_build_timeout` -- [in] timeout in milliseconds to use for the request
    /// and path build (if required).  This value takes presedence over `request_timeout` if
    /// provided, the request itself will be given a timeout of this value subtracting however long
    /// it took to build the path.
    /// - 'type' - [in] the type of paths to send the request across.
    void send_onion_request(
            onionreq::network_destination destination,
            std::optional<ustring> body,
            std::optional<session::onionreq::x25519_pubkey> swarm_pubkey,
            network_response_callback_t handle_response,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> request_and_path_build_timeout = std::nullopt,
            PathType type = PathType::standard);

    /// API: network/upload_file_to_server
    ///
    /// Uploads a file to a given server destination.
    ///
    /// Inputs:
    /// - 'data' - [in] the data to be uploaded to a server.
    /// - `server` -- [in] the server destination to upload the file to.
    /// - `file_name` -- [in, optional] optional name to use for the file.
    /// - `request_timeout` -- [in] timeout in milliseconds to use for the request.  This won't take
    /// the path build into account so if the path build takes forever then this request will never
    /// timeout.
    /// - `request_and_path_build_timeout` -- [in] timeout in milliseconds to use for the request
    /// and path build (if required).  This value takes presedence over `request_timeout` if
    /// provided, the request itself will be given a timeout of this value subtracting however long
    /// it took to build the path.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void upload_file_to_server(
            ustring data,
            onionreq::ServerDestination server,
            std::optional<std::string> file_name,
            network_response_callback_t handle_response,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> request_and_path_build_timeout = std::nullopt);

    /// API: network/download_file
    ///
    /// Download a file from a given server destination.
    ///
    /// Inputs:
    /// - `server` -- [in] the server destination to download the file from.
    /// - `request_timeout` -- [in] timeout in milliseconds to use for the request.  This won't take
    /// the path build into account so if the path build takes forever then this request will never
    /// timeout.
    /// - `request_and_path_build_timeout` -- [in] timeout in milliseconds to use for the request
    /// and path build (if required).  This value takes presedence over `request_timeout` if
    /// provided, the request itself will be given a timeout of this value subtracting however long
    /// it took to build the path.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void download_file(
            onionreq::ServerDestination server,
            network_response_callback_t handle_response,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> request_and_path_build_timeout = std::nullopt);

    /// API: network/download_file
    ///
    /// Convenience function to download a file from a given url and x25519 pubkey combination.
    /// Calls through to the above `download_file` function after constructing a server destination
    /// from the provided values.
    ///
    /// Inputs:
    /// - `download_url` -- [in] the url to download the file from.
    /// - `x25519_pubkey` -- [in] the server destination to download the file from.
    /// - `timeout` -- [in] timeout in milliseconds to use for the request.
    /// - `request_timeout` -- [in] timeout in milliseconds to use for the request.  This won't take
    /// the path build into account so if the path build takes forever then this request will never
    /// timeout.
    /// - `request_and_path_build_timeout` -- [in] timeout in milliseconds to use for the request
    /// and path build (if required).  This value takes presedence over `request_timeout` if
    /// provided, the request itself will be given a timeout of this value subtracting however long
    /// it took to build the path.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void download_file(
            std::string_view download_url,
            onionreq::x25519_pubkey x25519_pubkey,
            network_response_callback_t handle_response,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> request_and_path_build_timeout = std::nullopt);

    /// API: network/get_client_version
    ///
    /// Retrieves the version information for the given platform.
    ///
    /// Inputs:
    /// - `platform` -- [in] the platform to retrieve the client version for.
    /// - `seckey` -- [in] the users ed25519 secret key (to generated blinded auth).
    /// - `request_timeout` -- [in] timeout in milliseconds to use for the request.  This won't take
    /// the path build into account so if the path build takes forever then this request will never
    /// timeout.
    /// - `request_and_path_build_timeout` -- [in] timeout in milliseconds to use for the request
    /// and path build (if required).  This value takes presedence over `request_timeout` if
    /// provided, the request itself will be given a timeout of this value subtracting however long
    /// it took to build the path.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void get_client_version(
            Platform platform,
            onionreq::ed25519_seckey seckey,
            network_response_callback_t handle_response,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> request_and_path_build_timeout = std::nullopt);

  private:
    /// API: network/all_path_ips
    ///
    /// Internal function to retrieve all of the node ips current used in paths
    std::vector<oxen::quic::ipv4> all_path_ips() const {
        std::vector<oxen::quic::ipv4> result;

        for (const auto& [path_type, paths_for_type] : paths)
            for (const auto& path : paths_for_type)
                for (const auto& node : path.nodes)
                    result.emplace_back(node.to_ipv4());

        return result;
    };

    /// API: network/update_disk_cache_throttled
    ///
    /// Function which can be used to notify the disk write thread that a write can be performed.
    /// This function has a very basic throttling mechanism where it triggers the write a small
    /// delay after it is called, any subsequent calls to the function within the same period will
    /// be ignored.  This is done to avoid excessive disk writes which probably aren't needed for
    /// the cached network data.
    virtual void update_disk_cache_throttled(bool force_immediate_write = false);

    /// API: network/disk_write_thread_loop
    ///
    /// Body of the disk writer which runs until signalled to stop.  This is intended to run in its
    /// own thread.  The thread monitors a number of private variables and persists the snode pool
    /// and swarm caches to disk if a `cache_path` was provided during initialization.
    void disk_write_thread_loop();

    /// API: network/load_cache_from_disk
    ///
    /// Loads the snode pool and swarm caches from disk if a `cache_path` was provided and cached
    /// data exists.
    void load_cache_from_disk();

    /// API: network/_close_connections
    ///
    /// Triggered via the close_connections function but actually contains the logic to clear out
    /// paths, requests and connections.  This function is not thread safe so should should be
    /// called with that in mind.
    void _close_connections();

    /// API: network/update_status
    ///
    /// Internal function to update the connection status and trigger the `status_changed` hook if
    /// provided, this method ignores invalid or unchanged status changes.
    ///
    /// Inputs:
    /// - 'updated_status' - [in] the updated connection status.
    void update_status(ConnectionStatus updated_status);

    /// API: network/retry_delay
    ///
    /// A function which generates an exponential delay to wait before retrying a request/action
    /// based on the provided failure count.
    ///
    /// Inputs:
    /// - 'num_failures' - [in] the number of times the request has already failed.
    /// - 'max_delay' - [in] the maximum amount of time to delay for.
    virtual std::chrono::milliseconds retry_delay(
            int num_failures,
            std::chrono::milliseconds max_delay = std::chrono::milliseconds{5000});

    /// API: network/get_endpoint
    ///
    /// Retrieves or creates a new endpoint pointer.
    std::shared_ptr<oxen::quic::Endpoint> get_endpoint();

    /// API: network/min_snode_cache_size
    ///
    /// When talking to testnet it's occassionally possible for the cache size to be smaller than
    /// the `min_snode_cache_count` value (which would result in an endless loop re-fetching the
    /// node cache) so instead this function will return the smaller of the two if we've done a
    /// fetch from a seed node.
    size_t min_snode_cache_size() const;

    /// API: network/get_unused_nodes
    ///
    /// Retrieves a list of all nodes in the cache which are currently unused (ie. not present in an
    /// exising or pending path, connection or request).
    ///
    /// Outputs:
    /// - The list of unused nodes.
    std::vector<service_node> get_unused_nodes();

    /// API: network/establish_connection
    ///
    /// Establishes a connection to the target node and triggers the callback once the connection is
    /// established (or closed in case it fails).
    ///
    /// Inputs:
    /// - 'id' - [in] id for the request or path build which triggered the call.
    /// - `target` -- [in] the target service node to connect to.
    /// - `timeout` -- [in, optional] optional timeout for the request, if NULL the
    /// `quic::DEFAULT_HANDSHAKE_TIMEOUT` will be used.
    /// - `callback` -- [in] callback to be called with connection info once the connection is
    /// established or fails.
    void establish_connection(
            std::string id,
            service_node target,
            std::optional<std::chrono::milliseconds> timeout,
            std::function<void(connection_info info, std::optional<std::string> error)> callback);

    /// API: network/establish_and_store_connection
    ///
    /// Establishes a connection to a random unused node and stores it in the `unused_connections`
    /// list.
    ///
    /// Inputs:
    /// - 'path_id' - [in] id for the path build which triggered the call.
    virtual void establish_and_store_connection(std::string path_id);

    /// API: network/refresh_snode_cache_complete
    ///
    /// This function will be called from either `refresh_snode_cache` or
    /// `refresh_snode_cache_from_seed_nodes` and will actually update the state and persist the
    /// updated cache to disk.
    ///
    /// Inputs:
    /// - 'nodes' - [in] the nodes to use as the updated cache.
    void refresh_snode_cache_complete(std::vector<service_node> nodes);

    /// API: network/refresh_snode_cache_from_seed_nodes
    ///
    /// This function refreshes the snode cache for a random seed node. Unlike the
    /// `refresh_snode_cache` function this will update the cache with the response from a single
    /// seed node since it's a trusted source.
    ///
    /// Inputs:
    /// - 'request_id' - [in] id for an existing refresh_snode_cache request.
    /// - 'reset_unused_nodes' - [in] flag to indicate whether this should reset the unused nodes
    /// before kicking off the request.
    virtual void refresh_snode_cache_from_seed_nodes(
            std::string request_id, bool reset_unused_nodes);

    /// API: network/refresh_snode_cache
    ///
    /// This function refreshes the snode cache.  If the current cache is to small (or not present)
    /// this will trigger the above `refresh_snode_cache_from_seed_nodes` function, otherwise it
    /// will randomly pick a number of nodes from the existing cache and refresh the cache from the
    /// intersection of the results.
    ///
    /// Inputs:
    /// - 'existing_request_id' - [in, optional] id for an existing refresh_snode_cache request.
    virtual void refresh_snode_cache(std::optional<std::string> existing_request_id = std::nullopt);

    /// API: network/build_path
    ///
    /// Build a new onion request path for the specified type.  If there are no existing connections
    /// this will open a new connection to a random service nodes in the snode cache.
    ///
    /// Inputs:
    /// - 'path_id' - [in] id for the new path.
    /// - `path_type` -- [in] the type of path to build.
    virtual void build_path(std::string path_id, PathType path_type);

    /// API: network/find_valid_path
    ///
    /// Find a random path from the provided paths which is valid for the provided request.  Note:
    /// if the Network is setup in `single_path_mode` then the path returned may include the
    /// destination for the request.
    ///
    /// Inputs:
    /// - `info` -- [in] request to select a path for.
    /// - `paths` -- [in] paths to select from.
    ///
    /// Outputs:
    /// - The possible path, if found.
    virtual std::optional<onion_path> find_valid_path(
            const request_info info, const std::vector<onion_path> paths);

    /// API: network/build_path_if_needed
    ///
    /// Triggers a path build for the specified type if the total current or pending paths is below
    /// the minimum threshold for the given type.  Note: This may result in more paths than the
    /// minimum threshold being built in order to avoid a situation where a request may never get
    /// sent due to it's destination being present in the existing path(s) for the type.
    ///
    /// Inputs:
    /// - `path_type` -- [in] the type of path to be built.
    /// - `found_path` -- [in] flag indicating whether a valid path was found by calling
    /// `find_valid_path` above.
    virtual void build_path_if_needed(PathType path_type, bool found_valid_path);

    /// API: network/get_service_nodes
    ///
    /// Retrieves all or a random subset of service nodes from the given node.
    ///
    /// Inputs:
    /// - 'request_id' - [in] id for the request which triggered the call.
    /// - `conn_info` -- [in] the connection info to retrieve service nodes from.
    /// - `limit` -- [in, optional] the number of service nodes to retrieve.
    /// - `callback` -- [in] callback to be triggered once we receive nodes.  NOTE: If an error
    /// occurs an empty list and an error will be provided.
    void get_service_nodes(
            std::string request_id,
            connection_info conn_info,
            std::optional<int> limit,
            std::function<void(std::vector<service_node> nodes, std::optional<std::string> error)>
                    callback);

    /// API: network/check_request_queue_timeouts
    ///
    /// Checks if any of the requests in the request queue have timed out (and fails them if so).
    ///
    /// Inputs:
    /// - 'request_timeout_id' - [in] id for the timeout loop to prevent multiple loops from being
    /// scheduled.
    virtual void check_request_queue_timeouts(
            std::optional<std::string> request_timeout_id = std::nullopt);

    /// API: network/send_request
    ///
    /// Send a request via the network.
    ///
    /// Inputs:
    /// - `info` -- [in] wrapper around all of the information required to send a request.
    /// - `conn` -- [in] connection information used to send the request.
    /// - `handle_response` -- [in] callback to be called with the result of the request.
    void send_request(
            request_info info, connection_info conn, network_response_callback_t handle_response);

    /// API: network/_send_onion_request
    ///
    /// Internal function invoked by ::send_onion_request after request_info construction
    virtual void _send_onion_request(
            request_info info, network_response_callback_t handle_response);

    /// API: network/process_v3_onion_response
    ///
    /// Processes a v3 onion request response.
    ///
    /// Inputs:
    /// - `builder` -- [in] the builder that was used to build the onion request.
    /// - `response` -- [in] the response data returned from the destination.
    ///
    /// Outputs:
    /// - A tuple containing the status code, headers and body of the decrypted onion request
    /// response.
    std::tuple<
            int16_t,
            std::vector<std::pair<std::string, std::string>>,
            std::optional<std::string>>
    process_v3_onion_response(session::onionreq::Builder builder, std::string response);

    /// API: network/process_v4_onion_response
    ///
    /// Processes a v4 onion request response.
    ///
    /// Inputs:
    /// - `builder` -- [in] the builder that was used to build the onion request.
    /// - `response` -- [in] the response data returned from the destination.
    ///
    /// Outputs:
    /// - A tuple containing the status code, headers and body of the decrypted onion request
    /// response.
    std::tuple<
            int16_t,
            std::vector<std::pair<std::string, std::string>>,
            std::optional<std::string>>
    process_v4_onion_response(session::onionreq::Builder builder, std::string response);

    /// API: network/validate_response
    ///
    /// Processes a quic response to extract the status code and body or throw if it errored or
    /// received a non-successful status code.
    ///
    /// Inputs:
    /// - `resp` -- [in] the quic response.
    /// - `is_bencoded` -- [in] flag indicating whether the response will be bencoded or JSON.
    ///
    /// Returns:
    /// - `std::pair<uint16_t, std::string>` -- the status code and response body (for a bencoded
    /// response this is just the direct response body from quic as it simplifies consuming the
    /// response elsewhere).
    std::pair<uint16_t, std::string> validate_response(oxen::quic::message resp, bool is_bencoded);

    /// API: network/drop_path_when_empty
    ///
    /// Flags a path to be dropped once all pending requests have finished.
    ///
    /// Inputs:
    /// - `id` -- [in] id the request or path which triggered the path drop (if the id is a path_id
    /// then the drop was triggered by the connection being dropped).
    /// - `path_type` -- [in] the type of path to build.
    /// - `path` -- [in] the path to be dropped.
    void drop_path_when_empty(std::string id, PathType path_type, onion_path path);

    /// API: network/clear_empty_pending_path_drops
    ///
    /// Iterates through all paths flagged to be dropped and actually drops any which are no longer
    /// valid or have no more pending requests.
    void clear_empty_pending_path_drops();

    /// API: network/handle_errors
    ///
    /// Processes a non-success response to automatically perform any standard operations based on
    /// the errors returned from the service node network (ie. updating the service node cache,
    /// dropping nodes and/or onion request paths).
    ///
    /// Inputs:
    /// - `info` -- [in] the information for the request that was made.
    /// - `conn_info` -- [in] the connection info for the request that failed.
    /// - `timeout` -- [in, optional] flag indicating whether the request timed out.
    /// - `status_code` -- [in] the status code returned from the network.
    /// - `headers` -- [in] the response headers returned from the network.
    /// - `response` -- [in, optional] response data returned from the network.
    /// - `handle_response` -- [in, optional] callback to be called with updated response
    /// information after processing the error.
    virtual void handle_errors(
            request_info info,
            connection_info conn_info,
            bool timeout,
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> response,
            std::optional<network_response_callback_t> handle_response);
};

}  // namespace session::network
