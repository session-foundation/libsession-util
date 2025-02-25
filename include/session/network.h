#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "export.h"
#include "log_level.h"
#include "onionreq/builder.h"
#include "platform.h"

typedef enum CONNECTION_STATUS {
    CONNECTION_STATUS_UNKNOWN = 0,
    CONNECTION_STATUS_CONNECTING = 1,
    CONNECTION_STATUS_CONNECTED = 2,
    CONNECTION_STATUS_DISCONNECTED = 3,
} CONNECTION_STATUS;

typedef struct network_object {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;
} network_object;

typedef struct network_service_node {
    uint8_t ip[4];
    uint16_t quic_port;
    char ed25519_pubkey_hex[65];  // The 64-byte ed25519 pubkey in hex + null terminator.
} network_service_node;

typedef struct network_server_destination {
    const char* method;
    const char* protocol;
    const char* host;
    const char* endpoint;
    uint16_t port;
    const char* x25519_pubkey;
    const char** headers;
    const char** header_values;
    size_t headers_size;
} network_server_destination;

typedef struct onion_request_path {
    const network_service_node* nodes;
    const size_t nodes_count;
} onion_request_path;

/// API: network/network_init
///
/// Constructs a new network object.
///
/// When done with the object the `network_object` must be destroyed by passing the pointer to
/// network_free().
///
/// Inputs:
/// - `network` -- [out] Pointer to the network object
/// - `cache_path` -- [in] Path where the snode cache files should be stored.  Should be
/// NULL-terminated.
/// - `use_testnet` -- [in] Flag indicating whether the network should connect to testnet or
/// mainnet.
/// - `single_path_mode` -- [in] Flag indicating whether the network should be in "single path mode"
/// (ie. use a single path for everything - this is useful for iOS App Extensions which perform a
/// single action and then close so we don't waste time building other paths).
/// - `pre_build_paths` -- [in] Flag indicating whether the network should pre-build it's paths.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `bool` -- Returns true on success; returns false and write the exception message as a C-string
/// into `error` (if not NULL) on failure.
LIBSESSION_EXPORT bool network_init(
        network_object** network,
        const char* cache_path,
        bool use_testnet,
        bool single_path_mode,
        bool pre_build_paths,
        char* error) __attribute__((warn_unused_result));

/// API: network/network_free
///
/// Frees a network object.
///
/// Inputs:
/// - `network` -- [in] Pointer to network_object object
LIBSESSION_EXPORT void network_free(network_object* network);

/// API: network/network_suspend
///
/// Suspends the network preventing any further requests from creating new connections and paths.
/// This function also calls the `close_connections` function.
LIBSESSION_EXPORT void network_suspend(network_object* network);

/// API: network/network_resume
///
/// Resumes the network allowing new requests to creating new connections and paths.
LIBSESSION_EXPORT void network_resume(network_object* network);

/// API: network/network_close_connections
///
/// Closes any currently active connections.
LIBSESSION_EXPORT void network_close_connections(network_object* network);

/// API: network/network_clear_cache
///
/// Clears the cached from memory and from disk (if a cache path was provided during
/// initialization).
LIBSESSION_EXPORT void network_clear_cache(network_object* network);

/// API: network/network_get_cache_size
///
/// Retrieves the current size of the snode cache from memory (if a cache doesn't exist or
/// hasn't been loaded then this will return 0).
LIBSESSION_EXPORT size_t network_get_snode_cache_size(network_object* network);

/// API: network/network_set_status_changed_callback
///
/// Registers a callback to be called whenever the network connection status changes.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `callback` -- [in] callback to be called when the network connection status changes.
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_set_status_changed_callback(
        network_object* network, void (*callback)(CONNECTION_STATUS status, void* ctx), void* ctx);

/// API: network/network_set_paths_changed_callback
///
/// Registers a callback to be called whenever the onion request paths are updated.
///
/// The pointer provided to the callback belongs to the caller and must be freed via `free()` when
/// done with it.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `callback` -- [in] callback to be called when the onion request paths are updated.
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_set_paths_changed_callback(
        network_object* network,
        void (*callback)(onion_request_path* paths, size_t paths_len, void* ctx),
        void* ctx);

/// API: network/network_get_swarm
///
/// Retrieves the swarm for the given pubkey.  If there is already an entry in the cache for the
/// swarm then that will be returned, otherwise a network request will be made to retrieve the
/// swarm and save it to the cache.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - 'swarm_pubkey_hex' - [in] x25519 pubkey for the swarm in hex (64 characters).
/// - 'callback' - [in] callback to be called with the retrieved swarm (in the case of an error
/// the callback will be called with an empty list).
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_get_swarm(
        network_object* network,
        const char* swarm_pubkey_hex,
        void (*callback)(network_service_node* nodes, size_t nodes_len, void*),
        void* ctx);

/// API: network/network_get_random_nodes
///
/// Retrieves a number of random nodes from the snode pool.  If the are no nodes in the pool a
/// new pool will be populated and the nodes will be retrieved from that.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - 'count' - [in] the number of nodes to retrieve.
/// - 'callback' - [in] callback to be called with the retrieved nodes (in the case of an error
/// the callback will be called with an empty list).
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void network_get_random_nodes(
        network_object* network,
        uint16_t count,
        void (*callback)(network_service_node*, size_t, void*),
        void* ctx);

/// API: network/network_onion_response_callback_t
///
/// Function pointer typedef for the callback function pointer given to
/// network_send_onion_request_to_snode_destination and
/// network_send_onion_request_to_server_destination.
///
/// Fields:
/// - `success` -- true if the request was successful, false if it failed.
/// - `timeout` -- true if the request failed because of a timeout
/// - `status_code` -- the HTTP numeric status code of the request, e.g. 200 for OK
/// - `headers` -- the response headers, array of null-terminated C strings
/// - `header_values` -- the response header values, array of null-terminated C strings
/// - `headers_size` -- the number of `headers`/`header_values`
/// - `response` -- pointer to the beginning of the response body
/// - `response_size` -- length of the response body
/// - `ctx` -- the context pointer passed to the function that initiated the request.
typedef void (*network_onion_response_callback_t)(
        bool success,
        bool timeout,
        int16_t status_code,
        const char** headers,
        const char** header_values,
        size_t headers_size,
        const char* response,
        size_t response_size,
        void* ctx);

/// API: network/network_send_onion_request_to_snode_destination
///
/// Sends a request via onion routing to the provided service node.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object.
/// - `node` -- [in] address information about the service node the request should be sent to.
/// - `body` -- [in] data to send to the specified node.
/// - `body_size` -- [in] size of the `body`.
/// - `request_timeout_ms` -- [in] timeout in milliseconds to use for the request.  This won't take
/// the path build into account so if the path build takes forever then this request will never
/// timeout.
/// - `request_and_path_build_timeout_ms` -- [in] timeout in milliseconds to use for the request and
/// path build (if required).  This value takes presedence over `request_timeout_ms` if provided,
/// the request itself will be given a timeout of this value subtracting however long it took to
/// build the path.  A value of `0` will be ignored and `request_timeout_ms` will be used instead.
/// - `callback` -- [in] callback to be called with the result of the request.
/// - `ctx` -- [in, optional] Pointer to an optional context to pass through to the callback. Set to
/// NULL if unused.
LIBSESSION_EXPORT void network_send_onion_request_to_snode_destination(
        network_object* network,
        const network_service_node node,
        const unsigned char* body,
        size_t body_size,
        const char* swarm_pubkey_hex,
        int64_t request_timeout_ms,
        int64_t request_and_path_build_timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx);

/// API: network/network_send_onion_request_to_server_destination
///
/// Sends a request via onion routing to the provided server.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object.
/// - `server` -- [in] struct containing information about the server the request should be sent to.
/// - `body` -- [in] data to send to the specified endpoint.
/// - `body_size` -- [in] size of the `body`.
/// - `request_timeout_ms` -- [in] timeout in milliseconds to use for the request.  This won't take
/// the path build into account so if the path build takes forever then this request will never
/// timeout.
/// - `request_and_path_build_timeout_ms` -- [in] timeout in milliseconds to use for the request and
/// path build (if required).  This value takes presedence over `request_timeout_ms` if provided,
/// the request itself will be given a timeout of this value subtracting however long it took to
/// build the path.  A value of `0` will be ignored and `request_timeout_ms` will be used instead.
/// - `callback` -- [in] callback to be called with the result of the request.
/// - `ctx` -- [in, optional] Pointer to an optional context to pass through to the callback.  Set
/// to NULL if unused.
LIBSESSION_EXPORT void network_send_onion_request_to_server_destination(
        network_object* network,
        const network_server_destination server,
        const unsigned char* body,
        size_t body_size,
        int64_t request_timeout_ms,
        int64_t request_and_path_build_timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx);

/// API: network/network_upload_to_server
///
/// Uploads a file to a server.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object.
/// - `server` -- [in] struct containing information about the server the request should be sent to.
/// - `data` -- [in] data to upload to the file server.
/// - `data_len` -- [in] size of the `data`.
/// - `file_name` -- [in, optional] name of the file being uploaded. MUST be null terminated.
/// - `request_timeout_ms` -- [in] timeout in milliseconds to use for the request.  This won't take
/// the path build into account so if the path build takes forever then this request will never
/// timeout.
/// - `request_and_path_build_timeout_ms` -- [in] timeout in milliseconds to use for the request and
/// path build (if required).  This value takes presedence over `request_timeout_ms` if provided,
/// the request itself will be given a timeout of this value subtracting however long it took to
/// build the path.  A value of `0` will be ignored and `request_timeout_ms` will be used instead.
/// - `callback` -- [in] callback to be called with the result of the request.
/// - `ctx` -- [in, optional] Pointer to an optional context to pass through to the callback.  Set
/// to NULL if unused.
LIBSESSION_EXPORT void network_upload_to_server(
        network_object* network,
        const network_server_destination server,
        const unsigned char* data,
        size_t data_len,
        const char* file_name,
        int64_t request_timeout_ms,
        int64_t request_and_path_build_timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx);

/// API: network/network_download_from_server
///
/// Downloads a file from a server.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object.
/// - `server` -- [in] struct containing information about file to be downloaded.
/// - `request_timeout_ms` -- [in] timeout in milliseconds to use for the request.  This won't take
/// the path build into account so if the path build takes forever then this request will never
/// timeout.
/// - `request_and_path_build_timeout_ms` -- [in] timeout in milliseconds to use for the request and
/// path build (if required).  This value takes presedence over `request_timeout_ms` if provided,
/// the request itself will be given a timeout of this value subtracting however long it took to
/// build the path.  A value of `0` will be ignored and `request_timeout_ms` will be used instead.
/// - `callback` -- [in] callback to be called with the result of the request.
/// - `ctx` -- [in, optional] Pointer to an optional context to pass through to the callback.  Set
/// to NULL if unused.
LIBSESSION_EXPORT void network_download_from_server(
        network_object* network,
        const network_server_destination server,
        int64_t request_timeout_ms,
        int64_t request_and_path_build_timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx);

/// API: network/network_get_client_version
///
/// Retrieves the version information for the given platform.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object.
/// - `platform` -- [in] the platform to retrieve the client version for.
/// - `ed25519_secret` -- [in] the users ed25519 secret key (used for blinded auth - 64 bytes).
/// - `request_timeout_ms` -- [in] timeout in milliseconds to use for the request.  This won't take
/// the path build into account so if the path build takes forever then this request will never
/// timeout.
/// - `request_and_path_build_timeout_ms` -- [in] timeout in milliseconds to use for the request and
/// path build (if required).  This value takes presedence over `request_timeout_ms` if provided,
/// the request itself will be given a timeout of this value subtracting however long it took to
/// build the path.  A value of `0` will be ignored and `request_timeout_ms` will be used instead.
/// - `callback` -- [in] callback to be called with the result of the request.
/// - `ctx` -- [in, optional] Pointer to an optional context to pass through to the callback.  Set
/// to NULL if unused.
LIBSESSION_EXPORT void network_get_client_version(
        network_object* network,
        CLIENT_PLATFORM platform,
        const unsigned char* ed25519_secret, /* 64 bytes */
        int64_t request_timeout_ms,
        int64_t request_and_path_build_timeout_ms,
        network_onion_response_callback_t callback,
        void* ctx);

#ifdef __cplusplus
}
#endif
