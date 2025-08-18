#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "session/export.h"
#include "session/log_level.h"
#include "session/network/session_network_types.h"
#include "session/onionreq/builder.h"
#include "session/platform.h"

typedef struct network_object_v2 {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;
} network_object_v2;
typedef struct session_response_handle_cpp_t session_response_handle_t;

typedef enum {
    SESSION_NETWORK_MAINNET = 0,
    SESSION_NETWORK_TESTNET = 1,
    SESSION_NETWORK_DEVNET = 2
} SESSION_NETWORK_NETID;

typedef enum {
    SESSION_NETWORK_ROUTER_ONION_REQUESTS = 0,
    SESSION_NETWORK_ROUTER_LOKINET = 1,
    SESSION_NETWORK_ROUTER_DIRECT = 2,
} SESSION_NETWORK_ROUTER;

typedef enum {
    SESSION_NETWORK_TRANSPORT_QUIC = 0,
    SESSION_NETWORK_TRANSPORT_CALLBACKS = 1,
} SESSION_NETWORK_TRANSPORT;

typedef void (*session_network_request_t)(
        const char* url,
        const char* body_data,
        size_t body_size,
        session_response_handle_t* response_handle,
        void* ctx);

typedef struct {
    // Basic options
    SESSION_NETWORK_NETID netid;
    SESSION_NETWORK_ROUTER router;
    SESSION_NETWORK_TRANSPORT transport;
    uint8_t path_length;
    bool enforce_subnet_diversity;
    uint8_t redirect_retry_count;
    uint64_t min_retry_delay_ms;
    uint64_t max_retry_delay_ms;
    uint64_t request_timeout_check_frequency_ms;

    // Devnet options (only used when netid_target == SESSION_NETWORK_DEVNET)
    const network_service_node* devnet_seed_nodes;
    size_t devnet_seed_nodes_size;

    // Snode pool options
    const char* cache_dir;
    uint32_t cache_expiration_minutes;
    uint8_t cache_refresh_retry_limit;
    size_t cache_min_size;
    uint8_t cache_num_nodes_to_use_for_refresh;
    uint8_t cache_node_failure_threshold;
    bool cache_refresh_using_legacy_endpoint;

    // Onion request router options (only used when router ==
    // SESSION_NETWORK_ROUTER_ONION_REQUESTS)
    uint8_t onionreq_path_failure_threshold;
    uint8_t onionreq_path_build_retry_limit;
    uint8_t onionreq_min_path_count_standard;
    uint8_t onionreq_min_path_count_upload;
    uint8_t onionreq_min_path_count_download;
    bool onionreq_single_path_mode;
    bool onionreq_disable_pre_build_paths;

    // Quic transport options (for transport == SESSION_NETWORK_TRANSPORT_QUIC)
    uint32_t quic_handshake_timeout_seconds;
    uint32_t quic_keep_alive_seconds;
    bool quic_disable_mtu_discovery;

    // Callback options (for transport == SESSION_NETWORK_TRANSPORT_CALLBACKS)
    session_network_request_t transport_callback;

    // A user-defined context pointer passed back to every invocation of `transport_callback`
    void* transport_callback_ctx;

} session_network_config;

typedef void (*session_network_response_t)(
        bool success,
        bool timeout,
        int16_t status_code,
        const char* const* headers_kv_pairs,
        size_t headers_kv_pairs_len,
        const unsigned char* response,
        size_t response_size,
        void* ctx);

/// API: network/session_network_default_config
///
/// Populates an instance with the default configuration options.
///
/// Inputs:
/// - `config` -- [in] Pointer to session_network_config object
LIBSESSION_EXPORT session_network_config session_network_config_default();

LIBSESSION_EXPORT bool session_network_init(
        network_object_v2** network,
        const session_network_config* config,
        char* error) LIBSESSION_WARN_UNUSED;

/// API: network/session_network_free
///
/// Frees a network object.
///
/// Inputs:
/// - `network` -- [in] Pointer to network_object object
LIBSESSION_EXPORT void session_network_free(network_object_v2* network);

/// API: network/session_request_params_free
///
/// Frees a request params object.
///
/// Inputs:
/// - `params` -- [in] Pointer to session_request_params object
LIBSESSION_EXPORT void session_request_params_free(session_request_params* params);

LIBSESSION_EXPORT uint64_t session_network_time_offset(network_object_v2* network);
LIBSESSION_EXPORT int session_network_hardfork(network_object_v2* network);
LIBSESSION_EXPORT int session_network_softfork(network_object_v2* network);

LIBSESSION_EXPORT void session_network_callbacks_respond(
        network_object_v2* network,
        session_response_handle_t* response_handle,
        bool success,
        bool timeout,
        int16_t status_code,
        const char* const* headers,
        const char* const* header_values,
        size_t headers_size,
        const char* body,
        size_t body_len);

LIBSESSION_EXPORT void session_network_get_swarm(
        network_object_v2* network,
        const char* swarm_pubkey_hex,
        void (*callback)(network_service_node* nodes, size_t nodes_len, void*),
        void* ctx);

LIBSESSION_EXPORT void session_network_get_random_nodes(
        network_object_v2* network,
        uint16_t count,
        void (*callback)(network_service_node*, size_t, void*),
        void* ctx);

LIBSESSION_EXPORT void session_network_send_request(
        network_object_v2* network,
        const session_request_params* params,
        session_network_response_t callback,
        void* ctx);

#ifdef __cplusplus
}
#endif
