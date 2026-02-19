#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "session/export.h"
#include "session/network/session_network_types.h"
#include "session/onionreq/builder.h"
#include "session/platform.h"

/// API: session_file_server/download_url_requires_deterministic_decryption
///
/// Determines whether a given download url requires deterministic decryption.
///
/// Inputs:
/// - `url` -- [in] url to check.
///
/// Outputs:
/// - returns true if url contains information indicating deterministic decryption is required;
/// false otherwise.
LIBSESSION_EXPORT bool download_url_requires_deterministic_decryption(const char* url);

/// API: session_file_server/session_file_server_get_client_version
///
/// Constructs a request to retrieve the version information for the given platform.
///
/// Inputs:
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
LIBSESSION_EXPORT session_request_params* session_file_server_get_client_version(
        CLIENT_PLATFORM platform,
        const unsigned char* ed25519_secret, /* 64 bytes */
        int64_t request_timeout_ms,
        int64_t overall_timeout_ms);

#ifdef __cplusplus
}
#endif
