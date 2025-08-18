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

/// API: file_server/session_file_server_upload
///
/// Constructs a request to upload a file to the session file server.
///
/// Inputs:
/// - `data` -- [in] data to upload to the file server.
/// - `data_len` -- [in] size of the `data`.
/// - `file_name` -- [in, optional] name of the file being uploaded. MUST be null terminated.
/// - `request_timeout` -- [in] timeout in milliseconds to use for the request.  This won't take any
/// pre-flight operations into account so the request will never timeout if pre-flight operations
/// never complete.
/// - `overall_timeout` -- [in] timeout in milliseconds to use for the request and any pre-flight
/// operations that may need to occur (eg. path building).  This value takes presedence over
/// `request_timeout` if provided, the request itself will be given a timeout of this value
/// subtracting however long the pre-flight operations took.
LIBSESSION_EXPORT session_request_params* session_file_server_upload(
        const unsigned char* data,
        size_t data_len,
        const char* file_name,
        int64_t request_timeout_ms,
        int64_t overall_timeout_ms);

/// API: network/session_file_server_download
///
/// Constructs a request to download a file from the session file server.
///
/// Inputs:
/// - `file_id` -- [in] the id of the file to download, NULL terminated.
/// - `request_timeout` -- [in] timeout in milliseconds to use for the request.  This won't take any
/// pre-flight operations into account so the request will never timeout if pre-flight operations
/// never complete.
/// - `overall_timeout` -- [in] timeout in milliseconds to use for the request and any pre-flight
/// operations that may need to occur (eg. path building).  This value takes presedence over
/// `request_timeout` if provided, the request itself will be given a timeout of this value
/// subtracting however long the pre-flight operations took.
LIBSESSION_EXPORT session_request_params* session_file_server_download(
        const char* file_id, int64_t request_timeout_ms, int64_t overall_timeout_ms);

/// API: network/session_file_server_get_client_version
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
