#pragma once

#include "session/network/key_types.hpp"
#include "session/network/session_network_types.hpp"
#include "session/platform.hpp"

namespace session::network::file_server {

/// API: file_server/upload
///
/// Constructs a request to upload a file to the session file server.
///
/// Inputs:
/// - 'data' - [in] the data to be uploaded to a server.
/// - `file_name` -- [in, optional] optional name to use for the file.
/// - `request_timeout` -- [in] timeout in milliseconds to use for the request.  This won't take any
/// pre-flight operations into account so the request will never timeout if pre-flight operations
/// never complete.
/// - `overall_timeout` -- [in] timeout in milliseconds to use for the request and any pre-flight
/// operations that may need to occur (eg. path building).  This value takes presedence over
/// `request_timeout` if provided, the request itself will be given a timeout of this value
/// subtracting however long the pre-flight operations took.
Request upload(
        std::vector<unsigned char> data,
        std::optional<std::string> file_name,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout = std::nullopt);

/// API: file_server/download
///
/// Constructs a request to download a file from the session file server.
///
/// Inputs:
/// - `file_id` -- [in] the id of the file to download.
/// - `request_timeout` -- [in] timeout in milliseconds to use for the request.  This won't take any
/// pre-flight operations into account so the request will never timeout if pre-flight operations
/// never complete.
/// - `overall_timeout` -- [in] timeout in milliseconds to use for the request and any pre-flight
/// operations that may need to occur (eg. path building).  This value takes presedence over
/// `request_timeout` if provided, the request itself will be given a timeout of this value
/// subtracting however long the pre-flight operations took.
Request download(
        std::string file_id,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout = std::nullopt);

/// API: file_server/get_client_version
///
/// Constructs a request to retrieve the version information for the given platform.
///
/// Inputs:
/// - `platform` -- [in] the platform to retrieve the client version for.
/// - `seckey` -- [in] the users ed25519 secret key (to generated blinded auth).
/// - `request_timeout` -- [in] timeout in milliseconds to use for the request.  This won't take any
/// pre-flight operations into account so the request will never timeout if pre-flight operations
/// never complete.
/// - `overall_timeout` -- [in] timeout in milliseconds to use for the request and any pre-flight
/// operations that may need to occur (eg. path building).  This value takes presedence over
/// `request_timeout` if provided, the request itself will be given a timeout of this value
/// subtracting however long the pre-flight operations took.
Request get_client_version(
        Platform platform,
        network::ed25519_seckey seckey,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout = std::nullopt);

}  // namespace session::network::file_server
