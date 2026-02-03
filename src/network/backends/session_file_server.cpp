#include "session/network/backends/session_file_server.hpp"

#include <fmt/ranges.h>
#include <oxenc/base64.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "../session_network_internal.hpp"
#include "session/blinding.hpp"
#include "session/network/backends/session_file_server.h"
#include "session/random.hpp"

using namespace oxen;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network::file_server {

namespace {

    constexpr auto FILE_SERVER_HOST = "filev2.getsession.org"sv;
    constexpr auto FILE_SERVER_PUBKEY_HEX =
            "da21e1d886c6fbaea313f75298bd64aab03a97ce985b46bb2dad9f2089c8ee59"sv;

    constexpr auto ENDPOINT_FILE = "file";
}  // namespace

Request upload(
        std::vector<unsigned char> data,
        std::optional<std::string> file_name,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout) {
    return {"UL-{}"_format(random::random_base32(4)),
            ServerDestination{
                    "http",                         // protocol
                    std::string{FILE_SERVER_HOST},  // host
                    x25519_pubkey::from_hex(FILE_SERVER_PUBKEY_HEX),
                    80,            // port
                    std::nullopt,  // headers (Network will add them)
                    "POST"         // method
            },
            ENDPOINT_FILE,
            std::move(data),
            RequestCategory::file,
            request_timeout,
            overall_timeout,
            UploadInfo{std::move(file_name)}};
}

Request download(
        std::string file_id,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout) {
    return {"DL-{}"_format(random::random_base32(4)),
            ServerDestination{
                    "http",                         // protocol
                    std::string{FILE_SERVER_HOST},  // host
                    x25519_pubkey::from_hex(FILE_SERVER_PUBKEY_HEX),
                    80,            // port
                    std::nullopt,  // headers (Network will add them)
                    "GET"          // method
            },
            "{}/{}"_format(ENDPOINT_FILE, file_id),
            std::nullopt,
            RequestCategory::file,
            request_timeout,
            overall_timeout};
}

Request get_client_version(
        Platform platform,
        network::ed25519_seckey seckey,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout) {
    std::string endpoint;

    switch (platform) {
        case Platform::android: endpoint = "/session_version?platform=android"; break;
        case Platform::desktop: endpoint = "/session_version?platform=desktop"; break;
        case Platform::ios: endpoint = "/session_version?platform=ios"; break;
    }

    // Generate the auth signature
    auto blinded_keys = blind_version_key_pair(to_span(seckey.view()));
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                             (std::chrono::system_clock::now()).time_since_epoch())
                             .count();
    auto signature = blind_version_sign(to_span(seckey.view()), platform, timestamp);
    auto pubkey = x25519_pubkey::from_hex(FILE_SERVER_PUBKEY_HEX);
    std::string blinded_pk_hex;
    blinded_pk_hex.reserve(66);
    blinded_pk_hex += "07";
    oxenc::to_hex(
            blinded_keys.first.begin(),
            blinded_keys.first.end(),
            std::back_inserter(blinded_pk_hex));

    auto headers = std::vector<std::pair<std::string, std::string>>{};
    headers.emplace_back("X-FS-Pubkey", blinded_pk_hex);
    headers.emplace_back("X-FS-Timestamp", "{}"_format(timestamp));
    headers.emplace_back("X-FS-Signature", oxenc::to_base64(signature.begin(), signature.end()));

    return {"GCV-{}"_format(random::random_base32(4)),
            ServerDestination{
                    "http",                         // protocol
                    std::string{FILE_SERVER_HOST},  // host
                    x25519_pubkey::from_hex(FILE_SERVER_PUBKEY_HEX),
                    80,  // port
                    headers,
                    "GET"  // method
            },
            std::move(endpoint),
            std::nullopt,
            RequestCategory::file_small,
            request_timeout,
            overall_timeout};
}

}  // namespace session::network::file_server

extern "C" {

using namespace session;
using namespace session::network;

LIBSESSION_C_API session_request_params* session_file_server_upload(
        const unsigned char* data,
        size_t data_len,
        const char* file_name,
        int64_t request_timeout_ms,
        int64_t overall_timeout_ms) {
    try {
        auto req = file_server::upload(
                {data, data + data_len},
                (file_name ? std::optional{std::string{file_name}} : std::nullopt),
                std::chrono::milliseconds{request_timeout_ms},
                (overall_timeout_ms > 0
                         ? std::optional{std::chrono::milliseconds{overall_timeout_ms}}
                         : std::nullopt));

        return session::network::detail::convert_cpp_request_to_c(req);
    } catch (...) {
        return nullptr;
    }
}

LIBSESSION_C_API session_request_params* session_file_server_download(
        const char* file_id, int64_t request_timeout_ms, int64_t overall_timeout_ms) {
    try {
        auto req = file_server::download(
                file_id,
                std::chrono::milliseconds{request_timeout_ms},
                (overall_timeout_ms > 0
                         ? std::optional{std::chrono::milliseconds{overall_timeout_ms}}
                         : std::nullopt));

        return session::network::detail::convert_cpp_request_to_c(req);
    } catch (...) {
        return nullptr;
    }
}

LIBSESSION_C_API session_request_params* session_file_server_get_client_version(
        CLIENT_PLATFORM platform,
        const unsigned char* ed25519_secret, /* 64 bytes */
        int64_t request_timeout_ms,
        int64_t overall_timeout_ms) {
    try {
        auto req = file_server::get_client_version(
                static_cast<Platform>(platform),
                network::ed25519_seckey::from_bytes({ed25519_secret, 64}),
                std::chrono::milliseconds{request_timeout_ms},
                (overall_timeout_ms > 0
                         ? std::optional{std::chrono::milliseconds{overall_timeout_ms}}
                         : std::nullopt));

        return session::network::detail::convert_cpp_request_to_c(req);
    } catch (...) {
        return nullptr;
    }
}

}  // extern "C"