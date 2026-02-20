#include "session/network/backends/session_file_server.hpp"

#include <fmt/ranges.h>
#include <oxenc/base64.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "../session_network_internal.hpp"
#include "session/blinding.hpp"
#include "session/network/backends/session_file_server.h"
#include "session/random.hpp"

#if defined(__APPLE__) || !defined(__cpp_lib_chrono) || __cpp_lib_chrono < 201907L || \
        (defined(_LIBCPP_VERSION) && _LIBCPP_VERSION < 190000)
#include <date/date.h>
namespace chrono_for_parsing = date;
#else
namespace chrono_for_parsing = std::chrono;
#endif

using namespace oxen;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network::file_server {

const config::FileServer DEFAULT_CONFIG = {
        .scheme = "http",
        .host = "filev2.getsession.org",
        .port = 80,
        .pubkey_hex = "da21e1d886c6fbaea313f75298bd64aab03a97ce985b46bb2dad9f2089c8ee59",
        .max_file_size = 10'000'000};

const std::string_view ENDPOINT_FILE = "file";

std::optional<DownloadInfo> parse_download_url(std::string_view url) {
    // Expected format: {scheme}://{host}/file/{file_id}(?:#p={customPubkey})(?:d)
    // Examples:
    //   https://example.com/file/abc123
    //   https://example.com/file/abc123#p=da21e1d886c6fbaea313f75298bd64aab03a97ce985b46bb2dad9f2089c8ee59
    //   https://example.com/file/abc123#d
    //   https://example.com/file/abc123#p=abc123&d
    DownloadInfo info{};

    // Parse scheme
    auto scheme_end = url.find("://");
    if (scheme_end == std::string_view::npos)
        return std::nullopt;

    info.scheme = std::string{url.substr(0, scheme_end)};
    auto rest = url.substr(scheme_end + 3);

    // Parse host
    auto path_start = rest.find('/');
    if (path_start == std::string_view::npos)
        return std::nullopt;

    info.host = std::string{rest.substr(0, path_start)};
    auto path = rest.substr(path_start);

    // Check for /file/ prefix
    if (!path.starts_with(fmt::format("/{}/", ENDPOINT_FILE)))
        return std::nullopt;

    auto file_part = path.substr(ENDPOINT_FILE.size() + 2);  // Skip "/file/"

    // Split on fragment (#)
    auto fragment_pos = file_part.find('#');

    if (fragment_pos == std::string_view::npos) {
        // No fragments
        info.file_id = std::string{file_part};
        info.deterministic = false;
    } else {
        // Has fragments
        info.file_id = std::string{file_part.substr(0, fragment_pos)};
        auto fragments = file_part.substr(fragment_pos + 1);

        // Parse fragments (p=... and/or d)
        for (auto fragment : split(fragments, "&", true)) {
            if (fragment == "d"sv)
                info.deterministic = true;
            else if (
                    fragment.starts_with("p=") && fragment.size() == 66 &&  // 'p=' + pubkey
                    oxenc::is_hex(fragment.substr(2)))
                info.custom_pubkey_hex = fragment.substr(2);
            // else ignore (unknown or invalid fragment)
        }
    }

    return info;
}

std::optional<std::chrono::sys_seconds> parse_http_date(std::string_view date_str) {

    auto t = std::make_optional<std::chrono::sys_seconds>();
    std::istringstream ss{std::string{date_str}};
    ss.imbue(std::locale::classic());
    if (!(ss >> chrono_for_parsing::parse("%a, %d %b %Y %T %Z", *t) >> std::ws) || !ss.eof())
        t.reset();
    return t;
}

Request to_request(
        const std::string& upload_id,
        const config::FileServer& config,
        std::shared_ptr<UploadRequest> upload_request) {
    std::vector<unsigned char> all_data;

    while (true) {
        if (upload_request->is_cancelled())
            throw std::runtime_error{"Request cancelled"};

        auto chunk = upload_request->next_data();

        if (chunk.empty())
            break;

        // Safety check to prevent runaway memory usage
        if (all_data.size() + chunk.size() > config.max_file_size)
            throw std::runtime_error{"File too large"};

        all_data.insert(all_data.end(), chunk.begin(), chunk.end());
    }

    if (all_data.empty())
        throw std::runtime_error{"No data to upload"};

    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back("Content-Type", "application/octet-stream");

    if (upload_request->file_name) {
        headers.emplace_back(
                "Content-Disposition",
                fmt::format("attachment; filename=\"{}\"", *upload_request->file_name));
    } else {
        headers.emplace_back("Content-Disposition", "attachment");
    }

    if (upload_request->ttl)
        headers.emplace_back("X-FS-TTL", fmt::format("{}", *upload_request->ttl));

    return Request{
            upload_id,
            ServerDestination{
                    config.scheme,
                    config.host,
                    x25519_pubkey::from_hex(config.pubkey_hex),
                    config.port,
                    std::move(headers),
                    "POST"},
            std::string{file_server::ENDPOINT_FILE},
            std::move(all_data),
            RequestCategory::file,
            upload_request->request_timeout,
            upload_request->overall_timeout};
}

Request to_request(
        const std::string& download_id,
        const config::FileServer& config,
        std::shared_ptr<DownloadRequest> download_request) {
    auto download_info = file_server::parse_download_url(download_request->download_url);

    if (!download_info)
        throw invalid_url_exception{"Invalid download url"};

    std::string file_id = download_info->file_id;
    std::string scheme = download_info->scheme;
    std::string host = download_info->host;
    std::string pubkey_hex =
            (download_info->custom_pubkey_hex.has_value() ? *download_info->custom_pubkey_hex
                                                          : config.pubkey_hex);

    return Request{
            download_id,
            ServerDestination{
                    std::move(scheme),
                    std::move(host),
                    x25519_pubkey::from_hex(std::move(pubkey_hex)),
                    config.port,
                    std::nullopt,
                    "GET"},
            fmt::format("{}/{}", file_server::ENDPOINT_FILE, file_id),
            std::nullopt,
            RequestCategory::file,
            download_request->request_timeout,
            download_request->overall_timeout};
}

file_metadata parse_upload_response(const std::string& body, size_t upload_size) {
    auto json = nlohmann::json::parse(body);

    if (!json.contains("id") || !json["id"].is_string())
        throw std::runtime_error{"Upload response missing required 'id' field"};

    file_metadata metadata{};
    metadata.id = json["id"].get<std::string>();
    metadata.size = json.value("size", 0);

    if (metadata.size == 0)
        metadata.size = upload_size;

    if (json.contains("uploaded") && json["uploaded"].is_number()) {
        auto uploaded = json["uploaded"].get<int64_t>();
        metadata.uploaded = std::chrono::system_clock::time_point(std::chrono::seconds(uploaded));
    }

    if (json.contains("expires") && json["expires"].is_number()) {
        auto expiry = json["expires"].get<int64_t>();
        metadata.expiry = std::chrono::system_clock::time_point(std::chrono::seconds(expiry));
    }

    return metadata;
}

std::pair<file_metadata, std::vector<unsigned char>> parse_download_response(
        std::string_view download_url,
        const std::vector<std::pair<std::string, std::string>>& headers,
        const std::string& body) {
    auto download_info = parse_download_url(download_url);
    if (!download_info)
        throw invalid_url_exception{"Could not retrieve file_id"};

    file_metadata metadata{};
    metadata.id = download_info->file_id;

    for (const auto& [key, value] : headers) {
        if (key == "content-length") {
            int64_t size;

            if (quic::parse_int(value, size))
                metadata.size = std::stoll(value);
        } else if (key == "expires") {
            if (auto expiry_time = parse_http_date(value))
                metadata.expiry = *expiry_time;
        }
    }

    std::vector<unsigned char> data(body.begin(), body.end());

    if (metadata.size == 0)
        metadata.size = data.size();

    return {std::move(metadata), std::move(data)};
}

// TODO: [BEFORE RELEASE] Might be good to add in the new "expire" endpoint as well (and any others)
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
    auto pubkey = x25519_pubkey::from_hex(DEFAULT_CONFIG.pubkey_hex);
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
                    DEFAULT_CONFIG.scheme,
                    DEFAULT_CONFIG.host,
                    pubkey,
                    DEFAULT_CONFIG.port,
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

LIBSESSION_C_API bool download_url_requires_deterministic_decryption(const char* url) {
    if (auto info = file_server::parse_download_url(url))
        return info->deterministic;
    return false;
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
