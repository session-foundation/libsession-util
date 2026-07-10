#include "session/network/backends/session_open_group_server.hpp"

#include <fmt/ranges.h>
#include <oxenc/base64.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "../session_network_internal.hpp"
#include "session/network/backends/backend_util.hpp"
#include "session/network/backends/session_open_group_server.h"

using namespace oxen;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network::open_group_server {

constexpr std::string_view ENDPOINT_ROOM = "room/{}";
constexpr std::string_view ENDPOINT_FILE = "room/{}/file/{}";

std::optional<DownloadInfo> parse_download_url(std::string_view url) {
    // Expected format: {base_url}/room/{room}/file/{file_id}(?:#d)
    // Examples:
    //   https://example.com/room/file/123
    //   https://example.com/room/file/123#d
    DownloadInfo info{};

    auto match = backends::match_endpoint(ENDPOINT_FILE, url);

    if (!match || match->base.empty() || match->captures.size() != 2)
        return std::nullopt;

    info.room = std::string{match->captures[0]};

    int64_t file_id;

    if (!quic::parse_int(match->captures[1], file_id))
        return std::nullopt;

    info.file_id = file_id;
    info.base_url = match->base;
    info.wants_stream_decryption = false;

    // Parse fragments if present (d)
    auto fragment_pos = url.find('#');
    if (fragment_pos == std::string_view::npos)
        return info;

    auto fragments = url.substr(fragment_pos + 1);

    for (auto fragment : split(fragments, "&", true)) {
        if (fragment == backends::FRAGMENT_STREAM_ENCRYPTION)
            info.wants_stream_decryption = true;
        // else ignore (unknown or invalid fragment)
    }

    return info;
}

std::string generate_download_url(uint64_t file_id, const config::OpenGroupServer& config) {
    auto buf =
            fmt::format("{}/{}", config.base_url, fmt::format(ENDPOINT_FILE, config.room, file_id));

    if (config.use_stream_encryption)
        buf += fmt::format("#{}", backends::FRAGMENT_STREAM_ENCRYPTION);

    return buf;
}

}  // namespace session::network::open_group_server

extern "C" {

using namespace session;
using namespace session::network;

LIBSESSION_C_API bool session_open_group_server_parse_download_url(
        const char* url, open_group_server_parsed_download_url* out) {
    auto info = open_group_server::parse_download_url(url);
    if (!info)
        return false;

    auto copy = [](auto& dest, const std::string& src) {
        auto len = std::min(src.size(), sizeof(dest) - 1);
        std::memcpy(dest, src.c_str(), len);
        dest[len] = '\0';
    };

    copy(out->base_url, info->base_url);
    copy(out->room, info->room);
    out->file_id = info->file_id;
    out->wants_stream_decryption = info->wants_stream_decryption;
    return true;
}

LIBSESSION_C_API bool session_open_group_server_generate_download_url(
        uint64_t file_id,
        const char* base_url,
        const char* room,
        const char* pubkey_hex,
        bool use_stream_encryption,
        char* out_url,
        size_t out_url_len) {
    if (!file_id || !base_url || !room)
        return false;

    auto result = open_group_server::generate_download_url(
            file_id,
            network::config::OpenGroupServer{base_url, room, pubkey_hex, use_stream_encryption});
    if (result.size() >= out_url_len)
        return false;

    std::memcpy(out_url, result.c_str(), result.size() + 1);
    return true;
}

}  // extern "C"
