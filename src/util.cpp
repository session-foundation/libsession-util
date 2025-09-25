#include <zstd.h>

#include <charconv>
#include <memory>
#include <session/util.hpp>

namespace session {

std::vector<std::string_view> split(std::string_view str, const std::string_view delim, bool trim) {
    std::vector<std::string_view> results;
    // Special case for empty delimiter: splits on each character boundary:
    if (delim.empty()) {
        results.reserve(str.size());
        for (size_t i = 0; i < str.size(); i++)
            results.emplace_back(str.data() + i, 1);
        return results;
    }

    for (size_t pos = str.find(delim); pos != std::string_view::npos; pos = str.find(delim)) {
        if (!trim || !results.empty() || pos > 0)
            results.push_back(str.substr(0, pos));
        str.remove_prefix(pos + delim.size());
    }
    if (!trim || str.size())
        results.push_back(str);
    else
        while (!results.empty() && results.back().empty())
            results.pop_back();
    return results;
}

std::tuple<std::string, std::string, std::optional<uint16_t>, std::optional<std::string>> parse_url(
        std::string_view url) {
    std::tuple<std::string, std::string, std::optional<uint16_t>, std::optional<std::string>>
            result{};
    auto& [proto, host, port, path] = result;
    if (auto pos = url.find("://"); pos != std::string::npos) {
        auto proto_name = url.substr(0, pos);
        url.remove_prefix(proto_name.size() + 3);
        if (string_iequal(proto_name, "http"))
            proto = "http://";
        else if (string_iequal(proto_name, "https"))
            proto = "https://";
    }
    if (proto.empty())
        throw std::invalid_argument{"Invalid URL: invalid/missing protocol://"};

    bool next_allow_dot = false;
    bool has_dot = false;
    while (!url.empty()) {
        auto c = url.front();
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || c == '-') {
            host += c;
            next_allow_dot = true;
        } else if (c >= 'A' && c <= 'Z') {
            host += c + ('a' - 'A');
            next_allow_dot = true;
        } else if (next_allow_dot && c == '.') {
            host += '.';
            has_dot = true;
            next_allow_dot = false;
        } else {
            break;
        }
        url.remove_prefix(1);
    }
    if (host.size() < 4 || !has_dot || host.back() == '.')
        throw std::invalid_argument{"Invalid URL: invalid hostname"};

    if (!url.empty() && url.front() == ':') {
        url.remove_prefix(1);
        uint16_t target_port;
        if (auto [p, ec] = std::from_chars(url.data(), url.data() + url.size(), target_port);
            ec == std::errc{})
            url.remove_prefix(p - url.data());
        else
            throw std::invalid_argument{"Invalid URL: invalid port"};
        if (!(target_port == 80 && proto == "http://") && !(target_port == 443 && proto == "https:/"
                                                                                           "/"))
            port = target_port;
    }

    if (url.size() > 1 && url.front() == '/')
        path = url;
    else if (!url.empty() && url.front() == '/') {
        url.remove_prefix(1);
        path = std::nullopt;
    }

    return result;
}

static_assert(std::is_same_v<
              std::chrono::seconds,
              decltype(std::declval<std::chrono::sys_seconds>().time_since_epoch())>);

namespace {
    struct zstd_decomp_freer {
        void operator()(ZSTD_DStream* z) const { ZSTD_freeDStream(z); }
    };

    using zstd_decomp_ptr = std::unique_ptr<ZSTD_DStream, zstd_decomp_freer>;
}  // namespace

std::vector<unsigned char> zstd_compress(
        std::span<const unsigned char> data, int level, std::span<const unsigned char> prefix) {
    std::vector<unsigned char> compressed;
    if (prefix.empty())
        compressed.resize(ZSTD_compressBound(data.size()));
    else {
        compressed.resize(prefix.size() + ZSTD_compressBound(data.size()));
        std::copy(prefix.begin(), prefix.end(), compressed.begin());
    }
    auto size = ZSTD_compress(
            compressed.data() + prefix.size(),
            compressed.size() - prefix.size(),
            data.data(),
            data.size(),
            level);
    if (ZSTD_isError(size))
        throw std::runtime_error{"Compression failed: " + std::string{ZSTD_getErrorName(size)}};

    compressed.resize(prefix.size() + size);
    return compressed;
}

std::optional<std::vector<unsigned char>> zstd_decompress(
        std::span<const unsigned char> data, size_t max_size) {
    zstd_decomp_ptr z_decompressor{ZSTD_createDStream()};
    auto* zds = z_decompressor.get();

    ZSTD_initDStream(zds);
    ZSTD_inBuffer input{/*.src=*/data.data(), /*.size=*/data.size(), /*.pos=*/0};
    std::array<unsigned char, 4096> out_buf;
    ZSTD_outBuffer output{/*.dst=*/out_buf.data(), /*.size=*/out_buf.size(), /*.pos=*/0};

    std::vector<unsigned char> decompressed;

    size_t ret;
    do {
        output.pos = 0;
        if (ret = ZSTD_decompressStream(zds, &output, &input); ZSTD_isError(ret))
            return std::nullopt;

        if (max_size > 0 && decompressed.size() + output.pos > max_size)
            return std::nullopt;

        decompressed.insert(decompressed.end(), out_buf.begin(), out_buf.begin() + output.pos);
    } while (ret > 0 || input.pos < input.size);

    return decompressed;
}
}  // namespace session
