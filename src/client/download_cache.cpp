#include "download_cache.hpp"

#include <oxen/log.hpp>
#include <oxenc/hex.h>
#include <session/attachments.hpp>
#include <session/format.hpp>
#include <session/hash.hpp>
#include <session/random.hpp>

#include <cstring>
#include <fstream>

namespace session::client::cache {

namespace log = oxen::log;
static auto cat = log::Cat("client");

namespace {

std::string_view base_url(std::string_view url) {
    if (auto q = url.find_first_of("?#"); q != std::string_view::npos)
        url = url.substr(0, q);
    return url;
}

}  // namespace

std::filesystem::path path_for(
        const std::filesystem::path& dir, std::string_view kind, std::string_view url) {
    auto h = hash::blake2b<32>(base_url(url));
    return dir / kind / oxenc::to_hex(h.begin(), h.end());
}

std::optional<std::vector<std::byte>> read(
        const std::filesystem::path& file, std::span<const std::byte, 32> key) {
    std::error_code ec;
    if (!std::filesystem::exists(file, ec))
        return std::nullopt;

    try {
        std::ifstream in{file, std::ios::binary | std::ios::ate};
        in.exceptions(std::ios::failbit | std::ios::badbit);

        std::vector<std::byte> encrypted(static_cast<size_t>(in.tellg()));
        in.seekg(0);
        in.read(
                reinterpret_cast<char*>(encrypted.data()),
                static_cast<std::streamsize>(encrypted.size()));

        return attachment::decrypt(encrypted, key);
    } catch (const std::exception& e) {
        // A cache that cannot answer is a cache miss; the caller fetches instead.  Removed because
        // nothing else ever would: it is not referenced by anything that could notice it is bad.
        log::warning(cat, "Discarding unreadable cache entry {}: {}", file.string(), e.what());
        std::filesystem::remove(file, ec);
        return std::nullopt;
    }
}

void write(
        const std::filesystem::path& file,
        std::span<const std::byte, 32> key,
        std::span<const std::byte> data) {
    std::filesystem::create_directories(file.parent_path());

    // Unique, so two writes of the same url cannot land on one temporary and interleave.
    auto tmp = file;
    tmp += "{}{}"_format(random::unique_id("-", 8), PARTIAL_SUFFIX);

    {
        std::ofstream out{tmp, std::ios::binary | std::ios::trunc};
        out.exceptions(std::ios::failbit | std::ios::badbit);

        attachment::Encryptor enc{key};
        size_t pos = 0;
        enc.start_encryption(
                [&](std::span<std::byte> buf) -> size_t {
                    auto n = std::min(buf.size(), data.size() - pos);
                    std::memcpy(buf.data(), data.data() + pos, n);
                    pos += n;
                    return n;
                },
                true,
                data.size());

        for (auto chunk = enc.next(); !chunk.empty(); chunk = enc.next())
            out.write(
                    reinterpret_cast<const char*>(chunk.data()),
                    static_cast<std::streamsize>(chunk.size()));
    }

    // Atomic: the finished name never exists holding a partial file, so a reader either misses or
    // gets the whole thing.
    std::filesystem::rename(tmp, file);
}

std::vector<std::string> list(const std::filesystem::path& dir, std::string_view kind) {
    std::vector<std::string> names;

    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator{dir / kind, ec}) {
        auto name = entry.path().filename().string();
        // A download still running is not garbage, it is unfinished, and unlinking it mid-write
        // would make the fetch fail for a reason nothing could explain.
        if (name.ends_with(PARTIAL_SUFFIX))
            continue;
        names.push_back(std::move(name));
    }
    return names;
}

bool remove(const std::filesystem::path& dir, std::string_view kind, std::string_view name) {
    std::error_code ec;
    return std::filesystem::remove(dir / kind / name, ec);
}

}  // namespace session::client::cache
