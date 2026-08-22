#include <session/random.hpp>

#include <fstream>

#include "../../src/client/download_cache.hpp"
#include "common.hpp"

namespace cache = session::client::cache;

namespace {

// A temporary directory that removes itself, so a failing assertion cannot leave one behind.
struct TempDir {
    std::filesystem::path path{
            std::filesystem::temp_directory_path() /
            fmt::format("{}", session::random::unique_id("test_cache", 8))};

    TempDir() { std::filesystem::create_directories(path); }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

b32 a_key() {
    b32 k;
    session::random::fill(k);
    return k;
}

}  // namespace

TEST_CASE("Cache: a url names one file, whatever is hung off it", "[client][cache]") {
    TempDir dir;

    auto base = cache::path_for(dir.path, cache::PROFILE_DIR, "http://fs.example/file/1234");
    auto fragment = cache::path_for(
            dir.path, cache::PROFILE_DIR, "http://fs.example/file/1234#pubkey=abcdef");
    auto query =
            cache::path_for(dir.path, cache::PROFILE_DIR, "http://fs.example/file/1234?v=2");

    // The bytes at the base url are the bytes; a fragment says how to reach and unpack them, and a
    // query string is not part of which file this is.
    CHECK(base == fragment);
    CHECK(base == query);

    // A different file is a different entry.
    CHECK(base != cache::path_for(dir.path, cache::PROFILE_DIR, "http://fs.example/file/5678"));

    // And the two kinds do not share a directory, so a sweep of one cannot see the other's files.
    CHECK(base != cache::path_for(dir.path, cache::ATTACHMENT_DIR, "http://fs.example/file/1234"));

    // The name is a hash, not the url: usable as a filename whatever the url looked like.
    CHECK(base.filename().string().size() == 64);
    CHECK(base.filename().string().find('/') == std::string::npos);
}

TEST_CASE("Cache: what goes in comes back out", "[client][cache]") {
    TempDir dir;
    auto key = a_key();
    auto file = cache::path_for(dir.path, cache::PROFILE_DIR, "http://fs.example/file/1");

    CHECK_FALSE(cache::read(file, key).has_value());

    std::vector<std::byte> data(5000);
    session::random::fill(data);
    cache::write(file, key, data);

    REQUIRE(std::filesystem::exists(file));
    auto got = cache::read(file, key);
    REQUIRE(got);
    CHECK(*got == data);

    // On disk it is not the plaintext: the file is bigger than what went in (header, macs, padding)
    // and does not contain it.
    auto on_disk = std::filesystem::file_size(file);
    CHECK(on_disk > data.size());

    // Another key does not open it, and the unreadable entry is dropped rather than left to fail
    // forever.
    auto other = a_key();
    CHECK_FALSE(cache::read(file, other).has_value());
    CHECK_FALSE(std::filesystem::exists(file));
}

TEST_CASE("Cache: a corrupted entry is a miss, not a throw", "[client][cache]") {
    TempDir dir;
    auto key = a_key();
    auto file = cache::path_for(dir.path, cache::ATTACHMENT_DIR, "http://fs.example/file/2");

    std::vector<std::byte> data(100);
    session::random::fill(data);
    cache::write(file, key, data);

    {
        std::ofstream out{file, std::ios::binary | std::ios::app};
        out << "rubbish";
    }

    CHECK_FALSE(cache::read(file, key).has_value());
    CHECK_FALSE(std::filesystem::exists(file));
}

TEST_CASE("Cache: sweeping keeps what is still referenced", "[client][cache]") {
    TempDir dir;
    auto key = a_key();

    std::vector<std::byte> data(64);
    session::random::fill(data);

    std::string kept = "http://fs.example/file/keep";
    std::string dropped = "http://fs.example/file/drop";
    cache::write(cache::path_for(dir.path, cache::PROFILE_DIR, kept), key, data);
    cache::write(cache::path_for(dir.path, cache::PROFILE_DIR, dropped), key, data);

    // A download still running: no url references it yet, and unlinking it would fail the fetch for
    // a reason nothing could explain.
    auto partial = cache::path_for(dir.path, cache::PROFILE_DIR, "http://fs.example/file/busy");
    partial += "-abcdefgh";
    partial += std::string{cache::PARTIAL_SUFFIX};
    {
        std::ofstream out{partial, std::ios::binary};
        out << "half a file";
    }

    // The referencing url carries a fragment, as a stored one may: it still has to match.
    CHECK(cache::sweep(dir.path, cache::PROFILE_DIR, {kept + "#pubkey=aa"}) == 1);

    CHECK(std::filesystem::exists(cache::path_for(dir.path, cache::PROFILE_DIR, kept)));
    CHECK_FALSE(std::filesystem::exists(cache::path_for(dir.path, cache::PROFILE_DIR, dropped)));
    CHECK(std::filesystem::exists(partial));

    // Sweeping again has nothing left to do.
    CHECK(cache::sweep(dir.path, cache::PROFILE_DIR, {kept}) == 0);

    // Sweeping a kind with nothing referenced empties it; a directory that does not exist is not an
    // error.
    CHECK(cache::sweep(dir.path, cache::PROFILE_DIR, {}) == 1);
    CHECK(cache::sweep(dir.path, cache::ATTACHMENT_DIR, {}) == 0);
}
