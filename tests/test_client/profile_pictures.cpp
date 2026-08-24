#include <nettle/gcm.h>
#include <session/attachments.hpp>
#include <session/network/backends/session_file_server.hpp>
#include <session/random.hpp>

#include "../../src/client/download_cache.hpp"
#include "config_helpers.hpp"

namespace cache = session::client::cache;

namespace {

// Encrypts as a client did before the stream scheme: AES-256-GCM, nonce prepended, tag appended.
// Written here rather than in libsession because nothing of ours produces this format any more --
// it exists only to be read -- and a test that encrypted with our own code would be checking that
// we agree with ourselves.
std::vector<std::byte> gcm_encrypt(
        std::span<const std::byte> plain, std::span<const std::byte, 32> key) {
    std::vector<std::byte> out(12 + plain.size() + 16);
    session::random::fill(std::span{out.data(), 12});

    struct gcm_aes256_ctx ctx;
    gcm_aes256_set_key(&ctx, session::to_unsigned(key.data()));
    gcm_aes256_set_iv(&ctx, 12, session::to_unsigned(out.data()));
    gcm_aes256_encrypt(
            &ctx,
            plain.size(),
            session::to_unsigned(out.data() + 12),
            session::to_unsigned(plain.data()));
    gcm_aes256_digest(&ctx, 16, session::to_unsigned(out.data() + 12 + plain.size()));
    return out;
}

// Gives `them` a picture at `url` with `key`, as another device would have.
void set_picture(
        TempClient& c,
        const std::string& them,
        const std::string& url,
        std::span<const std::byte> key) {
    auto pushed = contacts_from_another_device(*c.client, them, [&](auto& e) {
        e.set_name("Padmé");
        e.profile_picture = config::profile_pic{url, {key.begin(), key.end()}};
    });
    merge_contacts(*c.client, pushed);
}

}  // namespace

TEST_CASE("Client: a stream-encrypted picture round-trips through the cache", "[client][pictures]") {
    TempCacheDir dir;
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> image(9000);
    session::random::fill(image);

    // As a current client uploads one: the stream scheme, with the url saying so.
    auto seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;
    auto [encrypted, key] =
            attachment::encrypt(seed, image, attachment::Domain::PROFILE_PIC);
    net->served["pic1"] = encrypted;
    auto url = network::file_server::generate_download_url("pic1", {}, true);

    auto them = "05" + std::string(64, 'a');
    set_picture(c, them, url, key);
    auto id = dm_from_hex(them);

    std::vector<std::optional<int>> progress;
    std::optional<std::vector<std::byte>> got;
    std::optional<std::string> err;
    c->profile_picture(
            id,
            [&](int64_t, int64_t, std::optional<int> r) { progress.push_back(r); },
            [&](std::optional<std::string> e, auto pic) {
                err = std::move(e);
                got = std::move(pic);
            });

    // The fetch is posted to the loop, so let it get as far as asking before answering it.
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);

    REQUIRE_FALSE(err.has_value());
    REQUIRE(got);
    CHECK(*got == image);

    // Watched from start to finish: the 0/0 that says it began, and the terminal 0 that says it
    // arrived.
    REQUIRE(progress.size() >= 2);
    CHECK_FALSE(progress.front().has_value());
    CHECK(progress.back() == 0);

    // It landed in the cache under the url, not under the url plus its fragment.
    auto file = cache::path_for(dir.path, cache::PROFILE_DIR, url);
    CHECK(std::filesystem::exists(file));

    // ...and the second ask is served from there: no download, and no progress reported, since
    // there is nothing to watch.
    progress.clear();
    got.reset();
    c->profile_picture(
            id,
            [&](int64_t, int64_t, std::optional<int> r) { progress.push_back(r); },
            [&](std::optional<std::string> e, auto pic) {
                err = std::move(e);
                got = std::move(pic);
            });
    sync(*c);

    CHECK(net->downloads.empty());
    REQUIRE(got);
    CHECK(*got == image);
    CHECK(progress.empty());
}

TEST_CASE("Client: a picture from before the stream scheme still opens", "[client][pictures]") {
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    std::vector<std::byte> image(2000);
    session::random::fill(image);

    b32 key;
    session::random::fill(key);
    net->served["pic2"] = gcm_encrypt(image, key);

    // No `d` fragment, which is what says "not the stream scheme" -- and for a display picture that
    // means GCM rather than the legacy *attachment* scheme, which is the distinction this exists to
    // check.  Nothing in the bytes says which.
    auto url = network::file_server::generate_download_url("pic2", {}, false);

    auto them = "05" + std::string(64, 'd');
    set_picture(c, them, url, key);

    std::optional<std::vector<std::byte>> got;
    std::optional<std::string> err;
    c->profile_picture(dm_from_hex(them), [&](std::optional<std::string> e, auto pic) {
        err = std::move(e);
        got = std::move(pic);
    });

    // The fetch is posted to the loop, so let it get as far as asking before answering it.
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);

    REQUIRE_FALSE(err.has_value());
    REQUIRE(got);
    CHECK(*got == image);
}

TEST_CASE("Client: a picture that will not decrypt is an error, not an absence",
          "[client][pictures]") {
    TempCacheDir dir;
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> image(500);
    session::random::fill(image);

    b32 key, wrong;
    session::random::fill(key);
    session::random::fill(wrong);
    net->served["pic3"] = gcm_encrypt(image, key);
    auto url = network::file_server::generate_download_url("pic3", {}, false);

    auto them = "05" + std::string(64, 'e');
    set_picture(c, them, url, wrong);

    std::optional<std::vector<std::byte>> got;
    std::optional<std::string> err;
    bool called = false;
    c->profile_picture(dm_from_hex(them), [&](std::optional<std::string> e, auto pic) {
        err = std::move(e);
        got = std::move(pic);
        called = true;
    });

    // The fetch is posted to the loop, so let it get as far as asking before answering it.
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);

    REQUIRE(called);
    // The difference that matters to a viewer: an empty pane because there is no picture, versus a
    // broken one because we could not read it.
    CHECK(err.has_value());
    CHECK_FALSE(got.has_value());

    // And nothing was cached, so asking again tries again rather than serving the failure forever.
    CHECK_FALSE(std::filesystem::exists(cache::path_for(dir.path, cache::PROFILE_DIR, url)));
}
