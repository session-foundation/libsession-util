#include <sodium/randombytes.h>

#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <session/attachments.hpp>
#include <session/network/backends/session_file_server.hpp>
#include <session/network/session_network.hpp>
#include <session/sodium_array.hpp>
#include <session/util.hpp>

#include "live_utils.hpp"

using namespace session;
using namespace std::literals;

// Default timeout for live network operations.
static constexpr auto LIVE_TIMEOUT = 60s;

// These tests require a QUIC file server and only work under --srouter or --direct mode
// (not --onionreq, which cannot support the QUIC file server protocol).

TEST_CASE("Live: file upload via QUIC", "[live][file]") {
    // Skip if running under onion request mode (no QUIC support)
    // Works under all routing modes: --srouter and --direct use the QUIC file server protocol,
    // --onionreq falls back to the legacy HTTP proxy path.

    auto core = make_live_core();
    auto net = core->network();
    REQUIRE(net);

    // Generate small test data and encrypt it
    std::vector<std::byte> plaintext(4096);
    randombytes_buf(plaintext.data(), plaintext.size());

    auto seed_acc = core->globals.account_seed();
    auto seed = seed_acc.seed();
    auto [encrypted, key] = attachment::encrypt(
            std::span<const std::byte>{
                    reinterpret_cast<const std::byte*>(seed.data()), seed.size()},
            plaintext,
            attachment::Domain::ATTACHMENT,
            true);

    // Upload
    std::promise<std::variant<network::file_metadata, int16_t>> promise;
    auto future = promise.get_future();

    network::UploadRequest req;
    req.request_timeout = 30s;
    req.overall_timeout = LIVE_TIMEOUT;

    bool consumed = false;
    req.next_data = [&]() -> std::vector<std::byte> {
        if (consumed)
            return {};
        consumed = true;
        return {encrypted.begin(), encrypted.end()};
    };
    req.ttl = 1min;
    req.on_complete = [&](auto result, bool) { promise.set_value(std::move(result)); };

    net->upload(std::move(req));

    REQUIRE(future.wait_for(LIVE_TIMEOUT) == std::future_status::ready);
    auto result = future.get();
    REQUIRE(std::holds_alternative<network::file_metadata>(result));

    auto& meta = std::get<network::file_metadata>(result);
    CHECK(!meta.id.empty());
    CHECK(meta.size > 0);
}

TEST_CASE("Live: streaming file upload via upload_file", "[live][file]") {
    auto core = make_live_core();
    auto net = core->network();
    REQUIRE(net);

    // Write test data to a temp file
    auto tmp = std::filesystem::temp_directory_path() / "upload_file_test.dat";
    {
        std::vector<std::byte> plaintext(8192);
        randombytes_buf(plaintext.data(), plaintext.size());
        std::ofstream f{tmp, std::ios::binary};
        REQUIRE(f);
        f.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    }

    std::array<std::byte, 32> seed;
    randombytes_buf(seed.data(), seed.size());

    std::promise<std::variant<std::pair<network::file_metadata, session::cleared_b32>, int16_t>>
            promise;
    auto future = promise.get_future();

    network::FileUploadRequest req;
    req.file = tmp;
    req.domain = attachment::Domain::ATTACHMENT;
    req.allow_large = true;
    req.ttl = 1min;
    req.request_timeout = 30s;
    req.overall_timeout = LIVE_TIMEOUT;
    req.on_complete = [&](auto result, bool) { promise.set_value(std::move(result)); };

    net->upload_file(std::move(req), seed);

    REQUIRE(future.wait_for(LIVE_TIMEOUT) == std::future_status::ready);
    auto result = future.get();

    std::filesystem::remove(tmp);

    using pair_t = std::pair<network::file_metadata, session::cleared_b32>;
    REQUIRE(std::holds_alternative<pair_t>(result));

    auto& [meta, key] = std::get<pair_t>(result);
    CHECK(!meta.id.empty());
    CHECK(meta.size > 0);
    CHECK(!key.empty());
}

TEST_CASE("Live: file upload and download round-trip via QUIC", "[live][file]") {
    // Works under all routing modes: --srouter and --direct use the QUIC file server protocol,
    // --onionreq falls back to the legacy HTTP proxy path.

    auto core = make_live_core();
    auto net = core->network();
    REQUIRE(net);

    // Generate test data
    std::vector<std::byte> plaintext(16384);
    randombytes_buf(plaintext.data(), plaintext.size());

    auto seed_acc = core->globals.account_seed();
    auto seed = seed_acc.seed();
    auto [encrypted, key] = attachment::encrypt(
            std::span<const std::byte>{
                    reinterpret_cast<const std::byte*>(seed.data()), seed.size()},
            plaintext,
            attachment::Domain::ATTACHMENT,
            true);

    // Upload
    std::promise<std::variant<network::file_metadata, int16_t>> upload_promise;
    auto upload_future = upload_promise.get_future();

    network::UploadRequest upload_req;
    upload_req.request_timeout = 30s;
    upload_req.overall_timeout = LIVE_TIMEOUT;

    bool consumed = false;
    upload_req.next_data = [&]() -> std::vector<std::byte> {
        if (consumed)
            return {};
        consumed = true;
        return {encrypted.begin(), encrypted.end()};
    };
    upload_req.ttl = 1min;
    upload_req.on_complete = [&](auto result, bool) {
        upload_promise.set_value(std::move(result));
    };

    net->upload(std::move(upload_req));

    REQUIRE(upload_future.wait_for(LIVE_TIMEOUT) == std::future_status::ready);
    auto upload_result = upload_future.get();
    REQUIRE(std::holds_alternative<network::file_metadata>(upload_result));
    auto& upload_meta = std::get<network::file_metadata>(upload_result);

    // Download
    auto download_url =
            network::file_server::generate_download_url(upload_meta.id, net->file_server_config);

    std::promise<std::variant<network::file_metadata, int16_t>> download_promise;
    auto download_future = download_promise.get_future();
    std::vector<std::byte> downloaded_data;

    network::DownloadRequest download_req;
    download_req.download_url = download_url;
    download_req.request_timeout = 30s;
    download_req.overall_timeout = LIVE_TIMEOUT;
    download_req.on_data = [&](auto&, std::span<const std::byte> data) {
        downloaded_data.insert(downloaded_data.end(), data.begin(), data.end());
    };
    download_req.on_complete = [&](auto result, bool) {
        download_promise.set_value(std::move(result));
    };

    net->download(std::move(download_req));

    REQUIRE(download_future.wait_for(LIVE_TIMEOUT) == std::future_status::ready);
    auto download_result = download_future.get();
    REQUIRE(std::holds_alternative<network::file_metadata>(download_result));

    // Decrypt and verify
    auto decrypted = attachment::decrypt(std::span<const std::byte>{downloaded_data}, key);
    REQUIRE(decrypted.size() == plaintext.size());
    CHECK(decrypted == plaintext);
}
