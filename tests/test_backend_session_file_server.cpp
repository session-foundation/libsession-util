#include <fmt/format.h>

#include <catch2/catch_test_macros.hpp>
#include <session/network/backends/session_file_server.hpp>

#include "utils.hpp"

using namespace session::network;

TEST_CASE("Download url parsing", "[backend][session_file_server]") {

    auto parsed_download_url = file_server::parse_download_url("https://example.com/file/abc123"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->custom_pubkey_hex.has_value());
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Strips a trailing forward slash from the file_id
    parsed_download_url = file_server::parse_download_url("https://example.com/file/abc123/"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->custom_pubkey_hex.has_value());
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Identifies that the url wants stream-based decryption
    parsed_download_url = file_server::parse_download_url("https://example.com/file/abc123/#d"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->custom_pubkey_hex.has_value());
    CHECK(parsed_download_url->wants_stream_decryption);

    // Extracts the custom pubkey
    parsed_download_url = file_server::parse_download_url(
            "https://example.com/file/abc123#p=0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK(parsed_download_url->custom_pubkey_hex ==
          "0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Ignores the pubkey if it matches the default one
    parsed_download_url = file_server::parse_download_url(fmt::format(
            "https://example.com/file/abc123#p={}"sv, file_server::DEFAULT_CONFIG.pubkey_hex));
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->custom_pubkey_hex.has_value());
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Handles both fragments
    parsed_download_url = file_server::parse_download_url(
            "https://example.com/file/abc123#p=0123456789abcdef0123456789abcdef00000000000000000000000000000000&d"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK(parsed_download_url->custom_pubkey_hex ==
          "0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    CHECK(parsed_download_url->wants_stream_decryption);

    // Handles both fragments in the opposite order
    parsed_download_url = file_server::parse_download_url(
            "https://example.com/file/abc123#d&p=0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK(parsed_download_url->custom_pubkey_hex ==
          "0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    CHECK(parsed_download_url->wants_stream_decryption);

    // Doesn't have an issue with a legacy url
    parsed_download_url = file_server::parse_download_url(
            "http://filev2.getsession.org/files/2478430809375318"sv);
    CHECK(parsed_download_url.has_value());

    // Doesn't have an issue with a url that isn't in the right format
    parsed_download_url = file_server::parse_download_url("https://example.com/test/test2"sv);
    CHECK_FALSE(parsed_download_url.has_value());
}

TEST_CASE("Download url generation", "[backend][session_file_server]") {
    auto url = file_server::generate_download_url(
            "abc123"sv,
            {"http",
             "example.com",
             123,
             "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
             12345,
             true});
    CHECK(url ==
          "http://example.com/file/"
          "abc123#p=0123456789abcdef0123456789abcdef00000000000000000000000000000000&d");

    // Omits the stream encryption fragment when disabled
    url = file_server::generate_download_url(
            "abc123"sv,
            {"http",
             "example.com",
             123,
             "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
             12345,
             false});
    CHECK(url ==
          "http://example.com/file/"
          "abc123#p=0123456789abcdef0123456789abcdef00000000000000000000000000000000");

    // Omits the pubkey when it matches the default pubkey
    url = file_server::generate_download_url(
            "abc123"sv,
            {"http", "example.com", 123, file_server::DEFAULT_CONFIG.pubkey_hex, 12345, true});
    CHECK(url == "http://example.com/file/abc123#d");

    // Omits all fragments when stream encryption is disabled and the default pubkey is used
    url = file_server::generate_download_url(
            "abc123"sv,
            {"http", "example.com", 123, file_server::DEFAULT_CONFIG.pubkey_hex, 12345, false});
    CHECK(url == "http://example.com/file/abc123");

    // Works with other values
    url = file_server::generate_download_url(
            "12345678"sv,
            {"https", "example2.com", 321, file_server::DEFAULT_CONFIG.pubkey_hex, 54321, false});
    CHECK(url == "https://example2.com/file/12345678");
}