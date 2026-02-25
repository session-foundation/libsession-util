#include <fmt/format.h>

#include <catch2/catch_test_macros.hpp>
#include <session/network/backends/session_open_group_server.hpp>

#include "utils.hpp"

using namespace session::network;

TEST_CASE("Download url parsing", "[backend][session_open_group_server]") {

    auto parsed_download_url =
            open_group_server::parse_download_url("https://example.com/room/test/file/abc123"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->base_url == "https://example.com"sv);
    CHECK(parsed_download_url->room == "test"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Strips a trailing forward slash from the file_id
    parsed_download_url =
            open_group_server::parse_download_url("https://example.com/room/test/file/abc123/"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->base_url == "https://example.com"sv);
    CHECK(parsed_download_url->room == "test"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Identifies that the url wants stream-based decryption
    parsed_download_url =
            open_group_server::parse_download_url("https://example.com/room/test/file/abc123/#d"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->base_url == "https://example.com"sv);
    CHECK(parsed_download_url->room == "test"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK(parsed_download_url->wants_stream_decryption);

    // Maintains the room casing
    parsed_download_url =
            open_group_server::parse_download_url("https://example.com/room/TeST/file/abc123"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->base_url == "https://example.com"sv);
    CHECK(parsed_download_url->room == "TeST"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);
}

TEST_CASE("Download url generation", "[backend][session_open_group_server]") {
    auto url = open_group_server::generate_download_url(
            "abc123"sv,
            {"https://example.com",
             "test",
             "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
             true});
    CHECK(url == "https://example.com/room/test/file/abc123#d");

    // Omits the stream encryption fragment when disabled
    url = open_group_server::generate_download_url(
            "abc123"sv,
            {"https://example.com",
             "test",
             "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
             false});
    CHECK(url == "https://example.com/room/test/file/abc123");

    // Maintains the case of the room
    url = open_group_server::generate_download_url(
            "abc123"sv,
            {"https://example.com",
             "TeST",
             "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
             true});
    CHECK(url == "https://example.com/room/TeST/file/abc123#d");
}