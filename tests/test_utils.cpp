#include <catch2/catch_test_macros.hpp>

#include "utils.hpp"

TEST_CASE("Network", "[network][parse_url]") {
    auto [proto1, host1, port1, path1] = session::parse_url("HTTPS://example.com/test");
    auto [proto2, host2, port2, path2] = session::parse_url("http://example2.com:1234/test/123456");
    auto [proto3, host3, port3, path3] = session::parse_url("https://example3.com");
    auto [proto4, host4, port4, path4] = session::parse_url("https://example4.com/test?value=test");

    CHECK(proto1 == "https://");
    CHECK(proto2 == "http://");
    CHECK(proto3 == "https://");
    CHECK(proto4 == "https://");
    CHECK(host1 == "example.com");
    CHECK(host2 == "example2.com");
    CHECK(host3 == "example3.com");
    CHECK(host4 == "example4.com");
    CHECK(port1.value_or(9999) == 9999);
    CHECK(port2.value_or(9999) == 1234);
    CHECK(port3.value_or(9999) == 9999);
    CHECK(port4.value_or(9999) == 9999);
    CHECK(path1.value_or("NULL") == "/test");
    CHECK(path2.value_or("NULL") == "/test/123456");
    CHECK(path3.value_or("NULL") == "NULL");
    CHECK(path4.value_or("NULL") == "/test?value=test");
}