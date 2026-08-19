#include <catch2/catch_test_macros.hpp>
#include <session/clock.hpp>

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

TEST_CASE("from_epoch helpers are the inverse of epoch_seconds/epoch_ms", "[clock]") {
    using namespace std::chrono;
    using namespace session;

    // Round-trip through epoch_seconds / from_epoch_s
    auto t_s = clock_now_s();
    int64_t count_s = epoch_seconds(t_s);
    auto t_s2 = from_epoch_s(count_s);
    CHECK(t_s == t_s2);

    // Round-trip through epoch_ms / from_epoch_ms
    auto t_ms = clock_now_ms();
    int64_t count_ms = epoch_ms(t_ms);
    auto t_ms2 = from_epoch_ms(count_ms);
    CHECK(t_ms == t_ms2);

    // Generic from_epoch with seconds precision
    int64_t unix_s = 1'700'000'000;
    auto tp_s = from_epoch_s(unix_s);
    CHECK(epoch_seconds(tp_s) == unix_s);

    // Generic from_epoch with milliseconds precision
    int64_t unix_ms = 1'700'000'000'000LL;
    auto tp_ms = from_epoch_ms(unix_ms);
    CHECK(epoch_ms(tp_ms) == unix_ms);

    // from_epoch<T> template returns sys_time<T>
    auto tp_generic = from_epoch<seconds>(unix_s);
    static_assert(std::same_as<decltype(tp_generic), sys_seconds>);
    CHECK(epoch_seconds(tp_generic) == unix_s);
}