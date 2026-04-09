#include <fmt/format.h>

#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <span>
#include <vector>

#include "session/formattable.hpp"
#include "utils.hpp"

TEST_CASE("byte span formatting - default hex", "[formattable]") {
    CHECK(fmt::format("{}", "abcd0123"_hex_b) == "abcd0123");
    CHECK(fmt::format("{:x}", "abcd0123"_hex_b) == "abcd0123");
}

TEST_CASE("byte span formatting - various types", "[formattable]") {
    auto arr = "deadbeef"_hex_b;

    SECTION("std::span with static extent") {
        CHECK(fmt::format("{}", arr) == "deadbeef");
    }

    SECTION("std::span with dynamic extent") {
        std::span<const std::byte> sp{arr};
        CHECK(fmt::format("{}", sp) == "deadbeef");
    }

    SECTION("std::vector") {
        std::vector<std::byte> vec{arr.begin(), arr.end()};
        CHECK(fmt::format("{}", vec) == "deadbeef");
    }

    SECTION("std::array") {
        std::array<std::byte, 4> a;
        std::copy(arr.begin(), arr.end(), a.begin());
        CHECK(fmt::format("{}", a) == "deadbeef");
    }
}

TEST_CASE("byte span formatting - empty span", "[formattable]") {
    std::span<const std::byte> empty;
    CHECK(fmt::format("{}", empty) == "");
    CHECK(fmt::format("{:x}", empty) == "");
    CHECK(fmt::format("{:z}", empty) == "0");
    // Note: empty base64 is skipped due to an oxenc bug producing "=" for empty input
    CHECK(fmt::format("{:a}", empty) == "");
    CHECK(fmt::format("{:r}", empty) == "");
}

TEST_CASE("byte span formatting - stripped hex", "[formattable]") {
    SECTION("all zeros") {
        CHECK(fmt::format("{:z}", "00000000"_hex_b) == "0");
    }

    SECTION("leading zeros stripped") {
        CHECK(fmt::format("{:z}", "00001234"_hex_b) == "1234");
    }

    SECTION("leading zero nibble stripped") {
        CHECK(fmt::format("{:z}", "000abc"_hex_b) == "abc");
    }

    SECTION("no leading zeros") {
        CHECK(fmt::format("{:z}", "ff01"_hex_b) == "ff01");
    }

    SECTION("single non-zero byte with leading nibble zero") {
        CHECK(fmt::format("{:z}", "0002"_hex_b) == "2");
    }
}

TEST_CASE("byte span formatting - base32z", "[formattable]") {
    auto val = "0001020304"_hex_b;
    auto hex_result = fmt::format("{:x}", val);
    auto b32z_result = fmt::format("{:a}", val);
    CHECK(hex_result == "0001020304");
    CHECK(!b32z_result.empty());
    CHECK(b32z_result != hex_result);
}

TEST_CASE("byte span formatting - base64", "[formattable]") {
    CHECK(fmt::format("{:b}", "00010203"_hex_b) == "AAECAw==");
    CHECK(fmt::format("{:B}", "00010203"_hex_b) == "AAECAw");
}

TEST_CASE("byte span formatting - raw", "[formattable]") {
    CHECK(fmt::format("{:r}", "6869"_hex_b) == "hi");
}

TEST_CASE("byte span formatting - ellipsis", "[formattable]") {
    // 8 bytes = 16 hex chars: "0123456789abcdef"
    auto val = "0123456789abcdef"_hex_b;
    CHECK(fmt::format("{}", val) == "0123456789abcdef");

    SECTION("truncation with tail") {
        // 10 display chars: 7 leading + ellipsis + 2 trailing
        CHECK(fmt::format("{:10.2}", val) == "0123456…ef");
    }

    SECTION("no truncation when value fits") {
        CHECK(fmt::format("{:20.4}", val) == "0123456789abcdef");
    }

    SECTION("ellipsis with explicit mode") {
        CHECK(fmt::format("{:10.2x}", val) == "0123456…ef");
    }

    SECTION("tail of zero") {
        CHECK(fmt::format("{:5.0}", val) == "0123…");
    }

    SECTION("minimum ellipsis") {
        CHECK(fmt::format("{:2.0}", val) == "0…");
    }
}

TEST_CASE("byte span formatting - 32 byte key ellipsis", "[formattable]") {
    auto key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"_hex_b;
    auto full = fmt::format("{}", key);
    CHECK(full.size() == 64);

    // Ellipsize to 12 display chars with 4-char tail:
    // 7 leading + 3 bytes UTF-8 ellipsis + 4 trailing = 14 bytes
    auto ellipsized = fmt::format("{:12.4}", key);
    CHECK(ellipsized == "0102030…1f20");
    CHECK(ellipsized.size() == 7 + 3 + 4);
}

TEST_CASE("byte span formatting - format errors", "[formattable]") {
    auto val = "01"_hex_b;

    // Use fmt::runtime() to bypass compile-time format string checking
    CHECK_THROWS_AS(fmt::format(fmt::runtime("{:0}"), val), fmt::format_error);
    CHECK_THROWS_AS(fmt::format(fmt::runtime("{:5}"), val), fmt::format_error);
    CHECK_THROWS_AS(fmt::format(fmt::runtime("{:q}"), val), fmt::format_error);
    CHECK_THROWS_AS(fmt::format(fmt::runtime("{:xx}"), val), fmt::format_error);
    CHECK_THROWS_AS(fmt::format(fmt::runtime("{:3.3}"), val), fmt::format_error);
    CHECK_THROWS_AS(fmt::format(fmt::runtime("{:1.0}"), val), fmt::format_error);
}

TEST_CASE("byte span formatting - _format UDL", "[formattable]") {
    using namespace session::literals;
    auto val = "deadbeef"_hex_b;
    CHECK("key: {}"_format(val) == "key: deadbeef");
    CHECK("key: {:z}"_format(val) == "key: deadbeef");
}
