#include <simdutf.h>

#include <catch2/catch_test_macros.hpp>
#include <session/util.hpp>

static std::vector<char16_t> operator""_utf16(const char* str, size_t len) {
    std::vector<char16_t> out(simdutf::utf16_length_from_utf8(str, len));
    out.resize(simdutf::convert_utf8_to_utf16(str, len, out.data()));
    return out;
}

TEST_CASE("utf16_count_truncated_to_codepoints works", "[util]") {
    // Given simple ASCII string, should return length equal to codepoints requested
    CHECK(session::utf16_count_truncated_to_codepoints("hello_world"_utf16, 11) == 11);

    // Given zero codepoints requested, should return zero length
    CHECK(session::utf16_count_truncated_to_codepoints("hello_world"_utf16, 0) == 0);

    // Given UTF-16 has surrogate pairs, should count them as single codepoints
    CHECK(session::utf16_count_truncated_to_codepoints("hello🎂world"_utf16, 11) == 12);

    // Given UTF-16 has more codepoints than requested, should return length up to that point
    CHECK(session::utf16_count_truncated_to_codepoints("hello🎂world"_utf16, 6) == 7);

    // Given UTF-16 has exactly the requested number of codepoints, should return full length
    CHECK(session::utf16_count_truncated_to_codepoints("hello🎂world"_utf16, 5) == 5);

    // Given UTF-16 has less codepoints than requested, should return full length
    CHECK(session::utf16_count_truncated_to_codepoints("hello🎂world"_utf16, 13) == 12);
}

TEST_CASE("utf16_count works", "[util]") {
    CHECK(session::utf16_count("hello_world"_utf16) == 11);
    CHECK(session::utf16_count("hello🎂world"_utf16) == 11);
    CHECK(session::utf16_count("🎂🎉🎈🎁"_utf16) == 4);
    CHECK(session::utf16_count(""_utf16) == 0);
}