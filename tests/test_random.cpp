#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <limits>

#include "session/random.h"
#include "session/random.hpp"
#include "utils.hpp"

TEST_CASE("Random generation", "[random][random]") {
    auto rand1 = session::random::random(10);
    auto rand2 = session::random::random(10);
    auto rand3 = session::random::random(20);

    CHECK(rand1.size() == 10);
    CHECK(rand2.size() == 10);
    CHECK(rand3.size() == 20);
    CHECK(rand1 != rand2);
}

TEST_CASE("Random uniform distribution", "[random][uniform]") {
    CHECK(session::random::get_uniform_distribution<int>(7, 7) == 7);
    CHECK(session::random::get_uniform_distribution<int>(9, 3) == 9);
    CHECK_NOTHROW(session::random::get_uniform_distribution<uint64_t>(
            0, std::numeric_limits<uint64_t>::max()));
    CHECK_NOTHROW(session::random::get_uniform_distribution<int64_t>(
            std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max()));

    for (int i = 0; i < 1000; ++i) {
        const auto signed_value = session::random::get_uniform_distribution<int>(-5, 5);
        CHECK(signed_value >= -5);
        CHECK(signed_value <= 5);

        const auto unsigned_value = session::random::get_uniform_distribution<size_t>(0, 10);
        CHECK(unsigned_value <= 10);
    }
}
