#pragma once

#include <cstdint>
#include <array>

namespace session {
using array_uc32 = std::array<std::uint8_t, 32>;
using array_uc64 = std::array<std::uint8_t, 64>;

namespace config {
    using seqno_t = std::int64_t;
}
}  // namespace session
