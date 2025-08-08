#pragma once

#include <cstdint>
#include <array>

namespace session {
using array_uc32 = std::array<std::uint8_t, 32>;
using array_uc33 = std::array<std::uint8_t, 33>;
using array_uc64 = std::array<std::uint8_t, 64>;

enum class SessionIDPrefix {
    standard = 0,
    group = 0x3,
    community_blinded_legacy = 0x5,
    community_blinded = 0x15,
    version_blinded = 0x25,
    unblinded = 0x7,
};

namespace config {
    using seqno_t = std::int64_t;
}
}  // namespace session
