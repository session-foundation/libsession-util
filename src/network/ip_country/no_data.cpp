#include "data.hpp"

// The database compiled in when WITH_IP_GEOLOCATION is off: an empty one, so that lookups miss
// rather than the API disappearing.  See data.hpp.

namespace session::ip_country::detail {

std::span<const ipv4> range_starts() {
    return {};
}

std::span<const uint8_t> range_codes() {
    return {};
}

std::span<const std::string_view> country_codes() {
    return {};
}

std::string_view attribution() {
    return {};
}

std::string_view database_version() {
    return {};
}

}  // namespace session::ip_country::detail
