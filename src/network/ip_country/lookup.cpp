#include <algorithm>
#include <session/network/ip_country.hpp>

#include "data.hpp"

namespace session::ip_country {

bool available() {
    return !detail::range_starts().empty();
}

std::optional<std::string_view> lookup(oxen::quic::ipv4 ip) {
    auto starts = detail::range_starts();
    auto next = std::ranges::upper_bound(starts, ip);
    // The table tiles the whole address space from 0.0.0.0 up, so the only way not to land in a
    // range is for there to be no ranges at all, i.e. a build without the bundled database.
    if (next == starts.begin())
        return std::nullopt;

    auto code = detail::range_codes()[next - starts.begin() - 1];
    if (code == 0)
        return std::nullopt;

    return detail::country_codes()[code];
}

std::string_view attribution() {
    return detail::attribution();
}

std::string_view database_version() {
    return detail::database_version();
}

}  // namespace session::ip_country
