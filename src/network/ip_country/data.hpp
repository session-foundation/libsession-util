#pragma once

#include <cstdint>
#include <session/network/ip_country.hpp>
#include <span>
#include <string_view>

namespace session::ip_country::detail {

/// The bundled database, as a tiling of the IPv4 space: `range_starts()` holds the first address of
/// each range in ascending order and `range_codes()` the country of each, so a range runs until the
/// next one starts and no end column is needed.  Both are empty when built without
/// `WITH_IP_GEOLOCATION`, which is what makes every lookup a miss in that build without the lookup
/// code itself knowing anything about the option.
///
/// Exactly one of `data.cpp` and `no_data.cpp` is compiled in, chosen by that option.  `data.cpp`
/// is not in git: `utils/update-ip-country-db.py` downloads a DB-IP release and generates it, and
/// cmake refuses to configure with the option on until it has been run.

/// First address of each range, ascending, starting at 0.0.0.0.  This is the only array a lookup
/// binary searches; the table's size rests on `ipv4` being nothing but its uint32_t.
static_assert(sizeof(ipv4) == sizeof(uint32_t));
std::span<const ipv4> range_starts();

/// Country of the range at the same index in `range_starts()`, as an index into
/// `country_codes()`; index 0 means unassigned or reserved.
///
/// The uint8_t element caps the code table at 256 entries (246 are in use).  Widening it is a
/// change to this type, to the array in the generated data, and to the generator's own check.
std::span<const uint8_t> range_codes();

/// The country code table that `range_codes()` indexes: two-letter ISO 3166-1 alpha-2 codes,
/// sorted, with the empty "unknown" code at index 0.
std::span<const std::string_view> country_codes();

/// The attribution required by the database's licence, empty when no database is bundled.
std::string_view attribution();

/// The bundled release, e.g. "dbip-country-lite-2026-09", empty when no database is bundled.
std::string_view database_version();

}  // namespace session::ip_country::detail
