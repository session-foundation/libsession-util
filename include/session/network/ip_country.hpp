#pragma once

#include <optional>
#include <oxen/quic/ip.hpp>
#include <string_view>

namespace session::ip_country {

using ipv4 = oxen::quic::ipv4;

/// API: ip_country/available
///
/// Whether this build of libsession-util carries a bundled IP-to-country database, i.e. whether it
/// was built with the `WITH_IP_GEOLOCATION` cmake option.  When it is false the database is empty
/// and every lookup returns nullopt, so a client compiles and runs identically either way and needs
/// no preprocessor test of its own.
///
/// Outputs:
/// - `bool` -- true if a database is bundled.
bool available();

/// API: ip_country/lookup
///
/// Looks up the country an IPv4 address is assigned to.
///
/// Inputs:
/// - `ip` -- the address.  `ipv4` (i.e. `oxen::quic::ipv4`) constructs from a string ("1.2.3.4"),
///   from an `in_addr`, or from octets, and is what `service_node::ip` already holds.
///
/// Outputs:
/// - `std::optional<std::string_view>` -- the ISO 3166-1 alpha-2 country code, or nullopt if the
///   address is in unassigned or reserved space, or if no database is bundled.  The view points at
///   static storage, so it stays valid forever.
std::optional<std::string_view> lookup(ipv4 ip);

/// API: ip_country/attribution
///
/// The credit that the bundled database's licence (CC BY 4.0) requires be displayed wherever its
/// results are.  Show this, rather than composing your own, so that every Session client credits it
/// identically.
///
/// Outputs:
/// - `std::string_view` -- the attribution line, or empty when no database is bundled (in which
///   case there is nothing to attribute).
std::string_view attribution();

/// API: ip_country/database_version
///
/// The bundled database's release, e.g. "dbip-country-lite-2026-09".  The snapshot is refreshed by
/// hand (see `utils/update-ip-country-db.py`), so this is how a client reports which vintage it
/// resolved an address against.
///
/// Outputs:
/// - `std::string_view` -- the release identifier, or empty when no database is bundled.
std::string_view database_version();

}  // namespace session::ip_country
