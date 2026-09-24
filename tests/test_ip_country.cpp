#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <oxen/log/format.hpp>
#include <session/network/ip_country.hpp>

#include "../src/network/ip_country/data.hpp"

using namespace session::ip_country;
using namespace oxen::log::literals;

namespace {

// The country a range's code index means, i.e. what a lookup anywhere in that range must return.
std::optional<std::string_view> country_of(uint8_t code) {
    if (code == 0)
        return std::nullopt;
    return detail::country_codes()[code];
}

}  // namespace

TEST_CASE("ip-to-country database shape", "[ip_country]") {
    auto starts = detail::range_starts();
    auto codes = detail::range_codes();
    auto table = detail::country_codes();

    REQUIRE(starts.size() == codes.size());
    REQUIRE(available() == !starts.empty());

    if (!available()) {
        // Built without WITH_IP_GEOLOCATION, so there is nothing to check the shape of beyond its
        // being consistently empty; the lookups themselves are exercised below either way.
        CHECK(table.empty());
        CHECK(attribution().empty());
        CHECK(database_version().empty());
        return;
    }

    CHECK_FALSE(attribution().empty());
    CHECK_FALSE(database_version().empty());

    // Index 0 is the unknown slot rather than a country; the rest are alpha-2 codes.
    REQUIRE(table.size() >= 2);
    CHECK(table[0].empty());

    for (size_t i = 1; i < table.size(); i++) {
        auto cc = table[i];
        if (cc.size() != 2 ||
            !std::ranges::all_of(cc, [](char c) { return c >= 'A' && c <= 'Z'; })) {
            FAIL("code table entry " << i << " (" << cc << ") is not an alpha-2 country code");
            break;
        }
    }

    // A lookup finds the range a search lands in and stops, so the table has to start at 0.0.0.0
    // and ascend; anything else silently mislabels the addresses below the first entry.
    CHECK(starts.front() == ipv4{0, 0, 0, 0});

    size_t out_of_order = 0, bad_code = 0, unmerged = 0;
    for (size_t i = 0; i < starts.size(); i++) {
        if (i > 0 && !(starts[i - 1] < starts[i]))
            out_of_order++;
        if (codes[i] >= table.size())
            bad_code++;
        // Not a correctness requirement, but the generator merges neighbours with the same country,
        // so a run of them means it stopped doing its job.
        if (i > 0 && codes[i - 1] == codes[i])
            unmerged++;
    }
    CHECK(out_of_order == 0);
    CHECK(bad_code == 0);
    CHECK(unmerged == 0);

    // The codes are numbered by descending range count (ties alphabetical), which is what keeps the
    // generated source small and its month-to-month diff shallow.  Recount them and check the
    // numbering still follows, since a generator that quietly stopped sorting would cost both.
    std::vector<size_t> ranges_per_country(table.size(), 0);
    for (auto code : codes)
        ranges_per_country[code]++;

    for (size_t i = 2; i < table.size(); i++) {
        auto prev = ranges_per_country[i - 1], cur = ranges_per_country[i];
        if (prev < cur || (prev == cur && !(table[i - 1] < table[i]))) {
            FAIL("country " << table[i] << " (" << cur << " ranges) is numbered after "
                            << table[i - 1] << " (" << prev << " ranges)");
            break;
        }
    }
}

TEST_CASE("ip-to-country range boundaries", "[ip_country]") {
    auto starts = detail::range_starts();
    auto codes = detail::range_codes();

    if (!available()) {
        // Every lookup misses, which is the whole point of the empty database: a client needs no
        // #ifdef of its own.
        CHECK_FALSE(lookup(ipv4{1, 1, 1, 1}));
        CHECK_FALSE(lookup(ipv4{"95.216.0.0"}));
        CHECK_FALSE(lookup(ipv4{0, 0, 0, 0}));
        CHECK_FALSE(lookup(ipv4{255, 255, 255, 255}));
        return;
    }

    // Walk a sample of ranges spread across the table, checking each one's first and last address
    // and the first address of the next range: an off-by-one in the search shows up as a range
    // bleeding into its neighbour.
    size_t step = std::max<size_t>(1, starts.size() / 500);
    size_t mismatches = 0;
    std::string first_failure;
    auto check = [&](ipv4 ip, std::optional<std::string_view> expected) {
        auto got = lookup(ip);
        if (got == expected)
            return;
        mismatches++;
        if (first_failure.empty())
            first_failure = "{} gave {} rather than {}"_format(
                    ip.to_string(), got.value_or("(unknown)"), expected.value_or("(unknown)"));
    };

    for (size_t i = 0; i < starts.size(); i += step) {
        auto expected = country_of(codes[i]);
        check(starts[i], expected);

        // The range runs until the next one starts, or to the top of the address space for the
        // last one.
        ipv4 last = i + 1 < starts.size() ? ipv4{starts[i + 1].addr - 1} : ipv4{255, 255, 255, 255};
        check(last, expected);
        if (i + 1 < starts.size())
            check(starts[i + 1], country_of(codes[i + 1]));
    }

    INFO(first_failure);
    CHECK(mismatches == 0);
}

TEST_CASE("ip-to-country reserved space", "[ip_country]") {
    if (!available())
        return;

    // DB-IP labels space that belongs to no country -- 0.0.0.0/8, the RFC1918 blocks, loopback,
    // link-local, multicast and up -- with its ZZ marker, which the generator folds into the
    // unknown code.  This is the code == 0 path.
    CHECK_FALSE(lookup(ipv4{"0.0.0.0"}));
    CHECK_FALSE(lookup(ipv4{"10.0.0.1"}));
    CHECK_FALSE(lookup(ipv4{"127.0.0.1"}));
    CHECK_FALSE(lookup(ipv4{"169.254.1.1"}));
    CHECK_FALSE(lookup(ipv4{"192.168.1.1"}));
    CHECK_FALSE(lookup(ipv4{"255.255.255.255"}));
}

TEST_CASE("ip-to-country smoke test against the bundled snapshot", "[ip_country]") {
    if (!available())
        return;

    // Unlike everything above, this asserts what the data says rather than how the lookup works,
    // so it can legitimately fail after a refresh: Hetzner's Helsinki space is about as stable an
    // anchor as free geo data offers, but if this is what breaks, check the new snapshot and move
    // the anchor rather than treating it as a bug.
    CHECK(lookup(ipv4{"95.216.0.0"}) == "FI");
    CHECK(lookup(ipv4{"95.216.33.113"}) == "FI");
}
