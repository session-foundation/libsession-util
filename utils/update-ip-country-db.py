#!/usr/bin/env python3

"""Refreshes the bundled IP-to-country database.

Downloads a DB-IP Country Lite CSV release and generates src/network/ip_country/data.cpp from it,
which is the translation unit compiled in when libsession-util is built with
-DWITH_IP_GEOLOCATION=ON.  The generated file is neither committed (it is several megabytes of
tables) nor fetched during a build, so run this before configuring with that option, and again
whenever the snapshot is due a refresh; cmake fails with these instructions if it is missing.

    utils/update-ip-country-db.py                     # current release
    utils/update-ip-country-db.py --month 2026-08     # a specific one
    utils/update-ip-country-db.py --csv dbip.csv.gz   # one already downloaded

DB-IP Lite is CC BY 4.0: redistribution is permitted with attribution, and unlike MaxMind's GeoLite2
there is no clause requiring the copy to stay current, so a stale bundled snapshot is a quality
question rather than a licensing one.
"""

import argparse
import collections
import datetime
import gzip
import io
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

DOWNLOAD_URL = "https://download.db-ip.com/free/{release}.csv.gz"
LANDING_PAGE = "https://db-ip.com/db/download/ip-to-country-lite"
ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com)"
USER_AGENT = "libsession-util update-ip-country-db"

# range_codes[] in data.hpp is uint8_t, so index 0 (unknown) plus the codes must fit in 256.
MAX_CODES = 256

CC_RE = re.compile(r"^[A-Z]{2}$")

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO / "src" / "network" / "ip_country" / "data.cpp"


def release_name(month):
    return f"dbip-country-lite-{month}"


def download(month):
    """Fetches a release, falling back to the previous month when the current one isn't out yet."""
    months = [month] if month else []
    if not months:
        today = datetime.date.today()
        months = [
            today.strftime("%Y-%m"),
            (today.replace(day=1) - datetime.timedelta(days=1)).strftime("%Y-%m"),
        ]

    for m in months:
        url = DOWNLOAD_URL.format(release=release_name(m))
        print(f"Fetching {url}", file=sys.stderr)
        # Cloudflare fronts the download and 403s urllib's default User-Agent, so send our own.
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request) as resp:
                return m, resp.read()
        except urllib.error.HTTPError as e:
            if e.code != 404 or m == months[-1]:
                raise
            print(f"  {m} not published yet, trying the previous month", file=sys.stderr)

    raise RuntimeError("no release found")


def parse(csv_bytes):
    """Reads the CSV into (start, end, cc) IPv4 rows, sorted, and the count of IPv6 rows skipped."""
    if csv_bytes[:2] == b"\x1f\x8b":
        csv_bytes = gzip.decompress(csv_bytes)

    rows = []
    skipped_v6 = 0
    for lineno, line in enumerate(io.StringIO(csv_bytes.decode()), 1):
        line = line.strip()
        if not line:
            continue
        try:
            start, end, cc = line.split(",")
        except ValueError:
            raise ValueError(f"line {lineno}: expected 'start,end,cc', got {line!r}")
        if ":" in start:
            skipped_v6 += 1
            continue
        rows.append((ip_to_int(start, lineno), ip_to_int(end, lineno), cc))

    rows.sort()
    return rows, skipped_v6


def ip_to_int(addr, lineno):
    octets = addr.split(".")
    if len(octets) != 4:
        raise ValueError(f"line {lineno}: {addr!r} is not an IPv4 address")
    value = 0
    for octet in octets:
        n = int(octet)
        if not 0 <= n <= 255:
            raise ValueError(f"line {lineno}: {addr!r} is not an IPv4 address")
        value = value << 8 | n
    return value


def tile(rows):
    """Turns the rows into the start-only tiling that data.cpp stores.

    The table covers the whole address space so that a lookup needs no end column: a range runs
    until the next start.  DB-IP's rows already tile it, but gaps are filled with the unknown code
    and adjacent same-country ranges merged in case a future release stops doing so.
    """
    tiles = []  # (start, cc), with "" for unknown

    def add(start, cc):
        if tiles and tiles[-1][1] == cc:
            return
        tiles.append((start, cc))

    position = 0
    for start, end, cc in rows:
        if start < position:
            raise ValueError(f"overlapping range at {start:#010x}")
        if start > position:
            add(position, "")
        # ZZ is DB-IP's marker for space it has no country for, which is our unknown slot.
        add(start, "" if cc == "ZZ" else cc)
        position = end + 1

    if position <= 0xFFFFFFFF:
        add(position, "")

    counts = collections.Counter(cc for _, cc in tiles if cc)
    for cc in counts:
        if not CC_RE.match(cc):
            raise ValueError(f"{cc!r} is not an ISO 3166-1 alpha-2 country code")
    if len(counts) + 1 > MAX_CODES:
        raise ValueError(
            f"{len(counts) + 1} country codes exceeds the {MAX_CODES} that a uint8_t index holds; "
            "widen range_codes() in src/network/ip_country/data.hpp, the array in data.cpp, and "
            "MAX_CODES here"
        )

    # Numbering by descending range count, ties alphabetical: the countries holding the most ranges
    # get the shortest indices, which takes ~0.4MB off the generated source.  It also keeps one
    # release's table close to the last one's, since the countries that come and go between releases
    # are the rare ones, numbered at the end where nothing follows them to shift.
    code_list = [""] + sorted(counts, key=lambda cc: (-counts[cc], cc))
    codes = {cc: i for i, cc in enumerate(code_list)}

    return [(start, codes[cc]) for start, cc in tiles], code_list


def group_by_16(tiles):
    """Groups the tiles by the /16 their start falls in, keeping them in order.

    Lines in the generated arrays never span a /16, so a refresh that adds or drops a range rewrites
    only that /16's few lines instead of reflowing every line below it, which keeps one release's
    file comparable to the last's.
    """
    groups = []
    for tile in tiles:
        key = tile[0] >> 16
        if not groups or groups[-1][0] != key:
            groups.append((key, []))
        groups[-1][1].append(tile)
    return groups


def columns(groups, per_line, index, formatter=str, label=False):
    """Formats one field of the grouped tiles as indented rows of comma-separated items."""
    out = io.StringIO()
    for key, tiles in groups:
        for i in range(0, len(tiles), per_line):
            row = ", ".join(formatter(t[index]) for t in tiles[i : i + per_line])
            # The addresses say where they are; the bare code indices need telling.
            prefix = "/*{}.{}*/ ".format(key >> 8, key & 0xFF) if label and i == 0 else ""
            out.write(f"            {prefix}{row},\n")
    return out.getvalue()


def octets(value):
    """An address as an `oxen::quic::ipv4` initializer, e.g. {95,216,0,0}."""
    return "{{{},{},{},{}}}".format(
        value >> 24, value >> 16 & 0xFF, value >> 8 & 0xFF, value & 0xFF
    )


def generate(path, release, tiles, code_list, rows, skipped_v6):
    groups = group_by_16(tiles)
    table_bytes = len(tiles) * 5 + len(code_list) * 2

    cc_lines = "".join(
        "            {},\n".format(", ".join('"{}"sv'.format(cc) for cc in code_list[i : i + 12]))
        for i in range(1, len(code_list), 12)
    )

    with open(path, "w") as out:
        out.write(
            f"""// Generated by utils/update-ip-country-db.py from {release}.csv.gz -- do not edit.
//
// {ATTRIBUTION}, licensed under CC BY 4.0.
// Source: {LANDING_PAGE}
//
// {len(rows)} IPv4 rows in, {len(tiles)} ranges and {len(code_list) - 1} country codes out,
// {table_bytes / 1e6:.2f} MB of .rodata.  {skipped_v6} IPv6 rows were skipped: nothing reads them
// yet, and adding them means a second table rather than a change to this one.
//
// The two range arrays hold plain integers rather than pointers on purpose: a table of pointers
// needs a relocation per entry, which under PIE would turn megabytes of shared, file-backed .rodata
// into dirty private memory at every process start.  The country table is 246 entries, so its
// relocations cost nothing worth avoiding.
//
// A line never spans a /16, and the code indices carry their /16 as a comment, so that a refresh
// that adds or drops a range rewrites those few lines rather than reflowing the whole file, and one
// release's table can be compared against the last's.

// clang-format off
// (utils/format.sh skips this file as well; reflowing a third of a million initializers is neither
// quick nor an improvement.)

#include "data.hpp"

#include <iterator>

namespace session::ip_country::detail {{

using namespace std::literals;

namespace {{

    constexpr ipv4 starts[] = {{
{columns(groups, 6, 0, octets)}    }};

    constexpr uint8_t codes[] = {{
{columns(groups, 20, 1, label=True)}    }};

    // Ordered by how many ranges each country holds, so that the common ones get the shortest
    // indices above and a country appearing or vanishing renumbers as little as possible.
    constexpr std::string_view countries[] = {{
            ""sv,  // index 0: unassigned or reserved
{cc_lines}    }};

    static_assert(std::size(starts) == std::size(codes), "every range needs exactly one country");
    static_assert(
            std::size(countries) <= 256, "codes[] is uint8_t and cannot index more countries");

}}  // namespace

std::span<const ipv4> range_starts() {{
    return starts;
}}

std::span<const uint8_t> range_codes() {{
    return codes;
}}

std::span<const std::string_view> country_codes() {{
    return countries;
}}

std::string_view attribution() {{
    return "{ATTRIBUTION}";
}}

std::string_view database_version() {{
    return "{release}";
}}

}}  // namespace session::ip_country::detail
"""
        )

    print(
        f"Wrote {path} ({path.stat().st_size / 1e6:.1f} MB of source):\n"
        f"  release      {release}\n"
        f"  ranges       {len(tiles)} (from {len(rows)} IPv4 rows, {skipped_v6} IPv6 skipped)\n"
        f"  codes        {len(code_list) - 1}\n"
        f"  compiled     {table_bytes / 1e6:.2f} MB",
        file=sys.stderr,
    )


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--csv", type=Path, help="use this CSV (.csv or .csv.gz) instead of downloading")
    parser.add_argument(
        "--month",
        help="release as YYYY-MM: which one to download, or which one --csv holds when its "
        "filename doesn't say (default: the current one)",
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=DEFAULT_OUTPUT, help=f"where to write (default: {DEFAULT_OUTPUT})"
    )
    args = parser.parse_args()

    if args.csv:
        csv_bytes = args.csv.read_bytes()
        # The release is what the API reports as its version, so it comes from the filename the
        # download hands out rather than being invented here.
        month = args.month or (m.group(1) if (m := re.search(r"\d{4}-\d{2}", args.csv.name)) else None)
        if not month:
            parser.error(
                f"can't tell the release month from {args.csv.name!r}; pass --month YYYY-MM"
            )
        release = release_name(month)
    else:
        month, csv_bytes = download(args.month)
        release = release_name(month)

    rows, skipped_v6 = parse(csv_bytes)
    if not rows:
        raise RuntimeError("no IPv4 rows in the CSV")
    tiles, code_list = tile(rows)
    generate(args.output, release, tiles, code_list, rows, skipped_v6)


if __name__ == "__main__":
    main()
