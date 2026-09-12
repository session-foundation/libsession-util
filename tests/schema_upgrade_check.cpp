/// Checks that a database created from an *older* full_schema.sql upgrades to the current schema.
///
/// full_schema.sql is the only thing that creates a schema; the migrations beside it are deltas
/// from an older full_schema.  So the migration chain cannot be replayed from nothing, and the only
/// starting points that exist are previous versions of full_schema.sql — which live in git history.
/// schema_history_check.sh digs them out and invokes this for each.
///
/// Given those historical files, this builds a database as that version would have, opens it with
/// the current code so any migrations since then run, and compares the result against a database
/// freshly created from today's full_schema.  Those two must agree, or an upgraded install and a
/// new one are running different schemas.
///
///     schema-upgrade-check --core-schema FILE [--client-schema FILE] [--applied KEY]...
///
/// --applied takes fully-qualified names as recorded in migrations_applied ("001_foo" for Core,
/// "client:001_foo" for the extension): the migrations that existed at that revision, which the
/// database of that era would have had recorded.

#include <fmt/format.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <session/client.hpp>
#include <session/core.hpp>
#include <session/random.hpp>
#include <session/sqlite.hpp>
#include <sstream>
#include <string>
#include <vector>

#include "schema_fingerprint.hpp"

namespace {

std::string read_file(const std::filesystem::path& p) {
    std::ifstream f{p, std::ios::binary};
    if (!f)
        throw std::runtime_error{fmt::format("cannot read {}", p.string())};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::filesystem::path temp_db(std::string_view tag) {
    auto p = std::filesystem::temp_directory_path() /
             fmt::format("{}.db", session::random::unique_id(std::string{tag}, 8));
    std::filesystem::remove(p);
    return p;
}

/// Recreates the database an older release would have had: its schema, and the bookkeeping rows
/// recording what it considered applied.  Deliberately does not go through Core, since Core at HEAD
/// would create *today's* schema.
void build_historical_db(
        const std::filesystem::path& path,
        const std::string& core_schema,
        const std::optional<std::string>& client_schema,
        const std::vector<std::string>& applied) {
    session::sqlite::Database db{path};
    auto conn = db.conn();

    session::sqlite::exec_query(
            conn.sql,
            "CREATE TABLE IF NOT EXISTS migrations_applied (name TEXT PRIMARY KEY NOT NULL) "
            "STRICT");

    conn.sql.exec(core_schema);
    conn.prepared_exec("INSERT INTO migrations_applied (name) VALUES (?)", "@created");

    if (client_schema) {
        conn.sql.exec(*client_schema);
        conn.prepared_exec("INSERT INTO migrations_applied (name) VALUES (?)", "client:@created");
    }

    for (const auto& key : applied)
        conn.prepared_exec("INSERT OR IGNORE INTO migrations_applied (name) VALUES (?)", key);
}

}  // namespace

int main(int argc, char** argv) {
    std::optional<std::filesystem::path> core_schema_path, client_schema_path;
    std::vector<std::string> applied;

    for (int i = 1; i < argc; i++) {
        std::string_view arg{argv[i]};
        auto next = [&]() -> std::string {
            if (++i >= argc)
                throw std::runtime_error{fmt::format("{} requires a value", arg)};
            return argv[i];
        };
        if (arg == "--core-schema")
            core_schema_path = next();
        else if (arg == "--client-schema")
            client_schema_path = next();
        else if (arg == "--applied")
            applied.push_back(next());
        else {
            std::cerr << "unrecognised argument: " << arg << "\n";
            return 2;
        }
    }

    if (!core_schema_path) {
        std::cerr << "--core-schema is required\n";
        return 2;
    }

    try {
        auto old_path = temp_db("schema_old");
        auto fresh_path = temp_db("schema_fresh");

        build_historical_db(
                old_path,
                read_file(*core_schema_path),
                client_schema_path ? std::optional{read_file(*client_schema_path)} : std::nullopt,
                applied);

        // Opening with the current code runs whatever migrations that era's database is missing.
        std::string upgraded, fresh;
        {
            session::client::Client c{old_path};
            auto conn = c.core.database().conn();
            upgraded = session::test::schema_fingerprint(conn);
        }
        {
            session::client::Client c{fresh_path};
            auto conn = c.core.database().conn();
            fresh = session::test::schema_fingerprint(conn);
        }

        std::error_code ec;
        std::filesystem::remove(old_path, ec);
        std::filesystem::remove(fresh_path, ec);

        if (upgraded == fresh)
            return 0;

        std::cerr << "schema mismatch after upgrade\n";

        // Reported as a set difference rather than line by line: one missing line would otherwise
        // shift everything after it and report a single fault as dozens.  Both fingerprints are
        // produced by the same function over the same objects, so their line order cannot differ
        // except as a consequence of content differing anyway.
        auto lines = [](const std::string& s) {
            std::vector<std::string> out;
            std::istringstream in{s};
            for (std::string l; std::getline(in, l);)
                out.push_back(l);
            std::ranges::sort(out);
            return out;
        };
        auto up = lines(upgraded), fr = lines(fresh);

        std::vector<std::string> missing, extra;
        std::ranges::set_difference(fr, up, std::back_inserter(missing));
        std::ranges::set_difference(up, fr, std::back_inserter(extra));

        for (const auto& l : missing)
            std::cerr << fmt::format("  missing after upgrade: {}\n", l);
        for (const auto& l : extra)
            std::cerr << fmt::format("  unexpected after upgrade: {}\n", l);
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "schema-upgrade-check failed: " << e.what() << "\n";
        return 1;
    }
}
