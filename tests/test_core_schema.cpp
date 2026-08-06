#include <catch2/catch_test_macros.hpp>
#include <session/core.hpp>

#include "test_helper.hpp"

using namespace session;
using namespace session::core;

namespace {

int ext_applied = 0;

void apply_ext_table(sqlite::Connection& conn, Core&) {
    ext_applied++;
    conn.prepared_exec("CREATE TABLE ext_thing (id INTEGER PRIMARY KEY NOT NULL) STRICT");
}

// Deliberately shares a name with one of Core's own migrations: the owner prefix is what has to
// keep them apart.
void apply_colliding_name(sqlite::Connection& conn, Core&) {
    conn.prepared_exec("CREATE TABLE ext_globals (id INTEGER PRIMARY KEY NOT NULL) STRICT");
}

const std::array ext_migrations{
        schema::Migration{"000_ext_thing", &apply_ext_table},
        schema::Migration{"000_globals", &apply_colliding_name},
};

bool table_exists(Core& core, std::string_view name) {
    return TestHelper::db_conn(core)
            .prepared_maybe_get<std::string>(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", name)
            .has_value();
}

}  // namespace

TEST_CASE(
        "schema_extension: migrations are applied and recorded under the owner prefix",
        "[core][schema]") {
    ext_applied = 0;
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_schema", 7));
    std::filesystem::remove(path);

    {
        Core core{path, schema_extension{"testext", ext_migrations}};

        CHECK(ext_applied == 1);
        CHECK(table_exists(core, "ext_thing"));
        // Core's own 000_globals must still have run despite the extension reusing the name.
        CHECK(table_exists(core, "globals"));
        CHECK(table_exists(core, "ext_globals"));

        CHECK(TestHelper::migration_applied(core, "testext:000_ext_thing"));
        CHECK(TestHelper::migration_applied(core, "testext:000_globals"));
        CHECK(TestHelper::migration_applied(core, "000_globals"));
        CHECK(!TestHelper::migration_applied(core, "000_ext_thing"));
    }

    // Reopening must not re-apply them.
    {
        Core core{path, schema_extension{"testext", ext_migrations}};
        CHECK(ext_applied == 1);
        CHECK(table_exists(core, "ext_thing"));
    }

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST_CASE("schema_extension: rejects unusable owners", "[core][schema]") {
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_schema", 7));
    std::filesystem::remove(path);

    CHECK_THROWS_AS(Core(path, schema_extension{"", ext_migrations}), std::invalid_argument);
    CHECK_THROWS_AS(
            Core(path, schema_extension{"has:colon", ext_migrations}), std::invalid_argument);
    // Two sets under one owner would let their names collide.
    CHECK_THROWS_AS(
            Core(path,
                 schema_extension{"dup", ext_migrations},
                 schema_extension{"dup", ext_migrations}),
            std::invalid_argument);

    std::error_code ec;
    std::filesystem::remove(path, ec);
}
