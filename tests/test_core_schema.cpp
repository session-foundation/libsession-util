#include <catch2/catch_test_macros.hpp>
#include <session/core.hpp>

#include "test_helper.hpp"
#include "test_schema_registry.hpp"

using namespace session;
using namespace session::core;

namespace {

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
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_schema", 7));
    std::filesystem::remove(path);

    {
        Core core{path, schema_extension{"testext", session::test::schema::MIGRATIONS}};

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
        Core core{path, schema_extension{"testext", session::test::schema::MIGRATIONS}};
        CHECK(table_exists(core, "ext_thing"));
    }

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST_CASE("schema_extension: rejects unusable owners", "[core][schema]") {
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_schema", 7));
    std::filesystem::remove(path);

    CHECK_THROWS_AS(
            Core(path, schema_extension{"", session::test::schema::MIGRATIONS}),
            std::invalid_argument);
    CHECK_THROWS_AS(
            Core(path, schema_extension{"has:colon", session::test::schema::MIGRATIONS}),
            std::invalid_argument);
    // Two sets under one owner would let their names collide.
    CHECK_THROWS_AS(
            Core(path,
                 schema_extension{"dup", session::test::schema::MIGRATIONS},
                 schema_extension{"dup", session::test::schema::MIGRATIONS}),
            std::invalid_argument);

    std::error_code ec;
    std::filesystem::remove(path, ec);
}
