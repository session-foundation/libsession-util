#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <session/format.hpp>
#include <session/placeholders.hpp>
#include <session/random.hpp>
#include <session/sqlite.hpp>
#include <string>
#include <vector>

using namespace session;
using namespace session::literals;

namespace {

/// A throwaway unencrypted database with one table, for exercising the bind helpers against real
/// SQLite rather than a mock: what is being tested is which parameter a value lands on, and only
/// SQLite can answer that.
struct TempDb {
    std::filesystem::path path;
    sqlite::Database db;

    TempDb() :
            path{std::filesystem::temp_directory_path() /
                 "{}.db"_format(random::unique_id("test_sqlite", 7))},
            db{path} {
        auto c = db.conn();
        c.sql.exec("CREATE TABLE t (id INTEGER PRIMARY KEY NOT NULL, name TEXT) STRICT");
    }

    ~TempDb() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        std::filesystem::remove(path.string() + "-wal", ec);
        std::filesystem::remove(path.string() + "-shm", ec);
    }
};

}  // namespace

TEST_CASE("sqlite - bind_each", "[sqlite][bind]") {
    TempDb t;
    auto c = t.db.conn();
    for (int i = 1; i <= 6; i++)
        c.prepared_exec("INSERT INTO t (id, name) VALUES (?, ?)", i, "row{}"_format(i));

    auto ids_in = [&](const auto& query, const auto&... bind) {
        std::vector<int64_t> got;
        for (auto&& id : c.prepared_results<int64_t>(query, bind...))
            got.push_back(id);
        return got;
    };

    SECTION("binds a container across a variable-length IN list") {
        std::vector<int64_t> want{2, 4, 5};
        CHECK(ids_in("SELECT id FROM t WHERE id IN ({}) ORDER BY id"_format(
                             sqlite::placeholders(want.size())),
                     sqlite::bind_each{want}) == want);
    }

    SECTION("a single element is not a special case") {
        std::vector<int64_t> want{3};
        CHECK(ids_in("SELECT id FROM t WHERE id IN ({}) ORDER BY id"_format(
                             sqlite::placeholders(want.size())),
                     sqlite::bind_each{want}) == want);
    }

    SECTION("the parameters around it number from where it leaves off") {
        // The point of the running counter: `hi` is the 5th parameter because the sequence consumed
        // three, not the 3rd because it is the third argument.
        std::vector<int64_t> some{1, 2, 6};
        auto got =
                ids_in("SELECT id FROM t WHERE id > ? AND id IN ({}) AND id < ? ORDER BY id"_format(
                               sqlite::placeholders(some.size())),
                       1,
                       sqlite::bind_each{some},
                       6);
        CHECK(got == std::vector<int64_t>{2});
    }

    SECTION("more than one sequence in the same call") {
        std::vector<int64_t> lo{1, 2, 3}, hi{3, 4, 5};
        auto got =
                ids_in("SELECT id FROM t WHERE id IN ({}) AND id IN ({}) ORDER BY id"_format(
                               sqlite::placeholders(lo.size()), sqlite::placeholders(hi.size())),
                       sqlite::bind_each{lo},
                       sqlite::bind_each{hi});
        CHECK(got == std::vector<int64_t>{3});
    }

    SECTION("an iterator pair binds part of a container") {
        std::vector<int64_t> all{2, 4, 5, 6};
        auto got = ids_in(
                "SELECT id FROM t WHERE id IN ({}) ORDER BY id"_format(sqlite::placeholders(2)),
                sqlite::bind_each{all.begin(), all.begin() + 2});
        CHECK(got == std::vector<int64_t>{2, 4});
    }

    SECTION("elements bind by type, not as blobs") {
        // Strings go through the same bind_oneshot_single as anywhere else, so a sequence of them
        // matches TEXT rather than arriving as something SQLite compares unequal to everything.
        std::vector<std::string> names{"row2", "row5"};
        std::vector<int64_t> got;
        for (auto&& id : c.prepared_results<int64_t>(
                     "SELECT id FROM t WHERE name IN ({}) ORDER BY id"_format(
                             sqlite::placeholders(names.size())),
                     sqlite::bind_each{names}))
            got.push_back(id);
        CHECK(got == std::vector<int64_t>{2, 5});
    }
}
