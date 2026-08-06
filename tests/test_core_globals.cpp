#include <catch2/catch_test_macros.hpp>
#include <session/core.hpp>

#include "test_helper.hpp"

using namespace session;
using namespace session::core;

TEST_CASE("Globals: set/get round-trip", "[core][globals]") {
    TempCore c{};

    CHECK(!c->globals.get_text("nope"));

    c->globals.set("a_string", "hello");
    c->globals.set("an_int", int64_t{42});
    c->globals.set("a_real", 1.5);

    CHECK(c->globals.get_text("a_string") == "hello");
    CHECK(c->globals.get_integer("an_int") == 42);
    CHECK(c->globals.get_real("a_real") == 1.5);

    // Wrong-type reads come back empty rather than throwing.
    CHECK(!c->globals.get_integer("a_string"));
}

TEST_CASE("Globals: erase", "[core][globals]") {
    TempCore c{};

    c->globals.set("doomed", "value");
    REQUIRE(c->globals.get_text("doomed") == "value");

    CHECK(c->globals.erase("doomed"));
    CHECK(!c->globals.get_text("doomed"));

    // Erasing something that was never set is not an error, just false.
    CHECK(!c->globals.erase("doomed"));
    CHECK(!c->globals.erase("never_existed"));
}

TEST_CASE("Globals: values persist across reopen", "[core][globals]") {
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_globals", 7));
    std::filesystem::remove(path);

    {
        Core core{path};
        core.globals.set("kept", "yes");
        core.globals.set("dropped", "no");
        CHECK(core.globals.erase("dropped"));
    }
    {
        Core core{path};
        CHECK(core.globals.get_text("kept") == "yes");
        CHECK(!core.globals.get_text("dropped"));
    }

    std::error_code ec;
    std::filesystem::remove(path, ec);
}
