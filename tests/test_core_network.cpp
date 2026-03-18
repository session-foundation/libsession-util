#include <catch2/catch_test_macros.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>
#include <session/sqlite.hpp>

#include "utils.hpp"

using namespace session;

TEST_CASE("Core can hold an optional Network interface", "[core][network]") {
    core::callbacks callbacks;
    auto db_path = std::filesystem::temp_directory_path() / "test_core_network.db";
    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);

    core::Core core{callbacks, db_path, sqlite::argon2id_password{"test"}};

    SECTION("Network is initially null") {
        CHECK(core.network() == nullptr);
    }

    SECTION("Network can be set and retrieved") {
        auto network = std::make_shared<network::Network>(network::config::Config{});
        core.set_network(network);
        CHECK(core.network() == network);
    }

    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);
}
