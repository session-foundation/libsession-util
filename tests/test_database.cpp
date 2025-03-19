#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <session/util.hpp>
#include <sqlcipher/sqlite3.h>
#include <iostream>

#include "session/database/connection.hpp"
#include "utils.hpp"

const std::string test_db_path = "";
const std::string test_db_key = "";

TEST_CASE("Database", "[database][open]") {
    auto db = session::database::Connection(test_db_path, test_db_key);

    db.query("SELECT id, name FROM profile", [&](sqlite3_stmt* stmt) {
        std::string id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        std::cout << "RAWR " + id + ", " + name << std::endl;
    });
}
