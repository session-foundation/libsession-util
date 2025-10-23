#include "session/database/connection.hpp"

#include <oxenc/hex.h>
#include <sqlcipher/sqlite3.h>

#include <chrono>
#include <chrono>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <stdexcept>

auto logcat = oxen::log::Cat("database");

namespace {
void close_db_and_throw_error(sqlite3** db, int sql_result, std::string_view error_prefix) {
    std::string msg = fmt::format("{}: {}", error_prefix, sqlite3_errstr(sql_result));
    sqlite3_close(*db);
    *db = nullptr;
    throw std::runtime_error(msg);
}

int set_db_version_or_throw(sqlite3* db, uint8_t db_version) {
    char sql[64];
    size_t sql_size = snprintf(sql, sizeof(sql), "PRAGMA user_version = %u", db_version);
    assert(sql_size < sizeof(sql));
    int result = sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
    return result;
}
};  // namespace

namespace session::database {
Connection::Connection(const std::string& path, const cleared_array<48> &raw_key) {
    cleared_array<48> ZERO_RAW_KEY = {};
    assert(memcmp(raw_key.data(), ZERO_RAW_KEY.data(), raw_key.size()) != 0 && "Raw key was not set");

    // Open DB
    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK)
        close_db_and_throw_error(&db_, rc, "Failed to open database");

    // According to the SQLCipher docs iOS needs the 'cipher_plaintext_header_size' value set to at
    // least 32 as iOS extends special privileges to the database and needs this header to be in
    // plaintext to determine the file type
    //
    // This keeps the first 32 bytes of the database unencrypted. iOS checks the headers of open
    // file-descriptors as a heuristic to determine which processes can get elevated permissions or
    // processes that can be culled. SQLite databases are one of those that get elevated.
    //
    // For more info, see:
    //   https://www.zetetic.net/sqlcipher/sqlcipher-api/#cipher_plaintext_header_size
    rc = sqlite3_exec(db_, "PRAGMA cipher_plaintext_header_size = 32", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK)
        close_db_and_throw_error(&db_, rc, "Failed to configure database");

    // Set encryption key, this is the underlying function that "PRAGMA key = .." calls
    std::string fmt_key = fmt::format("x'{}'", oxenc::to_hex(raw_key));
    rc                  = sqlite3_key(db_, fmt_key.c_str(), fmt_key.size());
    sodium_zero_buffer(fmt_key.data(), fmt_key.size());
    if (rc != SQLITE_OK)
        close_db_and_throw_error(&db_, rc, "Failed to set encryption key");

    // Verify the key works by reading the sqlite_master table
    rc = sqlite3_exec(db_, "SELECT COUNT(*) FROM sqlite_master", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK)
        close_db_and_throw_error(&db_, rc, "Failed to decrypt database with the given encryption key");
    oxen::log::debug(logcat, "Opened database {} successfully", path);

    // Query the DB version
    uint8_t curr_db_version = 0;
    query("PRAGMA user_version",
          [&](sqlite3_stmt* stmt) { curr_db_version = sqlite3_column_int(stmt, 0); });

    // Version migrations
    const uint8_t TARGET_DB_VERSION = 1;
    if (curr_db_version == 0) {
        std::string_view bootstrap_sql = R"(
CREATE TABLE IF NOT EXISTS pro_revocations (
    gen_index_hash    BLOB PRIMARY KEY NOT NULL,
    expiry_unix_ts_ms INTEGER NOT NULL
))";
        // Create the initial DB tables
        rc = sqlite3_exec(db_, bootstrap_sql.data(), nullptr, nullptr, nullptr);
        if (rc != SQLITE_OK)
            close_db_and_throw_error(&db_, rc, "Failed to bootstrap tables");

        // Teleport to the target version
        rc = set_db_version_or_throw(db_, ++curr_db_version);
        if (rc != SQLITE_OK)
            close_db_and_throw_error(
                    &db_, rc, fmt::format("Failed to set DB version to {}", curr_db_version));
    }

    // Requery the DB version and ensure all version migrations have occurred
    [[maybe_unused]] uint8_t final_version_in_db = 0;
    query("PRAGMA user_version", [&final_version_in_db](sqlite3_stmt* stmt) {
        final_version_in_db = sqlite3_column_int(stmt, 0);
    });
    assert(final_version_in_db == TARGET_DB_VERSION);
}

Connection::~Connection() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void Connection::exec(const std::string& sql) {
    char* error_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &error_msg);
    if (rc != SQLITE_OK) {
        std::string error = error_msg ? error_msg : "unknown error";
        sqlite3_free(error_msg);
        throw std::runtime_error("SQL execution failed: " + error);
    }
}

void Connection::query(std::string_view sql, std::function<void(sqlite3_stmt*)> callback) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.data(), sql.size(), &stmt, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(
                fmt::format("Failed to prepare statement: {}", sqlite3_errmsg(db_)));
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
        callback(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        throw std::runtime_error(fmt::format("Error executing query: {}", sqlite3_errmsg(db_)));
}

AddResult Connection::add_pro_revocations(
        std::span<const pro_backend::ProRevocationItem> revocations) noexcept {

    // The following consists of exception safe code so we do not need try catch and can trivially
    // commit or rollback the at the end of the function.
    exec("BEGIN DEFERRED TRANSACTION;");

    sqlite3_stmt* stmt = nullptr;
    std::string_view sql = R"(
INSERT INTO pro_revocations (gen_index_hash, expiry_unix_ts_ms)
VALUES (?, ?)
)";

    int rc = sqlite3_prepare_v2(db_, sql.data(), sql.size() + 1, &stmt, nullptr);
    for (size_t index = 0; (rc == SQLITE_OK || rc == SQLITE_DONE) && index < revocations.size();
         index++) {
        const auto& it = revocations[index];
        int bind = 0;
        int64_t expiry = static_cast<int64_t>(it.expiry_unix_ts.time_since_epoch().count());
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_bind_blob(
                                       stmt,
                                       ++bind,
                                       it.gen_index_hash.data(),
                                       static_cast<int>(it.gen_index_hash.size()),
                                       nullptr)
                             : rc;
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_bind_int64(stmt, ++bind, expiry) : rc;
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_step(stmt) : rc;
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_reset(stmt) : rc;
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_clear_bindings(stmt) : rc;
    }
    int finalize_rc = sqlite3_finalize(stmt);
    if (rc == SQLITE_OK || rc == SQLITE_DONE)
        rc = finalize_rc;

    AddResult result = {};
    result.return_code = rc;
    result.success = result.return_code == SQLITE_OK || result.return_code == SQLITE_DONE;
    exec(result.success ? "COMMIT;" : "ROLLBACK;");
    return result;
}

DeleteResult Connection::delete_pro_revocations(
        std::span<const pro_backend::ProRevocationItem> revocations) noexcept {

    // The following consists of exception safe code so we do not need try catch and can trivially
    // commit or rollback the at the end of the function.
    exec("BEGIN DEFERRED TRANSACTION;");

    std::string_view sql = R"(
DELETE FROM pro_revocations
WHERE gen_index_hash = ?
)";

    size_t row_count = 0;
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.data(), sql.size() + 1, &stmt, nullptr);
    for (size_t index = 0; (rc == SQLITE_OK || rc == SQLITE_DONE) && index < revocations.size();
         index++) {
        const auto& it = revocations[index];
        int64_t expiry = static_cast<int64_t>(it.expiry_unix_ts.time_since_epoch().count());
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE)
                   ? sqlite3_bind_blob(
                             stmt,
                             1,
                             it.gen_index_hash.data(),
                             static_cast<int>(it.gen_index_hash.size()),
                             nullptr)
                   : rc;
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_step(stmt) : rc;
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_reset(stmt) : rc;
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_clear_bindings(stmt) : rc;
        row_count += sqlite3_changes(db_);
    }
    int finalize_rc = sqlite3_finalize(stmt);
    if (rc == SQLITE_OK || rc == SQLITE_DONE)
        rc = finalize_rc;

    DeleteResult result = {};
    result.return_code = rc;
    result.success = result.return_code == SQLITE_OK || result.return_code == SQLITE_DONE;
    if (result.success) {
        exec("COMMIT;");
        result.count = row_count;
    } else {
        exec("ROLLBACK;");
        result.count = 0;
    }
    return result;
}

size_t Connection::get_pro_revocations_buffer(
        pro_backend::ProRevocationItem* buf, size_t buf_count, size_t offset) {
    size_t result = 0;
    query("SELECT COUNT(*) FROM pro_revocations",
          [&](sqlite3_stmt* stmt) { result = sqlite3_column_int(stmt, 0); });

    if (buf && buf_count) {
        char sql[128];
        size_t sql_size = snprintf(
                sql,
                sizeof(sql),
                R"(
SELECT gen_index_hash, expiry_unix_ts_ms
FROM pro_revocations
LIMIT %zu
OFFSET %zu
)",
                buf_count,
                offset);
        assert(sql_size < sizeof(sql));

        result = 0;
        query(std::string_view(sql, sql_size), [&buf, buf_count, &result](sqlite3_stmt* stmt) {
            pro_backend::ProRevocationItem& item = buf[result++];

            // Copy out the gen index blob
            const void* gen_index_blob = sqlite3_column_blob(stmt, 0);
            int gen_index_hash_size = sqlite3_column_bytes(stmt, 0);
            assert(gen_index_hash_size == 32);
            std::memcpy(
                    item.gen_index_hash.data(),
                    gen_index_blob,
                    std::min(gen_index_hash_size, static_cast<int>(item.gen_index_hash.size())));

            // Copy out the expiry timestmap
            auto expiry = std::chrono::milliseconds(sqlite3_column_int64(stmt, 1));
            item.expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(expiry);
        });
    }
    return result;
}

std::vector<pro_backend::ProRevocationItem> Connection::get_pro_revocations() {
    std::vector<pro_backend::ProRevocationItem> result;
    size_t size_req = get_pro_revocations_buffer(nullptr, 0, 0);
    result.resize(size_req);
    size_t items_read = get_pro_revocations_buffer(result.data(), result.size(), 0);
    assert(items_read == size_req);
    return result;
}
}  // namespace session::database
