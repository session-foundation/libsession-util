#include "session/database/connection.hpp"

#include <oxenc/hex.h>
#include <sqlcipher/sqlite3.h>

#include <chrono>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <stdexcept>

#include "session/database/connection.h"

auto logcat = oxen::log::Cat("database");
namespace {
void throw_sql_error(int sql_result, std::string_view error_prefix) {
    std::string msg = fmt::format("{}: {}", error_prefix, sqlite3_errstr(sql_result));
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

void sqlite3_deleter::operator()(sqlite3* db) const noexcept {
    sqlite3_close(db);
}

void Connection::open(const std::string& path, const cleared_array<48>& raw_key) {
    cleared_array<48> ZERO_RAW_KEY = {};
    assert(memcmp(raw_key.data(), ZERO_RAW_KEY.data(), raw_key.size()) != 0 &&
           "Raw key was not set");

    // Open DB
    sqlite3* db_ptr = nullptr;
    int rc = sqlite3_open(path.c_str(), &db_ptr);
    if (rc != SQLITE_OK)
        throw_sql_error(rc, "Failed to open database");

    // Replace the old connection w/ the new one (if there was one previously)
    db_.reset(db_ptr);

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
    rc = sqlite3_exec(
            db_.get(), "PRAGMA cipher_plaintext_header_size = 32", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK)
        throw_sql_error(rc, "Failed to configure database");

    // Set encryption key, this is the underlying function that "PRAGMA key = .." calls
    std::string fmt_key = fmt::format("x'{}'", oxenc::to_hex(raw_key));
    rc = sqlite3_key(db_.get(), fmt_key.c_str(), fmt_key.size());
    sodium_zero_buffer(fmt_key.data(), fmt_key.size());
    if (rc != SQLITE_OK)
        throw_sql_error(rc, "Failed to set encryption key");

    // Verify the key works by reading the sqlite_master table
    rc = sqlite3_exec(db_.get(), "SELECT COUNT(*) FROM sqlite_master", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK)
        throw_sql_error(rc, "Failed to decrypt database with the given encryption key");
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
);

CREATE TABLE IF NOT EXISTS runtime (
    id                     INTEGER PRIMARY KEY NOT NULL,
    pro_revocations_ticket INTEGER NOT NULL
);)";
        // Create the initial DB tables
        rc = sqlite3_exec(db_.get(), bootstrap_sql.data(), nullptr, nullptr, nullptr);
        if (rc != SQLITE_OK)
            throw_sql_error(rc, "Failed to bootstrap tables");

        // Seed the runtime table
        std::string_view seed_runtime_sql =
                R"(INSERT INTO runtime (pro_revocations_ticket) VALUES (0))";
        rc = sqlite3_exec(db_.get(), seed_runtime_sql.data(), nullptr, nullptr, nullptr);
        if (rc != SQLITE_OK)
            throw_sql_error(rc, "Failed to seed the runtime table");

        // Teleport to the target version
        rc = set_db_version_or_throw(db_.get(), ++curr_db_version);
        if (rc != SQLITE_OK)
            throw_sql_error(rc, fmt::format("Failed to set DB version to {}", curr_db_version));
    }

    // Requery the DB version and ensure all version migrations have occurred
    [[maybe_unused]] uint8_t final_version_in_db = 0;
    query("PRAGMA user_version", [&final_version_in_db](sqlite3_stmt* stmt) {
        final_version_in_db = sqlite3_column_int(stmt, 0);
    });
    assert(final_version_in_db == TARGET_DB_VERSION);
}

void Connection::exec(const std::string& sql) {
    char* error_msg = nullptr;
    int rc = sqlite3_exec(db_.get(), sql.c_str(), nullptr, nullptr, &error_msg);
    if (rc != SQLITE_OK) {
        std::string error = error_msg ? error_msg : "unknown error";
        sqlite3_free(error_msg);
        throw std::runtime_error("SQL execution failed: " + error);
    }
}

void Connection::query(std::string_view sql, std::function<void(sqlite3_stmt*)> callback) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_.get(), sql.data(), sql.size(), &stmt, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(
                fmt::format("Failed to prepare statement: {}", sqlite3_errmsg(db_.get())));
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
        callback(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        throw std::runtime_error(
                fmt::format("Error executing query: {}", sqlite3_errmsg(db_.get())));
}

Runtime Connection::get_runtime() {
    Runtime result = {};
    std::string_view sql = R"(SELECT id, pro_revocations_ticket FROM runtime LIMIT 1)";
    query(sql, [&result](sqlite3_stmt* stmt) {
        result.id = sqlite3_column_int(stmt, 0);
        result.pro_revocations_ticket = sqlite3_column_int(stmt, 1);
    });
    return result;
}

SetResult Connection::set_pro_revocations(
        uint32_t ticket, std::span<const pro_backend::ProRevocationItem> revocations) noexcept {

    // The following consists of exception safe code so we do not need try catch and can trivially
    // commit or rollback the at the end of the function.
    exec("BEGIN DEFERRED TRANSACTION;");
    exec("DELETE FROM pro_revocations");  // Clear the table

    // Assign the pro-revocations
    int rc = SQLITE_OK;
    if (rc == SQLITE_OK || rc == SQLITE_DONE) {
        sqlite3_stmt* stmt = nullptr;
        std::string_view sql = R"(
INSERT INTO pro_revocations (gen_index_hash, expiry_unix_ts_ms)
VALUES (?, ?)
)";

        rc = sqlite3_prepare_v2(db_.get(), sql.data(), sql.size() + 1, &stmt, nullptr);
        for (size_t index = 0; (rc == SQLITE_OK || rc == SQLITE_DONE) && index < revocations.size();
             index++) {
            const auto& it = revocations[index];
            int bind = 0;
            int64_t expiry = static_cast<int64_t>(it.expiry_unix_ts.time_since_epoch().count());
            rc = (rc == SQLITE_OK || rc == SQLITE_DONE)
                       ? sqlite3_bind_blob(
                                 stmt,
                                 ++bind,
                                 it.gen_index_hash.data(),
                                 static_cast<int>(it.gen_index_hash.size()),
                                 nullptr)
                       : rc;
            rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_bind_int64(stmt, ++bind, expiry)
                                                        : rc;
            rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_step(stmt) : rc;
            rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_reset(stmt) : rc;
            rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_clear_bindings(stmt) : rc;
        }
        int finalize_rc = sqlite3_finalize(stmt);
        if (rc == SQLITE_OK || rc == SQLITE_DONE)
            rc = finalize_rc;
    }

    // Update the ticket
    if (rc == SQLITE_OK || rc == SQLITE_DONE) {
        sqlite3_stmt* stmt = nullptr;
        std::string_view sql = R"(UPDATE runtime SET pro_revocations_ticket = ?)";

        int rc = sqlite3_prepare_v2(db_.get(), sql.data(), sql.size() + 1, &stmt, nullptr);
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_bind_int(stmt, 1, ticket) : rc;
        rc = (rc == SQLITE_OK || rc == SQLITE_DONE) ? sqlite3_step(stmt) : rc;

        int finalize_rc = sqlite3_finalize(stmt);
        if (rc == SQLITE_OK || rc == SQLITE_DONE)
            rc = finalize_rc;
    }

    SetResult result = {};
    result.sql_return_code = rc;
    result.sql_error = sqlite3_errstr(rc);
    result.success = result.sql_return_code == SQLITE_OK || result.sql_return_code == SQLITE_DONE;
    exec(result.success ? "COMMIT;" : "ROLLBACK;");
    return result;
}

size_t Connection::get_pro_revocations_buffer(
        pro_backend::ProRevocationItem* buf, size_t buf_count, size_t offset, uint32_t* ticket) {
    // Note this operation is not atomic, the collecting of revocations and the querying of the
    // ticket happens in 2 separate read steps. This is probably not an issue as I expect the
    // getting of revocations to only happen on startup where it'll get cached into runtime memory.
    // Startup and initialisation of the libsession core is single threaded.

    // Count the number of rows
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

        // Retrieve the rows
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

    // Retrieve the ticket
    if (ticket) {
        query("SELECT pro_revocations_ticket FROM runtime LIMIT 1", [&ticket](sqlite3_stmt* stmt) {
            *ticket = static_cast<uint32_t>(sqlite3_column_int(stmt, 0));
        });
    }
    return result;
}

std::vector<pro_backend::ProRevocationItem> Connection::get_pro_revocations(uint32_t* ticket) {
    std::vector<pro_backend::ProRevocationItem> result;
    size_t size_req = get_pro_revocations_buffer(nullptr, 0, 0, ticket);
    result.resize(size_req);
    size_t items_read = get_pro_revocations_buffer(result.data(), result.size(), 0, ticket);
    assert(items_read == size_req);
    return result;
}
}  // namespace session::database

using namespace session::database;

LIBSESSION_C_API session_database_result session_database_connection_open(
        session_database_connection* conn, string8 path, span_u8 raw_key) {
    session_database_result result = {};

    static_assert(
            sizeof(((session_database_connection*)0)->opaque) >= sizeof(Connection),
            "C struct instantiates the C++ instance with an `opaque` buffer via placement new so "
            "the capacity must be large enough to hold the `Connection` instance");

    session_database_connection_close(conn);
    Connection* conn_cpp = new (conn->opaque) Connection();

    session::cleared_array<48> raw_key_cpp;
    if (raw_key.size != raw_key_cpp.max_size()) {
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error),
                "Raw key must be 48 bytes, received %zu",
                raw_key.size);
        return result;
    }

    // Must be string because we need to guarantee that `path` was null-terminated for the SQL API.
    std::string path_cpp = std::string(path.data, path.data + path.size);
    memcpy(raw_key_cpp.data(), raw_key.data, raw_key.size);

    try {
        conn_cpp->open(path_cpp, raw_key_cpp);
        result.success = true;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }

    return result;
}

LIBSESSION_C_API void session_database_connection_close(session_database_connection* conn) {
    auto* conn_cpp = reinterpret_cast<Connection*>(conn->opaque);
    if (conn_cpp) {
        conn_cpp->~Connection();
        memset(conn->opaque, 0, sizeof(conn->opaque));
    }
}

LIBSESSION_C_API session_database_set_result session_database_connection_set_pro_revocations(
        session_database_connection* conn,
        uint32_t ticket,
        session_pro_backend_pro_revocation_item* revocations,
        size_t revocations_len) {
    session_database_set_result result = {};
    auto* conn_cpp = reinterpret_cast<Connection*>(conn->opaque);
    try {
        // Convert revocations to CPP instance
        std::vector<session::pro_backend::ProRevocationItem> revocations_cpp;
        revocations_cpp.reserve(revocations_len);
        for (size_t index = 0; index < revocations_len; index++) {
            const session_pro_backend_pro_revocation_item& src = revocations[index];
            session::pro_backend::ProRevocationItem& dest = revocations_cpp.emplace_back();
            dest = session::pro_backend::revocation_cpp_from_c(src);
        }

        // Do the operation
        SetResult result_cpp = conn_cpp->set_pro_revocations(ticket, revocations_cpp);
        result.db.success = result_cpp.success;
        result.sql_return_code = result_cpp.sql_return_code;
        result.sql_error = result_cpp.sql_error;
    } catch (const std::exception& e) {
        const std::string& error = e.what();
        result.db.error_count = snprintf_clamped(
                result.db.error,
                sizeof(result.db.error),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }

    return result;
}

LIBSESSION_C_API session_database_get_pro_revocation_result session_database_connection_get_pro_revocations_buffer(
        session_database_connection* conn,
        OPTIONAL session_pro_backend_pro_revocation_item* buf,
        size_t buf_count,
        size_t offset,
        OPTIONAL uint32_t* ticket) {
    auto* conn_cpp = reinterpret_cast<Connection*>(conn->opaque);
    session_database_get_pro_revocation_result result = {};
    try {
        std::vector<session::pro_backend::ProRevocationItem> buf_cpp;
        if (buf && buf_count)
            buf_cpp.resize(buf_count);

        result.count =
                conn_cpp->get_pro_revocations_buffer(buf_cpp.data(), buf_count, offset, ticket);
        buf_cpp.resize(result.count);

        if (buf) {
            for (size_t index = 0; index < result.count; index++)
                buf[index] = session::pro_backend::revocation_c_from_cpp(buf_cpp[index]);
        }

        result.db.success = true;
    } catch (std::exception& e) {
        const std::string& error = e.what();
        result.db.error_count = snprintf_clamped(
                result.db.error,
                sizeof(result.db.error),
                "%.*s",
                static_cast<int>(error.size()),
                error.data());
    }

    return result;
}
