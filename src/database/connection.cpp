#include "session/database/connection.hpp"
#include <oxen/log.hpp>
#include <oxenc/hex.h>
#include <stdexcept>
#include <sqlcipher/sqlite3.h>

namespace session::database {
Connection::Connection(const std::string& path, const std::string& key) : key_(key) {
    int rc = sqlite3_open(path.c_str(), &db_);
    
    if (rc != SQLITE_OK) {
        std::string error = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("Failed to open database: " + error);
    }
    
    // Set encryption key
    if (!key_.empty()) {
        std::string formatted_key = "x'" + key_ + "'";
        rc = sqlite3_key(db_, formatted_key.c_str(), formatted_key.size());

        if (rc != SQLITE_OK) {
            std::string error = sqlite3_errmsg(db_);
            sqlite3_close(db_);
            db_ = nullptr;
            throw std::runtime_error("Failed to set encryption key: " + error);
        }
    }

    // According to the SQLCipher docs iOS needs the 'cipher_plaintext_header_size' value set to at least
    // 32 as iOS extends special privileges to the database and needs this header to be in plaintext
    // to determine the file type
    //
    // For more info see: https://www.zetetic.net/sqlcipher/sqlcipher-api/#cipher_plaintext_header_size
    rc = sqlite3_exec(db_, "PRAGMA cipher_plaintext_header_size = 32", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        std::string error = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("Failed to configure database: " + error);
    }
    
    // Verify the key works by reading the sqlite_master table
    rc = sqlite3_exec(db_, "SELECT count(*) FROM sqlite_master", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        std::string error = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("Failed to decrypt database: " + error);
    }
    
    // oxen::log::debug("Database connection established successfully");
}

Connection::~Connection() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

Connection::Connection(Connection&& other) noexcept
    : db_(other.db_), key_(std::move(other.key_)) {
    other.db_ = nullptr;
}

Connection& Connection::operator=(Connection&& other) noexcept {
    if (this != &other) {
        if (db_) sqlite3_close(db_);
        db_ = other.db_;
        key_ = std::move(other.key_);
        other.db_ = nullptr;
    }
    return *this;
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

void Connection::query(const std::string& sql, std::function<void(sqlite3_stmt*)> callback) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db_)));
    }
    
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        callback(stmt);
    }
    
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Error executing query: " + std::string(sqlite3_errmsg(db_)));
    }
    
    sqlite3_finalize(stmt);
}

} // namespace session::database
