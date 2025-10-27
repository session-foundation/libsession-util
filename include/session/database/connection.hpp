#pragma once

#include <session/types.h>

#include <functional>
#include <session/pro_backend.hpp>
#include <session/sodium_array.hpp>
#include <string>

struct sqlite3;
struct sqlite3_stmt;

namespace session::database {

struct SetResult {
    bool success;
    int return_code;
};

struct Runtime {
    size_t id;
    size_t pro_revocations_ticket;
};

struct Connection {
    sqlite3* db_;

    Connection(const std::string& path, const cleared_array<48>& raw_key);
    ~Connection();

    // Prevent copying and moving
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&& other) = delete;
    Connection& operator=(Connection&& other) = delete;

    /// API: database/exec
    ///
    /// Prepares a statement and executes it. Throws if SQLite returned an error
    ///
    /// Inputs:
    /// - `sql` -- SQL statement to prepare and execute
    void exec(const std::string& sql);

    /// API: database/query
    ///
    /// Prepares a statement, steps the statement, calls the provided `callback` and then finalizes
    /// the statement once stepping no longer returns rows. Throws if SQLite returned an error
    ///
    /// Inputs:
    /// - `sql` -- SQL statement to prepare
    /// - `callback` -- User defined function to execute when a row is returned
    void query(std::string_view sql, std::function<void(sqlite3_stmt*)> callback);

    /// API: database/get_runtime
    ///
    /// Get the runtime row of the table which contains global metadata for the entire table.
    /// There's only one runtime row per database.
    ///
    /// Outputs:
    /// - `id` -- Row ID of the runtime row (essentially always 1 as there's only 1 runtime row)
    /// - `pro_revocations_ticket` -- Current version of the pro revocations list that has been
    ///   synced from the Session Pro Backend.
    Runtime get_runtime();

    /// API: database/add_pro_revocations
    ///
    /// Add a list of Session Pro revocations into the database associated with this connection.
    /// This function is transactional, on failure changes to the database are rolled back.
    ///
    /// Inputs:
    /// - `revocations` -- The list of revocations to add
    ///
    /// Outputs:
    /// - `success` -- True if the add was successful, false otherwise.
    /// - `return_code` -- The SQLite3 error code that caused the error if `success` was false
    SetResult set_pro_revocations(
            uint32_t ticket, std::span<const pro_backend::ProRevocationItem> revocations) noexcept;

    /// API: database/get_pro_revocations_buffer
    ///
    /// Retrieve the Session Pro Backend revocation list given and output the rows into the given
    /// `buf`. This function throws if SQLite returned an error
    ///
    /// Inputs:
    /// - `buf` -- Buffer to write loaded revocations into. This can be nullptr in which case the
    ///   function returns the number of revocations currently in the DB.
    /// - `buf_count` -- Size of the buffer and consequently the amount of revocations to load. This
    ///   can be 0 as well as setting `buf` to `nullptr` to make the function return the number of
    ///   revocations currently in the DB.
    /// - `offset` -- Start retrieving revocation rows from this specified index of the list. Pass
    ///   in 0 to start from the beginning.
    /// - `ticket` -- Retrieve the current ticket for the revocation list which represents the
    ///   current version of the list that has been synced from the Session Pro Backend.
    ///
    /// Outputs:
    /// - `size_t` -- Number of revocation items read from the database. If the buffer was
    ///   insufficient sized to receive the rows, the return value is always capped to the size of
    ///   the buffer. If `buf` and `buf_count` are nullptr or 0 respectively, then value returned
    ///   is the amount of revocation items in the DB at the time of execution.
    size_t get_pro_revocations_buffer(
            OPTIONAL pro_backend::ProRevocationItem* buf,
            size_t buf_count,
            size_t offset,
            OPTIONAL uint32_t* ticket);

    /// API: database/get_pro_revocations
    ///
    /// Retrieve the Session Pro Backend revocation list from the database. This function throws if
    /// there was an allocation or SQLite returned an error
    ///
    /// Inputs:
    /// - `ticket` -- Retrieve the current ticket for the revocation list which represents the
    ///   current version of the list that has been synced from the Session Pro Backend.
    ///
    /// Outputs:
    /// - `std::vector<pro_backend::ProRevocationItem>` -- List of revocation items
    std::vector<pro_backend::ProRevocationItem> get_pro_revocations(OPTIONAL uint32_t* ticket);
};
}  // namespace session::database
