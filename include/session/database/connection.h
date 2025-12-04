#pragma once

#include <session/types.h>
#include <stddef.h>
#include <stdint.h>

#include "../export.h"

#ifdef __cplusplus
extern "C" {
#endif

struct session_pro_backend_pro_revocation_item;

typedef struct session_database_connection session_database_connection;
struct session_database_connection {
    uint64_t opaque[2];
};

typedef struct session_database_set_result session_database_set_result;
struct session_database_set_result {
    session_c_result db;
    int sql_return_code;
    /// SQL's string-ified `sql_return_code` pointing to memory in the data segment. Should not be
    /// modified and is valid for program lifetime.
    const char* sql_error;
};

typedef struct session_database_get_pro_revocation_result
        session_database_get_pro_revocation_result;
struct session_database_get_pro_revocation_result {
    session_c_result db;
    size_t count;
};

struct session_database_get_account {
    bool found;
    uint32_t db_id;
    bytes64 long_term_privkey;
};

/// API: session_database_connection_open
///
/// Open a connection to the DB specified at `path`. If this connection previously has an open
/// DB that connection is gracefully closed before opening up the newly requested one.
///
/// This function returns an if the DB was not openable, if the `raw_key` was the incorrect key to
/// decrypt the DB or the contents of the DB were malformed.
///
/// If the DB has never been initialised before, the DB is initialised with the required schema.
///
/// Inputs:
/// - `conn` -- DB connection object that was zero-initialised or used previously
/// - `path` -- Path to the DB to open, this can be a URI or path on disk
/// - `raw_key` -- Encryption key to use to open the specified DB. If the DB does not exist then
///   the database will be created, encrypted with this key.
LIBSESSION_EXPORT session_c_result session_database_connection_open(
        session_database_connection* conn, string8 path, span_u8 raw_key) NON_NULL_ARG(1);

/// API: session_database_connection_close
///
/// Close the DB connection which closes the underlying file descriptor referencing the database
///
/// Inputs:
/// - `conn` -- DB connection object to close
LIBSESSION_EXPORT void session_database_connection_close(session_database_connection* conn);

/// API: session_database_connection::get_account
///
/// Get the Session account secrets stored in this database. If no account was initialised yet
/// then the output object's found flag is set to false.
///
/// Outputs:
/// - `found` -- True if there was an account secret in the DB, false otherwise
/// - `db_id` -- Primary key of the row that the secret was retrieved from. 0 if `found` is
///   false
/// - `long_term_privkey` -- Session account's long term 64 byte libsodium-style private key.
///   This key is all 0s if `found` was false.
LIBSESSION_EXPORT session_database_get_account
session_database_connection_get_account(session_database_connection* conn);

/// API: session_database_connection_set_account
///
/// Sets the long-term 64 byte libsodium-style private key as the Session account's secret
/// associated with this database. This overwrites any pre-existing key, if any.
///
/// This function errors if the key is incorrectly sized or if the DB insertion failed.
LIBSESSION_EXPORT session_c_result session_database_connection_set_account(
        session_database_connection* conn,
        void const* long_term_privkey,
        size_t long_term_privkey_size);

/// API: session_database_connection_set_pro_revocations
///
/// Set the list of Session Pro revocations into the database associated with this connection
/// replacing the old revocations. This function is transactional, on failure changes to the
/// database are rolled back.
///
/// Inputs:
/// - `ticket` -- Monotonic integer which is the version of the list, received by the Session
///   Pro Backend when syncing the revocation list.
/// - `revocations` -- The list of revocations to set
LIBSESSION_EXPORT session_database_set_result session_database_connection_set_pro_revocations(
        session_database_connection* conn,
        uint32_t ticket,
        session_pro_backend_pro_revocation_item* revocations,
        size_t revocations_len);

/// API: database/get_pro_revocations_buffer
///
/// Retrieve the Session Pro Backend revocation list given and output the rows into the given
/// `buf`. This function errors if SQLite returned an error
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
/// - `count` -- Number of revocation items read from the database. If the buffer was
///   insufficient sized to receive the rows, the return value is always capped to the size of
///   the buffer. If `buf` and `buf_count` are nullptr or 0 respectively, then value returned
///   is the amount of revocation items in the DB at the time of execution.
LIBSESSION_EXPORT session_database_get_pro_revocation_result
session_database_connection_get_pro_revocations_buffer(
        session_database_connection* conn,
        OPTIONAL session_pro_backend_pro_revocation_item* buf,
        size_t buf_count,
        size_t offset,
        OPTIONAL uint32_t* ticket);
#ifdef __cplusplus
}
#endif
