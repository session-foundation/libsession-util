#pragma once

#include <session/database/connection.h>
#include <stddef.h>
#include <stdint.h>

#include "export.h"
#include "types.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct session_core_core session_core_core;
struct session_core_core {
    uint64_t opaque[16];
};

/// API: core/session_core_core_init
///
/// Pass in a zero-initialised session core object to initialise core for usage in the core layer
/// This object should be considered unique, it should not be copied and it must only be initialised
/// and deinitialised once.
///
/// After initialisation you must call `session_database_connection_open` if you wish to use
/// functions requiring the database
LIBSESSION_EXPORT void session_core_core_init(session_core_core* core);

/// API: core/session_core_core_deinit
///
/// Shutdown a initialised core object. This function does a no-op if a NULL pointer is passed in
LIBSESSION_EXPORT void session_core_core_deinit(session_core_core* core);

/// API: core/session_core_core_db_conn
///
/// Get a DB handle from the core object if the DB has been opened before. If the DB has not been
/// opened, this function returns a nullptr. If libsession is built without DB support this will
/// also cause the function to return a nullptr.
///
/// This pointer's lifetime is bound to the current instance of the DB associated with the Core. The
/// caller must take care not to deinitialise the connection independently from the Core as
/// ownership of the database is bound to `session_core_core_deinit`.
LIBSESSION_EXPORT session_database_connection *session_core_core_db_conn(session_core_core* core)
        NON_NULL_ARG(1);

/// API: core/session_core_core_open_db
///
/// Create/open the SQLCipher DB at the specified `path`. Upon load the core in-memory runtime
/// state will be reset and populated with the contents of the DB. This closes the DB automatically
/// if the core previously opened it.
//
/// This function returns an error if there were issues opening the database. No-op if libsession
/// has been compiled without database support.
LIBSESSION_EXPORT session_c_result
session_core_core_open_db(session_core_core* core, string8 path, span_u8 raw_key);

/// API: core/session_core_core_pro_proof_is_revoked
///
/// Update the list of pro-revocations being managed by the core. This updates the in-memory
/// list as well as the copy stored in the database. If the `revocations_ticket` matches the
/// in-memory ticket, this is a no-op.
LIBSESSION_EXPORT bool session_core_core_pro_proof_is_revoked(
        session_core_core* core, const bytes32* gen_index_hash, uint64_t unix_ts_ms)
        NON_NULL_ARG(1, 2);

/// API: core/session_core_core_pro_update_revocations
///
/// Update the list of pro-revocations being managed by the core. This updates the in-memory list as
/// well as the copy stored in the database. If the `revocations_ticket` matches the in-memory
/// ticket, this is a no-op.
///
/// If the handle returned by `session_core_core_db_conn` does not have an open connection then only
/// the in-memory revocation list is updated.
LIBSESSION_EXPORT session_c_result session_core_core_pro_update_revocations(
        session_core_core* core,
        uint32_t revocations_ticket,
        session_pro_backend_pro_revocation_item* revocations,
        size_t revocations_count) NON_NULL_ARG(1);

#if defined(__cplusplus)
}
#endif
