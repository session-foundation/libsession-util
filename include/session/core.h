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
    uint64_t opaque[8];
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
/// Get a DB handle from the core object. This DB connection may be uninitialised if
/// `session_database_connection_open` has not been called on the returned database connection
/// before for this instance.
LIBSESSION_EXPORT session_database_connection session_core_core_db_conn(session_core_core* core)
        NON_NULL_ARG(1);

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
