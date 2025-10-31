#pragma once

#include <cstdint>
#if !defined(DISABLE_SQLCIPHER_DATABASE)
#include <session/database/connection.hpp>
#endif
#include <chrono>
#include <session/types.hpp>
#include <set>

/// The fundamental library context that an application should instantiate at the start of their
/// libsession integrated application. Its goal is to maintain libsession data structures for
/// communicating on the protocol at runtime but also persist it to disk if/where necessary to
/// maintain state across application restarts.
///
/// A typical application will instantiate the Core context, open a DB connection at the desired
/// path where libsession will persist state. Periodically the integrating application will invoke
/// the Core context to feed it data that it will managed. In future, the Core context will be
/// runnable in a background thread for it to maintain itself and automatically subscribe to the
/// Session Pro Backend, the swarms of the Session Account it manages to send and receive messages
/// in a way that abstracts that functionality from the implementing application.
///
/// Currently the integrating application must update the Core context when it receives the
/// appropriate data from the network.

namespace session::pro_backend {
struct ProRevocationItem;
};  // namespace session::pro_backend

namespace session::core {
struct ProRevocationItemComparer {
    bool operator()(
            const pro_backend::ProRevocationItem& lhs,
            const pro_backend::ProRevocationItem& rhs) const noexcept;
};

struct Core {
    /// List of Session Pro revocations that the core will reject proofs from
    std::set<session::pro_backend::ProRevocationItem, ProRevocationItemComparer> revocations_;

    /// Version of the revocation list that is currently stored in this core context. It is received
    /// from the Session Pro Backend when the revocation list is queried.
    uint32_t revocations_ticket_;

    /// After initialisation you must call `db_conn.open()` if you wish to use
    /// functions requiring the database which are denoted by DISABLE_SQLCIPHER_DATABASE.
#if !defined(DISABLE_SQLCIPHER_DATABASE)
    session::database::Connection db_conn;
#endif

    /// API: core/Core::pro_proof_is_revoked
    ///
    /// Check if the proof identified by its `gen_index_hash` is revoked with respect to the given
    /// timestamp from the list of proofs stored in memory. If `gen_index_hash` does not exist this
    /// function will always return `false`.
    ///
    /// Outputs:
    /// - `bool` -- True if the proof was revoked, false otherwise.
    bool pro_proof_is_revoked(
            const array_uc32& gen_index_hash,
            std::chrono::sys_time<std::chrono::milliseconds> unix_ts) const;

    /// API: core/Core::pro_update_revocations
    ///
    /// Update the list of pro-revocations being managed by the core. This updates the in-memory
    /// list as well as the copy stored in the database. If the `revocations_ticket` matches the
    /// in-memory ticket, this is a no-op.
    ///
    /// If `db_conn` does not have an open connection then only the in-memory revocation list is
    /// updated.
    void pro_update_revocations(
            uint32_t revocations_ticket,
            std::span<const session::pro_backend::ProRevocationItem> revocations);
};
}  // namespace session::core
