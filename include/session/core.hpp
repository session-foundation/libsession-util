#pragma once

#include <cstdint>
#if !defined(DISABLE_SQLCIPHER_DATABASE)
#include <session/database/connection.hpp>
#endif
#include <chrono>
#include <session/types.hpp>
#include <set>
#include <shared_mutex>

/// The fundamental library context that an application should instantiate at the start of their
/// libsession integrated application. Its goal is to maintain libsession data structures for
/// communicating on the protocol at runtime but also persist it to disk if/where necessary to
/// maintain state across application restarts.
///
/// A typical application will instantiate the Core context, open a DB connection at the desired
/// path where libsession will persist state. Periodically the integrating application will invoke
/// the Core context to feed it data that it will manage. In future, the Core context will be
/// runnable in a background thread for it to maintain itself and automatically subscribe to the
/// Session Pro Backend, the swarms of the Session Account it manages to send and receive messages
/// in a way that abstracts that book-keeping from the implementing application.
///
/// Currently the integrating application must update the Core context when it receives the
/// appropriate data from the network and you can opt out of using a database by either,
///
///  - Compiling without database support
///  - Not opening the database and/or ensuring the database is on the Core object is is closed
///    during use.
///
/// The typical intended flow for using the Core is as follows:
/*
```
  #include <sodium/randombytes.h>
  #include <session/core.hpp>

  int main() {
    session::core::Core core = {};

    // Optionally create/open the DB to persist state to. If this step is skipped the core will only
    // maintain libsession state (like the user's long term seed or the pro revocation list) in
    // runtime memory and will be lost on shutdown. Persisting user state is then left to the
    // integrating application's discretion.
    try {
      // Generate the encryption key for the DB (if you had a pre-existing DB this is where you
      // would load the key to pass in).
      session::cleared_array<48> db_enc_key = {};
      randombytes_buf(db_enc_key.data(), db_enc_key.size());

      core.open_db(":memory:", db_enc_key);
    } catch (const std::exception& e) {
      // ... error handling
    }

    // Update the revocation list stored in Core (if the DB was opened successfully, this will also
    // persist the revocation list to the DB for example).
    //
    // In a production application you would sleep on an event loop responsible for dispatching and
    // receiving the revocation list queries and call this function to update the revocation list
    // that is cached and the DB
    if (core.pro_update_revocations(...)) { ... }

    // Interfacing code calls this API to check if the specific proof in question is revoked or not
    if (core.pro_proof_is_revoked(...)) { ... }

    core.deinit();
  }
```
*/

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

    /// This class is intended to be use on an network event loop alongside the application which
    /// calls into functions that lookup the cache. When the event loop updates the data stored in
    /// the in-memory cache and database it requires an exclusive lock. When the application queries
    /// the in-memory caches and database, concurrent reads are accepted if there are ongoing writes
    mutable std::shared_mutex shared_mutex_;

#if !defined(DISABLE_SQLCIPHER_DATABASE)
    session::database::Connection db_conn_;
#endif

    /// API: core/Core::open_db
    ///
    /// Create/open the SQLCipher DB at the specified `path`. Upon load the core in-memory runtime
    /// state will be reset and populated with the contents of the DB. This closes the DB
    /// automatically if the core previously opened it.
    //
    /// This function throws if there was an error opening the database. No-op if libsession has
    /// been compiled without database support.
    void open_db(const std::string& path, const cleared_array<48>& raw_key);

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
    ///
    /// Inputs:
    /// - `revocations_ticket` -- Ticket that describes the version of the revocations. This value
    ///   comes alongside the revocation list when queried. If the ticket is the same as the ticket
    ///   stored in the core, this function no-ops (because the revocation list is the same in this
    ///   case).
    /// - `revocations` -- List of Session Pro revocations to update in the core. Overwrites the
    ///   previous list stored in the core.
    void pro_update_revocations(
            uint32_t revocations_ticket,
            std::span<const session::pro_backend::ProRevocationItem> revocations);
};
}  // namespace session::core
