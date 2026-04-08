#include <session/core.hpp>
#include <session/core/component.hpp>
#include <session/core/pro.hpp>
#include <session/pro_backend.hpp>
#include <unordered_set>

#include "SQLiteCpp/Transaction.h"
#include "session/sqlite.hpp"

namespace session::core {

bool Pro::proof_is_revoked(
        std::span<const std::byte, 32> gen_index_hash,
        std::chrono::sys_time<std::chrono::milliseconds> unix_ts) {
    return conn().prepared_get<int>(
            "SELECT EXISTS (SELECT 1 FROM pro_revocations"
            " WHERE gen_index_hash = ? AND expiry_unix_ts_ms <= ?)",
            gen_index_hash,
            unix_ts.time_since_epoch().count());
}

/// API: core/Pro::pro_update_revocations
///
/// Update the list of pro revocations.  If the `revocations_ticket` matches the current ticket,
/// this is a no-op.
///
/// Inputs:
/// - `ticket` -- Ticket that describes the version of the revocations. This value comes
///   alongside the revocation list when queried.  This ticket changes whenever the revocation
///   list is updated and is used to identify when an actual update is needed.
/// - `revocations` -- New list of Session Pro revocations.
void Pro::update_revocations(
        uint32_t ticket, std::span<const pro_backend::ProRevocationItem> revocations) {

    if (revocations_ticket_ && ticket == *revocations_ticket_)
        return;

    auto already_hashed = [](const b32& a) {
        size_t h;
        std::memcpy(&h, a.data(), sizeof(h));
        return h;
    };

    auto c = conn();

    SQLite::Transaction tx{c.sql};

    std::unordered_set<b32, decltype(already_hashed)> to_remove;
    for (auto id :
         c.prepared_results<sqlite::blob_guts<b32>>("SELECT gen_index_hash FROM pro_revocations"))
        to_remove.insert(id);

    for (auto st = c.prepared_st(
                 "INSERT INTO pro_revocations (gen_index_hash, expiry_unix_ts_ms) VALUES (?, ?)"
                 " ON CONFLICT (gen_index_hash) "
                 " DO UPDATE SET expiry_unix_ts_ms = excluded.expiry_unix_ts_ms"
                 " WHERE excluded.expiry_unix_ts_ms != expiry_unix_ts_ms");
         const auto& revoke : revocations) {

        exec_query(st, revoke.gen_index_hash, revoke.expiry_unix_ts.time_since_epoch().count());
        to_remove.erase(revoke.gen_index_hash);
        st->reset();
    }

    if (!to_remove.empty()) {
        auto st = c.prepared_st("DELETE FROM pro_revocations WHERE gen_index_hash = ?");
        for (const auto& id : to_remove) {
            exec_query(st, id);
            st->reset();
        }
    }

    tx.commit();
}

}  // namespace session::core
