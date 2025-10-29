#include <oxen/log.hpp>
#include <session/core.hpp>

auto logcat = oxen::log::Cat("core");

namespace session::core {
bool ProRevocationItemComparer::operator()(
        const pro_backend::ProRevocationItem& lhs,
        const pro_backend::ProRevocationItem& rhs) const noexcept {
    bool result = lhs.gen_index_hash < rhs.gen_index_hash;
    return result;
}

bool Core::pro_proof_is_revoked(
        const array_uc32& gen_index_hash,
        std::chrono::sys_time<std::chrono::milliseconds> unix_ts) const {
    bool result = false;
    pro_backend::ProRevocationItem item = {};
    item.gen_index_hash = gen_index_hash;
    auto it = revocations_.find(item);
    if (it != revocations_.end())
        result = unix_ts >= it->expiry_unix_ts;
    return result;
}

void Core::pro_update_revocations(
        int32_t revocations_ticket,
        std::span<const session::pro_backend::ProRevocationItem> revocations) {
    if (revocations_ticket_ == revocations_ticket)
        return;

    // Currently we just dump the entire thing and re-write it, we don't expect this list to get big
    revocations_.clear();
    revocations_.insert(revocations.begin(), revocations.end());
    revocations_ticket_ = revocations_ticket;

#if !defined(DISABLED_SQLCIPHER_DATABASE)
    session::database::SetResult set_result =
            db_conn.set_pro_revocations(revocations_ticket, revocations);

    // There's not much we can do here for whatever reason it failed. The runtime cache is updated
    // but not the DB. The DB is only for permanence of the list across restarts of libsession at
    // which point, it will load from the DB, query the backend and notice the ticket is out of sync
    // and try again.
    if (!set_result.success) {
        oxen::log::warning(
                logcat,
                "Failed to update SQL revocations from (items {}; ticket {}) -> (items {}; ticket "
                "{}): ({}) {}",
                revocations_.size(),
                revocations_ticket_,
                revocations.size(),
                revocations_ticket,
                set_result.sql_return_code,
                set_result.sql_error);
    }
#endif
}

};  // namespace session::core
