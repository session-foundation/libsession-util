#pragma once

#include <cstdint>
#if !defined(DISABLE_SQLCIPHER_DATABASE)
#include <session/database/connection.hpp>
#endif
#include <session/types.hpp>
#include <set>
#include <chrono>

namespace session {
namespace pro_backend {
    struct ProRevocationItem;
}
};  // namespace session

namespace session::core {
struct ProRevocationItemComparer {
    bool operator()(
            const pro_backend::ProRevocationItem& lhs,
            const pro_backend::ProRevocationItem& rhs) const noexcept;
};

struct Core {
    std::set<session::pro_backend::ProRevocationItem, ProRevocationItemComparer> revocations_;
    int32_t revocations_ticket_;
#if !defined(DISABLE_SQLCIPHER_DATABASE)
    session::database::Connection db_conn;
#endif

    bool pro_proof_is_revoked(
            const array_uc32& gen_index_hash,
            std::chrono::sys_time<std::chrono::milliseconds> unix_ts) const;

    void pro_update_revocations(
            int32_t revocations_ticket,
            std::span<const session::pro_backend::ProRevocationItem> revocations);
};

}  // namespace session::core
