#include <session/core.h>
#include <session/database/connection.h>
#include <session/pro_backend.h>

#include <oxen/log.hpp>
#include <session/core.hpp>

static auto logcat = oxen::log::Cat("core");

namespace {
enum class SaveToDB { No, Yes };
void pro_update_revocations_internal(
        uint32_t& core_revocations_ticket,
        std::set<session::pro_backend::ProRevocationItem, session::core::ProRevocationItemComparer>&
                core_revocations,
#if !defined(DISABLED_SQLCIPHER_DATABASE)
        session::database::Connection& core_db_conn,
#endif
        uint32_t revocations_ticket,
        std::span<const session::pro_backend::ProRevocationItem> revocations,
        [[maybe_unused]] SaveToDB save_to_db) {
    if (core_revocations_ticket == revocations_ticket)
        return;

#if !defined(DISABLED_SQLCIPHER_DATABASE)
    if (core_db_conn.db_ && save_to_db == SaveToDB::Yes) {
        session::database::SetResult set_result =
                core_db_conn.set_pro_revocations(revocations_ticket, revocations);

        // There's not much we can do here for whatever reason it failed. The runtime cache is
        // updated but not the DB. The DB is only for permanence of the list across restarts of
        // libsession at which point, it will load from the DB, query the backend and notice the
        // ticket is out of sync and try again.
        if (!set_result.success) {
            oxen::log::warning(
                    logcat,
                    "Failed to update SQL revocations from (items {}; ticket {}) -> (items {}; "
                    "ticket "
                    "{}): ({}) {}",
                    core_revocations.size(),
                    core_revocations_ticket,
                    revocations.size(),
                    revocations_ticket,
                    set_result.sql_return_code,
                    set_result.sql_error);
        }
    }
#endif

    // Currently we just dump the entire thing and re-write it, we don't expect this list to get big
    core_revocations.clear();
    core_revocations.insert(revocations.begin(), revocations.end());
    core_revocations_ticket = revocations_ticket;
}
};

namespace session::core {
bool ProRevocationItemComparer::operator()(
        const pro_backend::ProRevocationItem& lhs,
        const pro_backend::ProRevocationItem& rhs) const noexcept {
    bool result = lhs.gen_index_hash < rhs.gen_index_hash;
    return result;
}

void Core::open_db(
        [[maybe_unused]] const std::string& path,
        [[maybe_unused]] const cleared_array<48>& raw_key) {
#if !defined(DISABLE_SQLCIPHER_DATABASE)
    std::lock_guard<std::shared_mutex> lock{shared_mutex_};
    // NOTE: Zero initialise everything
    revocations_.clear();
    revocations_ticket_ = 0;

    // NOTE: Open the DB
    db_conn_.open(path, raw_key);

    // NOTE: Load in the pro-revocations from the DB
    uint32_t pro_revocations_ticket = 0;
    std::vector<pro_backend::ProRevocationItem> pro_revocations =
            db_conn_.get_pro_revocations(&pro_revocations_ticket);
    pro_update_revocations_internal(
            revocations_ticket_,
            revocations_,
            db_conn_,
            pro_revocations_ticket,
            pro_revocations,
            SaveToDB::No);
#endif
}

bool Core::pro_proof_is_revoked(
        const array_uc32& gen_index_hash,
        std::chrono::sys_time<std::chrono::milliseconds> unix_ts) const {
    bool result = false;
    pro_backend::ProRevocationItem item = {};
    item.gen_index_hash = gen_index_hash;

    std::shared_lock lock{shared_mutex_};
    auto it = revocations_.find(item);
    if (it != revocations_.end())
        result = unix_ts >= it->expiry_unix_ts;
    return result;
}

void Core::pro_update_revocations(
        uint32_t revocations_ticket,
        std::span<const session::pro_backend::ProRevocationItem> revocations) {
    std::lock_guard lock{shared_mutex_};
    pro_update_revocations_internal(
            revocations_ticket_,
            revocations_,
#if !defined(DISABLED_SQLCIPHER_DATABASE)
            db_conn_,
#endif
            revocations_ticket,
            revocations,
            SaveToDB::Yes);
}
};  // namespace session::core

using namespace session::core;

LIBSESSION_C_API void session_core_core_init(session_core_core* core) {
    static_assert(sizeof(core->opaque) >= sizeof(Core));
    if (core) {
        new (core->opaque) Core();
    }
}

LIBSESSION_C_API void session_core_core_deinit(session_core_core* core) {
    if (core) {
        auto* core_cpp = reinterpret_cast<Core*>(core->opaque);
        if (core_cpp) {
            core_cpp->~Core();
            memset(core->opaque, 0, sizeof(core->opaque));
        }
    }
}

LIBSESSION_C_API session_database_connection *session_core_core_db_conn(session_core_core* core) {
    session_database_connection *result = nullptr;
    auto* core_cpp = reinterpret_cast<Core*>(core->opaque);
#if !defined(DISABLED_SQLCIPHER_DATABASE)
    if (core_cpp->db_conn_.db_.get())
        result = reinterpret_cast<session_database_connection*>(&core_cpp->db_conn_);
#endif
    return result;
}

LIBSESSION_C_API session_c_result
session_core_core_open_db(session_core_core* core, string8 path, span_u8 raw_key) {
    auto* core_cpp = reinterpret_cast<Core*>(core->opaque);
    session::cleared_array<48> raw_key_cpp;

    session_c_result result = {};
    if (raw_key.size != raw_key_cpp.max_size()) {
        result.error_count = snprintf_clamped(
                result.error,
                sizeof(result.error),
                "Raw key must be %zu bytes, unable to open DB. Received: %zu",
                raw_key.size,
                raw_key_cpp.max_size());
        return result;
    }

    try {
        std::string path_cpp = std::string(path.data, path.size);
        core_cpp->open_db(path_cpp, raw_key_cpp);
        result.success = true;
    } catch (const std::exception& e) {
        session::write_exception_to_session_c_result(&result, e.what());
    }
    return result;
}

LIBSESSION_C_API bool session_core_core_pro_proof_is_revoked(
        session_core_core* core, const bytes32* gen_index_hash, uint64_t unix_ts_ms) {
    bool result = false;
    auto* core_cpp = reinterpret_cast<Core*>(core->opaque);
    session::array_uc32 gen_index_hash_cpp = {};
    memcpy(gen_index_hash_cpp.data(), gen_index_hash->data, gen_index_hash_cpp.max_size());
    auto unix_ts =
            std::chrono::sys_time<std::chrono::milliseconds>(std::chrono::milliseconds(unix_ts_ms));
    result = core_cpp->pro_proof_is_revoked(gen_index_hash_cpp, unix_ts);
    return result;
}

LIBSESSION_C_API session_c_result session_core_core_pro_update_revocations(
        session_core_core* core,
        uint32_t revocations_ticket,
        session_pro_backend_pro_revocation_item* revocations,
        size_t revocations_count) {
    session_c_result result = {};
    auto* core_cpp = reinterpret_cast<Core*>(core->opaque);
    try {
        if (revocations_count && revocations) {
            std::vector<session::pro_backend::ProRevocationItem> revocations_cpp;
            revocations_cpp.resize(revocations_count);
            for (size_t index = 0; index < revocations_count; index++)
                revocations_cpp[index] =
                        session::pro_backend::revocation_cpp_from_c(revocations[index]);
            core_cpp->pro_update_revocations(revocations_ticket, revocations_cpp);
        }
        result.success = true;
    } catch (const std::exception& e) {
        session::write_exception_to_session_c_result(&result, e.what());
    }
    return result;
}
