#include <SQLiteCpp/Statement.h>

#include <initializer_list>
#include <oxen/log.hpp>
#include <session/core.hpp>
#include <session/core/schema/schema_registry.hpp>
#include <unordered_set>

#include "session/core/component.hpp"

namespace session::core {

namespace log = oxen::log;
using namespace session::sqlite;

void Core::init() {
    apply_migrations();

    for (auto* component : _comp_init)
        component->init();

    _comp_init.clear();
}

void Core::register_comp_init(detail::CoreComponent* c) {
    _comp_init.push_back(c);
}

void Core::apply_migrations() {
    auto cat = log::Cat("schema");

    auto conn = db.conn();
    exec_query(conn.sql, R"(
CREATE TABLE IF NOT EXISTS migrations_applied (
    name TEXT PRIMARY KEY NOT NULL
) STRICT
)");

    std::unordered_set<std::string> applied;
    {
        SQLite::Statement st{conn.sql, "SELECT name FROM migrations_applied"};
        while (st.executeStep())
            applied.insert(get<std::string>(st));
    }

    log::debug(cat, "Checking schema migrations");
    for (const auto& [name, apply] : schema::MIGRATIONS) {
        if (applied.count(name)) {
            log::debug(cat, "Schema migration {} already applied", name);
            continue;
        }

        try {
            log::info(cat, "Applying database schema migration {}", name);

            SQLite::Transaction tx{conn.sql};

            apply(conn, *this);
            conn.prepared_exec("INSERT INTO migrations_applied (name) VALUES (?)", name);

            tx.commit();
        } catch (const std::exception& e) {
            log::critical(cat, "Database schema migration '{}' failed: {}", name, e.what());
            throw;
        }
    }
    log::debug(cat, "All schema migrations are applied");
}

}  // namespace session::core
