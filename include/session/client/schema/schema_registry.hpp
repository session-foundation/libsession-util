#pragma once

#include <session/core/schema/schema_registry.hpp>
#include <span>

/// Migrations for Client's tables, generated from src/client/schema/ and applied via Core's
/// schema_extension option under the owner name "client".
///
/// These run from Core::apply_migrations(), before any Core component's init() and long before the
/// Client that owns them exists, so they may depend on Core's tables but on nothing of Client's.
namespace session::client::schema {

extern const std::span<const session::core::schema::Migration> MIGRATIONS;

}  // namespace session::client::schema
