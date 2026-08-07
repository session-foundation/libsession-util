#pragma once

#include <session/core/schema/schema_registry.hpp>
#include <span>
#include <string_view>

/// Registry generated from tests/schema/, used to exercise Core's schema_extension option with a
/// second real consumer of session_schema_dir() rather than a hand-written migration array.
namespace session::test::schema {

extern const std::span<const session::core::schema::Migration> MIGRATIONS;

/// See session::core::schema::FULL_SCHEMA.
extern const std::string_view FULL_SCHEMA;

}  // namespace session::test::schema
