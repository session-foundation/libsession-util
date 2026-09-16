#pragma once

#include <span>
#include <string>
#include <string_view>

namespace session::sqlite {
class Connection;
}
namespace session::core {
class Core;
}

namespace session::core::schema {

struct Migration {
    std::string name;
    void (*apply)(session::sqlite::Connection&, Core& core);
};

extern const std::span<const Migration> MIGRATIONS;

/// The schema as it stands with every migration in MIGRATIONS applied, generated from the
/// directory's full_schema.sql; empty when that file does not exist.
///
/// A database with none of this set's migrations applied is built from this and has them all
/// recorded without being run, so the file is both the fresh-install path and the one place to read
/// the current schema — rather than having to replay the migration chain in your head.
extern const std::string_view FULL_SCHEMA;

}  // namespace session::core::schema
