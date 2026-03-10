#pragma once

#include <span>
#include <string>

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

}  // namespace session::core::schema
