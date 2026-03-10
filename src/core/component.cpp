#include <session/core.hpp>
#include <session/core/component.hpp>
#include <session/sqlite.hpp>

namespace session::core::detail {

sqlite::Connection CoreComponent::conn() {
    return core.db.conn();
}

CoreComponent::CoreComponent(Core& core) : core{core} {
    core.register_comp_init(this);
}

}  // namespace session::core::detail
