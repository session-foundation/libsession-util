#include <oxen/quic/loop.hpp>
#include <session/core.hpp>
#include <session/core/component.hpp>
#include <session/sqlite.hpp>

namespace session::core::detail {

sqlite::Connection CoreComponent::conn() {
    return core.db.conn();
}

core::callbacks& CoreComponent::cb() {
    return core.callbacks;
}

quic::Loop& CoreComponent::loop() {
    return *core._loop;
}

CoreComponent::CoreComponent(Core& core) : core{core} {
    core.register_comp_init(this);
}

}  // namespace session::core::detail
