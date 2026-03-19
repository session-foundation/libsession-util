#pragma once

#include <session/core.hpp>

namespace session {

class TestHelper {
public:
    static void poll(core::Core& core) {
        core._poll();
    }
};

} // namespace session
