#pragma once

namespace session::sqlite {
class Connection;
}
namespace oxen::quic {
class Loop;
}  // namespace oxen::quic
namespace session::core {

namespace quic = oxen::quic;

class Core;
struct callbacks;

namespace detail {
    // Internal base class bridge between Core and the various components of core.  This bridge
    // can be used to allow components to access selected private parts of core, such as the
    // database, without needing components to be direct friends of Core.
    class CoreComponent {
      protected:
        friend class core::Core;
        Core& core;

        // Gets a thread-unique database connection from the Core's Database's connection pool. This
        // is unique to the calling thread and must not be used across threads.
        sqlite::Connection conn();

        // Returns the application callbacks registered with Core.
        core::callbacks& cb();

        // Returns the event loop for scheduling async work.
        quic::Loop& loop();

        explicit CoreComponent(Core& core);

        // Default component `init()` does nothing; classes can override this if they want to be
        // called after database migrations are complete, but still during the parent Core
        // construction.  This will be called on each CoreComponent-derived member of Core, in the
        // same order that those members were constructed (i.e. class declaration order).
        virtual void init() {}
    };

}  // namespace detail

}  // namespace session::core
