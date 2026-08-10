#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <session/client/conversation_id.hpp>
#include <session/client/types.hpp>
#include <vector>

namespace session::client {

/// Notifications of everything the conversation layer changes, so that an application never has to
/// ask.  A caller sets the handlers it cares about and leaves the rest empty; an unset handler is
/// simply not called.
///
/// Every handler is given the new state outright rather than an identifier to go and fetch, which
/// is what makes a display bindable without reading anything back.  It also makes applying one
/// twice harmless, which in turn makes startup race-free — see subscribe().
///
/// **Handlers run on Core's event loop**, not the caller's thread.  A handler must not block and
/// must not throw (an escaping exception is caught and logged, and the change is not redelivered).
/// A UI will typically copy the argument into its own queue and wake its render thread.
///
/// The conversation list an application maintains from these is expected to be *complete*: ordering
/// is a comparison against every other conversation, so a partial list cannot be sorted.  Showing
/// only part of it is fine, holding only part of it is not.
struct callbacks {
    /// A conversation now exists that did not before.
    std::function<void(const Conversation&)> conversation_added;

    /// A conversation's contents changed: a new or edited message, a name, an unread count, its
    /// last activity.  Fired once with the conversation's settled state rather than once per
    /// underlying change, so a poll that delivers fifty messages to one conversation fires this
    /// once.
    std::function<void(const Conversation&)> conversation_updated;

    /// A conversation is gone and should be dropped from the list.
    std::function<void(const ConversationId&)> conversation_removed;

    /// Priorities changed — a pin, unpin, hide or unhide — carrying the whole list in its new
    /// order.  A replacement rather than a description of what moved, because one config update
    /// from another device can repin, reveal and hide arbitrarily many conversations at once, and
    /// because a replacement cannot leave the application subtly out of step the way a missed
    /// delta would.
    std::function<void(std::vector<Conversation>)> conversation_list_replaced;

    /// A message was added, whether received or sent from here.
    std::function<void(const ConversationId&, const Message&)> message_added;

    /// An existing message changed — currently only its send state.
    std::function<void(const ConversationId&, const Message&)> message_updated;
};

namespace detail {
    /// Shared registry of change listeners.  Held by shared_ptr so that a Subscription outliving
    /// its Client unsubscribes harmlessly instead of writing through a dangling pointer.
    ///
    /// Guarded by a mutex because these are the one part of Client not confined to the event loop:
    /// changes are emitted from the loop thread, while subscribing and unsubscribing happen
    /// wherever the application does them -- including a Subscription destructor running on a UI
    /// thread.
    struct SignalRegistry {
        std::mutex mutex;
        uint64_t next_id = 1;
        std::map<uint64_t, callbacks> handlers;
    };
}  // namespace detail

/// RAII handle for a change subscription: the handler stays registered for as long as this object
/// is alive.  Discarding it immediately unsubscribes, hence the [[nodiscard]] on subscribe().
///
/// Movable, not copyable.  Destroying it after the Client is destroyed is safe.
class Subscription {
  public:
    Subscription() = default;
    Subscription(Subscription&& other) noexcept { *this = std::move(other); }
    Subscription& operator=(Subscription&& other) noexcept;
    Subscription(const Subscription&) = delete;
    Subscription& operator=(const Subscription&) = delete;
    ~Subscription() { reset(); }

    /// Unsubscribes now rather than at destruction.  Idempotent.
    void reset();

    /// True if this handle currently refers to a live subscription.
    explicit operator bool() const { return _id != 0 && !_registry.expired(); }

  private:
    friend class Client;
    Subscription(std::weak_ptr<detail::SignalRegistry> reg, uint64_t id) :
            _registry{std::move(reg)}, _id{id} {}

    std::weak_ptr<detail::SignalRegistry> _registry;
    uint64_t _id = 0;
};

}  // namespace session::client
