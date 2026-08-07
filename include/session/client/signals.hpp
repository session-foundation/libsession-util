#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <session/client/conversation_id.hpp>

namespace session::client {

/// What changed.  Every Change names the conversation it happened in, so a listener that only cares
/// about one conversation can filter on that field alone without consulting the database.
enum class ChangeType {
    /// A message was added to the conversation.  `message_id` is set.  Fires for both received and
    /// locally-sent messages.
    new_message,

    /// An existing message changed — currently only its send state.  `message_id` is set.
    message_updated,

    /// Conversation metadata changed: display name, unread count, last activity, draft.  Fires
    /// alongside (after) new_message, since a new message also moves the conversation.
    conversation_updated,

    /// The conversation was created.  Always followed by whatever change created it.
    conversation_added,
};

struct Change {
    ChangeType type;
    ConversationId conversation;

    /// Set for new_message and message_updated; nullopt otherwise.
    std::optional<int64_t> message_id;
};

namespace detail {
    /// Shared registry of change listeners.  Held by shared_ptr so that a Subscription outliving
    /// its Client unsubscribes harmlessly instead of writing through a dangling pointer.
    struct SignalRegistry {
        uint64_t next_id = 1;
        std::map<uint64_t, std::function<void(const Change&)>> handlers;
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
