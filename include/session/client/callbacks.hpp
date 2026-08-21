#pragma once

#include <functional>
#include <optional>
#include <session/client/conversation.hpp>
#include <session/client/conversation_id.hpp>
#include <session/client/message.hpp>
#include <string>
#include <vector>

namespace session::client {

/// Runs a job on the application's own thread.
///
/// Client does its work on Core's event loop and, given one of these, hands everything it has to
/// say to the application over to it rather than calling from that loop.  An application with a
/// loop of its own -- Qt, node, GTK -- supplies the one-line transfer it already has, and is then
/// free to touch its own state in every handler without marshalling in each one.
///
/// It must not run the job inline, which would defeat the point, and it must preserve the order
/// jobs are given to it: what Client reports is a sequence, and delivering it out of order shows
/// an older state on top of a newer one.
///
/// Everything Client calls outward goes through it -- the change notifications and the handlers
/// passed to individual calls alike -- so an application never has to reason about which of its
/// handlers arrive on which thread.  Without one, everything runs on Core's loop, which is what a
/// program with no loop of its own wants.
using dispatcher = std::function<void(std::function<void()>)>;

namespace detail {
    template <typename Sig>
    struct failable_function;

    template <typename... A>
    struct failable_function<void(A...)> {
        using type = std::function<void(std::optional<std::string> error, A...)>;
    };
}  // namespace detail

/// A handler an application passes to one of Client's asynchronous methods, written in terms of
/// what that method produces: `failable_function<void(int64_t message_id)>` is a handler taking a
/// message id.
///
/// What it adds is the leading `error` argument every one of them carries -- unset when the call
/// succeeded, and otherwise saying what went wrong.  Every such handler is invoked exactly once,
/// unless the Client is destroyed before its work runs, so a caller is never left waiting on an
/// answer that is not coming; the error argument is how a failure says so, since a call that has
/// been dispatched has no caller left to throw to.
///
/// Written as an alias rather than spelled out at each declaration so that the convention is stated
/// once and the argument cannot be forgotten or put in the wrong place.
template <typename Sig>
using failable_function = typename detail::failable_function<Sig>::type;

/// Notifications of everything the conversation layer changes, so that an application never has to
/// ask.  A caller sets the handlers it cares about and leaves the rest empty; an unset handler is
/// simply not called.
///
/// Every handler is given the new state outright rather than an identifier to go and fetch, which
/// is what makes a display bindable without reading anything back.  It also makes applying one
/// twice harmless, which in turn makes startup race-free — see the Client constructor.
///
/// Handed to Client at construction and fixed thereafter, exactly as core::callbacks is.  There is
/// deliberately no way to register a second set: a process that wants to fan these out to somewhere
/// else — a notification daemon, a log — does that fanning out itself, which it has to anyway once
/// the other end is a separate process.
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
    std::function<void(const AnyConversation&)> conversation_added;

    /// A conversation's contents changed: a new or edited message, a name, an unread count, its
    /// last activity.  Fired once with the conversation's settled state rather than once per
    /// underlying change, so a poll that delivers fifty messages to one conversation fires this
    /// once.
    std::function<void(const AnyConversation&)> conversation_updated;

    /// A conversation is gone and should be dropped from the list.
    std::function<void(const ConversationId&)> conversation_removed;

    /// Priorities changed — a pin, unpin, hide or unhide — carrying the whole list in its new
    /// order.  A replacement rather than a description of what moved, because one config update
    /// from another device can repin, reveal and hide arbitrarily many conversations at once, and
    /// because a replacement cannot leave the application subtly out of step the way a missed
    /// delta would.
    std::function<void(std::vector<AnyConversation>)> conversation_list_replaced;

    /// The message requests changed, carrying the whole list of them, for the same reasons and with
    /// the same guarantees as the above.
    ///
    /// The two lists are disjoint and a conversation moves between them, so approving one fires
    /// both: it left the requests and joined the conversations.  `conversation_added` and the rest
    /// are shared between them — a request is a conversation in every respect except which list it
    /// belongs to — and `Conversation::request` is what says which one a given handler is about.
    std::function<void(std::vector<AnyConversation>)> request_list_replaced;

    /// A message was added, whether received or sent from here.
    std::function<void(const ConversationId&, const Message&)> message_added;

    /// An existing message changed — currently only its send state.
    std::function<void(const ConversationId&, const Message&)> message_updated;

    /// Messages were deleted from a conversation, and anything displaying its history should read
    /// it again.
    ///
    /// Unlike `conversation_list_replaced` this carries only the conversation and not the messages
    /// themselves: a history is unbounded, and an application showing one page of it has no use for
    /// the rest.  What deletes messages is a delete-before instruction, which can take any number
    /// of them at once and is not otherwise describable as a sequence of removals.
    std::function<void(const ConversationId&)> history_replaced;
};

}  // namespace session::client
