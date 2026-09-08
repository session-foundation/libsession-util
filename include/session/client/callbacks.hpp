#pragma once

#include <functional>
#include <optional>
#include <session/client/attachment.hpp>
#include <session/client/conversation.hpp>
#include <session/client/conversation_id.hpp>
#include <session/client/handler.hpp>
#include <session/client/message.hpp>
#include <string>
#include <vector>

namespace session::client {

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
/// What a handler receives is its own: it was read for this delivery and nothing else holds it, so
/// a UI moves it into its own queue and wakes its render thread.  The signatures say which is
/// which — what is given is taken by rvalue reference, what is lent by `const&`.  The two progress
/// handlers are the ones that lend, because they report repeatedly against one captured id and a
/// handler that moved from it would empty what the next report needs.
///
/// A handler may declare such a parameter as `T&&`, `const T&` or `T`, whichever suits it: only the
/// last constructs anything, and a handler that just reads pays nothing.  (`T&` is the one form
/// that will not bind.)  The `&&` is not perfect forwarding despite the spelling — `std::function`
/// is not a template on its argument — it is a promise by the caller that the object is spent
/// afterwards.
///
/// The conversation list an application maintains from these is expected to be *complete*: the
/// order is given as a whole list, so a partial one cannot be placed in it.  Showing only part of
/// it is fine, holding only part of it is not.
///
/// The order itself is **ours, not the application's**.  Every handler that carries a list carries
/// it already ordered, and `conversation_order_updated` reports a change to that order without
/// re-sending the rows — so an application never has to sort, and should not, because the two
/// lists are not sorted the same way and a comparator copied from one gets the other wrong.
struct callbacks {
    /// A conversation now exists that did not before.
    std::function<void(AnyConversation&&)> conversation_added;

    /// A conversation's contents changed: a new or edited message, a name, an unread count, its
    /// last activity.  Fired once with the conversation's settled state rather than once per
    /// underlying change, so a poll that delivers fifty messages to one conversation fires this
    /// once.
    std::function<void(AnyConversation&&)> conversation_updated;

    /// A conversation is gone and should be dropped from the list.
    std::function<void(ConversationId&&)> conversation_removed;

    /// Priorities changed — a pin, unpin, hide or unhide — carrying the whole list in its new
    /// order.  A replacement rather than a description of what moved, because one config update
    /// from another device can repin, reveal and hide arbitrarily many conversations at once, and
    /// because a replacement cannot leave the application subtly out of step the way a missed
    /// delta would.
    std::function<void(std::vector<AnyConversation>&&)> conversation_list_replaced;

    /// The message requests changed, carrying the whole list of them, for the same reasons and with
    /// the same guarantees as the above.
    ///
    /// The two lists are disjoint and a conversation moves between them, so approving one fires
    /// both: it left the requests and joined the conversations.  `conversation_added` and the rest
    /// are shared between them — a request is a conversation in every respect except which list it
    /// belongs to — and `Conversation::request` is what says which one a given handler is about.
    std::function<void(std::vector<AnyConversation>&&)> request_list_replaced;

    /// One list's order changed, carrying that list's conversation ids in their new order and
    /// nothing else.
    ///
    /// This is the cheap counterpart to the two `_list_replaced` handlers above.  What moves a
    /// conversation is `last_activity` and `priority`, and by far the most common thing that moves
    /// one is a message arriving — which also changes the row, so `conversation_updated` already
    /// carries the new snippet and unread count.  Sending the whole list again to say the row is
    /// now first would send every field of every other row to describe a change to one, and would
    /// send that row's snippet twice.
    ///
    /// So the division is: **`conversation_updated` says what a row now contains,
    /// `conversation_order_updated` says where the rows now are.**  A subscriber applying both has
    /// the same state a replacement would have given it.
    ///
    /// Only fired when the order actually differs from what was last reported, which is what makes
    /// it cheap in the common case: a message into the conversation already at the top of the list
    /// leaves it at the top, and nothing is sent at all.
    ///
    /// Ordering guarantee, which a subscriber is entitled to rely on: any `conversation_added`,
    /// `conversation_updated` or `conversation_removed` for the rows involved is delivered
    /// **before** this, so the ids here always name conversations the subscriber has already been
    /// told about.  An id in here that the subscriber does not hold — or one it holds that is
    /// absent — therefore means a notification was missed, and is worth treating as a reason to
    /// re-read the list rather than as a state to reconcile.
    std::function<void(std::vector<ConversationId>)> conversation_order_updated;

    /// The same, for the message request list, and separate for the same reason
    /// `request_list_replaced` is: the two lists are disjoint and are not even ordered the same way
    /// — conversations by `priority DESC, last_activity DESC, id` and requests by
    /// `last_activity DESC, id`, with no priority term, because a request cannot be pinned.
    ///
    /// A conversation only ever sits in one of the two, so a message arriving fires exactly one of
    /// these.  Approval moves a row between the lists, which is a change of membership rather than
    /// of order, and is still reported as a replacement of both.
    std::function<void(std::vector<ConversationId>)> request_order_updated;

    /// A message was added, whether received or sent from here.
    std::function<void(ConversationId&&, Message&&)> message_added;

    /// An existing message changed — currently only its send state.
    std::function<void(ConversationId&&, Message&&)> message_updated;

    /// Messages were deleted from a conversation, and anything displaying its history should read
    /// it again.
    ///
    /// Unlike `conversation_list_replaced` this carries only the conversation and not the messages
    /// themselves: a history is unbounded, and an application showing one page of it has no use for
    /// the rest.  What deletes messages is a delete-before instruction, which can take any number
    /// of them at once and is not otherwise describable as a sequence of removals.
    std::function<void(ConversationId&&)> history_replaced;

    /// An attachment is being fetched that nobody asked for — see `Conversation::auto_download`.
    ///
    /// Only for background fetches.  A `save_attachment` reports to the caller that started it, and
    /// does not come through here: this handler means "something is happening you did not ask for",
    /// which is exactly what a display has no other way of learning.
    ///
    /// The first report of a transfer arrives when it is *started*, before anything has been sent
    /// to a server, carrying 0 of 0 — so a row can show that a fetch is beginning rather than
    /// appearing to do nothing until the first bytes land.  Exactly one report carries a `result`.
    ///
    /// Reports are rate limited (see `set_dispatch_interval`) to keep the cost off the
    /// application's thread.  That is all the limiting is for: how often a spinner turns is the
    /// application's own business, and it should not be reading motion into the arrival of these.
    std::function<void(const ConversationId&, const AttachmentProgress&)> attachment_progress;

    /// The same, for a display picture, which belongs to a conversation rather than to a message —
    /// so it carries no message or index and gets its own handler rather than a struct with two
    /// fields that are never filled in.
    ///
    /// Display pictures are always fetched, with no setting to turn that off, so this fires for
    /// every one that is not already cached.
    std::function<void(
            const ConversationId&, int64_t done, int64_t total, std::optional<int> result)>
            display_picture_progress;
};

}  // namespace session::client
