#pragma once

#include <functional>
#include <optional>
#include <string>

namespace session::client {

/// Passed where a handler would go, to say "wait for this and give me the answer" instead.
///
/// Every asynchronous method has a blocking twin taking one of these.  The work is the same and
/// happens in the same place -- on Core's loop -- so the only difference is who waits: the twin
/// blocks the calling thread until the answer is ready, and *throws* what the handler form would
/// have reported through its `error` argument.
///
/// A tag rather than a second class, and rather than an overload with no handler at all, because
/// the point is that it be visible where it is used.  Waiting is a decision about the calling
/// thread, so it belongs at the call site: a render loop must not do it, and a review can grep for
/// it, neither of which works when the choice was made wherever the variable was declared.
///
/// Calling one from a Client handler is safe rather than a deadlock -- the loop runs the work
/// inline when it is already the current thread -- but it is still waiting, and anything else the
/// loop owes is waiting behind it.
struct wait_t {};
inline constexpr wait_t wait{};

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

/// A handler an application passes to one of the asynchronous methods, written in terms of what
/// that method produces: `failable_function<void(int64_t message_id)>` is a handler taking a
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

}  // namespace session::client
