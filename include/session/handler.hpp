#pragma once

#include <functional>
#include <optional>
#include <string>

namespace session {

/// Passed where a handler would go, to say "wait until this is done and give me the answer"
/// instead.
///
/// Every asynchronous method has a blocking twin taking one of these.  The work is the same and
/// happens in the same place -- on the owning event loop -- so the only difference is who waits:
/// the twin blocks the calling thread until the answer is ready, and *throws* what the handler
/// form would have reported through its `error` argument.
///
/// A tag rather than a second class, and rather than an overload with no handler at all, because
/// the point is that it be visible where it is used.  Blocking is a decision about the calling
/// thread, so it belongs at the call site: a render loop must not do it, and a review can grep for
/// it, neither of which works when the choice was made wherever the variable was declared.
///
/// Calling one from a handler is safe rather than a deadlock -- the loop runs the work inline when
/// it is already the current thread -- but it is still waiting, and anything else the loop owes is
/// waiting behind it.  That inlining is also what lets code already on the loop use the blocking
/// form and pay nothing for it, which is why there is no third "I am already on the loop" overload
/// of anything.
struct await_t {};
inline constexpr await_t await{};

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
/// unless the object it was given to is destroyed before its work runs, so a caller is never left
/// waiting on an answer that is not coming; the error argument is how a failure says so, since a
/// call that has been dispatched has no caller left to throw to.
///
/// Written as an alias rather than spelled out at each declaration so that the convention is stated
/// once and the argument cannot be forgotten or put in the wrong place.
template <typename Sig>
using failable_function = typename detail::failable_function<Sig>::type;

}  // namespace session
