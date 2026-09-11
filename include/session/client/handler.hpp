#pragma once

#include <functional>
#include <session/handler.hpp>

namespace session::client {

/// These are `session::`'s, and are used unqualified throughout this namespace.  They live one
/// level up because Core's components hand out the same shapes with the same convention, and Core
/// cannot depend on Client.  See <session/handler.hpp> for what each one means.
using session::await;
using session::await_t;
using session::failable_function;

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

}  // namespace session::client
