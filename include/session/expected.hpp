#pragma once

#include <cassert>
#include <concepts>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <version>

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
#include <expected>
#endif

namespace session {

/// Why something failed, as handed to whoever asked for it.
///
/// Deliberately a code *and* prose.  The code is what a caller acts on -- a UI translating it, a
/// retry deciding whether this is worth retrying -- and the message is what it falls back to when
/// it does not recognise the code, and what ends up in a log either way.
///
/// `final` on purpose: `Expected` stores one of these by value, so a subclass handed to it would be
/// sliced with no diagnostic at all.  If an error needs to carry more, it gets more fields here
/// rather than a derived type.
///
/// Must not become convertible to `bool`: that would make `Expected<bool>{some_error}` store a
/// successful `true` rather than the error, silently, because `is_constructible_v<bool, Error>`
/// decides which constructor wins.  Ask an `Expected` whether it succeeded, not an `Error`.
class Error final {
  public:
    /// A stable identifier for what went wrong, dotted to keep them apart as they accumulate:
    /// "contacts.name_too_long".
    ///
    /// Not owned, so it must have static storage -- a literal, or one of the named constants
    /// declared beside whatever produces it.  Naming the constants rather than repeating literals
    /// is what stops a comparison being defeated by a typo at either end.
    ///
    /// An open set rather than an enum: a caller that meets a code it does not know falls back to
    /// `message`, so adding an error is not a breaking change the way another enumerator would be.
    std::string_view code;

    /// English, for a log or for a caller with no translation for `code`.  Free to name specific
    /// values; whoever translates the code works from the code and the constants it already has,
    /// not from this.
    std::string message;

    Error() = delete;
    Error(std::string_view code, std::string message) : code{code}, message{std::move(message)} {}

    /// Deleted so a `std::string` cannot be used as the code: this does not own it, and a string's
    /// buffer will not outlive the Error in the cases where anyone would reach for one.
    ///
    /// Constrained rather than a plain `Error(std::string, std::string) = delete`, which would also
    /// reject string *literals*: `const char[N]` converts to `std::string` and to
    /// `std::string_view` at the same rank, so the call becomes ambiguous before the deletion is
    /// even considered.
    template <typename S>
        requires std::same_as<std::remove_cvref_t<S>, std::string>
    Error(S&&, std::string) = delete;
};

/// Thrown by work whose failure will be reported through a handler, carrying the `Error` verbatim
/// rather than flattening it to a string.
///
/// Deferred work cannot throw to its caller -- by the time it runs there is no caller left -- so
/// the `async` wrappers catch whatever it throws and report that through the handler instead.
/// Catching `std::exception` gets only `what()`, which would lose the code; this is how a thrower
/// says what the code is.
///
/// Anything else that escapes still becomes a well-formed `Error` under
/// `unexpected_exception_code`, so a helper deep in a call stack can go on throwing
/// `std::runtime_error` and its caller still receives something a handler can act on.
class error : public std::runtime_error {
    Error _error;

  public:
    explicit error(Error e) : std::runtime_error{e.message}, _error{std::move(e)} {}

    error(std::string_view code, std::string message) : error{Error{code, std::move(message)}} {}

    /// Moving one out needs a non-const handler -- `catch (session::error& e)` and then
    /// `std::move(e).err()`.  The usual `catch (const session::error&)` can only copy.
    Error& err() & noexcept { return _error; }
    const Error& err() const& noexcept { return _error; }
    Error&& err() && noexcept { return std::move(_error); }
};

/// The code anything that was *not* a `session::error` is reported under.  Nothing should match on
/// it beyond "this was not anticipated"; the message is the only part that says anything.
inline constexpr std::string_view unexpected_exception_code = "internal.exception";

/// The `Error` a caught exception should be reported as: its own, if it brought one, and otherwise
/// a generic code carrying `what()`.
///
/// Shared so that every place converting a throw into a handler's failure does it the same way --
/// there is more than one, and they would otherwise drift.
inline Error error_from(const std::exception& e) {
    if (auto* carried = dynamic_cast<const error*>(&e))
        return carried->err();
    return Error{unexpected_exception_code, e.what()};
}

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L

/// Built with a standard library that has the real thing, so use it.
///
/// This is what keeps the local implementation below honest, and why it is written as a strict
/// subset: under C++23 every use in the project is compiled against `std::expected` itself, so a
/// use that has drifted outside the subset is a build failure rather than something review has to
/// catch.  There is nothing to keep in step by hand.
using std::unexpected;

template <typename T, typename E = Error>
using Expected = std::expected<T, E>;

#else

/// Wraps an error so that it can be told apart from a value when constructing an `Expected`.
///
/// Required rather than optional: `std::expected` refuses a bare error and takes one only through
/// this, so an `Expected` that accepted a bare `Error` would compile today and stop compiling the
/// day it becomes an alias for `std::expected`.  Mirrors `std::unexpected`, and becomes it.
template <typename E>
class unexpected {
    E _error;

  public:
    constexpr explicit unexpected(E e) : _error{std::move(e)} {}

    constexpr E& error() & noexcept { return _error; }
    constexpr const E& error() const& noexcept { return _error; }
    constexpr E&& error() && noexcept { return std::move(_error); }
    constexpr const E&& error() const&& noexcept { return std::move(_error); }
};

template <typename E>
unexpected(E) -> unexpected<E>;

namespace detail {
    template <typename T>
    inline constexpr bool is_unexpected = false;
    template <typename E>
    inline constexpr bool is_unexpected<unexpected<E>> = true;
}  // namespace detail

/// Either what was produced, or why it could not be.
///
/// **A deliberate subset of `std::expected`, and deliberately no more permissive than one.**  The
/// intent is that when this project moves to C++23 the whole class is replaced by
///
///     template <typename T, typename E = Error> using Expected = std::expected<T, E>;
///
/// without a single call site changing.  That only holds if everything this accepts,
/// `std::expected` accepts too: being stricter is free, being looser is a trap that springs years
/// later on whoever does the switch.
///
/// What keeps that honest is that the alias above is *already* taken when the standard library has
/// `std::expected` -- so building at `-DCMAKE_CXX_STANDARD=23`, which CI does, compiles every use
/// in the project against the real thing.  A use that has drifted outside the subset fails there
/// rather than waiting for whoever eventually raises the standard.
///
/// A subset: `value()`, `value_or()`, `error_or()`, the monadic operations, comparisons, `swap`,
/// `emplace` and the `in_place` constructors are not provided.
template <typename T, typename E = Error>
class Expected {
    static_assert(!std::is_reference_v<T>, "Expected cannot hold a reference");

    // Index 0 is the value, 1 the error.  Addressed by index rather than by type so that T and E
    // being the same type is not a special case.
    std::variant<T, E> _v;

  public:
    using value_type = T;
    using error_type = E;

    constexpr Expected()
        requires std::is_default_constructible_v<T>
            : _v{std::in_place_index<0>} {}

    /// Implicit exactly when `std::expected`'s is.  Making it explicit would be the safe direction
    /// for correctness and the wrong one for churn: `cb(value)` would have to be rewritten now and
    /// would compile again afterwards.
    template <typename U = T>
        requires(
                !std::is_same_v<std::remove_cvref_t<U>, Expected> &&
                !detail::is_unexpected<std::remove_cvref_t<U>> && std::is_constructible_v<T, U>)
    constexpr explicit(!std::is_convertible_v<U, T>) Expected(U&& v) :
            _v{std::in_place_index<0>, std::forward<U>(v)} {}

    template <typename G = E>
        requires std::is_constructible_v<E, const G&>
    constexpr explicit(!std::is_convertible_v<const G&, E>) Expected(const unexpected<G>& u) :
            _v{std::in_place_index<1>, u.error()} {}

    template <typename G = E>
        requires std::is_constructible_v<E, G>
    constexpr explicit(!std::is_convertible_v<G, E>) Expected(unexpected<G>&& u) :
            _v{std::in_place_index<1>, std::move(u).error()} {}

    constexpr bool has_value() const noexcept { return _v.index() == 0; }
    constexpr explicit operator bool() const noexcept { return has_value(); }

    /// Reading the value of an errored Expected is undefined, as it is for `std::expected`.  The
    /// assertion is a debug-build courtesy rather than part of the contract: relying on it to throw
    /// would be relying on behaviour that disappears at the switch.
    constexpr T& operator*() & noexcept {
        assert(has_value());
        return *std::get_if<0>(&_v);
    }
    constexpr const T& operator*() const& noexcept {
        assert(has_value());
        return *std::get_if<0>(&_v);
    }
    constexpr T&& operator*() && noexcept {
        assert(has_value());
        return std::move(*std::get_if<0>(&_v));
    }
    constexpr const T&& operator*() const&& noexcept {
        assert(has_value());
        return std::move(*std::get_if<0>(&_v));
    }

    constexpr T* operator->() noexcept {
        assert(has_value());
        return std::get_if<0>(&_v);
    }
    constexpr const T* operator->() const noexcept {
        assert(has_value());
        return std::get_if<0>(&_v);
    }

    constexpr E& error() & noexcept {
        assert(!has_value());
        return *std::get_if<1>(&_v);
    }
    constexpr const E& error() const& noexcept {
        assert(!has_value());
        return *std::get_if<1>(&_v);
    }
    constexpr E&& error() && noexcept {
        assert(!has_value());
        return std::move(*std::get_if<1>(&_v));
    }
    constexpr const E&& error() const&& noexcept {
        assert(!has_value());
        return std::move(*std::get_if<1>(&_v));
    }
};

/// The no-value case, for work that either succeeded or did not.
///
/// Default-constructed means *success*, which is what lets a handler be told "that worked" with
/// `cb({})`.  Matches `std::expected<void, E>`.
template <typename E>
class Expected<void, E> {
    std::optional<E> _error;

  public:
    using value_type = void;
    using error_type = E;

    constexpr Expected() noexcept = default;

    template <typename G = E>
        requires std::is_constructible_v<E, const G&>
    constexpr explicit(!std::is_convertible_v<const G&, E>) Expected(const unexpected<G>& u) :
            _error{u.error()} {}

    template <typename G = E>
        requires std::is_constructible_v<E, G>
    constexpr explicit(!std::is_convertible_v<G, E>) Expected(unexpected<G>&& u) :
            _error{std::move(u).error()} {}

    constexpr bool has_value() const noexcept { return !_error.has_value(); }
    constexpr explicit operator bool() const noexcept { return has_value(); }

    constexpr void operator*() const noexcept { assert(has_value()); }

    constexpr E& error() & noexcept {
        assert(!has_value());
        return *_error;
    }
    constexpr const E& error() const& noexcept {
        assert(!has_value());
        return *_error;
    }
    constexpr E&& error() && noexcept {
        assert(!has_value());
        return std::move(*_error);
    }
    constexpr const E&& error() const&& noexcept {
        assert(!has_value());
        return std::move(*_error);
    }
};

#endif  // __cpp_lib_expected

}  // namespace session
