#include <catch2/catch_test_macros.hpp>
#include <session/expected.hpp>
#include <session/handler.hpp>
#include <string>
#include <utility>
#include <vector>

using namespace session;

namespace {

constexpr std::string_view test_code = "test.something_went_wrong";

Error an_error() {
    return Error{test_code, "something went wrong"};
}

/// Moving out of an Expected has to actually move, which a copy would hide.
struct MoveOnly {
    std::string s;
    MoveOnly(std::string s) : s{std::move(s)} {}
    MoveOnly(MoveOnly&&) = default;
    MoveOnly& operator=(MoveOnly&&) = default;
    MoveOnly(const MoveOnly&) = delete;
};

}  // namespace

TEST_CASE("Expected: carries either a value or an error", "[expected]") {
    SECTION("a value") {
        Expected<std::string> r{"hi"};
        REQUIRE(r.has_value());
        CHECK(static_cast<bool>(r));
        CHECK(*r == "hi");
        CHECK(r->size() == 2);
    }

    SECTION("an error") {
        Expected<std::string> r{unexpected{an_error()}};
        REQUIRE_FALSE(r.has_value());
        CHECK_FALSE(static_cast<bool>(r));
        CHECK(r.error().code == test_code);
        CHECK(r.error().message == "something went wrong");
    }

    SECTION("nothing at all, which is success") {
        Expected<void> r{};
        CHECK(r.has_value());
        CHECK(static_cast<bool>(r));
    }

    SECTION("nothing at all, which is failure") {
        Expected<void> r{unexpected{an_error()}};
        CHECK_FALSE(r.has_value());
        CHECK(r.error().code == test_code);
    }
}

TEST_CASE("Expected: value access keeps its category", "[expected]") {
    // The ref-qualified overloads are not polish: if `*std::move(r)` handed back a `T&` where
    // std::expected hands back a `T&&`, ours would be the more permissive of the two and code
    // written against it would stop compiling the day this becomes an alias.
    Expected<std::string> r{"hi"};
    const Expected<std::string> cr{"hi"};

    static_assert(std::is_same_v<decltype(*r), std::string&>);
    static_assert(std::is_same_v<decltype(*cr), const std::string&>);
    static_assert(std::is_same_v<decltype(*std::move(r)), std::string&&>);
    static_assert(std::is_same_v<decltype(*std::move(cr)), const std::string&&>);

    static_assert(std::is_same_v<decltype(r.operator->()), std::string*>);
    static_assert(std::is_same_v<decltype(cr.operator->()), const std::string*>);

    Expected<std::string> e{unexpected{an_error()}};
    const Expected<std::string> ce{unexpected{an_error()}};
    static_assert(std::is_same_v<decltype(e.error()), Error&>);
    static_assert(std::is_same_v<decltype(ce.error()), const Error&>);
    static_assert(std::is_same_v<decltype(std::move(e).error()), Error&&>);
    static_assert(std::is_same_v<decltype(std::move(ce).error()), const Error&&>);

    // And it really moves rather than copying.
    Expected<MoveOnly> m{MoveOnly{"owned"}};
    auto taken = *std::move(m);
    CHECK(taken.s == "owned");
}

TEST_CASE("Expected: an error is not mistaken for a value", "[expected]") {
    // The reason Error has no operator bool.  With one, `is_constructible_v<bool, Error>` is true,
    // and `Expected<bool>{some_error}` quietly stores a *successful* `true` -- which six of this
    // codebase's handlers would have been exposed to.
    static_assert(!std::is_constructible_v<Expected<bool>, Error>);
    static_assert(!std::is_convertible_v<Error, Expected<bool>>);

    // A bare Error is refused for any T, because std::expected refuses one and accepting it here
    // would compile now and fail at the switch.
    static_assert(!std::is_constructible_v<Expected<std::string>, Error>);

    Expected<bool> r{unexpected{an_error()}};
    REQUIRE_FALSE(r.has_value());

    Expected<bool> t{true};
    REQUIRE(t.has_value());
    CHECK(*t);
}

TEST_CASE(
        "Expected: value construction is implicit exactly where std::expected's is", "[expected]") {
    // Implicit, so `cb(value)` keeps working and will keep working afterwards.
    static_assert(std::is_convertible_v<std::string, Expected<std::string>>);
    static_assert(std::is_convertible_v<int64_t, Expected<int64_t>>);

    Expected<std::vector<int>> r = std::vector<int>{1, 2, 3};
    REQUIRE(r.has_value());
    CHECK(r->size() == 3);

    // Expected<void> has no value to construct from, only success or an error.
    static_assert(std::is_default_constructible_v<Expected<void>>);
    static_assert(!std::is_constructible_v<Expected<void>, int>);
}

TEST_CASE("Error: a code must outlive the Error", "[expected][error]") {
    // A std::string code is rejected: the Error does not own it.  Constrained rather than a plain
    // deleted overload, which would make string literals ambiguous and reject those too.
    static_assert(std::is_constructible_v<Error, const char(&)[6], std::string>);
    static_assert(!std::is_constructible_v<Error, std::string, std::string>);
    static_assert(!std::is_constructible_v<Error, std::string&, std::string>);
    static_assert(!std::is_constructible_v<Error, const std::string&, std::string>);

    // A literal and a constant both work, which is the whole point of constraining it.
    Error from_literal{"a.b", "boom"};
    Error from_constant{test_code, "boom"};
    CHECK(from_literal.code == "a.b");
    CHECK(from_constant.code == test_code);

    // And there is no default: an Error with no code would compare equal to nothing and mean
    // nothing.
    static_assert(!std::is_default_constructible_v<Error>);
}

TEST_CASE("result_function: one parameter, whatever it carries", "[expected][handler]") {
    std::optional<std::string> got;
    std::optional<Error> failed;

    result_function<std::string> on_name = [&](Expected<std::string> r) {
        if (r)
            got = *std::move(r);
        else
            failed = std::move(r).error();
    };

    on_name(std::string{"Leia"});
    CHECK(got == "Leia");
    CHECK_FALSE(failed);

    got.reset();
    on_name(unexpected{an_error()});
    CHECK_FALSE(got);
    REQUIRE(failed);
    CHECK(failed->code == test_code);

    // The no-value form: success is `{}`, which is what makes `cb({})` read as "that worked".
    int succeeded = 0;
    result_function<> on_done = [&](Expected<void> r) {
        if (r)
            succeeded++;
    };
    on_done({});
    on_done(unexpected{an_error()});
    CHECK(succeeded == 1);
}
