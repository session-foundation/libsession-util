#include <session/logging.h>

#include <catch2/catch_test_macros.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/network.hpp>
#include <regex>
#include <session/logging.hpp>

using namespace session;
using namespace oxen;
using namespace oxen::log::literals;

std::regex timestamp_re{R"(\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\] \[\+[\d.hms]+\])"};
// Clears timestamps out of a log statement for testing reproducibility
std::string fixup_log(std::string_view log) {
    std::string fixed;
    std::regex_replace(
            std::back_inserter(fixed),
            log.begin(),
            log.end(),
            timestamp_re,
            "[<timestamp>] [<reltime>]",
            std::regex_constants::format_first_only);
    return fixed;
}

std::vector<std::string> simple_logs;
std::vector<std::string> full_logs;  // "cat|level|msg"

TEST_CASE("Logging callbacks", "[logging]") {
    oxen::log::clear_sinks();
    simple_logs.clear();
    full_logs.clear();
    session::logger_reset_level(LogLevel::info);

    SECTION("C++ lambdas") {
        session::add_logger([&](std::string_view msg) { simple_logs.emplace_back(msg); });
        session::add_logger([&](auto msg, auto cat, auto level) {
            full_logs.push_back("{}|{}|{}"_format(cat, level.to_string(), msg));
        });
    }
    SECTION("C function pointers") {
        session_add_logger_simple(
                [](const char* msg, size_t msglen) { simple_logs.emplace_back(msg, msglen); });
        session_add_logger_full([](const char* msg,
                                   size_t msglen,
                                   const char* cat,
                                   size_t cat_len,
                                   LOG_LEVEL level) {
            full_logs.push_back("{}|{}|{}"_format(
                    std::string{cat, cat_len},
                    oxen::log::to_string(static_cast<log::Level>(level)),
                    std::string{msg, msglen}));
        });
    }

    log::critical(log::Cat("test.a"), "abc {}", 21 * 2);
#if defined(__APPLE__) && defined(__clang__)
#else
    int line0 = __LINE__ - 3;
#endif
    log::info(log::Cat("test.b"), "hi");
#if defined(__APPLE__) && defined(__clang__)
#else
    int line1 = __LINE__ - 3;
#endif

    oxen::log::clear_sinks();

    REQUIRE(simple_logs.size() == 2);
    REQUIRE(full_logs.size() == 2);

#if defined(__APPLE__) && defined(__clang__)
    CHECK(fixup_log(simple_logs[0]) ==
          "[<timestamp>] [<reltime>] [test.a:critical|log.hpp:177] abc 42\n");
    CHECK(fixup_log(simple_logs[1]) == "[<timestamp>] [<reltime>] [test.b:info|log.hpp:98] hi\n");
    CHECK(fixup_log(full_logs[0]) ==
          "test.a|critical|[<timestamp>] [<reltime>] [test.a:critical|log.hpp:177] abc 42\n");
    CHECK(fixup_log(full_logs[1]) ==
          "test.b|info|[<timestamp>] [<reltime>] [test.b:info|log.hpp:98] hi\n");
#else
    CHECK(fixup_log(simple_logs[0]) ==
          "[<timestamp>] [<reltime>] [test.a:critical|tests/test_logging.cpp:{}] abc 42\n"_format(
                  line0));
    CHECK(fixup_log(simple_logs[1]) ==
          "[<timestamp>] [<reltime>] [test.b:info|tests/test_logging.cpp:{}] hi\n"_format(line1));
    CHECK(fixup_log(full_logs[0]) ==
          "test.a|critical|[<timestamp>] [<reltime>] [test.a:critical|tests/test_logging.cpp:{}] abc 42\n"_format(
                  line0));
    CHECK(fixup_log(full_logs[1]) ==
          "test.b|info|[<timestamp>] [<reltime>] [test.b:info|tests/test_logging.cpp:{}] hi\n"_format(
                  line1));
#endif
}

TEST_CASE("Logging callbacks with quic::Network", "[logging][network]") {
    oxen::log::clear_sinks();
    simple_logs.clear();
    session::logger_set_level("quic", LogLevel::debug);

    session::add_logger([&](std::string_view msg) { simple_logs.emplace_back(msg); });

    { quic::Network net; }

    oxen::log::clear_sinks();

    CHECK(simple_logs.size() >= 2);
    // CHECK(simple_logs == std::vector<std::string>{"uncomment me to fail showing all log lines"});
#if defined(__APPLE__) && defined(__clang__) && defined(RELEASE_BUILD)
    CHECK(simple_logs.front().find("Started libevent") != std::string::npos);
#else
    CHECK(simple_logs.front().find("Starting libevent") != std::string::npos);
#endif
    CHECK(simple_logs.back().find("Loop shutdown complete") != std::string::npos);
}
