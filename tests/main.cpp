#include <catch2/catch_session.hpp>
#include <oxen/log.hpp>

std::string g_test_pro_backend_dev_server_url = "http://127.0.0.1:5000";

int main(int argc, char* argv[]) {
    Catch::Session session;

    using namespace Catch::Clara;
    std::string log_level = "critical", log_file = "stderr";
    bool test_case_tracing = false;

    auto cli = session.cli() |
               Opt(log_level,
                   "level")["--log-level"]("oxen-logging log level to apply to the test run") |
               Opt(log_file, "file")["--log-file"](
                       "oxen-logging log file to output logs to, or one of  or one of "
                       "stdout/-/stderr/syslog.") |
               Opt(test_case_tracing)["-T"]["--test-tracing"](
                       "enable oxen log tracing of test cases/sections") |
               Opt(g_test_pro_backend_dev_server_url, "url")["--pro-backend-dev-server-url"](
                       "URL to a SESH_PRO_BACKEND_DEV=1 enabled Session Pro Backend server. Only "
                       "used if compiled with -D TEST_PRO_BACKEND_WITH_DEV_SERVER=1 support");

    session.cli(cli);

    if (int rc = session.applyCommandLine(argc, argv); rc != 0)
        return rc;

    auto lvl = oxen::log::level_from_string(log_level);

    constexpr std::array print_vals = {
            "stdout", "-", "", "stderr", "nocolor", "stdout-nocolor", "stderr-nocolor"};
    oxen::log::Type type;
    if (std::count(print_vals.begin(), print_vals.end(), log_file))
        type = oxen::log::Type::Print;
    else if (log_file == "syslog")
        type = oxen::log::Type::System;
    else
        type = oxen::log::Type::File;

    oxen::log::add_sink(
            type, log_file, "[%T.%f] [%*] [\x1b[1m%n\x1b[0m:%^%l%$|\x1b[3m%g:%#\x1b[0m] %v");
    oxen::log::reset_level(lvl);

    oxen::log::set_level(
            oxen::log::Cat("testcase"),
            test_case_tracing ? oxen::log::Level::trace : oxen::log::Level::off);

    return session.run();
}
