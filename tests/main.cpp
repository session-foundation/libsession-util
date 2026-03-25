#include <catch2/catch_session.hpp>
#include <oxen/log.hpp>

#include "log_setup.hpp"

std::string g_test_pro_backend_dev_server_url = "http://127.0.0.1:5000";

int main(int argc, char* argv[]) {
    Catch::Session session;

    using namespace Catch::Clara;
    LogSetup log;
    bool test_case_tracing = false;

    auto cli = session.cli() | log.opts() |
               Opt(test_case_tracing)["-T"]["--test-tracing"](
                       "enable oxen log tracing of test cases/sections") |
               Opt(g_test_pro_backend_dev_server_url, "url")["--pro-backend-dev-server-url"](
                       "URL to a SESH_PRO_BACKEND_DEV=1 enabled Session Pro Backend server. Only "
                       "used if compiled with -D TEST_PRO_BACKEND_WITH_DEV_SERVER=1 support");

    session.cli(cli);

    if (int rc = session.applyCommandLine(argc, argv); rc != 0)
        return rc;

    log.apply();

    oxen::log::set_level(
            oxen::log::Cat("testcase"),
            test_case_tracing ? oxen::log::Level::trace : oxen::log::Level::off);

    return session.run();
}
