#include <cstdint>
#include <filesystem>
#include <lokinet.hpp>
#include <oxen/log.hpp>
#include <thread>

using namespace std::literals;

namespace session {

namespace log = oxen::log;
static auto logcat = log::Cat("session_lokinet");

void test_me(std::string target, uint16_t port) {
    lokinet::Lokinet loki{std::filesystem::path{"lokinet.ini"}};
    // lokinet::Lokinet loki{lokinet::Network::TESTNET};
    std::this_thread::sleep_for(5s);
    std::string ignored;
    log::info(logcat, "STARTING LOKINET SESSION TO {}:{}", target, port);
    try {
        auto udp_info = loki.establish_udp_blocking(target, port);
        log::info(
                logcat,
                "Session established: localhost:{} is now mapped to {}:{} for the next 60s",
                udp_info.local_port,
                target,
                port);
    } catch (const std::exception& e) {
        log::error(logcat, "Error establishing session to {}: {}", target, e.what());
    }

    std::this_thread::sleep_for(1min);
}

}  // namespace session
