#pragma once

#include <fmt/format.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <atomic>
#include <filesystem>
#include <future>
#include <memory>
#include <nlohmann/json.hpp>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/network/network_opt.hpp>
#include <session/network/session_network.hpp>
#include <session/network/session_network_types.hpp>
#include <session/util.hpp>

#include "../test_helper.hpp"

using namespace std::literals;

// Defined in live/main.cpp; consumed here and in all live test files.
extern session::network::opt::router live_router_mode;

// Creates a Network instance pointed at testnet using the current live_router_mode.
inline std::shared_ptr<session::network::Network> make_testnet_network(
        std::filesystem::path cache_dir) {
    return std::make_shared<session::network::Network>(
            session::network::opt::netid::testnet(),
            live_router_mode,
            session::network::opt::cache_directory{std::move(cache_dir)});
}

// Creates a session::TempCore connected to a fresh testnet Network.  A unique temporary directory
// is created for the network's snode-pool cache and stored in session::TempCore::extra_dir so it is
// removed when the session::TempCore is destroyed.  All CoreOption arguments are forwarded to the
// session::TempCore constructor (e.g. predefined_seed, encryption options).
template <session::core::CoreOption... Opts>
inline session::TempCore make_live_core(Opts&&... opts) {
    static std::atomic<int> n{0};
    auto cache_dir = std::filesystem::temp_directory_path() / fmt::format("live_net_cache_{}", ++n);
    std::filesystem::create_directories(cache_dir);

    session::TempCore tc{std::forward<Opts>(opts)...};
    tc.extra_dir = cache_dir;
    tc->set_network(make_testnet_network(std::move(cache_dir)));
    return tc;
}

// Builds the JSON params body for a signed "store" request targeting Core's AccountPubkeys
// namespace.  The returned bytes are the raw params (no "method"/"params" wrapper); the network
// routing layer adds the wrapper as required by the transport.
//
// See session-storage-server client_rpc_endpoints.h for the store endpoint spec.
inline std::vector<unsigned char> build_account_pubkeys_store_params(session::core::Core& core) {
    auto session_id_hex = oxenc::to_hex(core.globals.session_id());
    auto now_ms = session::epoch_ms(session::clock_now_ms());
    constexpr auto ns = static_cast<int16_t>(session::config::Namespace::AccountPubkeys);

    // Signature covers: "store" || namespace (decimal) || sig_timestamp (decimal)
    auto to_sign = fmt::format("store{}{}", ns, now_ms);
    std::array<unsigned char, 64> sig;
    auto seed = core.globals.account_seed();
    crypto_sign_ed25519_detached(
            sig.data(),
            nullptr,
            reinterpret_cast<const unsigned char*>(to_sign.data()),
            to_sign.size(),
            seed.ed25519_secret().data());

    auto msg = core.devices.build_account_pubkey_message();

    nlohmann::json params = {
            {"pubkey", session_id_hex},
            {"pubkey_ed25519", core.globals.pubkey_ed25519().hex()},
            {"namespace", ns},
            {"data",
             oxenc::to_base64(
                     std::string_view{reinterpret_cast<const char*>(msg.data()), msg.size()})},
            {"timestamp", now_ms},
            {"sig_timestamp", now_ms},
            {"signature", oxenc::to_base64(sig)},
            {"ttl", int64_t{2592000000}},  // 30 days in ms
    };
    return session::to_vector<unsigned char>(params.dump());
}

// Pushes Core's AccountPubkeys message to its swarm.  Resolves the swarm, sends the signed store
// request, and blocks until the response arrives or the timeout elapses.
// Returns true if the store was accepted by the swarm node.
inline bool store_account_pubkeys(
        session::core::Core& core, std::chrono::milliseconds timeout = 30s) {
    using namespace session::network;
    using namespace std::chrono_literals;

    auto net = core.network();
    if (!net)
        throw std::logic_error{"store_account_pubkeys called without a network object"};

    auto promise = std::make_shared<std::promise<bool>>();
    auto future = promise->get_future();

    auto body = build_account_pubkeys_store_params(core);

    net->get_swarm(
            core.globals.pubkey_x25519(),
            false,
            [promise, net, body = std::move(body)](
                    swarm_id_t, std::vector<service_node> swarm) mutable {
                if (swarm.empty()) {
                    promise->set_value(false);
                    return;
                }
                net->send_request(
                        Request{swarm.front(),
                                "store",
                                std::move(body),
                                RequestCategory::standard_small,
                                5s},
                        [promise](bool success, bool, int16_t, auto, auto) {
                            promise->set_value(success);
                        });
            });

    return future.wait_for(timeout) == std::future_status::ready && future.get();
}
