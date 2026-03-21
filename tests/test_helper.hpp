#pragma once

#include <fmt/format.h>

#include <atomic>
#include <filesystem>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/network/key_types.hpp>
#include <session/network/session_network.hpp>
#include <session/sodium_array.hpp>
#include <session/sqlite.hpp>

namespace session {

/// A minimal in-process mock of network::Network for unit tests.
/// Tests can set `current_node` to control which node get_swarm returns, and inspect
/// `sent_requests` to observe outgoing requests and fire their callbacks.
class MockNetwork : public network::Network {
  public:
    MockNetwork() : network::Network(network::config::Config{}) {}

    struct SentRequest {
        network::Request request;
        network::network_response_callback_t callback;
    };
    std::vector<SentRequest> sent_requests;

    // The node returned by get_swarm; tests can change this to simulate swarm-member switches.
    network::service_node current_node;

    void send_request(
            network::Request request, network::network_response_callback_t callback) override {
        sent_requests.push_back({std::move(request), std::move(callback)});
    }

    void get_swarm(
            network::x25519_pubkey /*swarm_pubkey*/,
            bool /*ignore_strike_count*/,
            std::function<
                    void(network::swarm_id_t swarm_id, std::vector<network::service_node> swarm)>
                    callback) override {
        callback(0, {current_node});
    }
};

// Smart-pointer-like RAII wrapper around a Core backed by a unique temporary DB file.
// The DB file is removed on destruction.  Default encryption uses a zeroed raw_key.
struct TempCore {
    std::filesystem::path path;
    std::unique_ptr<core::Core> core;

    template <core::CoreOption... Opts>
    explicit TempCore(Opts&&... opts) :
            path{[] {
                static std::atomic<int> n{0};
                return std::filesystem::temp_directory_path() / fmt::format("test_core_{}.db", ++n);
            }()},
            core{std::make_unique<core::Core>(path, std::forward<Opts>(opts)...)} {}

    ~TempCore() {
        core.reset();  // close DB before removing the file
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }

    core::Core* operator->() { return core.get(); }
    core::Core& operator*() { return *core; }
};

class TestHelper {
  public:
    static void poll(core::Core& core) { core._poll(); }

    // Returns the last_hash stored for the given namespace+sn_pubkey pair (or nullopt if none).
    static std::optional<std::string> namespace_last_hash(
            core::Core& core, int16_t ns, const network::ed25519_pubkey& sn_pubkey) {
        return core.db.conn().prepared_maybe_get<std::string>(
                "SELECT last_hash FROM namespace_sync WHERE namespace = ? AND sn_pubkey = ?",
                ns,
                sn_pubkey);
    }

    // Returns the raw 32-byte seed for the account key identified by the given x25519 public key.
    static cleared_b32 account_key_seed(
            core::Devices& d, std::span<const unsigned char, 32> x25519_pub) {
        cleared_b32 seed;
        auto c = d.conn();
        auto blob = c.prepared_get<sqlite::blob_guts<std::array<std::byte, 32>>>(
                "SELECT seed FROM device_account_keys WHERE pubkey_x25519 = ?",
                std::as_bytes(x25519_pub));
        std::ranges::copy(blob, seed.begin());
        return seed;
    }

    // Returns the {pubkey_x25519, pubkey_mlkem768} of the active (unrotated) account key.
    static std::pair<std::array<std::byte, 32>, std::array<std::byte, 1184>> active_account_pubkeys(
            core::Core& core) {
        auto [x25519, mlkem768] =
                core.db.conn()
                        .prepared_get<
                                sqlite::blob_guts<std::array<std::byte, 32>>,
                                sqlite::blob_guts<std::array<std::byte, 1184>>>(
                                "SELECT pubkey_x25519, pubkey_mlkem768"
                                " FROM device_account_keys WHERE rotated IS NULL");
        return {x25519, mlkem768};
    }

    // Cached PFS key entry as stored in the pfs_key_cache table.
    // fetched_at and pubkeys are nullopt when the entry is a NAK (no valid keys).
    struct PfsCacheEntry {
        std::optional<int64_t> fetched_at;
        std::optional<int64_t> nak_at;
        std::optional<std::array<std::byte, 32>> pubkey_x25519;
        std::optional<std::array<std::byte, 1184>> pubkey_mlkem768;
    };

    // Returns the pfs_key_cache entry for the given session_id, or nullopt if absent.
    static std::optional<PfsCacheEntry> pfs_cache_entry(
            core::Core& core, std::span<const unsigned char, 33> session_id) {
        using X = sqlite::blob_guts<std::array<std::byte, 32>>;
        using M = sqlite::blob_guts<std::array<std::byte, 1184>>;
        auto row = core.db.conn()
                           .prepared_maybe_get<
                                   std::optional<int64_t>,
                                   std::optional<int64_t>,
                                   std::optional<X>,
                                   std::optional<M>>(
                                   "SELECT fetched_at, nak_at, pubkey_x25519, pubkey_mlkem768"
                                   " FROM pfs_key_cache WHERE session_id = ?",
                                   session_id);
        if (!row)
            return std::nullopt;
        auto [fetched_at, nak_at, pk_x25519, pk_mlkem768] = *row;
        return PfsCacheEntry{
                fetched_at,
                nak_at,
                pk_x25519 ? std::optional{(std::array<std::byte, 32>)*pk_x25519} : std::nullopt,
                pk_mlkem768 ? std::optional{(std::array<std::byte, 1184>)*pk_mlkem768}
                            : std::nullopt};
    }
};

}  // namespace session
