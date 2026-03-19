#include <fmt/format.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/core/globals.hpp>
#include <session/xed25519.hpp>

#include "test_helper.hpp"
#include "utils.hpp"

using namespace session;
using namespace session::core;
using namespace std::literals;

static constexpr std::array<std::byte, 32> test_key_bytes{};

// Smart-pointer-like wrapper around a unique_ptr<Core> with RAII cleanup of the temp DB file.
struct TempCore {
    std::filesystem::path path;
    std::unique_ptr<Core> core;

    explicit TempCore(core::callbacks cb = {}) :
            path{[] {
                static std::atomic<int> n{0};
                return std::filesystem::temp_directory_path() /
                       fmt::format("test_core_devices_{}.db", ++n);
            }()},
            core{std::make_unique<Core>(std::move(cb), path, sqlite::raw_key{test_key_bytes})} {}

    ~TempCore() {
        core.reset();  // close DB before removing the file
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }

    Core* operator->() { return core.get(); }
    Core& operator*() { return *core; }
};

TEST_CASE("Devices - identity", "[core][devices]") {
    TempCore c;

    SECTION("device_id is 64-char hex") {
        auto id = c->devices.device_id();
        REQUIRE(id.size() == 64);
        CHECK(std::all_of(id.begin(), id.end(), [](char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        }));
    }

    SECTION("device_id is stable") {
        CHECK(c->devices.device_id() == c->devices.device_id());
    }

    SECTION("two independent cores have different device IDs") {
        TempCore c2;
        CHECK(c->devices.device_id() != c2->devices.device_id());
    }
}

TEST_CASE("Devices - initial state", "[core][devices]") {
    TempCore c;

    SECTION("device_info defaults") {
        auto [info, is_registered] = c->devices.device_info();
        // seqno == 0 is the sentinel meaning no row exists yet
        CHECK(info.seqno == 0);
        CHECK_FALSE(is_registered);
    }

    SECTION("devices() is empty") {
        CHECK(c->devices.devices(true, true, true).empty());
    }

    SECTION("needs_push is false") {
        auto np = c->devices.needs_push();
        CHECK_FALSE(np.device_group);
        CHECK_FALSE(np.account_pubkey);
    }
}

TEST_CASE("Devices - update_info and same_user_fields", "[core][devices]") {
    TempCore c;

    SECTION("update_info persists fields and sets seqno=1") {
        device::Info info{};
        info.type = device::Type::Session_iOS;
        info.description = "test phone";
        info.version = {1, 2, 3};

        c->devices.update_info(info);

        auto [got, is_registered] = c->devices.device_info();
        CHECK(got.seqno == 1);
        CHECK(got.type == device::Type::Session_iOS);
        CHECK(got.description == "test phone");
        CHECK(got.version == std::array<int, 3>{1, 2, 3});
        CHECK(got.state == device::State::Unregistered);
        CHECK_FALSE(is_registered);
    }

    SECTION("identical update does not bump seqno") {
        device::Info info{};
        info.type = device::Type::Session_Desktop;
        info.description = "desktop";
        info.version = {0, 1, 0};

        c->devices.update_info(info);
        CHECK(c->devices.device_info().first.seqno == 1);

        c->devices.update_info(info);  // identical — should not bump
        CHECK(c->devices.device_info().first.seqno == 1);
    }

    SECTION("changed description bumps seqno") {
        device::Info info{};
        info.description = "first";
        c->devices.update_info(info);
        CHECK(c->devices.device_info().first.seqno == 1);

        info.description = "second";
        c->devices.update_info(info);
        CHECK(c->devices.device_info().first.seqno == 2);
    }

    SECTION("changed type bumps seqno") {
        device::Info info{};
        info.type = device::Type::Session_Android;
        c->devices.update_info(info);
        CHECK(c->devices.device_info().first.seqno == 1);

        info.type = device::Type::Session_Desktop;
        c->devices.update_info(info);
        CHECK(c->devices.device_info().first.seqno == 2);
    }

    SECTION("changed version bumps seqno") {
        device::Info info{};
        info.version = {1, 0, 0};
        c->devices.update_info(info);
        CHECK(c->devices.device_info().first.seqno == 1);

        info.version = {2, 0, 0};
        c->devices.update_info(info);
        CHECK(c->devices.device_info().first.seqno == 2);
    }

    SECTION("extra fields round-trip and participate in comparison") {
        device::Info info{};
        info.extra["custom_key"] = std::string{"hello"};
        c->devices.update_info(info);

        auto [got, _] = c->devices.device_info();
        CHECK(got.seqno == 1);
        REQUIRE(got.extra.count("custom_key"));
        CHECK(std::get<std::string>(got.extra.at("custom_key")) == "hello");

        // Same extra — no bump
        c->devices.update_info(info);
        CHECK(c->devices.device_info().first.seqno == 1);

        // Changed extra — bump
        info.extra["custom_key"] = std::string{"world"};
        c->devices.update_info(info);
        CHECK(c->devices.device_info().first.seqno == 2);
    }

    SECTION("same_user_fields ignores state/seqno/pk_*") {
        device::Info a{}, b{};
        a.type = device::Type::Session_iOS;
        a.description = "foo";
        a.version = {1, 2, 3};
        b = a;

        CHECK(a.same_user_fields(b));

        // Differ in seqno — should still be "same" user fields
        b.seqno = 99;
        CHECK(a.same_user_fields(b));

        // Differ in description — not same
        b.seqno = a.seqno;
        b.description = "bar";
        CHECK_FALSE(a.same_user_fields(b));
    }

    SECTION("update_info device appears in devices(include_unregistered=true)") {
        device::Info info{};
        info.description = "my device";
        c->devices.update_info(info);

        auto devs = c->devices.devices(false, false, true);
        CHECK(devs.size() == 1);
        CHECK(devs.begin()->second.description == "my device");
    }
}

TEST_CASE("Devices - device keys", "[core][devices]") {
    TempCore c;

    SECTION("active_device_keys returns at least one key with correct sizes") {
        auto keys = c->devices.active_device_keys();
        REQUIRE_FALSE(keys.empty());
        CHECK(keys.front().x25519_pub.size() == 32);
        CHECK(keys.front().mlkem768_pub.size() == 1184);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("rotate_device_keys produces a distinct key") {
        auto before = c->devices.active_device_keys();
        REQUIRE_FALSE(before.empty());

        c->devices.rotate_device_keys();
        auto after = c->devices.active_device_keys();

        CHECK(after.front().x25519_pub != before.front().x25519_pub);
        CHECK(after.front().mlkem768_pub != before.front().mlkem768_pub);
        CHECK_FALSE(after.front().rotated.has_value());
    }

    SECTION("after one rotation active_device_keys has two entries") {
        auto initial = c->devices.active_device_keys();  // ensure initial key exists
        REQUIRE(initial.size() == 1);
        c->devices.rotate_device_keys();
        auto keys = c->devices.active_device_keys();
        CHECK(keys.size() == 2);
        CHECK_FALSE(keys.front().rotated.has_value());
        CHECK(keys.back().rotated.has_value());
    }

    SECTION("after two rotations active_device_keys has three entries") {
        c->devices.active_device_keys();  // ensure initial key exists
        c->devices.rotate_device_keys();
        c->devices.rotate_device_keys();
        auto keys = c->devices.active_device_keys();
        CHECK(keys.size() == 3);
        CHECK_FALSE(keys[0].rotated.has_value());
        CHECK(keys[1].rotated.has_value());
        CHECK(keys[2].rotated.has_value());
    }
}

TEST_CASE("Devices - account keys", "[core][devices]") {
    TempCore c;

    SECTION("active_account_keys returns at least one key with correct sizes") {
        auto keys = c->devices.active_account_keys();
        REQUIRE_FALSE(keys.empty());
        CHECK(keys.front().x25519_pub.size() == 32);
        CHECK(keys.front().mlkem768_pub.size() == 1184);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("rotate_account_keys produces a distinct key: newer timestamp wins") {
        auto before = c->devices.active_account_keys();
        REQUIRE(before.size() == 1);

        // Advance clock by 1s so the new key has a strictly later created timestamp and
        // deterministically wins tie-breaking (created DESC, seed ASC).
        ScopedClockOffset adv{1s};
        c->devices.rotate_account_keys();
        auto after = c->devices.active_account_keys();

        REQUIRE(after.size() == 2);
        CHECK_FALSE(after.front().rotated.has_value());
        CHECK(after.back().rotated.has_value());
        CHECK(after.front().x25519_pub != before.front().x25519_pub);
    }

    SECTION("rotate_account_keys produces a distinct key: same timestamp, seed tiebreak") {
        // Snap the adjusted clock to the start of the next second so both key-creation calls
        // land in the same second with no risk of spanning a second boundary.
        ScopedClockOffset pin{(clock_now_s() + 1s) - std::chrono::system_clock::now()};

        c->devices.active_account_keys();  // ensure initial key exists at pinned second
        c->devices.rotate_account_keys();  // new key created at same second
        auto keys = c->devices.active_account_keys();
        REQUIRE(keys.size() == 2);
        CHECK_FALSE(keys.front().rotated.has_value());
        CHECK(keys.back().rotated.has_value());

        // Look up each key's seed via its x25519 pubkey and verify the tie-breaking rule:
        // the active key must have the lexicographically smaller seed.
        auto active_seed = TestHelper::account_key_seed(c->devices, keys.front().x25519_pub);
        auto rotated_seed = TestHelper::account_key_seed(c->devices, keys.back().x25519_pub);
        CHECK(active_seed < rotated_seed);
    }

    SECTION("after one rotation active_account_keys has two entries") {
        c->devices.active_account_keys();  // ensure initial key exists
        c->devices.rotate_account_keys();
        auto keys = c->devices.active_account_keys();
        CHECK(keys.size() == 2);
        CHECK_FALSE(keys.front().rotated.has_value());
        CHECK(keys.back().rotated.has_value());
    }

    SECTION("old key pruned after ACCOUNT_KEY_RETENTION") {
        c->devices.active_account_keys();  // ensure initial key exists
        c->devices.rotate_account_keys();
        {
            auto keys = c->devices.active_account_keys();
            CHECK(keys.size() == 2);
        }

        // Advance clock past retention window: old rotated key should be pruned
        ScopedClockOffset adv{Devices::ACCOUNT_KEY_RETENTION + 1s};
        auto keys = c->devices.active_account_keys();
        CHECK(keys.size() == 1);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("next_account_rotation returns nullopt when not in device group") {
        CHECK_FALSE(c->devices.next_account_rotation().has_value());
        CHECK_FALSE(c->devices.account_rotation_due());
    }

    SECTION("next_device_rotation returns nullopt when not in device group") {
        CHECK_FALSE(c->devices.next_device_rotation().has_value());
        CHECK_FALSE(c->devices.device_rotation_due());
    }
}

TEST_CASE("Devices - build_link_request", "[core][devices]") {
    TempCore c;

    SECTION("returns non-empty message and 21-entry SAS") {
        auto result = c->devices.build_link_request();
        CHECK_FALSE(result.message.empty());
        CHECK(result.sas.size() == 21);
        for (const auto& s : result.sas)
            CHECK_FALSE(s.empty());
    }

    SECTION("consecutive calls produce different messages") {
        auto r1 = c->devices.build_link_request();
        auto r2 = c->devices.build_link_request();
        CHECK(r1.message != r2.message);
    }
}

TEST_CASE("Devices - build_account_pubkey_message", "[core][devices]") {
    TempCore c;

    SECTION("non-empty output with correct structure") {
        auto msg = c->devices.build_account_pubkey_message();
        REQUIRE_FALSE(msg.empty());

        auto dict = oxenc::bt_dict_consumer{msg};

        // "M" — mlkem768 pubkey (1184 bytes)
        CHECK(dict.require<std::string_view>("M").size() == 1184);

        // "X" — x25519 pubkey (32 bytes)
        CHECK(dict.require<std::string_view>("X").size() == 32);

        // "~" — XEd25519 signature (64 bytes)
        CHECK(dict.require<std::string_view>("~").size() == 64);
    }

    SECTION("M and X match active account keys") {
        auto keys = c->devices.active_account_keys();
        REQUIRE_FALSE(keys.empty());

        auto msg = c->devices.build_account_pubkey_message();
        auto dict = oxenc::bt_dict_consumer{msg};

        auto M = dict.require<std::string_view>("M");
        auto X = dict.require<std::string_view>("X");

        CHECK(std::memcmp(M.data(), keys.front().mlkem768_pub.data(), 1184) == 0);
        CHECK(std::memcmp(X.data(), keys.front().x25519_pub.data(), 32) == 0);
    }

    SECTION("signature verifies against account x25519 pubkey") {
        auto msg = c->devices.build_account_pubkey_message();
        auto dict = oxenc::bt_dict_consumer{msg};

        dict.require<std::string_view>("M");
        dict.require<std::string_view>("X");

        // Use require_signature to correctly extract the signed body (everything in the dict
        // before the "~" key) and the signature value.
        auto x25519_pub = c->globals.session_id().template subspan<1>();  // skip 0x05 prefix
        bool sig_valid = false;
        dict.require_signature(
                "~", [&](std::span<const unsigned char> body, std::span<const unsigned char> sig) {
                    sig_valid = xed25519::verify(sig, x25519_pub, body);
                });
        CHECK(sig_valid);
    }
}
