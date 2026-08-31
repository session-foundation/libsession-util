#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
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

namespace {

/// A Core whose account was *restored* rather than generated, and which therefore owes no device
/// group: this is the state a device is in before it has joined one.
///
/// A plain `TempCore` generates its account, which now establishes a group with itself as the only
/// member -- so anything asserting on an unregistered device has to say which of the two it means.
TempCore restored_core() {
    std::array<std::byte, 32> seed{};
    random::fill(seed);
    return TempCore{core::predefined_seed{std::span<const std::byte, 32>{seed}}};
}

}  // namespace

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
    auto c = restored_core();

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
    auto c = restored_core();

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

TEST_CASE("Devices - device group payload padding", "[core][devices]") {
    TempCore c;

    // Real keys, not random bytes: ML-KEM encapsulation is performed against each device's pubkey.
    // Rotating produces distinct valid keypairs, and all of them stay in this device's active key
    // set, so this Core can also decrypt whatever it encrypts below.
    std::vector<device::Info> infos;
    for (int i = 0; i < 5; i++) {
        auto k = c->devices.rotate_device_keys();
        auto& info = infos.emplace_back();
        random::fill(info.id);
        info.seqno = 1;
        info.timestamp = clock_now_s();
        info.type = device::Type::Session_Desktop;
        info.description = "test device";
        info.state = device::State::Registered;
        info.version = {1, 0, 0};
        info.pk_x25519 = k.x25519_pub;
        info.pk_mlkem768 = k.mlkem768_pub;
    }

    auto encrypted_size = [&](size_t n) {
        device::map m;
        for (size_t i = 0; i < n; i++)
            m.emplace(infos[i].id, infos[i]);
        return TestHelper::encrypt_device_data(c->devices, m).size();
    };

    SECTION("groups of up to 4 devices are indistinguishable by size") {
        auto one = encrypted_size(1);
        CHECK(encrypted_size(2) == one);
        CHECK(encrypted_size(3) == one);
        CHECK(encrypted_size(4) == one);

        // The 5th device crosses into the next bucket, which is expected and unavoidable — the
        // guarantee is bucketing, not constant size.
        CHECK(encrypted_size(5) > one);
    }

    SECTION("padding round-trips off again") {
        device::map m;
        for (size_t i = 0; i < 3; i++)
            m.emplace(infos[i].id, infos[i]);

        auto enc = TestHelper::encrypt_device_data(c->devices, m);
        auto plaintext = TestHelper::decrypt_device_data(c->devices, enc);

        // A bt-encoded dict always ends in 'e'; if any padding survived, it would not.
        REQUIRE_FALSE(plaintext.empty());
        CHECK(plaintext.back() == std::byte{'e'});

        // And the recovered payload really is the device dict, not a truncation of it.
        oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
        REQUIRE(btdc.skip_until("D"));
        auto devs = btdc.consume_dict_consumer();
        int count = 0;
        while (!devs.is_finished()) {
            devs.skip_until(devs.key());
            devs.consume_dict_consumer();
            count++;
        }
        CHECK(count == 3);
    }
}

TEST_CASE("Devices - account keys", "[core][devices]") {
    // Restored: two sections here are about what the rotation timers say for a device that is *not*
    // in a group, and a generated account is in one from the moment it exists.
    auto c = restored_core();

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
        ScopedClockOffset pin_to_next_second{
                (clock_now_s() + 1s) - std::chrono::system_clock::now()};

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
        ScopedClockOffset advance_past_retention{Devices::ACCOUNT_KEY_RETENTION + 1s};
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
    // Restored, not generated: asking to join a group only makes sense for a device that adopted
    // an existing account's seed.  A device that generated the account *is* the group.
    auto c = restored_core();

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
                "~", [&](std::span<const std::byte> body, std::span<const std::byte> sig) {
                    sig_valid =
                            sig.size() == 64 && xed25519::verify(sig.first<64>(), x25519_pub, body);
                });
        CHECK(sig_valid);
    }
}

TEST_CASE("Devices - establishing the group", "[core][devices]") {

    SECTION("a generated account establishes a group with itself") {
        TempCore c;

        auto [info, registered] = c->devices.device_info();
        CHECK(registered);
        CHECK(info.state == device::State::Registered);
        CHECK(info.id == c->devices.device_info().first.id);

        // Exactly one device, and it is us.
        auto devs = c->devices.devices(true, true, true);
        REQUIRE(devs.size() == 1);
        CHECK(devs.begin()->first == info.id);

        // The whole point: a registered device is one that `needs_push` will speak for.  Before
        // this existed, nothing ever registered a device, so nothing was ever owed a push and no
        // group could come into being.
        CHECK(c->devices.needs_push().device_group);

        // The group payload carries the account's shared key seeds, so one is minted here.
        auto keys = c->devices.active_account_keys();
        REQUIRE(keys.size() == 1);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("a restored account does not") {
        auto c = restored_core();

        auto [info, registered] = c->devices.device_info();
        CHECK_FALSE(registered);
        CHECK(c->devices.devices(true, true, true).empty());
        CHECK_FALSE(c->devices.needs_push().device_group);
    }

    SECTION("it survives a restart, and does not happen twice") {
        std::optional<std::array<std::byte, 32>> first_id;
        int64_t first_seqno = 0;
        auto path = std::filesystem::temp_directory_path() /
                    fmt::format("{}.db", random::unique_id("test_estab", 7));
        {
            Core c{path};
            auto [info, registered] = c.devices.device_info();
            REQUIRE(registered);
            first_id = info.id;
            first_seqno = info.seqno;
        }
        {
            // Reopened: the flag was cleared the first time, so this must not re-register or
            // re-mint anything -- a second establish would bump the seqno and mint a second key.
            Core c{path};
            auto [info, registered] = c.devices.device_info();
            CHECK(registered);
            CHECK(info.id == *first_id);
            CHECK(info.seqno == first_seqno);
            CHECK(c.devices.active_account_keys().size() == 1);
        }
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
}
