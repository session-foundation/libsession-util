#include <oxenc/hex.h>
#include <session/config/encrypt.h>
#include <session/config/local.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <session/config/local.hpp>
#include <session/config/notify.hpp>
#include <session/config/theme.hpp>
#include <session/util.hpp>
#include <string_view>

#include "utils.hpp"

using namespace std::literals;

TEST_CASE("Local", "[config][local]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::Local local{std::span<const unsigned char>{seed}, std::nullopt};

    CHECK(local.get_notification_content() == session::config::notify_content::defaulted);
    CHECK(local.get_ios_notification_sound() == 0);
    CHECK(local.get_theme() == session::config::theme::defaulted);
    CHECK(local.get_theme_primary_color() == session::config::theme_primary_color::defaulted);

    local.set_notification_content(session::config::notify_content::name_no_preview);
    CHECK(local.get_notification_content() == session::config::notify_content::name_no_preview);
    local.set_ios_notification_sound(5);
    CHECK(local.get_ios_notification_sound() == 5);
    local.set_theme(session::config::theme::ocean_dark);
    CHECK(local.get_theme() == session::config::theme::ocean_dark);
    local.set_theme_primary_color(session::config::theme_primary_color::orange);
    CHECK(local.get_theme_primary_color() == session::config::theme_primary_color::orange);
    CHECK(local.needs_dump());
    local.dump();
    CHECK_FALSE(local.needs_dump());

    // Check arbitrary settings work
    local.set_setting("test_setting", true);
    CHECK(local.get_setting("test_setting"));
    CHECK_FALSE(local.get_setting("test_setting2")
                        .has_value());  // nullopt when it doesn't have a value
    CHECK(local.needs_dump());
    CHECK(local.size_settings() == 1);

    // Ensure all of these settings were stored in the dump and loaded correctly
    session::config::Local local2{std::span<const unsigned char>{seed}, local.dump()};
    CHECK_FALSE(local.needs_dump());

    CHECK(local2.get_notification_content() == session::config::notify_content::name_no_preview);
    CHECK(local2.get_ios_notification_sound() == 5);
    CHECK(local2.get_theme() == session::config::theme::ocean_dark);
    CHECK(local2.get_theme_primary_color() == session::config::theme_primary_color::orange);
    CHECK(local2.get_setting("test_setting"));
    CHECK(local2.size_settings() == 1);

    CHECK_FALSE(local.needs_push());  // Sanity check (should always return false)
}