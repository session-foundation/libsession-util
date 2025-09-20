#include <fmt/format.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <session/attachments.hpp>

#include "utils.hpp"

using namespace session::config;

namespace attachment = session::attachment;

static std::vector<std::byte> make_data(size_t len) {
    std::vector<std::byte> v;
    v.reserve(len);
    for (int i = 0; i < len; i++)
        v.push_back(static_cast<std::byte>(i * 7 % 256));
    return v;
}

using Catch::Matchers::Message;

TEST_CASE("Attachment encryption/decryption", "[attachments]") {

    auto DATA_SIZE = GENERATE(
            0,
            1,
            2,
            10,
            100,
            1000,
            2000,
            4000,
            4053,
            4054,
            8149,
            8150,
            33333,
            261982,
            261983,
            523990,
            523991,
            6543210,
            10218286);

    auto expected_size = DATA_SIZE < 4054      ? 4096
                       : DATA_SIZE < 8150      ? 8192
                       : DATA_SIZE < 10000     ? 12288
                       : DATA_SIZE == 33333    ? 36864
                       : DATA_SIZE < 261983    ? 262144
                       : DATA_SIZE < 262000    ? 270336
                       : DATA_SIZE < 523991    ? 524288
                       : DATA_SIZE < 524000    ? 540672
                       : DATA_SIZE == 6543210  ? 6553600
                       : DATA_SIZE == 10218286 ? 10223616
                                               : -1;

    auto seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(DATA_SIZE);

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);

    auto [enc2, key2] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);

    CHECK(oxenc::to_hex(key) == oxenc::to_hex(key2));
    CHECK(enc.size() == expected_size);
    CHECK(!!(enc == enc2));  // Prevent catch2 from trying to expand this on failure

    auto decr = attachment::decrypt(enc, key);
    CHECK(decr == data);
}

TEST_CASE("Attachment encryption/decryption -- large files", "[attachments][large]") {

    auto DATA_SIZE = GENERATE(0, 60'000, 10'000'000, 25'000'000);

    auto expected_size = DATA_SIZE == 0        ? 4096
                       : DATA_SIZE == 60000    ? 61440
                       : DATA_SIZE == 10000000 ? 10223616
                       : DATA_SIZE == 25000000 ? 25165824
                                               : -1;

    auto seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    std::vector<std::byte> data;
    data.reserve(DATA_SIZE);
    for (int i = 0; i < DATA_SIZE; i++)
        data.push_back(static_cast<std::byte>(i * 7 % 256));

    std::vector<std::byte> enc;
    std::array<std::byte, attachment::ENCRYPT_KEY_SIZE> key;
    if (DATA_SIZE > 10'000'000) {
        CHECK_THROWS_MATCHES(
                std::tie(enc, key) =
                        attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT),
                std::invalid_argument,
                Message("data to encrypt is too large"));
    }
    std::tie(enc, key) = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT, true);

    CHECK(enc.size() == expected_size);

    auto decr = attachment::decrypt(enc, key);
    CHECK(!!(decr == data));
}

const auto bad_data_message =
        Message("Attachment decryption failed: invalid key or corrupted data");

TEST_CASE("Attachment encryption/decryption -- key separation", "[attachments][key-sep]") {

    auto DATA_SIZE = GENERATE(0, 20, 100, 1000, 33333);

    auto seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;
    auto seed2 = "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(DATA_SIZE);

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
    auto [enc2, key2] = attachment::encrypt(seed2, data, attachment::Domain::ATTACHMENT);

    CHECK(oxenc::to_hex(key) != oxenc::to_hex(key2));
    CHECK(!(enc == enc2));

    CHECK_THROWS_MATCHES(attachment::decrypt(enc, key2), std::runtime_error, bad_data_message);
    CHECK_THROWS_MATCHES(attachment::decrypt(enc2, key), std::runtime_error, bad_data_message);
}

TEST_CASE("Attachment encryption/decryption -- key separation", "[attachments][domain-sep]") {

    auto DATA_SIZE = GENERATE(0, 20, 100, 1000, 33333);

    auto seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(DATA_SIZE);

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
    auto [enc2, key2] = attachment::encrypt(seed, data, attachment::Domain::PROFILE_PIC);

    CHECK(oxenc::to_hex(key) != oxenc::to_hex(key2));
    CHECK(!(enc == enc2));

    CHECK_THROWS_MATCHES(attachment::decrypt(enc, key2), std::runtime_error, bad_data_message);
    CHECK_THROWS_MATCHES(attachment::decrypt(enc2, key), std::runtime_error, bad_data_message);
}

TEST_CASE("Attachment encryption/decryption -- content separation", "[attachments][content-sep]") {

    auto seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(50000);
    auto data2 = data;
    data2[43210] = std::byte{0x42};

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
    auto [enc2, key2] = attachment::encrypt(seed, data2, attachment::Domain::ATTACHMENT);

    CHECK(oxenc::to_hex(key) != oxenc::to_hex(key2));
    CHECK(enc.size() == enc2.size());
    CHECK(!(enc == enc2));

    CHECK_THROWS_MATCHES(attachment::decrypt(enc, key2), std::runtime_error, bad_data_message);
    CHECK_THROWS_MATCHES(attachment::decrypt(enc2, key), std::runtime_error, bad_data_message);
}

TEST_CASE("Attachment Decryptor", "[attachments][decryptor]") {

    auto DATA_SIZE = GENERATE(
            0, 1, 2, 10, 100, 1000, 2000, 4000, 4053, 4054, 8149, 8150, 33333, 6543210, 10218286);

    auto FEED_SIZE = GENERATE(1, 2, 41, 4096, 10000000000);

    auto seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(DATA_SIZE);

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);

    std::vector<std::byte> decrypted;
    attachment::Decryptor d{key, [&decrypted](std::span<const std::byte> data) {
                                decrypted.insert(decrypted.end(), data.begin(), data.end());
                            }};

    std::span input{enc};
    while (!input.empty()) {
        auto sz = std::min<size_t>(FEED_SIZE, input.size());
        REQUIRE(d.update(input.first(sz)));
        input = input.subspan(sz);
    }

    REQUIRE(d.finalize());
    CHECK(!!(decrypted == data));
}
