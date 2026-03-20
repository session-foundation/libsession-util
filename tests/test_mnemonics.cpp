#include <catch2/catch_test_macros.hpp>
#include <random>
#include <session/mnemonics.hpp>
#include <vector>

using namespace session::mnemonics;

TEST_CASE("Mnemonic round-trip tests", "[mnemonics]") {
    std::vector<std::byte> data_128(16);
    std::vector<std::byte> data_256(32);

    std::mt19937 gen(42);
    std::uniform_int_distribution<int> dist(0, 255);

    auto fill_random = [&](std::vector<std::byte>& v) {
        for (auto& b : v)
            b = static_cast<std::byte>(dist(gen));
    };

    fill_random(data_128);
    fill_random(data_256);

    for (auto lang : get_languages()) {
        SECTION("Language: " + std::string(lang->english_name)) {
            // 128-bit -> 12 words -> 128-bit
            auto words12 = bytes_to_words(data_128, *lang);
            CHECK(words12.size() == 12);
            auto back12 = words_to_bytes(words12, *lang);
            CHECK(back12 == data_128);

            // 256-bit -> 24 words -> 256-bit
            auto words24 = bytes_to_words(data_256, *lang);
            CHECK(words24.size() == 24);
            auto back24 = words_to_bytes(words24, *lang);
            CHECK(back24 == data_256);
        }
    }
}

TEST_CASE("Mnemonic case-insensitivity and prefix matching", "[mnemonics]") {
    auto english = find_language("English");
    REQUIRE(english);

    // 4 bytes: [0x01, 0x02, 0x03, 0x04]
    // V = 0x04030201 = 67305985
    // A = 67305985 % 1626 = 1443
    // B = (67305985 / 1626 + 1443) % 1626 = (41393 + 1443) % 1626 = 42836 % 1626 = 180
    // C = (67305985 / 1626 / 1626 + 180) % 1626 = (25 + 180) % 1626 = 205

    // Words for English at indices 1443, 180, 205
    std::vector<std::byte> data = {
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
    auto words = bytes_to_words(data, *english);
    REQUIRE(words.size() == 3);

    SECTION("Exact match") {
        auto back = words_to_bytes(words, *english);
        CHECK(back == data);
    }

    SECTION("Case-insensitive match (ASCII)") {
        std::vector<std::string_view> upper_words;
        std::vector<std::string> storage;
        for (auto w : words) {
            std::string upper(w);
            for (auto& c : upper)
                c = std::toupper(static_cast<unsigned char>(c));
            storage.push_back(upper);
        }
        for (const auto& s : storage)
            upper_words.push_back(s);

        auto back = words_to_bytes(upper_words, *english);
        CHECK(back == data);
    }

    SECTION("Prefix match") {
        std::vector<std::string_view> prefix_words;
        std::vector<std::string> storage;
        for (auto w : words) {
            storage.push_back(std::string(w.substr(0, english->prefix_len)));
        }
        for (const auto& s : storage)
            prefix_words.push_back(s);

        auto back = words_to_bytes(prefix_words, *english);
        CHECK(back == data);
    }

    SECTION("Prefix match with typo after prefix") {
        std::vector<std::string_view> typo_words;
        std::vector<std::string> storage;
        for (auto w : words) {
            storage.push_back(std::string(w.substr(0, english->prefix_len)) + "xyz");
        }
        for (const auto& s : storage)
            typo_words.push_back(s);

        auto back = words_to_bytes(typo_words, *english);
        CHECK(back == data);
    }
}

TEST_CASE("Mnemonic language lookup", "[mnemonics]") {
    CHECK(find_language("English") != nullptr);
    CHECK(find_language("German") != nullptr);
    CHECK(find_language("Deutsch") != nullptr);
    CHECK(find_language("русский язык") != nullptr);
    CHECK(find_language("NonExistent") == nullptr);
}

TEST_CASE("Mnemonic error handling", "[mnemonics]") {
    auto english = find_language("English");

    SECTION("Invalid byte length") {
        std::vector<std::byte> data(15);
        CHECK_THROWS_AS(bytes_to_words(data, *english), std::invalid_argument);
    }

    SECTION("Invalid word count") {
        std::vector<std::string_view> words = {"abbey", "abducts"};
        CHECK_THROWS_AS(words_to_bytes(words, *english), std::invalid_argument);
    }

    SECTION("Unknown word") {
        std::vector<std::string_view> words = {"abbey", "abducts", "zzzzzz"};
        CHECK_THROWS_AS(words_to_bytes(words, *english), std::invalid_argument);
    }
}
