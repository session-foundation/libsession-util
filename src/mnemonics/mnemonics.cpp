#include <oxenc/endian.h>

#include <cassert>
#include <cctype>
#include <mutex>
#include <vector>
#include <oxen/log/format.hpp>
#include <session/mnemonics.hpp>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace session::mnemonics {

using namespace oxen::log::literals;

unknown_word_error::unknown_word_error(std::string word) :
        std::invalid_argument{"Unknown mnemonic word: {}"_format(word)},
        word_{std::move(word)} {}

const Mnemonics* find_language(std::string_view name) {
    for (auto lang : get_languages()) {
        if (lang->english_name == name || lang->native_name == name)
            return lang;
    }
    return nullptr;
}

namespace {
    // Returns the lowercased first `n_codepoints` UTF-8 codepoints of `s`.  ASCII characters are
    // lowercased; non-ASCII codepoints are copied as-is.
    std::string word_prefix(std::string_view s, int n_codepoints) {
        std::string result;
        result.reserve(s.size());
        const char* it = s.data();
        const char* end = it + s.size();
        for (int count = 0; it < end && count < n_codepoints; count++) {
            uint8_t b = static_cast<uint8_t>(*it);
            int len;
            if ((b & 0b11100000) == 0b11000000)       // 110xxxxx: 2-byte sequence
                len = 2;
            else if ((b & 0b11110000) == 0b11100000)  // 1110xxxx: 3-byte sequence
                len = 3;
            else if ((b & 0b11111000) == 0b11110000)  // 11110xxx: 4-byte sequence
                len = 4;
            else                                       // 0xxxxxxx: ASCII, or invalid byte
                len = 1;
            if (len == 1) {
                result.push_back(static_cast<char>(std::tolower(b)));
                it++;
            } else {
                for (int k = 0; k < len && it < end; k++)
                    result.push_back(*it++);
            }
        }
        return result;
    }

    using WordMap = std::unordered_map<std::string, int>;

    const WordMap& get_word_map(const Mnemonics& lang) {
        auto langs = get_languages();
        size_t idx = std::find(langs.begin(), langs.end(), &lang) - langs.begin();

        static std::vector<WordMap> maps(langs.size());
        static std::vector<std::once_flag> flags(langs.size());

        std::call_once(flags[idx], [&] {
            for (int i = 0; i < static_cast<int>(NWORDS); ++i) {
                std::string prefix = word_prefix(lang.words[i], lang.prefix_len);
                assert(!prefix.empty());
                maps[idx][prefix] = i;
            }
        });
        return maps[idx];
    }

    int get_word_index(const Mnemonics& lang, std::string_view word) {
        const auto& wm = get_word_map(lang);
        auto it = wm.find(word_prefix(word, lang.prefix_len));
        return it != wm.end() ? it->second : -1;
    }
}  // namespace

std::vector<std::string_view> bytes_to_words(
        std::span<const std::byte> bytes, const Mnemonics& lang) {
    if (bytes.size() % 4 != 0)
        throw std::invalid_argument("Input length must be a multiple of 4 bytes");

    std::vector<std::string_view> result;
    result.reserve((bytes.size() / 4) * 3);

    for (size_t i = 0; i < bytes.size(); i += 4) {
        uint32_t val = oxenc::load_little_to_host<uint32_t>(&bytes[i]);

        uint32_t a = val % NWORDS;
        uint32_t b = (val / NWORDS + a) % NWORDS;
        uint32_t c = (val / NWORDS / NWORDS + b) % NWORDS;

        result.push_back(lang.words[a]);
        result.push_back(lang.words[b]);
        result.push_back(lang.words[c]);
    }

    return result;
}

std::vector<std::string_view> bytes_to_words(
        std::span<const std::byte> bytes, std::string_view lang_name) {
    auto lang = find_language(lang_name);
    if (!lang)
        throw std::invalid_argument("Unknown mnemonic language: " + std::string(lang_name));
    return bytes_to_words(bytes, *lang);
}

std::vector<std::byte> words_to_bytes(
        std::span<const std::string_view> words, const Mnemonics& lang) {
    if (words.size() % 3 != 0)
        throw std::invalid_argument("Input word count must be a multiple of 3");

    std::vector<std::byte> result;
    result.resize((words.size() / 3) * 4);

    for (size_t i = 0; i < words.size(); i += 3) {
        std::array<uint32_t, 3> w;
        for (int j = 0; j < 3; j++) {
            int idx = get_word_index(lang, words[i + j]);
            if (idx < 0)
                throw unknown_word_error{std::string(words[i + j])};
            w[j] = static_cast<uint32_t>(idx);
        }
        auto [a, b, c] = w;

        uint32_t x = a + ((NWORDS - a + b) % NWORDS) * NWORDS +
                     ((NWORDS - b + c) % NWORDS) * (NWORDS * NWORDS);

        if (x % NWORDS != a)
            throw std::invalid_argument("Mnemonic word sequence encodes an invalid value");

        oxenc::write_host_as_little<uint32_t>(x, &result[(i / 3) * 4]);
    }

    return result;
}

std::vector<std::byte> words_to_bytes(
        std::span<const std::string_view> words, std::string_view lang_name) {
    auto lang = find_language(lang_name);
    if (!lang)
        throw std::invalid_argument("Unknown mnemonic language: " + std::string(lang_name));
    return words_to_bytes(words, *lang);
}

}  // namespace session::mnemonics
