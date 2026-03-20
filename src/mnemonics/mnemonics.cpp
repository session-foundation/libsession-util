#include <oxenc/endian.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <memory>
#include <mutex>
#include <session/mnemonics.hpp>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace session::mnemonics {

const Mnemonics* find_language(std::string_view name) {
    for (auto lang : get_languages()) {
        if (lang->english_name == name || lang->native_name == name)
            return lang;
    }
    return nullptr;
}

namespace {
    /**
     * Converts ASCII characters in a UTF-8 string to lowercase.
     * Non-ASCII characters are left unchanged.
     */
    std::string to_lower_ascii(std::string_view s) {
        std::string result;
        result.reserve(s.size());
        for (char c : s) {
            if (static_cast<unsigned char>(c) < 128)
                result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            else
                result.push_back(c);
        }
        return result;
    }

    /**
     * Gets a prefix of a UTF-8 string containing at most n_codepoints.
     */
    std::string_view get_prefix(std::string_view s, int n_codepoints) {
        if (n_codepoints <= 0)
            return "";

        const char* it = s.data();
        const char* end = it + s.size();
        int count = 0;
        while (it < end && count < n_codepoints) {
            uint8_t b = static_cast<uint8_t>(*it);
            if (b < 0x80)  // 0xxxxxxx: 1-byte ASCII
                it += 1;
            else if ((b & 0xE0) == 0xC0)  // 110xxxxx: 2-byte sequence
                it += 2;
            else if ((b & 0xF0) == 0xE0)  // 1110xxxx: 3-byte sequence
                it += 3;
            else if ((b & 0xF8) == 0xF0)  // 11110xxx: 4-byte sequence
                it += 4;
            else  // Invalid UTF-8 start byte or continuation byte
                it += 1;

            count++;
        }
        return std::string_view(s.data(), std::min<size_t>(it - s.data(), s.size()));
    }

    struct WordMap {
        std::unordered_map<std::string, int> map;
        std::unordered_map<std::string, int> prefix_map;
        std::mutex mutex;
        bool initialized = false;
    };

    WordMap& get_word_map(const Mnemonics& lang) {
        static std::mutex maps_mutex;
        static std::unordered_map<const Mnemonics*, std::unique_ptr<WordMap>> maps;

        std::lock_guard lock(maps_mutex);
        auto& ptr = maps[&lang];
        if (!ptr)
            ptr = std::make_unique<WordMap>();
        return *ptr;
    }

    int get_word_index(const Mnemonics& lang, std::string_view word) {
        auto& wm = get_word_map(lang);
        {
            std::lock_guard lock(wm.mutex);
            if (!wm.initialized) {
                for (int i = 0; i < static_cast<int>(NWORDS); ++i) {
                    std::string_view w = lang.words[i];
                    std::string lower_w = to_lower_ascii(w);
                    wm.map[lower_w] = i;

                    std::string lower_prefix = to_lower_ascii(get_prefix(w, lang.prefix_len));
                    if (!lower_prefix.empty())
                        wm.prefix_map[lower_prefix] = i;
                }
                wm.initialized = true;
            }
        }

        std::string lower_input = to_lower_ascii(word);

        auto it = wm.map.find(lower_input);
        if (it != wm.map.end())
            return it->second;

        std::string lower_input_prefix = to_lower_ascii(get_prefix(lower_input, lang.prefix_len));
        if (!lower_input_prefix.empty()) {
            auto pit = wm.prefix_map.find(lower_input_prefix);
            if (pit != wm.prefix_map.end())
                return pit->second;
        }

        return -1;
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
        int w1 = get_word_index(lang, words[i]);
        int w2 = get_word_index(lang, words[i + 1]);
        int w3 = get_word_index(lang, words[i + 2]);

        if (w1 < 0 || w2 < 0 || w3 < 0)
            throw std::invalid_argument("Word not found in mnemonic dictionary");

        uint32_t a = static_cast<uint32_t>(w1);
        uint32_t b = static_cast<uint32_t>(w2);
        uint32_t c = static_cast<uint32_t>(w3);

        uint32_t x = a + ((NWORDS - a + b) % NWORDS) * NWORDS +
                     ((NWORDS - b + c) % NWORDS) * (NWORDS * NWORDS);

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
