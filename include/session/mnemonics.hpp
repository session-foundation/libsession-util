#pragma once

#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace session::mnemonics {

/**
 * The number of words in each mnemonic language word list.
 *
 * This value (1626) is chosen because 1626^24 is just enough to represent a 256-bit (32-byte)
 * random value.
 *
 * The math:
 * log2(1626^24) = 24 * log2(1626) ≈ 24 * 10.6669... ≈ 256.006... bits.
 *
 * Thus, 24 words from a 1626-word dictionary can represent 2^256 states with a tiny amount of
 * extra space that is simply unused.
 */
constexpr size_t NWORDS = 1626;

/**
 * A struct containing information about a mnemonic language.
 *
 * All string values (english_name, native_name, and words) are encoded in UTF-8.
 *
 * prefix_len represents the number of unique UTF-8 codepoints (not bytes) required
 * to uniquely identify a word in this language.
 */
struct Mnemonics {
    std::string_view english_name;
    std::string_view native_name;
    int prefix_len;
    std::array<std::string_view, NWORDS> words;
};

/**
 * Returns a list of all supported mnemonic languages.
 * English is always the first element, followed by other languages sorted by name.
 */
std::span<const Mnemonics* const> get_languages();

/**
 * Finds a language by its English or native name.
 *
 * @param name The name to look for.
 * @return A pointer to the Mnemonics struct if found, otherwise nullptr.
 */
const Mnemonics* find_language(std::string_view name);

/**
 * Converts a byte span to a mnemonic word list using the specified language.
 *
 * @param bytes The input byte span. Its length must be a multiple of 4.
 * @param lang The language to use for the mnemonic.
 * @return A vector of words representing the input bytes.
 * @throws std::invalid_argument if the input length is not a multiple of 4.
 */
std::vector<std::string_view> bytes_to_words(
        std::span<const std::byte> bytes, const Mnemonics& lang);

/**
 * Converts a byte span to a mnemonic word list using the specified language.
 *
 * @param bytes The input byte span. Its length must be a multiple of 4.
 * @param lang_name The name of the language (English or native) to use.
 * @return A vector of words representing the input bytes.
 * @throws std::invalid_argument if the language is unknown or the input length is invalid.
 */
std::vector<std::string_view> bytes_to_words(
        std::span<const std::byte> bytes, std::string_view lang_name);

/**
 * Converts a mnemonic word list to a byte span using the specified language.
 *
 * @param words The input word list. Its length must be a multiple of 3.
 * @param lang The language used for the mnemonic.
 * @return A vector of bytes representing the input mnemonic.
 * @throws std::invalid_argument if the input length is not a multiple of 3, or if a word
 *         is not found in the language dictionary.
 */
std::vector<std::byte> words_to_bytes(
        std::span<const std::string_view> words, const Mnemonics& lang);

/**
 * Converts a mnemonic word list to a byte span using the specified language.
 *
 * @param words The input word list. Its length must be a multiple of 3.
 * @param lang_name The name of the language (English or native) used.
 * @return A vector of bytes representing the input mnemonic.
 * @throws std::invalid_argument if the language is unknown or the input is invalid.
 */
std::vector<std::byte> words_to_bytes(
        std::span<const std::string_view> words, std::string_view lang_name);

}  // namespace session::mnemonics
