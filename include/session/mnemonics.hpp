#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace session::mnemonics {

/**
 * The number of words in each mnemonic language word list.
 *
 * The encoding uses 3 words per 32-bit chunk, so 24 words encodes 256 bits.  1626 was chosen
 * because 1626³ (≈ 4.299 × 10⁹) just barely exceeds 2³² (≈ 4.295 × 10⁹), meaning three words
 * can represent any 32-bit value — with a small number of 3-word combinations (~0.09%) that
 * exceed 2³²-1 and are therefore invalid.
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

/// Exception thrown when a word is not found in the mnemonic dictionary.
class unknown_word_error : public std::invalid_argument {
  public:
    explicit unknown_word_error(std::string word);

    /// The word that was not found in the dictionary.
    const std::string& word() const { return word_; }

  private:
    std::string word_;
};

/// Exception thrown when a checksum word is present but does not match the expected value.
class checksum_error : public std::invalid_argument {
  public:
    checksum_error();
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
 * @param checksum If true (the default), append a checksum word after the encoded words.  The
 *        checksum word is the seed word at position (sum of all word indices) % N, where N is
 *        the number of encoded words.
 * @return A vector of words representing the input bytes, plus a checksum word if requested.
 * @throws std::invalid_argument if the input length is not a multiple of 4.
 */
std::vector<std::string_view> bytes_to_words(
        std::span<const std::byte> bytes, const Mnemonics& lang, bool checksum = true);

/**
 * Converts a byte span to a mnemonic word list using the specified language.
 *
 * @param bytes The input byte span. Its length must be a multiple of 4.
 * @param lang_name The name of the language (English or native) to use.
 * @param checksum If true (the default), append a checksum word after the encoded words.
 * @return A vector of words representing the input bytes, plus a checksum word if requested.
 * @throws std::invalid_argument if the language is unknown or the input length is invalid.
 */
std::vector<std::string_view> bytes_to_words(
        std::span<const std::byte> bytes, std::string_view lang_name, bool checksum = true);

/**
 * Converts a mnemonic word list to a byte span using the specified language.
 *
 * Accepts a word count that is either a multiple of 3 (no checksum) or one more than a multiple
 * of 3 (with checksum).  If a checksum word is present it is validated.
 *
 * @param words The input word list.
 * @param lang The language used for the mnemonic.
 * @return A vector of bytes representing the input mnemonic.
 * @throws std::invalid_argument if the input length is invalid, or if the word sequence encodes
 *         an invalid (overflowing) value.
 * @throws unknown_word_error if a word is not found in the language dictionary.
 * @throws checksum_error if a checksum word is present but does not match.
 */
std::vector<std::byte> words_to_bytes(
        std::span<const std::string_view> words, const Mnemonics& lang);

/**
 * Converts a mnemonic word list to a byte span using the specified language.
 *
 * Accepts a word count that is either a multiple of 3 (no checksum) or one more than a multiple
 * of 3 (with checksum).  If a checksum word is present it is validated.
 *
 * @param words The input word list.
 * @param lang_name The name of the language (English or native) used.
 * @return A vector of bytes representing the input mnemonic.
 * @throws std::invalid_argument if the language is unknown, the input length is invalid, or the
 *         word sequence encodes an invalid (overflowing) value.
 * @throws unknown_word_error if a word is not found in the language dictionary.
 * @throws checksum_error if a checksum word is present but does not match.
 */
std::vector<std::byte> words_to_bytes(
        std::span<const std::string_view> words, std::string_view lang_name);

}  // namespace session::mnemonics
