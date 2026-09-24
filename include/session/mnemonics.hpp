#pragma once

#include <array>
#include <cstddef>
#include <session/secure_buffer.hpp>
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

/// Exception thrown when a language name is not found in the language registry.
class unknown_language_error : public std::invalid_argument {
  public:
    explicit unknown_language_error(std::string name);

    /// The language name that was not found.
    const std::string& name() const { return name_; }

  private:
    std::string name_;
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
 * Looks up a language by its English or native name, throwing if not found.
 *
 * @param name The name to look for.
 * @return A reference to the Mnemonics struct.
 * @throws unknown_language_error if the language name is not found.
 */
const Mnemonics& get_language(std::string_view name);

/// Stores mnemonic string_view objects (each pointing into the language word list) in secure
/// (sodium) memory so that the word identities are zeroed on destruction.
///
/// Call open() to iterate over the words.  The returned opened_span holds a read accessor
/// that keeps the buffer readable for its own lifetime, so the following are both safe:
///
///     for (auto w : m.open()) { ... }
///     auto s = m.open(); for (auto w : s.words) { ... }
///
/// Do NOT do: `for (auto w : m.open().words)` — the opened_span (and its accessor) would be
/// destroyed before the loop body runs, re-locking the buffer and causing a crash.
struct secure_mnemonic {
    session::secure_buffer storage;

    struct opened_span {
        session::secure_buffer::r_accessor acc;
        std::span<const std::string_view> words;

        const std::string_view& operator[](size_t i) const { return words[i]; }
        const std::string_view* begin() const { return words.data(); }
        const std::string_view* end() const { return words.data() + words.size(); }
    };

    opened_span open() {
        auto acc = storage.access();
        std::span<const std::string_view> words{
                reinterpret_cast<const std::string_view*>(acc.buf.data()),
                acc.buf.size() / sizeof(std::string_view)};
        return {std::move(acc), words};
    }

    size_t size() const { return storage.size() / sizeof(std::string_view); }
};

/**
 * Converts a byte span to a mnemonic word list using the specified language, stored in secure
 * memory.
 *
 * @param bytes The input byte span. Its length must be a multiple of 4.
 * @param lang The language to use for the mnemonic.
 * @param checksum If true (the default), append a checksum word after the encoded words.  The
 *        checksum word repeats one of the seed words, chosen by a CRC-32 over their concatenated
 *        prefixes (the first `prefix_len` codepoints of each) modulo the word count.  This matches
 *        the Monero/Electrum scheme that Session clients use.
 *
 * @return A secure_mnemonic containing the words, plus a checksum word if requested.
 * @throws std::invalid_argument if the input length is not a multiple of 4.
 */
secure_mnemonic bytes_to_words(
        std::span<const std::byte> bytes, const Mnemonics& lang, bool checksum = true);

/// Same as above, but takes a language by name instead of by reference.
/// @throws unknown_language_error if the language name is not found.
secure_mnemonic bytes_to_words(
        std::span<const std::byte> bytes, std::string_view lang_name, bool checksum = true);

/**
 * Converts a mnemonic word list to bytes using the specified language, stored in secure memory.
 *
 * Accepts a word count that is either a multiple of 3 (no checksum) or one more than a multiple
 * of 3 (with checksum).  If a checksum word is present it is validated.
 *
 * @param words The input word list.
 * @param lang The language used for the mnemonic.
 * @return A secure_buffer containing the decoded bytes.
 * @throws std::invalid_argument if the input length is invalid, or if the word sequence encodes
 *         an invalid (overflowing) value.
 * @throws unknown_word_error if a word is not found in the language dictionary.
 * @throws checksum_error if a checksum word is present but does not match.
 */
session::secure_buffer words_to_bytes(
        std::span<const std::string_view> words, const Mnemonics& lang);

/// Same as above, but takes a language by name instead of by reference.
/// @throws unknown_language_error if the language name is not found.
session::secure_buffer words_to_bytes(
        std::span<const std::string_view> words, std::string_view lang_name);

/**
 * Converts a mnemonic word list to bytes, writing directly into a caller-provided output span.
 *
 * The size of `out` determines the expected number of seed words: out.size() must be a multiple
 * of 4, and words.size() must equal (out.size() / 4 * 3) or (out.size() / 4 * 3) + 1 (the
 * latter if a checksum word is appended).
 *
 * @param words The input word list.
 * @param lang The language used for the mnemonic.
 * @param out Output span to write decoded bytes into; must be a multiple-of-4 size exactly
 *        matching the decoded byte count implied by the word count.
 * @throws std::invalid_argument if the word count does not match the output size, the word
 *         sequence encodes an invalid (overflowing) value, or out.size() is not a multiple of 4.
 * @throws unknown_word_error if a word is not found in the language dictionary.
 * @throws checksum_error if a checksum word is present but does not match.
 */
void words_to_bytes(
        std::span<const std::string_view> words, const Mnemonics& lang, std::span<std::byte> out);

/// Same as above, but takes a language by name instead of by reference.
/// @throws unknown_language_error if the language name is not found.
void words_to_bytes(
        std::span<const std::string_view> words,
        std::string_view lang_name,
        std::span<std::byte> out);

}  // namespace session::mnemonics
