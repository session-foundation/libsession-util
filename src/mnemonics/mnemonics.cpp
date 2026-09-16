#include <oxenc/endian.h>
#include <utf8proc.h>

#include <cassert>
#include <cctype>
#include <memory>
#include <mutex>
#include <oxen/log/format.hpp>
#include <session/mnemonics.hpp>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace session::mnemonics {

using namespace oxen::log::literals;

unknown_word_error::unknown_word_error(std::string word) :
        std::invalid_argument{"Unknown mnemonic word: {}"_format(word)}, word_{std::move(word)} {}

checksum_error::checksum_error() :
        std::invalid_argument{"Seed phrase checksum word does not match"} {}

unknown_language_error::unknown_language_error(std::string name) :
        std::invalid_argument{"Unknown mnemonic language: {}"_format(name)},
        name_{std::move(name)} {}

const Mnemonics* find_language(std::string_view name) {
    for (auto lang : get_languages()) {
        if (lang->english_name == name || lang->native_name == name)
            return lang;
    }
    return nullptr;
}

const Mnemonics& get_language(std::string_view name) {
    auto* lang = find_language(name);
    if (!lang)
        throw unknown_language_error{std::string(name)};
    return *lang;
}

namespace {
    // CRC-32/ISO-HDLC -- the same function as zlib's crc32() and boost::crc_32_type, which is what
    // the reference mnemonic implementations use to derive the checksum word.  Implemented here
    // rather than pulled in: the only input is a hundred-odd bytes of word prefixes, once per
    // encode or decode, which does not justify a compression library as a link dependency.
    //
    // Deliberately not in session/hash.hpp: this detects accidental corruption and nothing more,
    // and sitting it next to BLAKE2b would invite someone to use it as though it were a hash.
    constexpr std::array<uint32_t, 256> crc32_table = [] {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }();

    constexpr uint32_t crc32(std::string_view data) {
        uint32_t c = 0xFFFFFFFFu;
        for (unsigned char b : data)
            c = crc32_table[(c ^ b) & 0xFF] ^ (c >> 8);
        return c ^ 0xFFFFFFFFu;
    }

    // The standard CRC-32 check value; a mistyped table cannot compile.
    static_assert(crc32("123456789") == 0xCBF43926u);

    // Returns the first `n_codepoints` codepoints of `s`, composed and case folded.
    //
    // Composition matters because the word lists are NFC and a decomposed input is a different byte
    // sequence for the same word: `ö` typed as `o` + U+0308 puts the combining mark outside the
    // prefix window, so the accent is dropped rather than mismatched.  Mostly that fails to match
    // anything, but Russian `тайна` decomposed truncates to `таи`, which *is* `таинство` -- the
    // lookup silently succeeds against the wrong word.
    //
    // Case folding is done here rather than with towlower because towlower is locale-dependent:
    // under LC_CTYPE=C it leaves U+00D6 alone, so case-insensitivity would work or not depending on
    // the environment the process happens to run in.
    //
    // Both the word lists and user input go through this, so downstream comparisons are plain byte
    // comparisons on canonical data.
    std::string word_prefix(std::string_view s, int n_codepoints) {
        utf8proc_uint8_t* folded = nullptr;
        auto len = utf8proc_map(
                reinterpret_cast<const utf8proc_uint8_t*>(s.data()),
                static_cast<utf8proc_ssize_t>(s.size()),
                &folded,
                static_cast<utf8proc_option_t>(
                        UTF8PROC_STABLE | UTF8PROC_COMPOSE | UTF8PROC_CASEFOLD));
        if (len < 0)
            // Not valid UTF-8, so it cannot be one of the words; the caller reports it as unknown.
            return {};

        std::unique_ptr<utf8proc_uint8_t, decltype(&std::free)> owned{folded, &std::free};
        std::string_view canonical{reinterpret_cast<const char*>(folded), static_cast<size_t>(len)};

        // Take n codepoints by skipping continuation bytes: canonical UTF-8 needs no decoding to
        // find codepoint boundaries.
        size_t end = 0;
        for (int count = 0; end < canonical.size() && count < n_codepoints; count++) {
            end++;
            while (end < canonical.size() &&
                   (static_cast<unsigned char>(canonical[end]) & 0xC0) == 0x80)
                end++;
        }
        return std::string{canonical.substr(0, end)};
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
    // Which of `words` is repeated as the checksum word: a CRC-32 over their concatenated prefixes,
    // modulo the count.  Only the prefix of each word participates, which is what makes a phrase
    // survive a typo past the significant letters -- the same property that lets the words be
    // recognised at all.  `words` excludes the checksum word itself.
    size_t checksum_index(std::span<const std::string_view> words, const Mnemonics& lang) {
        std::string prefixes;
        for (const auto& w : words)
            prefixes += word_prefix(w, lang.prefix_len);
        return crc32(prefixes) % words.size();
    }

}  // namespace

// string_view objects stored in secure_mnemonic::storage are placement-new constructed below.
// We rely on string_view being trivially destructible so that secure_buffer can zero and free
// the memory without needing to call destructors.
static_assert(std::is_trivially_destructible_v<std::string_view>);

secure_mnemonic bytes_to_words(
        std::span<const std::byte> bytes, const Mnemonics& lang, bool checksum) {
    if (bytes.size() % 4 != 0)
        throw std::invalid_argument("Input length must be a multiple of 4 bytes");

    size_t n = (bytes.size() / 4) * 3;
    size_t total = n + checksum;

    secure_mnemonic result;
    auto rw = result.storage.resize(total * sizeof(std::string_view));
    auto* out = reinterpret_cast<std::string_view*>(rw.buf.data());

    for (size_t i = 0; i < bytes.size(); i += 4) {
        uint32_t val = oxenc::load_little_to_host<uint32_t>(&bytes[i]);

        uint32_t a = val % NWORDS;
        uint32_t b = (val / NWORDS + a) % NWORDS;
        uint32_t c = (val / NWORDS / NWORDS + b) % NWORDS;

        std::construct_at(out + i / 4 * 3 + 0, lang.words[a]);
        std::construct_at(out + i / 4 * 3 + 1, lang.words[b]);
        std::construct_at(out + i / 4 * 3 + 2, lang.words[c]);
    }

    if (checksum)
        std::construct_at(out + n, out[checksum_index({out, n}, lang)]);

    return result;
}

secure_mnemonic bytes_to_words(
        std::span<const std::byte> bytes, std::string_view lang_name, bool checksum) {
    return bytes_to_words(bytes, get_language(lang_name), checksum);
}

// Validates the word count against `out.size()` and decodes words directly into `out`.
// out.size() must be a multiple of 4; words.size() must be (out.size()/4*3) or +1 with checksum.
static void words_to_bytes_impl(
        std::span<const std::string_view> words, const Mnemonics& lang, std::span<std::byte> out) {
    if (out.size() % 4 != 0)
        throw std::invalid_argument(
                "Output buffer size must be a multiple of 4 (got {})"_format(out.size()));

    size_t expected_seed_words = out.size() / 4 * 3;
    size_t n = words.size();
    bool has_checksum = n == expected_seed_words + 1;
    if (n != expected_seed_words && !has_checksum)
        throw std::invalid_argument(
                "Seed phrase word count ({}) does not match output buffer size ({} bytes, "
                "expecting {} or {} words)"_format(
                        n, out.size(), expected_seed_words, expected_seed_words + 1));

    uint32_t sum = 0;
    for (size_t i = 0; i < expected_seed_words; i += 3) {
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
            throw std::invalid_argument("Seed phrase encodes an invalid value");

        oxenc::write_host_as_little<uint32_t>(x, &out[(i / 3) * 4]);
    }

    if (has_checksum) {
        int checksum_idx = get_word_index(lang, words[n - 1]);
        if (checksum_idx < 0)
            throw unknown_word_error{std::string(words[n - 1])};

        // Compared by index, not by spelling: get_word_index() resolves a word by its prefix, so a
        // phrase whose words differ only past the significant letters still validates -- which is
        // the point of a prefix-based word list.
        auto expected = words.first(expected_seed_words);
        int expected_idx = get_word_index(lang, expected[checksum_index(expected, lang)]);
        if (checksum_idx != expected_idx)
            throw checksum_error{};
    }
}

session::secure_buffer words_to_bytes(
        std::span<const std::string_view> words, const Mnemonics& lang) {
    size_t n = words.size();
    bool has_checksum = n % 3 == 1;
    if (n % 3 != 0 && !has_checksum)
        throw std::invalid_argument(
                "Seed phrase word count must be a multiple of 3, or a multiple of 3 plus one "
                "checksum word (got {})"_format(n));

    size_t nbytes = ((n - has_checksum) / 3) * 4;
    session::secure_buffer result;
    auto rw = result.resize(nbytes);
    words_to_bytes_impl(words, lang, rw.buf);
    return result;
}

session::secure_buffer words_to_bytes(
        std::span<const std::string_view> words, std::string_view lang_name) {
    return words_to_bytes(words, get_language(lang_name));
}

void words_to_bytes(
        std::span<const std::string_view> words, const Mnemonics& lang, std::span<std::byte> out) {
    words_to_bytes_impl(words, lang, out);
}

void words_to_bytes(
        std::span<const std::string_view> words,
        std::string_view lang_name,
        std::span<std::byte> out) {
    words_to_bytes_impl(words, get_language(lang_name), out);
}

}  // namespace session::mnemonics
