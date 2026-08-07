#include <fmt/ranges.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <random>
#include <session/mnemonics.hpp>
#include <string_view>
#include <vector>

#include "utils.hpp"

using namespace session::mnemonics;
using namespace oxenc::literals;

// Test vectors: SHA-512("libsession-util mnemonic test vector") encoded as 48 words per language.
// These pin the exact word list contents and ordering; if any word list changes this test fails.
TEST_CASE("Mnemonic word list test vectors", "[mnemonics]") {
    // seed = SHA-512("libsession-util mnemonic test vector")
    auto seed =
            "0dd5d9bc3d68c25a396f4aacd922a4d620a19cf3c9054cb825dd8a2c5420f4f3"
            "ca314c582ffef5388df36e2546cc9103dd1776a634f676e1e631289b8d280b2e"_hex_b;

    // clang-format off
    const std::pair<std::string_view, std::array<std::string_view, 48>> expected[] = {
        {"English", {
            "threaten", "efficient", "wives",    "skirting", "repent",   "ashtray",
            "rural",    "ammo",      "reunion",  "yoyo",     "already",  "tucks",
            "attire",   "waxing",    "uphill",   "template", "ghetto",   "anxiety",
            "utensils", "newt",      "safety",   "paper",    "quote",    "pebbles",
            "album",    "gnaw",      "puppy",    "tidy",     "foxes",    "menu",
            "evenings", "spying",    "wallets",  "plotting", "fuselage", "geometry",
            "toilet",   "cylinder",  "swagger",  "eels",     "when",     "tether",
            "cowl",     "saga",      "gossip",   "vats",     "bias",     "federal",
        }},
        {"Chinese (simplified)", {
            "忆", "众", "瓷", "坡", "残", "合", "麻", "度", "综", "淀", "得", "炭",
            "四", "弃", "隆", "违", "亚", "物", "博", "娘", "缓", "薄", "纤", "暗",
            "方", "减", "爷", "浆", "官", "乐", "称", "阀", "蜡", "予", "谈", "落",
            "罚", "志", "蓝", "音", "浅", "森", "百", "净", "波", "灌", "无", "格",
        }},
        {"Dutch", {
            "tray",      "erna",       "zetbaas",    "spijgat",   "rits",      "bedwelmd",
            "salade",    "arubaan",    "rodijk",     "zottebol",  "aorta",     "vanmiddag",
            "belboei",   "worp",       "voip",       "tosti",     "glaasje",   "auping",
            "waas",      "neuzelaar",  "saus",       "pacht",     "ramselaar", "pauze",
            "amnestie",  "goeierd",    "puzzelaar",  "treur",     "gegraaid",  "mantel",
            "feilbaar",  "tabak",      "witmaker",   "plausibel", "gemiddeld", "giepmans",
            "tyfoon",    "derf",       "ticket",     "ermitage",  "zalig",     "trabant",
            "danenberg", "scampi",     "groosman",   "warklomp",  "bolvormig", "formule",
        }},
        {"Esperanto", {
            "sizifa",    "ebena",    "viskoza",      "rapida",   "optimisto",   "anjono",
            "pezoforto", "alfabeto", "orfino",       "zeto",     "akselo",      "stomako",
            "aplikado",  "vazaro",   "timida",       "sidejo",   "fermi",       "alzaca",
            "tosti",     "latitudo", "pilkoludo",    "moskito",  "ofsajdo",     "muro",
            "akademio",  "fimensa",  "oblikva",      "sklavo",   "eskapi",      "kisi",
            "elektro",   "rojo",     "vampiro",      "neulo",    "etullernejo", "feino",
            "sodakvo",   "cigaredo", "safario",      "duzo",     "veziko",      "simpla",
            "cemento",   "pimento",  "flirti",       "tunelo",   "babili",      "enciklopedio",
        }},
        {"French", {
            "skier",   "devoir",   "vingt",   "rideau",  "profond", "aucun",
            "rail",    "angoisse", "propre",  "vous",    "amener",  "star",
            "avant",   "vampire",  "tenter",  "sigle",   "fixe",    "ardeur",
            "toge",    "navrer",   "rang",    "parmi",   "pompier", "pause",
            "album",   "focus",    "poids",   "socle",   "faible",  "miel",
            "eaux",    "rustre",   "vague",   "pilote",  "faveur",  "final",
            "songeur", "chiot",    "sauge",   "devin",   "version", "sinon",
            "chasse",  "rapace",   "fosse",   "tour",    "billet",  "enlever",
        }},
        {"German", {
            "Salz",     "Dezibel",  "Wind",     "plündern", "Mund",     "Anker",
            "Oberarzt", "Alter",    "Nabel",    "Zielfoto", "Almosen",  "Skikurs",
            "Anrecht",  "Wahlen",   "Tempo",    "Rüstung",  "Espe",     "Amulett",
            "Topmodel", "Kampagne", "Ofenholz", "Lavasee",  "Milchkuh", "Lerche",
            "Aktfoto",  "Exil",     "melden",   "Sanftmut", "Erde",     "Hufeisen",
            "Edelweiß", "Rapsöl",   "Vorrat",   "Luxus",    "erkalten", "Erzeuger",
            "Schulbus", "Bogen",    "Respekt",  "Detektiv", "wechseln", "Sack",
            "Blauwal",  "öffnen",   "Fakultät", "Trödel",   "Bach",     "Einzug",
        }},
        {"Italian", {
            "spegnere", "comune",   "vigilare", "sartoria", "pulire",   "arachidi",
            "retorica", "amnistia", "quaderno", "zainetto", "amante",   "subire",
            "armonia",  "velluto",  "tirare",   "sospiro",  "enigma",   "anello",
            "trattore", "moglie",   "ricambio", "panino",   "porzione", "parodia",
            "allarme",  "esaltare", "polimero", "spezzare", "dorso",    "madama",
            "cupola",   "seme",     "vegetale", "pianeta",  "eclissi",  "emisfero",
            "stadio",   "cannone",  "silicone", "compagna", "vertebra", "spalla",
            "calzone",  "ricetta",  "estrarre", "tulipano", "bagaglio", "dialogo",
        }},
        {"Japanese", {
            "なさけ",       "きかく",     "はらう",     "でこぼこ",   "たんとう",   "いとこ",
            "ちゃんこなべ", "いさましい", "たんぴん",   "ひかく",     "いきもの",   "にっさん",
            "いふく",       "はせる",     "ねっしん",   "どんぶり",   "けちゃっぷ", "いそがしい",
            "ねんかん",     "せいよう",   "ちらみ",     "そめる",     "たぼう",     "そんぞく",
            "あんてい",     "けとばす",   "だったい",   "ななおし",   "くめる",     "しょっけん",
            "きまる",       "てんぷら",   "はこぶ",     "たいめん",   "けいけん",   "けしき",
            "なれる",       "おじさん",   "とくしゅう", "きかい",     "はったつ",   "ないそう",
            "おくる",       "ちりがみ",   "けみかる",   "のがす",     "うせつ",     "くうき",
        }},
        {"Lojban", {
            "vasxu",  "ferti",   "rarbau", "tadji",  "sisku",  "cando",
            "sobde",  "bloti",   "skami",  "faumlu", "birka",  "xabju",
            "carna",  "jbogu'e", "xruki",  "tutci",  "jicmu",  "briju",
            "zbabu",  "panje",   "sombo",  "ransu",  "senpi",  "rekto",
            "bifce",  "jinku",   "savru",  "vensa",  "jarco",  "murta",
            "gapru",  "temse",   "jbocre", "rupnu",  "jdini",  "jgira",
            "viska",  "dansu",   "toldi",  "fepri",  "reisku", "vamji",
            "dacti",  "sonci",   "jivbu",  "zifre",  "cinza",  "grake",
        }},
        {"Portuguese", {
            "sonso",     "druso",       "vontade",  "riacho",    "paxa",      "arlequim",
            "porvir",    "alvura",      "pegaso",   "xodo",      "alhures",   "tavola",
            "ascorbico", "vetusto",     "trovoar",  "slide",     "feto",      "anotar",
            "ufologo",   "mausoleu",    "prezar",   "nouveau",   "otite",     "nutritivo",
            "ajudante",  "fiorde",      "orla",     "sossego",   "exaustor",  "lele",
            "emulsao",   "rural",       "veja",     "ojeriza",   "faixas",    "feltro",
            "suor",      "cluster",     "seara",    "dropes",    "viquingue", "soerguer",
            "cinzento",  "privilegios", "foco",     "unheiro",   "bemol",     "ereto",
        }},
        {"Russian", {
            "уровень",  "древний",  "эмблема",  "тайна",    "сельский", "бегство",
            "согласие", "арсенал",  "сечение",  "язык",     "аптека",   "фишка",
            "бивень",   "шрам",     "центр",    "умолять",  "исходить", "атрибут",
            "чепуха",   "отбор",    "сонный",   "пуля",     "рюкзак",   "пшеница",
            "анкета",   "капитан",  "рыба",     "ускорять", "иголка",   "область",
            "женщина",  "трибуна",  "шорох",    "ресурс",   "изоляция", "ипподром",
            "ушко",     "гамма",    "тянуть",   "драка",    "щель",     "уплата",
            "выходить", "сообщать", "кенгуру",  "чужой",    "быстрый",  "зачет",
        }},
        {"Spanish", {
            "pasta",   "chiste",   "relieve", "obtener", "mito",    "anillo",
            "músculo", "aleta",    "moho",    "riego",   "alambre", "pésimo",
            "añejo",   "reacción", "pompa",   "parcela", "diente",  "altura",
            "previo",  "intuir",   "nación",  "llanto",  "mensaje", "loción",
            "aguja",   "divino",   "mecha",   "pausa",   "curva",   "héroe",
            "collar",  "óptica",   "rasgo",   "mamut",   "dejar",   "diamante",
            "pellejo", "brote",    "otoño",   "chico",   "reflejo", "párrafo",
            "bozal",   "nadar",    "droga",   "pronto",  "astro",   "crear",
        }},
    };
    // clang-format on

    for (auto& [lang_name, exp_words] : expected) {
        SECTION(std::string(lang_name)) {
            auto* lang = find_language(lang_name);
            REQUIRE(lang);
            auto mnemonic = bytes_to_words(seed, *lang, false);
            REQUIRE(mnemonic.size() == 48);
            auto wspan = mnemonic.open();
            for (size_t i = 0; i < 48; i++)
                CHECK(wspan[i] == exp_words[i]);
        }
    }
}

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
            auto words12 = bytes_to_words(data_128, *lang, false);
            CHECK(words12.size() == 12);
            auto back12 = words_to_bytes(words12.open().words, *lang);
            CHECK(std::ranges::equal(back12.access().buf, data_128));

            // 128-bit -> 13 words (with checksum) -> 128-bit
            auto words13 = bytes_to_words(data_128, *lang);
            CHECK(words13.size() == 13);
            auto back13 = words_to_bytes(words13.open().words, *lang);
            CHECK(std::ranges::equal(back13.access().buf, data_128));

            // 256-bit -> 24 words -> 256-bit
            auto words24 = bytes_to_words(data_256, *lang, false);
            CHECK(words24.size() == 24);
            auto back24 = words_to_bytes(words24.open().words, *lang);
            CHECK(std::ranges::equal(back24.access().buf, data_256));

            // 256-bit -> 25 words (with checksum) -> 256-bit
            auto words25 = bytes_to_words(data_256, *lang);
            CHECK(words25.size() == 25);
            auto back25 = words_to_bytes(words25.open().words, *lang);
            CHECK(std::ranges::equal(back25.access().buf, data_256));
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
    auto words = bytes_to_words(data, *english, false);
    REQUIRE(words.size() == 3);

    SECTION("Exact match") {
        auto back = words_to_bytes(words.open().words, *english);
        CHECK(std::ranges::equal(back.access().buf, data));
    }

    SECTION("Case-insensitive match (ASCII)") {
        std::vector<std::string_view> upper_words;
        std::vector<std::string> storage;
        for (auto w : words.open()) {
            std::string upper(w);
            for (auto& c : upper)
                c = std::toupper(static_cast<unsigned char>(c));
            storage.push_back(upper);
        }
        for (const auto& s : storage)
            upper_words.push_back(s);

        auto back = words_to_bytes(upper_words, *english);
        CHECK(std::ranges::equal(back.access().buf, data));
    }

    SECTION("Prefix match") {
        std::vector<std::string_view> prefix_words;
        std::vector<std::string> storage;
        for (auto w : words.open()) {
            storage.push_back(std::string(w.substr(0, english->prefix_len)));
        }
        for (const auto& s : storage)
            prefix_words.push_back(s);

        auto back = words_to_bytes(prefix_words, *english);
        CHECK(std::ranges::equal(back.access().buf, data));
    }

    SECTION("Prefix match with typo after prefix") {
        std::vector<std::string_view> typo_words;
        std::vector<std::string> storage;
        for (auto w : words.open()) {
            storage.push_back(std::string(w.substr(0, english->prefix_len)) + "xyz");
        }
        for (const auto& s : storage)
            typo_words.push_back(s);

        auto back = words_to_bytes(typo_words, *english);
        CHECK(std::ranges::equal(back.access().buf, data));
    }
}

TEST_CASE("Mnemonic language lookup", "[mnemonics]") {
    CHECK(find_language("English") != nullptr);
    CHECK(find_language("German") != nullptr);
    CHECK(find_language("Deutsch") != nullptr);
    CHECK(find_language("русский язык") != nullptr);
    CHECK(find_language("NonExistent") == nullptr);
}

TEST_CASE("Mnemonic checksum", "[mnemonics]") {
    auto english = find_language("English");
    REQUIRE(english);

    std::vector<std::byte> data = {
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
    auto words3 = bytes_to_words(data, *english, false);
    REQUIRE(words3.size() == 3);
    auto words4 = bytes_to_words(data, *english);
    REQUIRE(words4.size() == 4);

    SECTION("Checksum word duplicates one of the seed words") {
        // Which one is chosen is pinned by the reference vectors below; the invariant here is that
        // it is always a repeat of a seed word rather than an independent thirteenth word.
        auto s3 = words3.open();
        auto s4 = words4.open();
        CHECK((s4[3] == s3[0] || s4[3] == s3[1] || s4[3] == s3[2]));
    }

    SECTION("Checksum round-trip") {
        auto back = words_to_bytes(words4.open().words, *english);
        CHECK(std::ranges::equal(back.access().buf, data));
    }

    SECTION("Bad checksum throws checksum_error") {
        // A known word that is not any of the seed words cannot be the checksum word, whichever of
        // them the CRC selects.
        auto s4 = words4.open();
        std::string_view other;
        for (auto w : english->words)
            if (w != s4[0] && w != s4[1] && w != s4[2]) {
                other = w;
                break;
            }
        REQUIRE(!other.empty());
        std::vector<std::string_view> bad = {s4[0], s4[1], s4[2], other};
        CHECK_THROWS_AS(words_to_bytes(bad, *english), checksum_error);
    }

    SECTION("Unknown checksum word throws unknown_word_error") {
        auto s4 = words4.open();
        std::vector<std::string_view> bad = {s4[0], s4[1], s4[2], "ZZZunknown"};
        CHECK_THROWS_AS(words_to_bytes(bad, *english), unknown_word_error);
    }
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
        // Use mixed case to verify word() returns the original input, not a lowercased prefix.
        // "ZZZ..." has prefix "zzz" which is not in the English word list.
        std::vector<std::string_view> words = {"abbey", "abducts", "ZZZunknown"};
        CHECK_THROWS_AS(words_to_bytes(words, *english), unknown_word_error);
        try {
            words_to_bytes(words, *english);
        } catch (const unknown_word_error& e) {
            CHECK(e.word() == "ZZZunknown");
        }
    }

    SECTION("Overflow word triplet") {
        // a=0 (abbey), b=0 (abbey), c=1625 (zoom):
        // 0 + 0 + 1625*1626² = 4,296,298,500 > UINT32_MAX — must be rejected
        std::vector<std::string_view> words = {"abbey", "abbey", "zoom"};
        CHECK_THROWS_AS(words_to_bytes(words, *english), std::invalid_argument);
    }
}

// ── Checksum word ───────────────────────────────────────────────────────────────────────────────
//
// The checksum word repeats one of the seed words, selected by a CRC-32 over their concatenated
// prefixes modulo the word count.  The vectors below were produced from that algorithm as it is
// implemented in oxen-core's electrum-words.cpp (boost::crc_32_type over the trimmed words) and,
// independently, session-ios' Mnemonic.swift -- the two shipping implementations libsession has to
// interoperate with.
TEST_CASE("mnemonics: checksum word matches the reference algorithm", "[mnemonics][checksum]") {
    constexpr auto seed16 = "000102030405060708090a0b0c0d0e0f"_hex_b;
    constexpr auto seed32 =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"_hex_b;

    auto words_of = [](std::span<const std::byte> seed) {
        auto m = session::mnemonics::bytes_to_words(seed, "English");
        auto opened = m.open();
        return std::vector<std::string>{opened.begin(), opened.end()};
    };

    SECTION("13 words") {
        auto w = words_of(seed16);
        REQUIRE(w.size() == 13);
        CHECK(fmt::format("{}", fmt::join(w, " ")) ==
              "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed "
              "faxed");
        // The checksum word is a repeat of one of the seed words, not a thirteenth distinct one.
        CHECK(w.back() == w[11]);
    }

    SECTION("25 words") {
        auto w = words_of(seed32);
        REQUIRE(w.size() == 25);
        CHECK(fmt::format("{}", fmt::join(w, " ")) ==
              "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed "
              "update vague zinger boxes ornament renting glass gained island nabbing afield "
              "calamity boxes");
        CHECK(w.back() == w[15]);
    }

    SECTION("an all-zero seed still checksums") {
        auto w = words_of("00000000000000000000000000000000"_hex_b);
        REQUIRE(w.size() == 13);
        for (const auto& word : w)
            CHECK(word == "abbey");
    }
}

TEST_CASE("mnemonics: phrases round-trip through the checksum", "[mnemonics][checksum]") {
    for (auto hex :
         {"000102030405060708090a0b0c0d0e0f",
          "ffffffffffffffffffffffffffffffff",
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}) {
        auto seed = oxenc::from_hex(std::string_view{hex});
        auto bytes = std::as_bytes(std::span{seed});

        auto m = session::mnemonics::bytes_to_words(bytes, "English");
        auto back = session::mnemonics::words_to_bytes(
                m.open().words, session::mnemonics::get_language("English"));
        auto acc = back.access();
        CHECK(std::ranges::equal(std::span{acc.buf}, bytes));
    }
}

TEST_CASE("mnemonics: only the significant prefix matters", "[mnemonics][checksum]") {
    // English uses a 3-codepoint prefix, so anything past the third letter is decoration: a phrase
    // stays valid when the tail of a word is mistyped, or truncated to just the prefix.  This is
    // the property that makes the word list usable at all, and it has to hold for the checksum word
    // as well as the seed words, since the checksum is computed over prefixes too.
    constexpr auto seed = "000102030405060708090a0b0c0d0e0f"_hex_b;
    auto expected = std::vector<std::byte>{seed.begin(), seed.end()};

    auto decodes_to_seed = [&](std::vector<std::string_view> w) {
        auto back =
                session::mnemonics::words_to_bytes(w, session::mnemonics::get_language("English"));
        auto acc = back.access();
        return std::ranges::equal(std::span{acc.buf}, expected);
    };

    // amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed | faxed
    SECTION("typos past the third letter") {
        CHECK(decodes_to_seed(
                {"amazing",
                 "buffalo",
                 "cakewalk",
                 "entropy",
                 "symbol",
                 "tigger",
                 "lambda",
                 "mazurka",
                 "nestling",
                 "pythons",
                 "dustpan",
                 "faxing",
                 "faxing"}));
    }

    SECTION("words truncated to their prefix") {
        CHECK(decodes_to_seed(
                {"ama",
                 "buf",
                 "cak",
                 "ent",
                 "sym",
                 "tig",
                 "lam",
                 "maz",
                 "nes",
                 "pyt",
                 "dus",
                 "fax",
                 "fax"}));
    }

    SECTION("a mistyped tail on the checksum word alone") {
        CHECK(decodes_to_seed(
                {"amaze",
                 "buffet",
                 "cake",
                 "entrance",
                 "symptoms",
                 "tiger",
                 "lamb",
                 "maze",
                 "nestle",
                 "python",
                 "dusted",
                 "faxed",
                 "faxidermy"}));
    }
}

TEST_CASE("mnemonics: rejects bad phrases", "[mnemonics][checksum]") {
    auto lang = std::cref(session::mnemonics::get_language("English"));
    auto decode = [&](std::vector<std::string_view> w) {
        return session::mnemonics::words_to_bytes(w, lang.get());
    };

    // Correct phrase, for reference:
    // amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed | faxed
    SECTION("wrong checksum word") {
        CHECK_THROWS_AS(
                decode({"amaze",
                        "buffet",
                        "cake",
                        "entrance",
                        "symptoms",
                        "tiger",
                        "lamb",
                        "maze",
                        "nestle",
                        "python",
                        "dusted",
                        "faxed",
                        "amaze"}),
                session::mnemonics::checksum_error);
    }

    SECTION("two seed words transposed") {
        // Same words, so a sum-of-indices checksum would not notice; a CRC over the ordered
        // prefixes does.
        CHECK_THROWS_AS(
                decode({"buffet",
                        "amaze",
                        "cake",
                        "entrance",
                        "symptoms",
                        "tiger",
                        "lamb",
                        "maze",
                        "nestle",
                        "python",
                        "dusted",
                        "faxed",
                        "faxed"}),
                session::mnemonics::checksum_error);
    }

    SECTION("one seed word altered before the prefix boundary") {
        CHECK_THROWS_AS(
                decode({"amaze",
                        "buffet",
                        "cake",
                        "entrance",
                        "symptoms",
                        "tiger",
                        "lamb",
                        "maze",
                        "nestle",
                        "python",
                        "dusted",
                        "gagged",
                        "faxed"}),
                session::mnemonics::checksum_error);
    }

    SECTION("a word that is not in the list at all") {
        CHECK_THROWS_AS(
                decode({"amaze",
                        "buffet",
                        "cake",
                        "entrance",
                        "symptoms",
                        "tiger",
                        "lamb",
                        "maze",
                        "nestle",
                        "python",
                        "dusted",
                        "faxed",
                        "zzzzz"}),
                session::mnemonics::unknown_word_error);
    }
}
