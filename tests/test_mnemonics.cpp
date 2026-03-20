#include <catch2/catch_test_macros.hpp>
#include <random>
#include <session/mnemonics.hpp>
#include <string_view>
#include <vector>

#include "utils.hpp"

using namespace session::mnemonics;

// Test vectors: SHA-512("libsession-util mnemonic test vector") encoded as 48 words per language.
// These pin the exact word list contents and ordering; if any word list changes this test fails.
TEST_CASE("Mnemonic word list test vectors", "[mnemonics]") {
    // seed = SHA-512("libsession-util mnemonic test vector")
    auto seed = "0dd5d9bc3d68c25a396f4aacd922a4d620a19cf3c9054cb825dd8a2c5420f4f3"
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
            auto words = bytes_to_words(seed, *lang);
            REQUIRE(words.size() == 48);
            for (size_t i = 0; i < 48; i++)
                CHECK(words[i] == exp_words[i]);
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
