#include <oxenc/hex.h>
#include <session/config/convo_info_volatile.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <iostream>
#include <session/config/convo_info_volatile.hpp>
#include <session/types.hpp>
#include <string_view>
#include <variant>
#include <vector>

#include "utils.hpp"

static std::string convo_key_1o1(const std::string& session_id) {
    return "1-to-1: " + session_id;
}
static std::string convo_key_group(const std::string& id) {
    return "gr: " + id;
}
static std::string convo_key_community(const std::string& base_url, const std::string& room) {
    return "comm: " + base_url + "/r/" + room;
}
static std::string convo_key_legacy_group(const std::string& id) {
    return "lgr: " + id;
}
static std::string convo_key_blinded_1o1(
        const std::string& blinded_session_id, bool legacy_blinding) {
    return (legacy_blinding ? "lb: " : "b: ") + blinded_session_id;
}

static std::string convo_key(const session::config::convo::any& c) {
    if (auto* x = std::get_if<session::config::convo::one_to_one>(&c))
        return convo_key_1o1(x->session_id);
    if (auto* x = std::get_if<session::config::convo::group>(&c))
        return convo_key_group(x->id);
    if (auto* x = std::get_if<session::config::convo::community>(&c))
        return convo_key_community(x->base_url(), x->room());
    if (auto* x = std::get_if<session::config::convo::legacy_group>(&c))
        return convo_key_legacy_group(x->id);
    auto* x = std::get_if<session::config::convo::blinded_one_to_one>(&c);
    return convo_key_blinded_1o1(x->blinded_session_id, x->legacy_blinding);
}

static std::vector<std::string> convo_key_lines(const session::config::ConvoInfoVolatile& convos) {
    std::vector<std::string> lines;
    lines.push_back("-- active --");
    if (convos.begin() == convos.end())
        lines.push_back("none");
    for (auto it = convos.begin(false); !it.done(); ++it)
        lines.push_back(convo_key(*it));
    lines.push_back("-- archived --");
    if (convos.begin_archived() == convos.end())
        lines.push_back("none");
    for (auto it = convos.begin_archived(); !it.done(); ++it)
        lines.push_back("" + convo_key(*it));
    return lines;
}

std::string dump_convo_keys(const session::config::ConvoInfoVolatile& convos) {
    std::string out;
    for (const auto& line : convo_key_lines(convos))
        out += line + "\n";
    return out;
}

TEST_CASE("Conversations", "[config][conversations]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::ConvoInfoVolatile convos{std::span<const unsigned char>{seed}, std::nullopt};

    std::string definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000";

    std::string benders_nightmare_group =
            "030111101001001000101010011011010010101010111010000110100001210000";

    std::string legacy_blinded_id =
            "150000000000000000000000000000000000101010111010000110100001210000";
    std::string blinded_id = "255000000000000000000000000000000000101010111010000110100001210000";

    CHECK_FALSE(convos.get_1to1(definitely_real_id));

    CHECK(convos.empty());
    CHECK(convos.size() == 0);

    auto c = convos.get_or_construct_1to1(definitely_real_id);

    CHECK(c.session_id == definitely_real_id);
    CHECK(c.last_read == 0);

    CHECK_FALSE(convos.needs_push());
    CHECK_FALSE(convos.needs_dump());
    CHECK(std::get<seqno_t>(convos.push()) == 0);

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    c.last_read = now_ms;

    // The new data doesn't get stored until we call this:
    convos.set(c);  // active, definitely_real_id

    REQUIRE_FALSE(convos.get_legacy_group(definitely_real_id).has_value());
    REQUIRE(convos.get_1to1(definitely_real_id).has_value());
    CHECK(convos.get_1to1(definitely_real_id)->last_read == now_ms);

    CHECK(convos.needs_push());
    CHECK(convos.needs_dump());

    const auto community_pubkey =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    std::string comm_url = "http://Example.ORG:5678";
    std::string comm_room = "SudokuRoom";

    std::string comm_url_lowercase;
    std::ranges::transform(comm_url, std::back_inserter(comm_url_lowercase), ::tolower);

    std::string comm_room_lowercase;
    std::ranges::transform(comm_room, std::back_inserter(comm_room_lowercase), ::tolower);

    auto og = convos.get_or_construct_community(comm_url, comm_room, community_pubkey);
    CHECK(og.base_url() == comm_url_lowercase);  // Note: lower-case
    CHECK(og.room() == comm_room_lowercase);     // Note: lower-case
    CHECK(og.pubkey().size() == 32);
    CHECK(og.pubkey_hex() == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    og.unread = true;
    og.last_read = now_ms;

    // The new data doesn't get stored until we call this:
    convos.set(og);  // active, comm_url_lowercase/comm_room_lowercase

    CHECK_FALSE(convos.get_group(benders_nightmare_group));

    auto g = convos.get_or_construct_group(benders_nightmare_group);
    CHECK(g.id == benders_nightmare_group);
    CHECK(g.last_read == 0);
    CHECK_FALSE(g.unread);

    g.last_read = now_ms;
    g.unread = true;
    convos.set(g);  // active, benders_nightmare_group

    CHECK_FALSE(convos.get_blinded_1to1(legacy_blinded_id));
    CHECK_FALSE(convos.get_blinded_1to1(blinded_id));

    auto lb = convos.get_or_construct_blinded_1to1(legacy_blinded_id);
    CHECK(lb.blinded_session_id == legacy_blinded_id);
    CHECK(lb.last_read == 0);
    CHECK_FALSE(lb.unread);

    lb.last_read = now_ms;
    lb.unread = true;
    convos.set(lb);  // active, legacy_blinded_id

    auto b = convos.get_or_construct_blinded_1to1(blinded_id);
    CHECK(b.blinded_session_id == blinded_id);
    CHECK(b.last_read == 0);
    CHECK_FALSE(b.unread);

    b.last_read = now_ms;
    b.unread = true;
    convos.set(b);  // active, blinded_id

    // At this point we should have 5 entries in active, 0 in archive
    CHECK(convos.size() == 5);
    // here we should have
    CHECK(convo_key_lines(convos) ==
          std::vector<std::string>{
                  "-- active --",
                  convo_key_1o1(definitely_real_id),
                  convo_key_group(benders_nightmare_group),
                  convo_key_community(comm_url_lowercase, comm_room_lowercase),
                  convo_key_blinded_1o1(legacy_blinded_id, true),
                  convo_key_blinded_1o1(blinded_id, false),
                  "-- archived --",
                  "none"});

    auto [seqno, to_push, obs] = convos.push();

    CHECK(seqno == 1);

    // Pretend we uploaded it
    convos.confirm_pushed(seqno, {"hash1"});
    CHECK(convos.needs_dump());
    CHECK_FALSE(convos.needs_push());

    // NB: Not going to check encrypted data and decryption here because that's general (not
    // specific to convos) and is covered already in the user profile tests.

    session::config::ConvoInfoVolatile convos2{seed, convos.dump()};
    CHECK_FALSE(convos.needs_push());
    CHECK_FALSE(convos.needs_dump());
    CHECK(std::get<seqno_t>(convos.push()) == 1);
    CHECK_FALSE(convos.needs_dump());  // Because we just called dump() above, to load up
                                       // convos2.

    auto x1 = convos2.get_1to1(definitely_real_id);
    REQUIRE(x1);
    CHECK(x1->last_read == now_ms);
    CHECK(x1->session_id == definitely_real_id);
    CHECK_FALSE(x1->unread);

    auto x2 = convos2.get_community(comm_url, comm_room);
    REQUIRE(x2);
    CHECK(x2->base_url() == comm_url_lowercase);
    CHECK(x2->room() == comm_room_lowercase);
    CHECK(x2->pubkey_hex() == to_hex(community_pubkey));
    CHECK(x2->unread);
    CHECK(x2->last_read == now_ms);

    auto x3 = convos2.get_group(benders_nightmare_group);
    REQUIRE(x3);
    CHECK(x3->last_read == now_ms);
    CHECK(x3->unread);

    auto x4 = convos2.get_blinded_1to1(legacy_blinded_id);
    REQUIRE(x4);
    CHECK(x4->blinded_session_id == legacy_blinded_id);
    CHECK(x4->last_read == now_ms);
    CHECK(x4->unread);

    auto x5 = convos2.get_blinded_1to1(blinded_id);
    REQUIRE(x5);
    CHECK(x5->blinded_session_id == blinded_id);
    CHECK(x5->last_read == now_ms);
    CHECK(x5->unread);

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111"sv;
    auto c2 = convos.get_or_construct_1to1(another_id);
    c2.unread = true;
    convos2.set(c2);  // archived

    std::string legacy_group_id =
            "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    auto c3 = convos2.get_or_construct_legacy_group(legacy_group_id);
    c3.last_read = now_ms - 50;
    convos2.set(c3);  // active

    std::string another_blinded_id =
            "2512345ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    auto c4 = convos2.get_or_construct_blinded_1to1(another_blinded_id);
    c4.unread = true;
    convos2.set(c4);  // archived

    CHECK(convos2.needs_push());

    std::tie(seqno, to_push, obs) = convos2.push();

    CHECK(seqno == 2);

    REQUIRE(to_push.size() == 1);
    std::vector<std::pair<std::string, std::span<const unsigned char>>> merge_configs;
    merge_configs.emplace_back("hash2", to_push[0]);
    convos.merge(merge_configs);
    convos2.confirm_pushed(seqno, {"hash2"});

    CHECK_FALSE(convos.needs_push());
    CHECK(convos.needs_dump());
    CHECK(std::get<seqno_t>(convos.push()) == seqno);

    using session::config::convo::blinded_one_to_one;
    using session::config::convo::community;
    using session::config::convo::group;
    using session::config::convo::legacy_group;
    using session::config::convo::one_to_one;

    std::vector<std::string> seen, expected;
    for (const auto& e : {
                 convo_key_1o1(definitely_real_id),
                 convo_key_group(benders_nightmare_group),
                 convo_key_community(comm_url_lowercase, comm_room_lowercase),
                 convo_key_legacy_group(legacy_group_id),
                 convo_key_blinded_1o1(legacy_blinded_id, true),
                 convo_key_blinded_1o1(blinded_id, false),
         })
        expected.emplace_back(e);

    // We've merged convos2 push result to convos, but also inserted (as archived) some entries
    // in convos2. Those 2 should only be present in convos2 and not in convos
    CHECK(convos2.size_archived() == 2);
    CHECK(convos2.size_1to1_archived() == 1);
    CHECK(convos2.size_blinded_1to1_archived() == 1);
    CHECK(convos.size_archived() == 0);

    auto archived1to1 = convos2.get_1to1(another_id);
    CHECK(archived1to1);
    CHECK(archived1to1->unread);
    CHECK(archived1to1->last_read == 0);  // this was archived as last_read wasn't set

    auto archived_blinded = convos2.get_blinded_1to1(another_blinded_id);
    CHECK(archived_blinded);
    CHECK(archived_blinded->unread);
    CHECK(archived_blinded->last_read == 0);  // this was archived as last_read wasn't set

    for (auto* conv : {&convos, &convos2}) {
        // Iterate through and make sure we got everything we expected
        seen.clear();
        CHECK(conv->size() == 6);
        CHECK(conv->size_1to1() == 1);  // 2 were inserted, but one is archived
        CHECK(conv->size_communities() == 1);
        CHECK(conv->size_legacy_groups() == 1);
        CHECK(conv->size_groups() == 1);
        CHECK(conv->size_blinded_1to1() == 2);
        CHECK_FALSE(conv->empty());
        // create the iterator manually so that we exclude the archived entries (as we've
        // checked for those just above)
        for (auto it = conv->begin(false); !it.done(); ++it) {
            auto convo = *it;
            if (auto* c = std::get_if<one_to_one>(&convo))
                seen.push_back(convo_key_1o1(c->session_id));
            else if (auto* c = std::get_if<group>(&convo))
                seen.push_back(convo_key_group(c->id));
            else if (auto* c = std::get_if<community>(&convo))
                seen.push_back(convo_key_community(c->base_url(), c->room()));
            else if (auto* c = std::get_if<legacy_group>(&convo))
                seen.push_back(convo_key_legacy_group(c->id));
            else if (auto* c = std::get_if<blinded_one_to_one>(&convo); c->legacy_blinding)
                seen.push_back(convo_key_blinded_1o1(c->blinded_session_id, true));
            else if (auto* c = std::get_if<blinded_one_to_one>(&convo); !c->legacy_blinding)
                seen.push_back(convo_key_blinded_1o1(c->blinded_session_id, false));
            else
                seen.push_back("unknown convo type!");
        }

        CHECK(seen == expected);
    }

    CHECK_FALSE(convos.needs_push());

    // remove a non existing entry
    convos.erase_1to1("052000000000000000000000000000000000000000000000000000000000000000");

    CHECK_FALSE(convos.needs_push());

    convos.erase_1to1(definitely_real_id);  // active
    convos.erase_blinded_1to1(blinded_id);  // active
    CHECK(convos.needs_push());
    CHECK(convos.needs_dump());
    CHECK(convos.size_archived() == 0);          // no archived entries on convos (only on convos2)
    CHECK(convos.size() == 6 - 2);               // size was 6 before erase x2
    CHECK(convos.size_1to1() == 1 - 1);          // size was 1 before erase of 1x 1o1
    CHECK(convos.size_groups() == 1);            // no erase on group
    CHECK(convos.size_blinded_1to1() == 2 - 1);  // one erase on blinded that was active

    convos2.dump();
    CHECK_FALSE(convos2.needs_dump());

    // check that we can erase an entry from the archived entries
    // archived only on convos2
    CHECK(convos2.size_archived() == 2);
    CHECK(convos2.size_1to1_archived() == 1);
    CHECK(convos2.size_blinded_1to1_archived() == 1);
    convos2.erase_1to1(another_id);
    // we've removed some entries from convos, but not from convos2
    CHECK(convos2.needs_dump());
    CHECK(convos2.size() == 6);
    CHECK(convos2.size_1to1() == 1);
    CHECK(convos2.size_groups() == 1);
    CHECK(convos2.size_blinded_1to1() == 2);
    CHECK(convos2.size_archived() == 2 - 1);       // we've just removed an archived 1o1
    CHECK(convos2.size_1to1_archived() == 1 - 1);  // we've just removed an archived 1o1
    CHECK(convos2.size_blinded_1to1_archived() == 1);

    // Check the single-type iterators:
    seen.clear();
    // definitely_real_id is archived in convos2
    for (auto it = convos2.begin_1to1(true); it != convos2.end(); ++it)
        seen.push_back(it->session_id);
    CHECK(seen == std::vector<std::string>{
                          std::string(definitely_real_id),
                  });

    seen.clear();
    for (auto it = convos.begin_communities(); it != convos.end(); ++it)
        seen.emplace_back(it->base_url());
    CHECK(seen == std::vector<std::string>{
                          comm_url_lowercase,
                  });

    seen.clear();
    for (auto it = convos.begin_legacy_groups(); it != convos.end(); ++it)
        seen.emplace_back(it->id);
    CHECK(seen == std::vector<std::string>{
                          legacy_group_id,
                  });

    seen.clear();
    for (auto it = convos.begin_blinded_1to1(); it != convos.end(); ++it)
        seen.emplace_back(it->blinded_session_id);
    CHECK(seen == std::vector<std::string>{
                          legacy_blinded_id,
                  });

    // convos has no archived configs as all of them are on convos2
    CHECK(convos.size_archived() == 0);
    CHECK(convos2.size_archived() == 2);

    // Ensure that we throw correctly when giving invalid blinded ids
    auto invalid_id_1 = "072222222222222222222222222222222222222222222222222222222222222222"sv;
    auto invalid_id_2 = "992222222222222222222222222222222222222222222222222222222222222222"sv;
    CHECK_THROWS(convos.get_or_construct_blinded_1to1(invalid_id_1));
    CHECK_THROWS(convos.get_or_construct_blinded_1to1(invalid_id_2));
}

TEST_CASE("Conversations (C API)", "[config][conversations][c]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    config_object* conf;
    REQUIRE(0 == convo_info_volatile_init(&conf, ed_sk.data(), NULL, 0, NULL));

    std::string definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000";

    convo_info_volatile_1to1 c;
    CHECK_FALSE(convo_info_volatile_get_1to1(conf, &c, definitely_real_id.c_str()));
    CHECK(conf->last_error == nullptr);

    CHECK_FALSE(convo_info_volatile_get_1to1(conf, &c, "05123456"));
    CHECK(conf->last_error ==
          "Invalid session ID: expected 66 hex digits starting with 05; got 05123456"sv);

    CHECK(convo_info_volatile_size(conf) == 0);

    CHECK(convo_info_volatile_get_or_construct_1to1(conf, &c, definitely_real_id.c_str()));

    CHECK(c.session_id == definitely_real_id);
    CHECK(c.last_read == 0);
    CHECK_FALSE(c.unread);

    CHECK_FALSE(config_needs_push(conf));
    CHECK_FALSE(config_needs_dump(conf));

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    c.last_read = now_ms;

    // The new data doesn't get stored until we call this:
    convo_info_volatile_set_1to1(conf, &c);

    convo_info_volatile_legacy_group cg;
    REQUIRE_FALSE(convo_info_volatile_get_legacy_group(conf, &cg, definitely_real_id.c_str()));
    REQUIRE(convo_info_volatile_get_1to1(conf, &c, definitely_real_id.c_str()));
    CHECK(c.last_read == now_ms);

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));

    const auto community_pubkey =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    convo_info_volatile_community og;

    CHECK_FALSE(convo_info_volatile_get_or_construct_community(
            conf,
            &og,
            "bad-url",
            "room",
            "0000000000000000000000000000000000000000000000000000000000000000"_hexbytes.data()));
    CHECK(conf->last_error == "Invalid URL: invalid/missing protocol://"sv);
    CHECK_FALSE(convo_info_volatile_get_or_construct_community(
            conf,
            &og,
            "https://example.com",
            "bad room name",
            "0000000000000000000000000000000000000000000000000000000000000000"_hexbytes.data()));
    CHECK(conf->last_error == "Invalid community URL: room token contains invalid characters"sv);

    CHECK(convo_info_volatile_get_or_construct_community(
            conf, &og, "http://Example.ORG:5678", "SudokuRoom", community_pubkey.data()));
    CHECK(conf->last_error == nullptr);
    CHECK(og.base_url == "http://example.org:5678"sv);  // Note: lower-case
    CHECK(og.room == "sudokuroom"sv);                   // Note: lower-case
    CHECK(oxenc::to_hex(og.pubkey, og.pubkey + 32) ==
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    og.unread = true;

    // The new data doesn't get stored until we call this:
    convo_info_volatile_set_community(conf, &og);

    const char* const blinded_id =
            "150000000000000000000000000000000000101010111010000110100001210000";
    convo_info_volatile_blinded_1to1 b1;
    REQUIRE_FALSE(convo_info_volatile_get_blinded_1to1(conf, &b1, blinded_id));
    REQUIRE(convo_info_volatile_get_or_construct_blinded_1to1(conf, &b1, blinded_id));
    b1.last_read = now_ms;
    convo_info_volatile_set_blinded_1to1(conf, &b1);

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));

    config_push_data* to_push = config_push(conf);
    auto seqno = to_push->seqno;
    CHECK(seqno == 1);
    REQUIRE(to_push->n_configs == 1);
    free(to_push);

    const char* tmphash;  // test suite cheat: &(tmphash = "asdf") to fake a length-1 array.

    // Pretend we uploaded it
    config_confirm_pushed(conf, seqno, &(tmphash = "hash1"), 1);
    CHECK(config_needs_dump(conf));
    CHECK_FALSE(config_needs_push(conf));

    unsigned char* dump;
    size_t dumplen;
    config_dump(conf, &dump, &dumplen);

    config_object* conf2;
    REQUIRE(convo_info_volatile_init(&conf2, ed_sk.data(), dump, dumplen, NULL) == 0);
    free(dump);

    CHECK_FALSE(config_needs_push(conf2));
    CHECK_FALSE(config_needs_dump(conf2));

    REQUIRE(convo_info_volatile_get_1to1(conf2, &c, definitely_real_id.c_str()));
    CHECK(c.last_read == now_ms);
    CHECK(c.session_id == definitely_real_id);
    CHECK_FALSE(c.unread);

    REQUIRE(convo_info_volatile_get_community(conf2, &og, "http://EXAMPLE.org:5678", "sudokuRoom"));
    CHECK(og.base_url == "http://example.org:5678"sv);
    CHECK(og.room == "sudokuroom"sv);
    CHECK(oxenc::to_hex(og.pubkey, og.pubkey + 32) == to_hex(community_pubkey));

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111";
    convo_info_volatile_1to1 c2;
    REQUIRE(convo_info_volatile_get_or_construct_1to1(conf2, &c2, another_id));
    c2.unread = true;
    convo_info_volatile_set_1to1(conf2, &c2);

    REQUIRE(convo_info_volatile_get_or_construct_legacy_group(
            conf2, &cg, "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    cg.last_read = now_ms - 50;
    convo_info_volatile_set_legacy_group(conf2, &cg);
    CHECK(config_needs_push(conf2));

    convo_info_volatile_blinded_1to1 b2;
    REQUIRE(convo_info_volatile_get_or_construct_blinded_1to1(
            conf2, &b2, "2512345ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    b2.unread = true;
    convo_info_volatile_set_blinded_1to1(conf2, &b2);
    CHECK(config_needs_push(conf2));

    to_push = config_push(conf2);
    CHECK(to_push->seqno == 2);
    REQUIRE(to_push->n_configs == 1);

    const char* hash_data[1];
    const unsigned char* merge_data[1];
    size_t merge_size[1];
    hash_data[0] = "hash123";
    merge_data[0] = to_push->config[0];
    merge_size[0] = to_push->config_lens[0];
    config_string_list* accepted = config_merge(conf, hash_data, merge_data, merge_size, 1);
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "hash123"sv);
    free(accepted);
    config_confirm_pushed(conf2, seqno, &(tmphash = "hash123"), 1);
    free(to_push);

    CHECK_FALSE(config_needs_push(conf));

    std::vector<std::string> seen;
    for (auto* conf : {conf, conf2}) {
        // Iterate through and make sure we got everything we expected
        seen.clear();
        CHECK(convo_info_volatile_size(conf) == 6);
        CHECK(convo_info_volatile_size_1to1(conf) == 2);
        CHECK(convo_info_volatile_size_communities(conf) == 1);
        CHECK(convo_info_volatile_size_legacy_groups(conf) == 1);
        CHECK(convo_info_volatile_size_blinded_1to1(conf) == 2);

        convo_info_volatile_1to1 c1;
        convo_info_volatile_community c2;
        convo_info_volatile_legacy_group c3;
        convo_info_volatile_blinded_1to1 c4;
        convo_info_volatile_iterator* it = convo_info_volatile_iterator_new(conf);
        for (; !convo_info_volatile_iterator_done(it); convo_info_volatile_iterator_advance(it)) {
            if (convo_info_volatile_it_is_1to1(it, &c1)) {
                seen.push_back("1-to-1: "s + c1.session_id);
            } else if (convo_info_volatile_it_is_community(it, &c2)) {
                seen.push_back("comm: "s + c2.base_url + "/r/" + c2.room);
            } else if (convo_info_volatile_it_is_legacy_group(it, &c3)) {
                seen.push_back("lgr: "s + c3.group_id);
            } else if (convo_info_volatile_it_is_blinded_1to1(it, &c4)) {
                seen.push_back("b: "s + c4.blinded_session_id);
            }
        }
        convo_info_volatile_iterator_free(it);

        CHECK(seen == std::vector<std::string>{
                              "1-to-1: "
                              "0511111111111111111111111111111111111111111111111111111111111111"
                              "11",
                              "1-to-1: "
                              "0550000000000000000000000000000000000000000000000000000000000000"
                              "00",
                              "comm: http://example.org:5678/r/sudokuroom",
                              "lgr: "
                              "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                              "cc",
                              "b: "
                              "1500000000000000000000000000000000001010101110100001101000012100"
                              "00",
                              "b: "
                              "2512345ccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                              "c"
                              "c"});
    }

    CHECK_FALSE(config_needs_push(conf));
    // remove a non existing entry
    convo_info_volatile_erase_1to1(
            conf, "052000000000000000000000000000000000000000000000000000000000000000");
    CHECK_FALSE(config_needs_push(conf));
    convo_info_volatile_erase_1to1(
            conf, "055000000000000000000000000000000000000000000000000000000000000000");
    convo_info_volatile_erase_blinded_1to1(
            conf, "2512345ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    CHECK(config_needs_push(conf));
    CHECK(convo_info_volatile_size(conf) == 4);
    CHECK(convo_info_volatile_size_1to1(conf) == 1);
    CHECK(convo_info_volatile_size_blinded_1to1(conf) == 1);

    // Check the single-type iterators:
    seen.clear();

    convo_info_volatile_iterator* it;
    convo_info_volatile_1to1 ci;
    for (it = convo_info_volatile_iterator_new_1to1(conf); !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_1to1(it, &ci));
        seen.push_back(ci.session_id);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "051111111111111111111111111111111111111111111111111111111111111111",
                  }});

    seen.clear();
    convo_info_volatile_community ogi;
    for (it = convo_info_volatile_iterator_new_communities(conf);
         !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_community(it, &ogi));
        seen.emplace_back(ogi.base_url);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{
                          "http://example.org:5678",
                  });

    seen.clear();
    convo_info_volatile_legacy_group cgi;
    for (it = convo_info_volatile_iterator_new_legacy_groups(conf);
         !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_legacy_group(it, &cgi));
        seen.emplace_back(cgi.group_id);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{
                          "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                  });

    seen.clear();
    convo_info_volatile_blinded_1to1 bi;
    for (it = convo_info_volatile_iterator_new_blinded_1to1(conf);
         !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_blinded_1to1(it, &bi));
        seen.emplace_back(bi.blinded_session_id);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{
                          "150000000000000000000000000000000000101010111010000110100001210000",
                  });
}

TEST_CASE("Conversation pruning", "[config][conversations][pruning]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::ConvoInfoVolatile convos{std::span<const unsigned char>{seed}, std::nullopt};

    auto some_pubkey = [](unsigned char x) -> std::vector<unsigned char> {
        std::vector<unsigned char> s =
                "0000000000000000000000000000000000000000000000000000000000000000"_hexbytes;
        s[31] = x;
        return s;
    };
    auto some_session_id = [&](unsigned char x) -> std::string {
        auto pk = some_pubkey(x);
        return "05" + oxenc::to_hex(pk.begin(), pk.end());
    };
    const auto now = std::chrono::system_clock::now() - 1ms;
    auto unix_timestamp = [&now](int days_ago) -> int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                       (now - days_ago * 24h).time_since_epoch())
                .count();
    };

    for (int i = 0; i <= 65; i++) {
        if (i % 3 == 0) {
            auto c = convos.get_or_construct_1to1(some_session_id(i));
            c.last_read = unix_timestamp(i);
            if (i % 5 == 0)
                c.unread = true;

            if (i % 7 == 0) {
                c.pro_expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>{
                        std::chrono::milliseconds{unix_timestamp(i)}};

                session::array_uc32 hash{};
                std::fill(hash.begin(), hash.end(), static_cast<uint8_t>(i % 256));
                c.pro_gen_index_hash = hash;
            }

            convos.set(c);
        } else if (i % 3 == 1) {
            auto c = convos.get_or_construct_legacy_group(some_session_id(i));
            c.last_read = unix_timestamp(i);
            if (i % 5 == 0)
                c.unread = true;
            convos.set(c);
        } else {
            auto c = convos.get_or_construct_community(
                    "https://example.org", "room{}"_format(i), some_pubkey(i));
            c.last_read = unix_timestamp(i);
            if (i % 5 == 0)
                c.unread = true;
            convos.set(c);
        }
    }

    // 1to1s (i%3==0 in 0..65): recent (i<30)
    // Archived 1to1s (i%3==0 in 0..65): not recent (i>=30)
    CHECK(convos.size_1to1() == 10);           // 0 3 6 9 12 15 18 21 24 27
    CHECK(convos.size_1to1_archived() == 12);  // 30 33 36 39 42 45 48 51 54 57 60 63
    // legacy groups (i%3==1 in 0..65): recent (i<30)
    // Archived legacy groups (i%3==1 in 0..65): not recent (i>=30)
    CHECK(convos.size_legacy_groups() == 10);           // 1 4 7 10 13 16 19 22 25 28
    CHECK(convos.size_legacy_groups_archived() == 12);  // 31 34 37 40 43 46 49 52 55 58 61 64

    // communities (i%3==2 in 0..65): recent (i<30)
    // Archived communities (i%3==2 in 0..65): not recent (i>=30)
    CHECK(convos.size_communities() == 10);           // 2 5 8 11 14 17 20 23 26 29
    CHECK(convos.size_communities_archived() == 12);  // 32 35 38 41 44 47 50 53 56 59 62 65
    CHECK(convos.size() == 10 + 10 + 10);
    CHECK(convos.size_archived() == 12 + 12 + 12);

    // Now we deliberately set some values in the internals that are too old to see that they
    // get properly archive when we push.  (This is only for testing, clients should never touch
    // the internals like this!)

    convos.data["1"][oxenc::from_hex(some_session_id(79))]["r"] =
            unix_timestamp(29);  // this one should be kept as active
    // All of those should be archived as soon as we push

    convos.data["1"][oxenc::from_hex(some_session_id(80))]["r"] = unix_timestamp(33);
    convos.data["1"][oxenc::from_hex(some_session_id(81))]["r"] = unix_timestamp(40);
    convos.data["1"][oxenc::from_hex(some_session_id(82))]["r"] = unix_timestamp(44);
    convos.data["1"][oxenc::from_hex(some_session_id(83))]["r"] = unix_timestamp(45);
    convos.data["1"][oxenc::from_hex(some_session_id(84))]["r"] = unix_timestamp(46);
    convos.data["1"][oxenc::from_hex(some_session_id(85))]["r"] = unix_timestamp(1000);

    // 7 additional 1-to-1s got added unconditionally
    CHECK(convos.size_1to1() == 17);
    int count = 0;
    for (auto it = convos.begin_1to1(false); it != convos.end(); it++) {
        count++;
    }
    CHECK(count == 17);

    // we had 30 above and have added 7 more bypassing the set_base call
    CHECK(convos.size() == 37);

    // Push and confirm the archived
    auto [seqno, push_data, obs] = convos.push();

    // The push should have archived these from the active config:
    // 80, 81, 82, 83, 84, 85 - where last_read is too old (>= ARCHIVE_AFTER=30d)
    // only 79 remains active
    CHECK(convos.size_1to1() == 17 - 6);
    CHECK(convos.size() == 37 - 6);
    // we had 12 archived 1o1 above, and push should have archived 6 more
    CHECK(convos.size_1to1_archived() == 12 + 6);
    // we had 36 archived above, and push should have archived 6 more
    CHECK(convos.size_archived() == 36 + 6);
}

TEST_CASE("Conversation dump/load state bug", "[config][conversations][dump-load]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    config_object* conf;
    REQUIRE(0 == convo_info_volatile_init(&conf, ed_sk.data(), NULL, 0, NULL));

    convo_info_volatile_1to1 c;
    CHECK(convo_info_volatile_get_or_construct_1to1(
            conf, &c, "050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    convo_info_volatile_set_1to1(conf, &c);

    // Fake push:
    config_push_data* to_push = config_push(conf);
    seqno_t seqno = to_push->seqno;
    REQUIRE(to_push->n_configs == 1);
    free(to_push);
    CHECK(seqno == 1);

    const char* tmphash;  // test suite cheat: &(tmphash = "asdf") to fake a length-1 array.

    config_confirm_pushed(conf, seqno, &(tmphash = "somehash"), 1);
    CHECK(config_needs_dump(conf));

    // Dump:
    unsigned char* dump;
    size_t dumplen;
    config_dump(conf, &dump, &dumplen);

    // Load the dump:
    config_object* conf2;
    REQUIRE(0 == convo_info_volatile_init(&conf2, ed_sk.data(), dump, dumplen, NULL));

    free(dump);

    // Change the original again, then push it for conf2:
    CHECK(convo_info_volatile_get_or_construct_1to1(
            conf, &c, "051111111111111111111111111111111111111111111111111111111111111111"));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    convo_info_volatile_set_1to1(conf, &c);

    to_push = config_push(conf);
    CHECK(to_push->seqno == 2);
    REQUIRE(to_push->n_configs == 1);
    config_confirm_pushed(conf, to_push->seqno, &(tmphash = "hash5235"), 1);

    // But *before* we load the push make a dirtying change to conf2 that we *don't* push (so
    // that we'll be merging into a dirty-state config):
    CHECK(convo_info_volatile_get_or_construct_1to1(
            conf2, &c, "052222111111111111111111111111111111111111111111111111111111111111"));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    convo_info_volatile_set_1to1(conf2, &c);

    // And now, *before* we push the dirty config, also merge the incoming push from `conf`:
    const char* merge_hash[1];
    const unsigned char* merge_data[1];
    size_t merge_size[1];
    merge_hash[0] = "hash5235";
    REQUIRE(to_push->n_configs == 1);
    merge_data[0] = to_push->config[0];
    merge_size[0] = to_push->config_lens[0];

    config_string_list* accepted = config_merge(conf2, merge_hash, merge_data, merge_size, 1);
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "hash5235"sv);
    free(accepted);
    free(to_push);

    CHECK(config_needs_push(conf2));

    convo_info_volatile_1to1 c1;
    REQUIRE(convo_info_volatile_get_or_construct_1to1(
            conf2, &c1, "051111111111111111111111111111111111111111111111111111111111111111"));
    c1.last_read += 10;
    // Prior to the commit that added this test case (and fix), this call would fail with:
    //     Internal error: unexpected dirty but non-mutable ConfigMessage
    // because of the above dirty->merge->dirty (without an intermediate push) pattern.
    REQUIRE_NOTHROW(convo_info_volatile_set_1to1(conf2, &c1));

    CHECK(config_needs_push(conf2));
    to_push = config_push(conf2);
    CHECK(to_push->seqno == 3);
    REQUIRE(to_push->n_configs == 1);
    config_confirm_pushed(conf2, to_push->seqno, &(tmphash = "hashz"), 1);
    CHECK_FALSE(config_needs_push(conf2));

    config_dump(conf2, &dump, &dumplen);
    free(dump);
    CHECK_FALSE(config_needs_dump(conf2));
}

TEST_CASE("Conversation pro data", "[config][conversations][pro]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    config_object* conf;
    REQUIRE(0 == convo_info_volatile_init(&conf, ed_sk.data(), NULL, 0, NULL));

    convo_info_volatile_1to1 c;
    CHECK(convo_info_volatile_get_or_construct_1to1(
            conf, &c, "051111111111111111111111111111111111111111111111111111111111111111"));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    c.pro_expiry_unix_ts_ms = 10000;

    session::array_uc32 hash{};
    std::fill(hash.begin(), hash.end(), static_cast<uint8_t>(3));
    std::memcpy(c.pro_gen_index_hash.data, hash.data(), hash.size());
    c.has_pro_gen_index_hash = true;
    convo_info_volatile_set_1to1(conf, &c);

    // Fake push:
    config_push_data* to_push = config_push(conf);
    seqno_t seqno = to_push->seqno;
    REQUIRE(to_push->n_configs == 1);
    free(to_push);
    CHECK(seqno == 1);

    const char* tmphash;  // test suite cheat: &(tmphash = "asdf") to fake a length-1 array.

    config_confirm_pushed(conf, seqno, &(tmphash = "somehash"), 1);
    CHECK(config_needs_dump(conf));

    // Dump:
    unsigned char* dump;
    size_t dumplen;
    config_dump(conf, &dump, &dumplen);

    // Load the dump:
    config_object* conf2;
    REQUIRE(0 == convo_info_volatile_init(&conf2, ed_sk.data(), dump, dumplen, NULL));

    free(dump);

    convo_info_volatile_1to1 c2;
    CHECK(convo_info_volatile_get_or_construct_1to1(
            conf2, &c2, "051111111111111111111111111111111111111111111111111111111111111111"));

    CHECK(c2.pro_expiry_unix_ts_ms == c.pro_expiry_unix_ts_ms);
    CHECK(c.has_pro_gen_index_hash);
    CHECK(c2.has_pro_gen_index_hash);
    CHECK(oxenc::to_hex(c2.pro_gen_index_hash.data) == oxenc::to_hex(c.pro_gen_index_hash.data));
}

TEST_CASE("Conversation archive", "[config][conversations][archive]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;

    const auto now = std::chrono::system_clock::now() - 1ms;
    auto unix_timestamp = [&](int days_ago) -> int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                       (now - days_ago * 24h).time_since_epoch())
                .count();
    };

    auto some_pubkey = [](unsigned char x) -> std::vector<unsigned char> {
        std::vector<unsigned char> s =
                "0000000000000000000000000000000000000000000000000000000000000000"_hexbytes;
        s[31] = x;
        return s;
    };
    auto some_session_id = [&](unsigned char x) -> std::string {
        auto pk = some_pubkey(x);
        return "05" + oxenc::to_hex(pk.begin(), pk.end());
    };
    auto some_group_id = [&](unsigned char x) -> std::string {
        auto pk = some_pubkey(x);
        return "03" + oxenc::to_hex(pk.begin(), pk.end());
    };
    auto some_blinded_id = [&](unsigned char x) -> std::string {
        auto pk = some_pubkey(x);
        return "25" + oxenc::to_hex(pk.begin(), pk.end());
    };

    session::config::ConvoInfoVolatile convos{std::span<const unsigned char>{seed}, std::nullopt};

    // Inject stale conversations directly, bypassing set_base()'s ARCHIVE_AFTER guard.
    // All below are > ARCHIVE_AFTER (30 days) old and will be archived when push() is called.
    convos.data["1"][oxenc::from_hex(some_session_id(1))]["r"] = unix_timestamp(50);  // 1-to-1
    convos.data["C"][oxenc::from_hex(some_session_id(2))]["r"] = unix_timestamp(50);  // legacy
    convos.data["g"][oxenc::from_hex(some_group_id(4))]["r"] = unix_timestamp(50);    // group
    convos.data["b"][oxenc::from_hex(some_blinded_id(5))]["r"] = unix_timestamp(50);  // blinded
    convos.data["o"]["https://example.org"]["#"] = some_pubkey(10);                   // community
    convos.data["o"]["https://example.org"]["R"]["archiveroom"]["r"] = unix_timestamp(50);

    // A fresh (recent) 1-to-1 — should NOT be archived.
    auto fresh = convos.get_or_construct_1to1(some_session_id(3));
    fresh.last_read = unix_timestamp(1);
    convos.set(fresh);

    REQUIRE(convos.size_1to1() == 2);
    REQUIRE(convos.size_legacy_groups() == 1);
    REQUIRE(convos.size_groups() == 1);
    REQUIRE(convos.size_blinded_1to1() == 1);
    REQUIRE(convos.size_communities() == 1);
    // Nothing is archived yet — all stale entries are still in active config before push()
    REQUIRE(convos.size_1to1_archived() == 0);
    REQUIRE(convos.size_legacy_groups_archived() == 0);
    REQUIRE(convos.size_groups_archived() == 0);
    REQUIRE(convos.size_blinded_1to1_archived() == 0);
    REQUIRE(convos.size_communities_archived() == 0);

    SECTION("push archives stale conversations instead of deleting them") {

        auto [seqno, push_data, obs] = convos.push();
        convos.confirm_pushed(seqno, {"hash1"});

        // Stale entries are archived from the active config after push
        CHECK(convos.size_1to1() == 1);
        CHECK(convos.size_legacy_groups() == 0);
        CHECK(convos.size_groups() == 0);
        CHECK(convos.size_blinded_1to1() == 0);
        CHECK(convos.size_communities() == 0);
        // … and land in the archive (one of each type)
        CHECK(convos.size_1to1_archived() == 1);
        CHECK(convos.size_legacy_groups_archived() == 1);
        CHECK(convos.size_groups_archived() == 1);
        CHECK(convos.size_blinded_1to1_archived() == 1);
        CHECK(convos.size_communities_archived() == 1);
        CHECK(convos.get_1to1(some_session_id(1)) == std::nullopt);
        CHECK(convos.get_1to1(some_session_id(3)) != std::nullopt);
        CHECK(convos.get_group(some_group_id(4)) == std::nullopt);
        CHECK(convos.get_blinded_1to1(some_blinded_id(5)) == std::nullopt);

        // Dump must be larger than an equivalent fresh instance that never had the stale
        // entries: the extra size comes from the archive section in extra_data.
        session::config::ConvoInfoVolatile convos_no_archive{
                std::span<const unsigned char>{seed}, std::nullopt};
        auto fresh2 = convos_no_archive.get_or_construct_1to1(some_session_id(3));
        fresh2.last_read = unix_timestamp(1);
        convos_no_archive.set(fresh2);
        auto [sq2, pd2, ob2] = convos_no_archive.push();
        convos_no_archive.confirm_pushed(sq2, {"hash1"});

        CHECK(convos.dump().size() > convos_no_archive.dump().size());
    }

    SECTION("archive persists through dump and reload") {
        auto [seqno, push_data, obs] = convos.push();
        convos.confirm_pushed(seqno, {"hash1"});

        auto dump1 = convos.dump();

        // Reload from dump — archive should survive
        session::config::ConvoInfoVolatile convos2{std::span<const unsigned char>{seed}, dump1};

        // Active conversations remain accessible
        CHECK(convos2.size_1to1() == 1);
        CHECK(convos2.size_legacy_groups() == 0);
        CHECK(convos2.size_groups() == 0);
        CHECK(convos2.size_blinded_1to1() == 0);
        CHECK(convos2.size_communities() == 0);
        // Archive survived the reload
        CHECK(convos2.size_1to1_archived() == 1);
        CHECK(convos2.size_legacy_groups_archived() == 1);
        CHECK(convos2.size_groups_archived() == 1);
        CHECK(convos2.size_blinded_1to1_archived() == 1);
        CHECK(convos2.size_communities_archived() == 1);
        CHECK(convos2.get_1to1(some_session_id(3)) != std::nullopt);
        CHECK(convos2.get_1to1(some_session_id(1)) == std::nullopt);
        CHECK(convos2.get_group(some_group_id(4)) == std::nullopt);
        CHECK(convos2.get_blinded_1to1(some_blinded_id(5)) == std::nullopt);

        auto dump2 = convos2.dump();

        // Dump sizes match — archive was preserved in extra_data
        CHECK(dump2.size() == dump1.size());

        // A second reload also preserves the archive
        session::config::ConvoInfoVolatile convos3{
                std::span<const unsigned char>{seed}, convos2.dump()};
        auto dump3 = convos3.dump();
        CHECK(dump3.size() == dump1.size());
    }

    SECTION("explicit erase removes conversation from archive") {
        auto [seqno, push_data, obs] = convos.push();
        convos.confirm_pushed(seqno, {"hash1"});

        auto dump1 = convos.dump();
        session::config::ConvoInfoVolatile convos2{std::span<const unsigned char>{seed}, dump1};

        // convos2 starts with one archived entry of each type
        CHECK(convos2.size_1to1_archived() == 1);
        CHECK(convos2.size_legacy_groups_archived() == 1);
        CHECK(convos2.size_groups_archived() == 1);
        CHECK(convos2.size_blinded_1to1_archived() == 1);
        CHECK(convos2.size_communities_archived() == 1);

        // Erase the archived 1-to-1: it is not in the active config, but the archive entry
        // should be cleaned up.  Returns false because it was not in _config->data().
        bool was_active = convos2.erase_1to1(some_session_id(1));
        CHECK_FALSE(was_active);
        CHECK(convos2.needs_dump());
        CHECK(convos2.size_1to1_archived() == 0);

        // Dump after erase is smaller — one archive entry was removed
        auto dump2 = convos2.dump();
        CHECK(dump2.size() < dump1.size());

        // Removal persists through another reload
        session::config::ConvoInfoVolatile convos3{std::span<const unsigned char>{seed}, dump2};
        auto dump3 = convos3.dump();
        CHECK(dump3.size() == dump2.size());
        CHECK(convos3.size_1to1_archived() == 0);

        // Erase archived group — returns false (not in active config)
        CHECK_FALSE(convos2.erase_group(some_group_id(4)));
        CHECK(convos2.needs_dump());
        CHECK(convos2.size_groups_archived() == 0);

        auto dump4 = convos2.dump();
        CHECK(dump4.size() < dump2.size());

        // Erase archived blinded — returns false (not in active config)
        CHECK_FALSE(convos2.erase_blinded_1to1(some_blinded_id(5)));
        CHECK(convos2.needs_dump());
        CHECK(convos2.size_blinded_1to1_archived() == 0);

        auto dump5 = convos2.dump();
        CHECK(dump5.size() < dump4.size());

        // Erase archived community — returns false (not in active config)
        CHECK_FALSE(convos2.erase_community("https://example.org", "archiveroom"));
        CHECK(convos2.needs_dump());
        CHECK(convos2.size_communities_archived() == 0);

        auto dump6 = convos2.dump();
        CHECK(dump6.size() < dump5.size());
    }

    SECTION("re-activated conversation is not kept in archive after reload") {
        auto [seqno, push_data, obs] = convos.push();
        convos.confirm_pushed(seqno, {"hash1"});

        auto dump1 = convos.dump();
        session::config::ConvoInfoVolatile convos2{std::span<const unsigned char>{seed}, dump1};

        // Re-activate the archived 1-to-1 with a fresh last_read
        auto reactivated = convos2.get_or_construct_1to1(some_session_id(1));
        reactivated.last_read = unix_timestamp(1);
        convos2.set(reactivated);

        CHECK(convos2.size_1to1() == 2);
        // Re-activating removes it from archive
        CHECK(convos2.size_1to1_archived() == 0);
        CHECK(convos2.get_1to1(some_session_id(1)) != std::nullopt);

        // Push: the re-activated conv is recent, so it is not re-archived
        auto [seqno2, push2, obs2] = convos2.push();
        convos2.confirm_pushed(seqno2, {"hash2"});
        CHECK(convos2.size_1to1() == 2);
        CHECK(convos2.size_1to1_archived() == 0);

        // On reload, load_extra_data skips the archived entry for session_id(1) because it is
        // now present in the active config.  So the re-loaded archive is smaller than dump1.
        auto dump2 = convos2.dump();

        session::config::ConvoInfoVolatile convos3{std::span<const unsigned char>{seed}, dump2};
        auto dump3_before_erase = convos3.dump();

        // session_id(1) is in the active config
        auto found = convos3.get_1to1(some_session_id(1));
        REQUIRE(found != std::nullopt);
        CHECK(found->last_read == unix_timestamp(1));

        // Erasing it from convos3 should succeed (was in active config, not just archive)
        CHECK(convos3.erase_1to1(some_session_id(1)));
        CHECK(convos3.size_1to1() == 1);

        // Verify session_id(1) is completely gone — not in active config or archive.
        session::config::ConvoInfoVolatile convos4{
                std::span<const unsigned char>{seed}, convos3.dump()};
        CHECK(convos4.get_1to1(some_session_id(1)) == std::nullopt);
        CHECK(convos4.size_1to1() == 1);  // only session_id(3)
        bool found_in_archive = false;
        for (auto it = convos4.begin_1to1(); !it.done(); ++it)
            if (it->session_id == some_session_id(1))
                found_in_archive = true;
        CHECK_FALSE(found_in_archive);
    }

    SECTION("iterator yields both active and archived conversations") {
        auto [seqno, push_data, obs] = convos.push();
        convos.confirm_pushed(seqno, {"hash1"});

        // After push: 1 active 1-to-1 (session_id(3)), 5 archived entries.
        // The full iterator must yield all 6.
        size_t total = 0;
        std::set<std::string> seen_ids;
        for (const auto& entry : convos) {
            ++total;
            if (const auto* c = std::get_if<session::config::convo::one_to_one>(&entry))
                seen_ids.insert(c->session_id);
            else if (const auto* c = std::get_if<session::config::convo::community>(&entry))
                seen_ids.insert(c->base_url() + "/" + c->room_norm());
            else if (const auto* c = std::get_if<session::config::convo::group>(&entry))
                seen_ids.insert(c->id);
            else if (const auto* c = std::get_if<session::config::convo::legacy_group>(&entry))
                seen_ids.insert(c->id);
            else if (
                    const auto* c = std::get_if<session::config::convo::blinded_one_to_one>(&entry))
                seen_ids.insert(c->blinded_session_id);
        }
        CHECK(total == 6);                                         // 1 active + 5 archived
        CHECK(seen_ids.count(some_session_id(3)));                 // active 1-to-1
        CHECK(seen_ids.count(some_session_id(1)));                 // archived 1-to-1
        CHECK(seen_ids.count(some_session_id(2)));                 // archived legacy_group
        CHECK(seen_ids.count(some_group_id(4)));                   // archived group
        CHECK(seen_ids.count(some_blinded_id(5)));                 // archived blinded
        CHECK(seen_ids.count("https://example.org/archiveroom"));  // archived community

        // Type-specific iterators also include archived entries of that type.
        auto count = [](auto it) {
            size_t n = 0;
            for (; !it.done(); ++it)
                ++n;
            return n;
        };
        CHECK(count(convos.begin_1to1()) == 2);
        CHECK(count(convos.begin_legacy_groups()) == 1);
        CHECK(count(convos.begin_groups()) == 1);
        CHECK(count(convos.begin_blinded_1to1()) == 1);
        CHECK(count(convos.begin_communities()) == 1);

        // With include_archived = false, only active entries are yielded.
        size_t active_total = 0;
        for (auto it = convos.begin(false); !it.done(); ++it)
            ++active_total;
        CHECK(active_total == 1);  // only session_id(3)

        CHECK(count(convos.begin_1to1(false)) == 1);
        CHECK(count(convos.begin_legacy_groups(false)) == 0);
        CHECK(count(convos.begin_groups(false)) == 0);
        CHECK(count(convos.begin_blinded_1to1(false)) == 0);
        CHECK(count(convos.begin_communities(false)) == 0);

        // After reload from dump the iterator still works the same way.
        session::config::ConvoInfoVolatile convos2{
                std::span<const unsigned char>{seed}, convos.dump()};
        size_t reloaded_total = 0;
        for ([[maybe_unused]] const auto& _ : convos2)
            ++reloaded_total;
        CHECK(reloaded_total == 6);

        // Verify that archived entry fields are accessible via the iterator.
        bool found_archived_1to1 = false;
        for (const auto& entry : convos) {
            if (const auto* c = std::get_if<session::config::convo::one_to_one>(&entry))
                if (c->session_id == some_session_id(1)) {
                    found_archived_1to1 = true;
                    CHECK(c->last_read == unix_timestamp(50));
                }
        }
        CHECK(found_archived_1to1);
    }

    SECTION("set() with stale last_read and pro proof routes to archive with pro details "
            "preserved") {
        session::array_uc32 expected_hash{};
        std::fill(expected_hash.begin(), expected_hash.end(), 0xAB);

        auto c = convos.get_or_construct_1to1(some_session_id(20));
        c.last_read = unix_timestamp(40);  // 40 days ago — stale (> ARCHIVE_AFTER=30d)
        c.unread = false;
        c.pro_gen_index_hash = expected_hash;
        // Pro expiry 30 days in the future — proof is still valid
        c.pro_expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>{
                std::chrono::milliseconds{unix_timestamp(-30)}};
        convos.set(c);

        // Must NOT appear in the active config despite having a pro proof
        CHECK_FALSE(convos.get_1to1(some_session_id(20)).has_value());
        CHECK(convos.size_1to1_archived() == 1);

        // Must appear in the archive with pro fields intact
        bool found_in_archive = false;
        for (auto it = convos.begin_1to1(); !it.done(); ++it) {
            if (it->session_id == some_session_id(20)) {
                found_in_archive = true;
                CHECK(it->last_read == c.last_read);
                REQUIRE(it->pro_gen_index_hash.has_value());
                CHECK(*it->pro_gen_index_hash == expected_hash);
                CHECK(it->pro_expiry_unix_ts == c.pro_expiry_unix_ts);
            }
        }
        CHECK(found_in_archive);

        // Pro details survive dump/reload
        session::config::ConvoInfoVolatile convos2{
                std::span<const unsigned char>{seed}, convos.dump()};
        bool found_after_reload = false;
        for (auto it = convos2.begin_1to1(); !it.done(); ++it) {
            if (it->session_id == some_session_id(20)) {
                found_after_reload = true;
                CHECK(it->last_read == c.last_read);
                REQUIRE(it->pro_gen_index_hash.has_value());
                CHECK(*it->pro_gen_index_hash == expected_hash);
                CHECK(it->pro_expiry_unix_ts == c.pro_expiry_unix_ts);
            }
        }
        CHECK(found_after_reload);
    }

    SECTION("set() with stale last_read routes to archive; fresh last_read re-activates") {
        // A 1-to-1 with a last_read 40 days ago (> ARCHIVE_AFTER=30d) — should go to archive.
        auto stale = convos.get_or_construct_1to1(some_session_id(10));
        stale.last_read = unix_timestamp(40);
        convos.set(stale);

        // It must NOT appear in the active config dict.
        CHECK_FALSE(convos.get_1to1(some_session_id(10)).has_value());
        CHECK(convos.size_1to1_archived() == 1);

        // But it IS reachable via the iterator (archived section).
        bool found_in_archive = false;
        for (auto it = convos.begin_1to1(); !it.done(); ++it)
            if (it->session_id == some_session_id(10))
                found_in_archive = true;
        CHECK(found_in_archive);

        // Not reachable when archived entries are excluded.
        bool found_active_only = false;
        for (auto it = convos.begin_1to1(false); !it.done(); ++it)
            if (it->session_id == some_session_id(10))
                found_active_only = true;
        CHECK_FALSE(found_active_only);

        // Re-activate: call set() with a fresh last_read (5 days ago).
        auto fresh = convos.get_or_construct_1to1(some_session_id(10));
        fresh.last_read = unix_timestamp(5);
        convos.set(fresh);

        // Now it must appear in the active config.
        auto got = convos.get_1to1(some_session_id(10));
        REQUIRE(got.has_value());
        CHECK(got->last_read == fresh.last_read);

        // And it must NOT appear in the archive anymore (re-activation erased the archived
        // copy).
        CHECK(convos.size_1to1_archived() == 0);
        int archive_count = 0;
        for (auto it = convos.begin_1to1(); !it.done(); ++it)
            if (it->session_id == some_session_id(10))
                ++archive_count;
        // Exactly one copy — the active one.
        CHECK(archive_count == 1);
        bool in_active_only = false;
        for (auto it = convos.begin_1to1(false); !it.done(); ++it)
            if (it->session_id == some_session_id(10))
                in_active_only = true;
        CHECK(in_active_only);
    }
}