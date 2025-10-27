#include <oxenc/hex.h>
#include <sodium.h>
#include <sqlcipher/sqlite3.h>

#include <catch2/catch_test_macros.hpp>
#include <session/util.hpp>

#include "session/database/connection.hpp"
#include "session/pro_backend.hpp"

TEST_CASE("Database", "[database][open]") {
    session::cleared_array<48> raw_key = {};
    randombytes_buf(raw_key.data(), raw_key.size());
    auto db = session::database::Connection(":memory:", raw_key);
}

TEST_CASE("Database", "[database][pro][revocations]") {
    session::cleared_array<48> raw_key = {};
    randombytes_buf(raw_key.data(), raw_key.size());
    auto db = session::database::Connection(":memory:", raw_key);

    // Check runtime was seeded to ticket 0
    session::database::Runtime runtime = db.get_runtime();
    REQUIRE(runtime.id == 1);
    REQUIRE(runtime.pro_revocations_ticket == 0);

    // Check that the DB has no revocations in it
    uint32_t ticket = 0;
    size_t db_item_count = db.get_pro_revocations_buffer(nullptr, 0, 0, &ticket);
    REQUIRE(db_item_count == 0);

    // Create the revocations we will put into the DB
    uint64_t unix_ts_ms = 1698765432ULL * 1000;  // Arbitrary timestamp
    auto unix_ts =
            std::chrono::sys_time<std::chrono::milliseconds>(std::chrono::milliseconds(unix_ts_ms));

    session::pro_backend::ProRevocationItem src_items[] = {
            {
                    .gen_index_hash = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                       0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                    .expiry_unix_ts = unix_ts,
            },
            {
                    .gen_index_hash = {0x33, 0xa1, 0xc4, 0x4e, 0x60, 0x94, 0x48, 0x8f,
                                       0x5c, 0xeb, 0xe2, 0x4b, 0xfc, 0xf9, 0x89, 0xda,
                                       0x07, 0xdd, 0xc4, 0x8d, 0xe2, 0xae, 0x86, 0x6c,
                                       0x8c, 0x78, 0xb9, 0x16, 0x60, 0xc8, 0x49, 0xf1},
                    .expiry_unix_ts = unix_ts,
            },
    };

    // Set the items
    session::database::SetResult set_result = db.set_pro_revocations(1, src_items);
    INFO("Set w/ 2 items failed: " << sqlite3_errstr(set_result.return_code));
    REQUIRE(set_result.success);
    REQUIRE(set_result.return_code == SQLITE_OK);

    // Check runtime ticket was changed to 1
    runtime = db.get_runtime();
    REQUIRE(runtime.id == 1);
    REQUIRE(runtime.pro_revocations_ticket == 1);

    // Count the number of revocations in the DB (should be 2 as we've inserted them)
    db_item_count = db.get_pro_revocations_buffer(nullptr, 0, 0, &ticket);
    REQUIRE(ticket == runtime.pro_revocations_ticket);
    REQUIRE(db_item_count == 2);

    // Check that the revocations was in the DB
    std::vector<session::pro_backend::ProRevocationItem> db_items = db.get_pro_revocations(&ticket);
    REQUIRE(ticket == 1);
    REQUIRE(src_items[0].gen_index_hash == db_items[0].gen_index_hash);
    REQUIRE(src_items[0].expiry_unix_ts == db_items[0].expiry_unix_ts);
    REQUIRE(src_items[1].gen_index_hash == db_items[1].gen_index_hash);
    REQUIRE(src_items[1].expiry_unix_ts == db_items[1].expiry_unix_ts);

    // Delete the first item (src[0]) from the DB
    session::pro_backend::ProRevocationItem set_item = src_items[1];
    set_result = db.set_pro_revocations(2, std::span(&set_item, 1));
    INFO("Set w/ 1 item failed: " << sqlite3_errstr(set_result.return_code));
    REQUIRE(set_result.success);
    REQUIRE(set_result.return_code == SQLITE_OK);

    // Count the number of revocations in the DB (should be 1 as we've deleted one of them)
    db_item_count = db.get_pro_revocations_buffer(nullptr, 0, 0, &ticket);
    REQUIRE(db_item_count == 1);
    REQUIRE(ticket == 2);

    // Verify that the DB now has just the item at src[1]
    std::vector<session::pro_backend::ProRevocationItem> db_items_after_delete = db.get_pro_revocations(&ticket);
    REQUIRE(db_items_after_delete.size() == 1);
    REQUIRE(src_items[1].gen_index_hash == db_items_after_delete[0].gen_index_hash);
    REQUIRE(src_items[1].expiry_unix_ts == db_items_after_delete[0].expiry_unix_ts);
    REQUIRE(ticket == 2);
}
