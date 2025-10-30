#include <session/core.h>
#include <session/database/connection.h>

#include <catch2/catch_test_macros.hpp>
#include <session/sodium_array.hpp>
#include <session/util.hpp>

#if !defined(DISABLE_SQLCIPHER_DATABASE)
#include <sodium.h>
#include <sqlcipher/sqlite3.h>

#include <session/database/connection.hpp>
#endif

TEST_CASE("Core", "[core][database][open]") {
    session_core_core core = {};
    session_core_core_init(&core);
    auto on_exit = session::scope_exit([&]() { session_core_core_deinit(&core); });

    // Check that the core opaque handle is not zero
    session_core_core zero_core = {};
    REQUIRE(memcmp(core.opaque, zero_core.opaque, sizeof(core.opaque)) != 0);

#if !defined(DISABLE_SQLCIPHER_DATABASE)
    // Setup the encryption key
    session::cleared_array<48> raw_key = {};
    randombytes_buf(raw_key.data(), raw_key.size());
    span_u8 raw_key_span = {raw_key.data(), raw_key.size()};

    // Get the DB connection from core, and check that the handle is not zero
    session_database_connection db = session_core_core_db_conn(&core);
    session_database_connection zero_db = {};
    REQUIRE(memcmp(db.opaque, zero_db.opaque, sizeof(db.opaque)) != 0);

    // Open a DB connection
    session_c_result open_result =
            session_database_connection_open(&db, string8_literal(":memory:"), raw_key_span);
    REQUIRE(open_result.success);

    // Close the DB connection
    session_database_connection_close(&db);
    REQUIRE(memcmp(db.opaque, zero_db.opaque, sizeof(db.opaque)) == 0);
#endif
}

#if !defined(DISABLE_SQLCIPHER_DATABASE)
TEST_CASE("Core", "[core][database][pro][revocations]") {
    session_core_core core = {};
    session_core_core_init(&core);
    auto on_exit = session::scope_exit([&]() { session_core_core_deinit(&core); });

    // Setup the encryption key
    session::cleared_array<48> raw_key = {};
    randombytes_buf(raw_key.data(), raw_key.size());
    span_u8 raw_key_span = {raw_key.data(), raw_key.size()};

    // Open the DB
    session_database_connection db = session_core_core_db_conn(&core);
    session_database_connection_open(&db, string8_literal(":memory:"), raw_key_span);
    auto* db_cpp = reinterpret_cast<session::database::Connection*>(db.opaque);

    // Check runtime was seeded to ticket 0
    session::database::Runtime runtime = db_cpp->get_runtime();
    REQUIRE(runtime.id == 1);
    REQUIRE(runtime.pro_revocations_ticket == 0);

    // Check that the DB has no revocations in it
    uint32_t ticket = 0;
    session_database_get_pro_revocation_result get_result =
            session_database_connection_get_pro_revocations_buffer(&db, nullptr, 0, 0, &ticket);
    REQUIRE(get_result.db.success);
    REQUIRE(get_result.count == 0);

    // Create the revocations we will put into the DB
    uint64_t unix_ts_ms = 1698765432ULL * 1000;  // Arbitrary timestamp
    auto unix_ts =
            std::chrono::sys_time<std::chrono::milliseconds>(std::chrono::milliseconds(unix_ts_ms));

    session_pro_backend_pro_revocation_item src_items[] = {
            {
                    .gen_index_hash = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                       0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                    .expiry_unix_ts_ms = static_cast<uint64_t>(unix_ts.time_since_epoch().count()),
            },
            {
                    .gen_index_hash = {0x33, 0xa1, 0xc4, 0x4e, 0x60, 0x94, 0x48, 0x8f,
                                       0x5c, 0xeb, 0xe2, 0x4b, 0xfc, 0xf9, 0x89, 0xda,
                                       0x07, 0xdd, 0xc4, 0x8d, 0xe2, 0xae, 0x86, 0x6c,
                                       0x8c, 0x78, 0xb9, 0x16, 0x60, 0xc8, 0x49, 0xf1},
                    .expiry_unix_ts_ms = static_cast<uint64_t>(unix_ts.time_since_epoch().count()),
            },
    };

    // Set the items
    session_database_set_result set_result = session_database_connection_set_pro_revocations(
            &db, 1, src_items, sizeof(src_items) / sizeof(src_items[0]));
    INFO("Set w/ 2 items failed: " << sqlite3_errstr(set_result.sql_return_code));
    REQUIRE(set_result.db.success);
    REQUIRE(set_result.sql_return_code == SQLITE_OK);

    // Check runtime ticket was changed to 1
    runtime = db_cpp->get_runtime();
    REQUIRE(runtime.id == 1);
    REQUIRE(runtime.pro_revocations_ticket == 1);

    // Count the number of revocations in the DB (should be 2 as we've inserted them)
    get_result =
            session_database_connection_get_pro_revocations_buffer(&db, nullptr, 0, 0, &ticket);
    REQUIRE(ticket == runtime.pro_revocations_ticket);
    REQUIRE(get_result.db.success);
    REQUIRE(get_result.count == 2);

    // Check that the revocations was in the DB
    std::vector<session::pro_backend::ProRevocationItem> db_items =
            db_cpp->get_pro_revocations(&ticket);
    REQUIRE(ticket == 1);
    REQUIRE(memcmp(src_items[0].gen_index_hash.data,
                   db_items[0].gen_index_hash.data(),
                   db_items[0].gen_index_hash.size()) == 0);
    REQUIRE(src_items[0].expiry_unix_ts_ms ==
            db_items[0].expiry_unix_ts.time_since_epoch().count());

    REQUIRE(memcmp(src_items[1].gen_index_hash.data,
                   db_items[1].gen_index_hash.data(),
                   db_items[1].gen_index_hash.size()) == 0);
    REQUIRE(src_items[1].expiry_unix_ts_ms ==
            db_items[1].expiry_unix_ts.time_since_epoch().count());

    // Delete the first item (src[0]) from the DB
    session_pro_backend_pro_revocation_item set_item = src_items[1];
    set_result = session_database_connection_set_pro_revocations(&db, 2, &set_item, 1);
    INFO("Set w/ 1 item failed: " << sqlite3_errstr(set_result.sql_return_code));
    REQUIRE(set_result.db.success);
    REQUIRE(set_result.sql_return_code == SQLITE_OK);

    // Count the number of revocations in the DB (should be 1 as we've deleted one of them)
    get_result =
            session_database_connection_get_pro_revocations_buffer(&db, nullptr, 0, 0, &ticket);
    REQUIRE(get_result.db.success);
    REQUIRE(get_result.count == 1);
    REQUIRE(ticket == 2);

    // Verify that the DB now has just the item at src[1]
    session_pro_backend_pro_revocation_item db_items_after_delete[2];
    assert(sizeof(db_items_after_delete) / sizeof(db_items_after_delete[0]) >= get_result.count);

    session_database_get_pro_revocation_result db_items_after_delete_result =
            session_database_connection_get_pro_revocations_buffer(
                    &db,
                    db_items_after_delete,
                    sizeof(db_items_after_delete) / sizeof(db_items_after_delete[0]),
                    0,
                    &ticket);

    REQUIRE(db_items_after_delete_result.db.success);
    REQUIRE(db_items_after_delete_result.count == 1);
    REQUIRE(memcmp(src_items[1].gen_index_hash.data,
                   db_items_after_delete[0].gen_index_hash.data,
                   sizeof(db_items_after_delete[0].gen_index_hash.data)) == 0);
    REQUIRE(src_items[1].expiry_unix_ts_ms == db_items_after_delete[0].expiry_unix_ts_ms);
    REQUIRE(ticket == 2);
}
#endif  // !defined(DISABLE_SQLCIPHER_DATABASE)
