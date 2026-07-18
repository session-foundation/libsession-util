#include <oxenc/hex.h>
#include <session/pro_backend.h>
#include <sodium.h>

#include <catch2/catch_test_macros.hpp>
#include <cinttypes>
#include <nlohmann/json.hpp>
#include <session/pro_backend.hpp>
#include <string>

#include "utils.hpp"

using namespace session::pro_backend;

// NOTE: This is defined in main.cpp because it accepts a value from the CLI
extern std::string g_test_pro_backend_dev_server_url;

static bool string8_equals(string8 s8, std::string_view str) {
    return s8.size == str.size() && std::memcmp(s8.data, str.data(), s8.size) == 0;
}
[[maybe_unused]] static void dump_pro_proof_to_stderr(const session_protocol_pro_proof& proof) {
    fprintf(stderr, "proof.version: %u\n", proof.version);
    fprintf(stderr,
            "proof.revocation_tag: %s\n",
            oxenc::to_hex(proof.revocation_tag.data, std::end(proof.revocation_tag.data)).c_str());
    fprintf(stderr,
            "proof.rotating_pubkey: %s\n",
            oxenc::to_hex(proof.rotating_pubkey.data, std::end(proof.rotating_pubkey.data))
                    .c_str());
    fprintf(stderr, "proof.expiry_ts: %" PRId64 "\n", proof.expiry_ts);
    fprintf(stderr,
            "proof.sig: %s\n",
            oxenc::to_hex(proof.sig.data, std::end(proof.sig.data)).c_str());
}

[[maybe_unused]] static void dump_pro_payment_item(
        const session_pro_backend_pro_payment_item& item) {
    fprintf(stderr, "item.status: %d\n", item.status);
    fprintf(stderr, "item.plan: %.*s\n", (int)item.plan_count, item.plan);
    fprintf(stderr,
            "item.payment_provider: %.*s\n",
            (int)item.payment_provider_count,
            item.payment_provider);
    fprintf(stderr, "item.auto_renewing: %d\n", item.auto_renewing);
    fprintf(stderr, "item.purchased_ts: %f\n", item.purchased_ts);
    fprintf(stderr, "item.redeemed_ts: %" PRId64 "zu\n", item.redeemed_ts);
    fprintf(stderr, "item.expiry_ts: %" PRId64 "\n", item.expiry_ts);
    fprintf(stderr, "item.grace_period_duration: %" PRId64 "zu\n", item.grace_period_duration);
    fprintf(stderr,
            "item.platform_refund_expiry_ts: %" PRId64 "zu\n",
            item.platform_refund_expiry_ts);
    fprintf(stderr, "item.revoked_ts: %f\n", item.revoked_ts);
    fprintf(stderr, "item.payment_id: %.*s\n", (int)item.payment_id_count, item.payment_id);
}

[[maybe_unused]] static void dump_pro_revocation(
        const session_pro_backend_pro_revocation_item& item) {
    fprintf(stderr, "item.effective_ts: %" PRId64 "\n", item.effective_ts);
    fprintf(stderr,
            "item.revocation_tag: %s\n",
            oxenc::to_hex(item.revocation_tag.data, std::end(item.revocation_tag.data)).c_str());
}

TEST_CASE("Pro Backend C API", "[pro_backend]") {
    // Setup: Generate keys and payment token hash
    bytes32 master_pubkey = {};
    bytes64 master_privkey = {};
    crypto_sign_ed25519_keypair(master_pubkey.data, master_privkey.data);

    bytes32 rotating_pubkey = {};
    bytes64 rotating_privkey = {};
    crypto_sign_ed25519_keypair(rotating_pubkey.data, rotating_privkey.data);

    {
        std::array<uint8_t, 8> fake_google_payment_token;
        randombytes_buf(fake_google_payment_token.data(), fake_google_payment_token.size());
        std::array<uint8_t, 8> fake_google_order_id;
        randombytes_buf(fake_google_order_id.data(), fake_google_order_id.size());
        // Google's composite payment_id is "<payment_token>|<order_id>"; libsession treats the
        // whole thing as one opaque value.
        std::string fake_payment_id = "DEV." + oxenc::to_hex(fake_google_payment_token) + "|DEV." +
                                      oxenc::to_hex(fake_google_order_id);

        session_pro_backend_add_pro_payment_user_transaction payment_tx = {};
        payment_tx.provider_code_count =
                sizeof(SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY) - 1;
        std::memcpy(
                payment_tx.provider_code,
                SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY,
                sizeof(SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY));
        payment_tx.payment_id_count = fake_payment_id.size();
        std::memcpy(payment_tx.payment_id, fake_payment_id.data(), payment_tx.payment_id_count);

        int64_t unix_ts = 1698765432;  // Arbitrary timestamp (unix epoch seconds)

        SECTION("session_pro_backend_add_pro_payment_request_build_sigs") {
            // Valid inputs
            session_pro_backend_master_rotating_signatures result =
                    session_pro_backend_add_pro_payment_request_build_sigs(
                            master_privkey.data,
                            sizeof(master_privkey.data),
                            rotating_privkey.data,
                            sizeof(rotating_privkey.data),
                            payment_tx.provider_code,
                            reinterpret_cast<const uint8_t*>(payment_tx.payment_id),
                            payment_tx.payment_id_count);
            INFO(result.error);
            REQUIRE(result.success);
            REQUIRE(result.error_count == 0);

            // Verify signatures match C++ implementation
            auto cpp = add_payment_sigs(
                    master_privkey.data,
                    rotating_privkey.data,
                    payment_tx.provider_code,
                    std::span<const uint8_t>(
                            reinterpret_cast<const uint8_t*>(payment_tx.payment_id),
                            payment_tx.payment_id_count));

            REQUIRE(std::memcmp(
                            result.master_sig.data,
                            cpp.master_sig.data(),
                            sizeof(result.master_sig.data)) == 0);
            REQUIRE(std::memcmp(
                            result.rotating_sig.data,
                            cpp.rotating_sig.data(),
                            sizeof(result.rotating_sig.data)) == 0);

            // Invalid master key size
            result = session_pro_backend_add_pro_payment_request_build_sigs(
                    master_privkey.data,
                    sizeof(master_privkey.data) - 1,
                    rotating_privkey.data,
                    sizeof(rotating_privkey.data),
                    payment_tx.provider_code,
                    reinterpret_cast<const uint8_t*>(payment_tx.payment_id),
                    payment_tx.payment_id_count);
            REQUIRE(!result.success);
            REQUIRE(result.error_count > 0);
        }

        SECTION("session_pro_backend_generate_pro_proof_request_build_sigs") {
            session_pro_backend_master_rotating_signatures result = {};

            // Valid inputs
            result = session_pro_backend_generate_pro_proof_request_build_sigs(
                    master_privkey.data,
                    sizeof(master_privkey.data),
                    rotating_privkey.data,
                    sizeof(rotating_privkey.data),
                    unix_ts);
            REQUIRE(result.success);
            REQUIRE(result.error_count == 0);

            // Verify signatures match C++ implementation
            auto cpp_sigs = pro_proof_sigs(
                    master_privkey.data, rotating_privkey.data, session::as_sys_seconds(unix_ts));
            REQUIRE(std::memcmp(
                            result.master_sig.data,
                            cpp_sigs.master_sig.data(),
                            sizeof(result.master_sig.data)) == 0);
            REQUIRE(std::memcmp(
                            result.rotating_sig.data,
                            cpp_sigs.rotating_sig.data(),
                            sizeof(result.rotating_sig.data)) == 0);

            // Invalid rotating key size
            result = session_pro_backend_generate_pro_proof_request_build_sigs(
                    master_privkey.data,
                    sizeof(master_privkey.data),
                    rotating_privkey.data,
                    sizeof(rotating_privkey.data) - 1,
                    unix_ts);
            REQUIRE(!result.success);
            REQUIRE(result.error_count > 0);
        }

        SECTION("session_pro_backend_add_pro_payment_request_to_json") {
            session_pro_backend_add_pro_payment_request request = {};
            request.master_pkey = master_pubkey;
            request.rotating_pkey = rotating_pubkey;
            request.payment_tx = payment_tx;

            session_pro_backend_master_rotating_signatures sigs =
                    session_pro_backend_add_pro_payment_request_build_sigs(
                            master_privkey.data,
                            sizeof(master_privkey.data),
                            rotating_privkey.data,
                            sizeof(rotating_privkey.data),
                            payment_tx.provider_code,
                            reinterpret_cast<const uint8_t*>(payment_tx.payment_id),
                            payment_tx.payment_id_count);

            request.master_sig = sigs.master_sig;
            request.rotating_sig = sigs.rotating_sig;

            // Valid request
            auto result = session_pro_backend_add_pro_payment_request_to_json(&request);
            {
                scope_exit result_free{[&]() { session_pro_backend_to_json_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.json.data != nullptr);
                REQUIRE(result.json.size > 0);

                // Verify JSON + route match the C++ free-function implementation
                auto cpp = add_payment_request(
                        master_privkey.data,
                        rotating_privkey.data,
                        payment_tx.provider_code,
                        std::span<const uint8_t>(
                                reinterpret_cast<const uint8_t*>(payment_tx.payment_id),
                                payment_tx.payment_id_count));
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_ENDPOINT);
                REQUIRE(string8_equals(result.json, cpp.body));
            }

            // After freeing
            REQUIRE(result.json.data == nullptr);
            REQUIRE(result.json.size == 0);

            // Null request
            result = session_pro_backend_add_pro_payment_request_to_json(nullptr);
            REQUIRE(!result.success);
            REQUIRE(result.json.data == nullptr);
            REQUIRE(result.json.size == 0);
        }

        SECTION("session_pro_backend_generate_pro_proof_request_to_json") {
            session_pro_backend_generate_pro_proof_request request = {};
            request.master_pkey = master_pubkey;
            request.rotating_pkey = rotating_pubkey;
            request.ts = unix_ts;

            session_pro_backend_master_rotating_signatures sigs =
                    session_pro_backend_generate_pro_proof_request_build_sigs(
                            master_privkey.data,
                            sizeof(master_privkey.data),
                            rotating_privkey.data,
                            sizeof(rotating_privkey.data),
                            request.ts);

            request.master_sig = sigs.master_sig;
            request.rotating_sig = sigs.rotating_sig;

            // Valid request
            auto result = session_pro_backend_generate_pro_proof_request_to_json(&request);
            {
                scope_exit result_free{[&]() { session_pro_backend_to_json_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.json.data != nullptr);
                REQUIRE(result.json.size > 0);

                // Verify JSON + route match the C++ free-function implementation
                auto cpp = pro_proof_request(
                        master_privkey.data,
                        rotating_privkey.data,
                        session::as_sys_seconds(unix_ts));
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_GENERATE_PRO_PROOF_ENDPOINT);
                REQUIRE(string8_equals(result.json, cpp.body));
            }

            // After freeing
            REQUIRE(result.json.data == nullptr);
            REQUIRE(result.json.size == 0);

            // Null request
            result = session_pro_backend_generate_pro_proof_request_to_json(nullptr);
            REQUIRE(!result.success);
            REQUIRE(result.json.data == nullptr);
            REQUIRE(result.json.size == 0);
        }

        SECTION("session_pro_backend_get_pro_revocations_request_to_json") {
            session_pro_backend_get_pro_revocations_request request = {};
            request.ticket = 123;

            // Valid request
            auto result = session_pro_backend_get_pro_revocations_request_to_json(&request);
            {
                scope_exit result_free{[&]() { session_pro_backend_to_json_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.json.data != nullptr);
                REQUIRE(result.json.size > 0);

                // Verify JSON + route match the C++ free-function implementation
                auto cpp = revocations_request(request.ticket);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_GET_PRO_REVOCATIONS_ENDPOINT);
                REQUIRE(string8_equals(result.json, cpp.body));
            }

            // After freeing
            REQUIRE(result.json.data == nullptr);
            REQUIRE(result.json.size == 0);

            // Null request
            result = session_pro_backend_get_pro_revocations_request_to_json(nullptr);
            REQUIRE(!result.success);
            REQUIRE(result.json.data == nullptr);
            REQUIRE(result.json.size == 0);
        }

        SECTION("session_pro_backend_get_pro_details_request_to_json") {
            session_pro_backend_get_pro_details_request request = {};
            request.master_pkey = master_pubkey;
            request.ts = unix_ts;
            request.count = 10'000;

            session_pro_backend_signature sig =
                    session_pro_backend_get_pro_details_request_build_sig(
                            master_privkey.data,
                            sizeof(master_privkey.data),
                            request.ts,
                            request.count);

            request.master_sig = sig.sig;

            // Valid request
            auto result = session_pro_backend_get_pro_details_request_to_json(&request);
            {
                scope_exit result_free{[&]() { session_pro_backend_to_json_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.json.data != nullptr);
                REQUIRE(result.json.size > 0);

                // Verify JSON + route match the C++ free-function implementation
                auto cpp = payment_details_request(
                        master_privkey.data, session::as_sys_seconds(unix_ts), request.count);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_GET_PRO_DETAILS_ENDPOINT);
                REQUIRE(string8_equals(result.json, cpp.body));
            }

            // After freeing
            REQUIRE(result.json.data == nullptr);
            REQUIRE(result.json.size == 0);

            // Null request
            result = session_pro_backend_get_pro_details_request_to_json(nullptr);
            REQUIRE(!result.success);
            REQUIRE(result.json.data == nullptr);
            REQUIRE(result.json.size == 0);
        }

        SECTION("session_pro_backend_pro_proof_response_parse") {
            std::array<uint8_t, 32> fake_revocation_tag;
            randombytes_buf(fake_revocation_tag.data(), fake_revocation_tag.size());

            nlohmann::json j;
            j["status"] = SESSION_PRO_BACKEND_STATUS_SUCCESS;
            j["result"] = {
                    {"version", 0},
                    {"expiry_ts", unix_ts},
                    {"revocation_tag", oxenc::to_hex(fake_revocation_tag)},
                    {"rotating_pkey",
                     oxenc::to_hex(rotating_pubkey.data, std::end(rotating_pubkey.data))},
                    {"sig", oxenc::to_hex(master_privkey.data, std::end(master_privkey.data))}};
            std::string json = j.dump();

            // Valid JSON
            session_pro_backend_pro_proof_response result =
                    session_pro_backend_pro_proof_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_pro_proof_response_free(&result); }};

                for (size_t index = 0; index < result.header.errors_count; index++)
                    INFO(result.header.errors[index].data);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
                REQUIRE(result.header.errors_count == 0);
                REQUIRE(result.header.errors == nullptr);
                REQUIRE(result.proof.expiry_ts == unix_ts);
                REQUIRE(std::memcmp(
                                result.proof.revocation_tag.data,
                                fake_revocation_tag.data(),
                                fake_revocation_tag.size()) == 0);
                REQUIRE(std::memcmp(
                                result.proof.rotating_pubkey.data,
                                rotating_pubkey.data,
                                sizeof(rotating_pubkey.data)) == 0);
                REQUIRE(std::memcmp(
                                result.proof.sig.data,
                                master_privkey.data,
                                sizeof(master_privkey.data)) == 0);

                // Here we also create the CPP version, we will run the conversion functions into
                // pro proofs (both C and CPP variants) and then compare the two structures to make
                // sure the conversion functions are sound.
                auto result_cpp = parse_add_payment(json);

                // Validate C and CPP variants
                REQUIRE(result.proof.version == result_cpp.proof.version);
                REQUIRE(std::memcmp(
                                result.proof.revocation_tag.data,
                                result_cpp.proof.revocation_tag.data(),
                                result_cpp.proof.revocation_tag.size()) == 0);
                REQUIRE(std::memcmp(
                                result.proof.rotating_pubkey.data,
                                result_cpp.proof.rotating_pubkey.data(),
                                result_cpp.proof.rotating_pubkey.size()) == 0);
                REQUIRE(result.proof.expiry_ts ==
                        result_cpp.proof.expiry_unix_ts.time_since_epoch().count());
                REQUIRE(std::memcmp(
                                result.proof.sig.data,
                                result_cpp.proof.sig.data(),
                                result_cpp.proof.sig.size()) == 0);
            }

            // After freeing
            REQUIRE(result.header.internal_arena_buf_ == nullptr);
            REQUIRE(result.header.errors == nullptr);
            REQUIRE(result.header.errors_count == 0);

            // Invalid JSON
            json = "{invalid}";
            result = session_pro_backend_pro_proof_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_pro_proof_response_free(&result); }};
                REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
                REQUIRE(result.header.errors_count > 0);
                REQUIRE(result.header.errors != nullptr);
            }

            // After freeing
            session_pro_backend_pro_proof_response_free(&result);
            REQUIRE(result.header.internal_arena_buf_ == nullptr);

            // Null JSON
            result = session_pro_backend_pro_proof_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
            REQUIRE(result.header.errors_count == 1);
            REQUIRE(result.header.errors != nullptr);

            // No need to free, as errors point to static memory
        }

        SECTION("session_pro_backend_get_pro_revocations_response_parse") {
            nlohmann::json j;
            j["status"] = SESSION_PRO_BACKEND_STATUS_SUCCESS;
            j["result"]["ticket"] = 123;
            j["result"]["retry_in"] = 3600;
            j["result"]["retain_for"] = 2592000;
            j["result"]["items"] = nlohmann::json::array();

            std::array<uint8_t, 32> fake_revocation_tag;
            randombytes_buf(fake_revocation_tag.data(), fake_revocation_tag.size());

            auto obj = nlohmann::json::object();
            obj["effective_ts"] = unix_ts;
            obj["revocation_tag"] = oxenc::to_hex(fake_revocation_tag);
            j["result"]["items"].push_back(obj);

            std::string json = j.dump();

            // Valid JSON
            auto result = session_pro_backend_get_pro_revocations_response_parse(
                    json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_get_pro_revocations_response_free(&result); }};
                for (size_t index = 0; index < result.header.errors_count; index++)
                    INFO(result.header.errors[index].data);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
                REQUIRE(result.header.errors_count == 0);
                REQUIRE(result.header.errors == nullptr);
                REQUIRE(result.ticket == 123);
                REQUIRE(result.retry_in == 3600);
                REQUIRE(result.retain_for == 2592000);
                REQUIRE(result.items_count == 1);
                REQUIRE(result.items != nullptr);
                REQUIRE(result.items[0].effective_ts == unix_ts);
                REQUIRE(std::memcmp(
                                result.items[0].revocation_tag.data,
                                fake_revocation_tag.data(),
                                fake_revocation_tag.size()) == 0);
            }

            // After freeeing
            REQUIRE(result.header.internal_arena_buf_ == nullptr);
            REQUIRE(result.items == nullptr);
            REQUIRE(result.items_count == 0);

            // Invalid JSON
            json = "{invalid}";
            {
                result = session_pro_backend_get_pro_revocations_response_parse(
                        json.data(), json.size());
                scope_exit result_free{
                        [&]() { session_pro_backend_get_pro_revocations_response_free(&result); }};
                for (size_t index = 0; index < result.header.errors_count; index++)
                    REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
                REQUIRE(result.header.errors_count > 0);
                REQUIRE(result.header.errors != nullptr);
            }

            // After freeing
            REQUIRE(result.header.internal_arena_buf_ == nullptr);

            // Null JSON
            result = session_pro_backend_get_pro_revocations_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
            REQUIRE(result.header.errors_count == 1);
            REQUIRE(result.header.errors != nullptr);
        }

        SECTION("session_pro_backend_get_pro_details_response_parse") {
            nlohmann::json j;
            j["status"] = SESSION_PRO_BACKEND_STATUS_SUCCESS;
            j["result"] = {
                    {"status", SESSION_PRO_BACKEND_USER_PRO_STATUS_EXPIRED},
                    {"error_report",
                     SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_GENERIC_ERROR},
                    {"auto_renewing", true},
                    {"expiry_ts", unix_ts + 2},
                    {"grace_period_duration", 1000},
                    {"refund_requested_ts", unix_ts + 3602},
                    {"payments_total", 3},
                    {"items",
                     nlohmann::json::array(
                             {{{"status", SESSION_PRO_BACKEND_PAYMENT_STATUS_REDEEMED},
                               {"plan", "1m"},
                               {"payment_provider",
                                SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY},
                               {"auto_renewing", false},
                               // purchased_ts/revoked_ts are floats on the wire (sub-second
                               // precision); libsession truncates to whole seconds.
                               {"purchased_ts", unix_ts - 3600 + 0.5},
                               {"redeemed_ts", unix_ts - 3600},
                               {"expiry_ts", unix_ts},
                               {"grace_period_duration", 1001},
                               {"platform_refund_expiry_ts", unix_ts + 1},
                               {"revoked_ts", unix_ts + 3600 + 0.75},
                               {"refund_requested_ts", unix_ts + 3601},
                               {"payment_id",
                                std::string(
                                        payment_tx.payment_id, payment_tx.payment_id_count)}}})}};
            std::string json = j.dump();

            // Valid Google JSON
            auto result =
                    session_pro_backend_get_pro_details_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_get_pro_details_response_free(&result); }};
                for (size_t index = 0; index < result.header.errors_count; index++)
                    INFO(result.header.errors[index].data);

                REQUIRE(result.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
                REQUIRE(result.header.errors_count == 0);
                REQUIRE(result.header.errors == nullptr);
                REQUIRE(result.status == SESSION_PRO_BACKEND_USER_PRO_STATUS_EXPIRED);
                REQUIRE(result.error_report ==
                        SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_GENERIC_ERROR);
                REQUIRE(result.items_count == 1);
                REQUIRE(result.auto_renewing == true);
                REQUIRE(result.grace_period_duration == 1000);
                REQUIRE(result.expiry_ts == unix_ts + 2);
                REQUIRE(result.refund_requested_ts == unix_ts + 3602);
                REQUIRE(result.payments_total == 3);
                REQUIRE(result.items != nullptr);
                REQUIRE(result.items[0].status == SESSION_PRO_BACKEND_PAYMENT_STATUS_REDEEMED);
                REQUIRE(std::string_view(result.items[0].plan, result.items[0].plan_count) == "1m");
                REQUIRE(std::string_view(
                                result.items[0].payment_provider,
                                result.items[0].payment_provider_count) ==
                        SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY);
                // Sub-second precision preserved through sys_ms (0.5s = 500ms) round-trips exactly
                REQUIRE(result.items[0].purchased_ts == unix_ts - 3600 + 0.5);
                REQUIRE(result.items[0].redeemed_ts == unix_ts - 3600);
                REQUIRE(result.items[0].expiry_ts == unix_ts);
                REQUIRE(result.items[0].grace_period_duration == 1001);
                REQUIRE(result.items[0].platform_refund_expiry_ts == unix_ts + 1);
                REQUIRE(result.items[0].revoked_ts == unix_ts + 3600 + 0.75);  // 750ms preserved
                REQUIRE(result.items[0].refund_requested_ts == unix_ts + 3601);
                REQUIRE(result.items[0].payment_id_count == payment_tx.payment_id_count);
                REQUIRE(std::memcmp(
                                result.items[0].payment_id,
                                payment_tx.payment_id,
                                payment_tx.payment_id_count) == 0);
            }

            // Tweak JSON for a different provider. payment_id is opaque so nothing
            // provider-specific changes in how libsession parses it.
            j["result"]["items"][0]["payment_provider"] =
                    SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_RANGEPROOF;
            j["result"]["items"][0]["payment_id"] = "rangeproof-opaque-id";
            json = j.dump();

            // Valid Rangeproof JSON
            auto result_rangeproof =
                    session_pro_backend_get_pro_details_response_parse(json.data(), json.size());
            {
                scope_exit result_free{[&]() {
                    session_pro_backend_get_pro_details_response_free(&result_rangeproof);
                }};
                for (size_t index = 0; index < result.header.errors_count; index++)
                    INFO(result_rangeproof.header.errors[index].data);

                // Only check what we expect to be different
                REQUIRE(std::string_view(
                                result_rangeproof.items[0].payment_provider,
                                result_rangeproof.items[0].payment_provider_count) ==
                        SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_RANGEPROOF);
                REQUIRE(std::string_view(
                                result_rangeproof.items[0].payment_id,
                                result_rangeproof.items[0].payment_id_count) ==
                        "rangeproof-opaque-id");
            }

            // After freeing
            REQUIRE(result.header.internal_arena_buf_ == nullptr);
            REQUIRE(result.items == nullptr);
            REQUIRE(result.items_count == 0);

            // Invalid JSON
            json = "{invalid}";
            result = session_pro_backend_get_pro_details_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_get_pro_details_response_free(&result); }};
                REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
                REQUIRE(result.header.errors_count > 0);
                REQUIRE(result.header.errors != nullptr);
            }

            // After freeing
            session_pro_backend_get_pro_details_response_free(&result);
            REQUIRE(result.header.internal_arena_buf_ == nullptr);

            // Null JSON
            result = session_pro_backend_get_pro_details_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
            REQUIRE(result.header.errors_count == 1);
            REQUIRE(result.header.errors != nullptr);
        }

        SECTION("Memory management edge cases") {
            // Test freeing null/empty structs
            session_pro_backend_to_json to_json = {};
            session_pro_backend_to_json_free(&to_json);
            REQUIRE(to_json.json.data == nullptr);
            REQUIRE(to_json.json.size == 0);

            session_pro_backend_pro_proof_response proof_response = {};
            session_pro_backend_pro_proof_response_free(&proof_response);
            REQUIRE(proof_response.header.internal_arena_buf_ == nullptr);

            session_pro_backend_get_pro_revocations_response rev_response = {};
            session_pro_backend_get_pro_revocations_response_free(&rev_response);
            REQUIRE(rev_response.header.internal_arena_buf_ == nullptr);

            session_pro_backend_get_pro_details_response pay_response = {};
            session_pro_backend_get_pro_details_response_free(&pay_response);
            REQUIRE(pay_response.header.internal_arena_buf_ == nullptr);
        }

        SECTION("session_pro_backend_set_payment_refund_requested_request_to_json") {
            session_pro_backend_set_payment_refund_requested_request request = {};
            request.master_pkey = master_pubkey;
            request.ts = unix_ts;
            request.refund_requested_ts = unix_ts + 1;
            request.payment_tx = payment_tx;

            session_pro_backend_signature sig =
                    session_pro_backend_set_payment_refund_requested_request_build_sigs(
                            master_privkey.data,
                            sizeof(master_privkey.data),
                            request.ts,
                            request.refund_requested_ts,
                            payment_tx.provider_code,
                            reinterpret_cast<const uint8_t*>(payment_tx.payment_id),
                            payment_tx.payment_id_count);
            request.master_sig = sig.sig;
            REQUIRE(sig.success);

            // Valid request
            auto result =
                    session_pro_backend_set_payment_refund_requested_request_to_json(&request);
            {
                scope_exit result_free{[&]() { session_pro_backend_to_json_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.json.data != nullptr);
                REQUIRE(result.json.size > 0);

                // Verify JSON + route match the C++ free-function implementation
                auto cpp = refund_request(
                        master_privkey.data,
                        session::as_sys_seconds(request.ts),
                        session::as_sys_seconds(request.refund_requested_ts),
                        payment_tx.provider_code,
                        std::span<const uint8_t>(
                                reinterpret_cast<const uint8_t*>(payment_tx.payment_id),
                                payment_tx.payment_id_count));
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_SET_PAYMENT_REFUND_REQUESTED_ENDPOINT);
                REQUIRE(string8_equals(result.json, cpp.body));
            }

            // After freeing
            REQUIRE(result.json.data == nullptr);
            REQUIRE(result.json.size == 0);

            // Null request
            result = session_pro_backend_set_payment_refund_requested_request_to_json(nullptr);
            REQUIRE(!result.success);
            REQUIRE(result.json.data == nullptr);
            REQUIRE(result.json.size == 0);
        }

        SECTION("session_pro_backend_set_payment_refund_requested_response_parse") {
            nlohmann::json j;
            j["status"] = SESSION_PRO_BACKEND_STATUS_SUCCESS;
            j["result"]["updated"] = true;
            j["result"]["version"] = 0;
            std::string json = j.dump();

            // Valid JSON
            auto result = session_pro_backend_set_payment_refund_requested_response_parse(
                    json.data(), json.size());
            {
                scope_exit result_free{[&]() {
                    session_pro_backend_set_payment_refund_requested_response_free(&result);
                }};
                for (size_t index = 0; index < result.header.errors_count; index++)
                    INFO(result.header.errors[index].data);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
                REQUIRE(result.header.errors_count == 0);
                REQUIRE(result.header.errors == nullptr);
                REQUIRE(result.updated);
                REQUIRE(result.version == 0);
            }

            // After freeing
            REQUIRE(result.header.internal_arena_buf_ == nullptr);

            // Invalid JSON
            json = "{invalid}";
            {
                result = session_pro_backend_set_payment_refund_requested_response_parse(
                        json.data(), json.size());
                scope_exit result_free{[&]() {
                    session_pro_backend_set_payment_refund_requested_response_free(&result);
                }};
                for (size_t index = 0; index < result.header.errors_count; index++)
                    REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
                REQUIRE(result.header.errors_count > 0);
                REQUIRE(result.header.errors != nullptr);
            }

            // After freeing
            REQUIRE(result.header.internal_arena_buf_ == nullptr);

            // Null JSON
            result = session_pro_backend_set_payment_refund_requested_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
            REQUIRE(result.header.errors_count == 1);
            REQUIRE(result.header.errors != nullptr);
        }
    }
}

#if defined(TEST_PRO_BACKEND_WITH_DEV_SERVER)
#include <curl/curl.h>

size_t curl_perform_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    auto* response_json = static_cast<std::string*>(userp);
    *response_json += std::string_view(static_cast<char*>(contents), total);
    return total;
};

std::string curl_do_basic_blocking_post_request(
        CURL* curl, curl_slist* headers, const std::string& url, std::string_view post_body) {
    std::string result;
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_perform_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    if (post_body.size()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, post_body.size());
    }

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        INFO("ERROR: Post to " << url << " with " << post_body << ": " << curl_easy_strerror(res));
        REQUIRE(res == CURLE_OK);
    }
    return result;
}

TEST_CASE("Pro Backend Dev Server", "[pro_backend][dev_server]") {
    // Setup: Generate keys and payment token hash
    bytes32 master_pubkey = {};
    bytes64 master_privkey = {};
    crypto_sign_ed25519_keypair(master_pubkey.data, master_privkey.data);

    bytes32 rotating_pubkey = {};
    bytes64 rotating_privkey = {};
    crypto_sign_ed25519_keypair(rotating_pubkey.data, rotating_privkey.data);

    const auto DEV_BACKEND_PUBKEY =
            "fc947730f49eb01427a66e050733294d9e520e545c7a27125a780634e0860a27"_hexbytes;

    // Setup CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    scope_exit curl_cleanup{[&]() { curl_global_cleanup(); }};

    CURL* curl = curl_easy_init();
    REQUIRE(curl);
    scope_exit curl_free{[&]() { curl_easy_cleanup(curl); }};

    struct curl_slist* curl_headers = nullptr;
    curl_headers = curl_slist_append(curl_headers, "Content-Type: application/json");
    REQUIRE(curl_headers);
    scope_exit curl_headers_free{[&]() { curl_slist_free_all(curl_headers); }};

    // Add pro payment
    session_protocol_pro_proof first_pro_proof = {};
    {
        std::array<uint8_t, 8> fake_google_payment_token;
        randombytes_buf(fake_google_payment_token.data(), fake_google_payment_token.size());
        std::array<uint8_t, 8> fake_google_order_id;
        randombytes_buf(fake_google_order_id.data(), fake_google_order_id.size());
        // Google's composite payment_id is "<payment_token>|<order_id>"; libsession treats the
        // whole thing as one opaque value.
        std::string fake_payment_id = "DEV." + oxenc::to_hex(fake_google_payment_token) + "|DEV." +
                                      oxenc::to_hex(fake_google_order_id);

        session_pro_backend_add_pro_payment_user_transaction payment_tx = {};
        payment_tx.provider_code_count =
                sizeof(SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY) - 1;
        std::memcpy(
                payment_tx.provider_code,
                SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY,
                sizeof(SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY));
        payment_tx.payment_id_count = fake_payment_id.size();
        std::memcpy(payment_tx.payment_id, fake_payment_id.data(), payment_tx.payment_id_count);

        // Build request
        session_pro_backend_master_rotating_signatures add_pro_sigs =
                session_pro_backend_add_pro_payment_request_build_sigs(
                        master_privkey.data,
                        sizeof(master_privkey.data),
                        rotating_privkey.data,
                        sizeof(rotating_privkey.data),
                        payment_tx.provider_code,
                        reinterpret_cast<const uint8_t*>(payment_tx.payment_id),
                        payment_tx.payment_id_count);

        session_pro_backend_add_pro_payment_request request = {};
        request.master_pkey = master_pubkey;
        request.rotating_pkey = rotating_pubkey;
        request.payment_tx = payment_tx;
        request.master_sig = add_pro_sigs.master_sig;
        request.rotating_sig = add_pro_sigs.rotating_sig;

        session_pro_backend_to_json request_json =
                session_pro_backend_add_pro_payment_request_to_json(&request);
        scope_exit request_json_free{[&]() { session_pro_backend_to_json_free(&request_json); }};

        // Do curl request
        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/add_pro_payment",
                std::string_view(request_json.json.data, request_json.json.size));

        // Parse response
        session_pro_backend_pro_proof_response response =
                session_pro_backend_pro_proof_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{[&]() { session_pro_backend_pro_proof_response_free(&response); }};

        for (size_t index = 0; index < response.header.errors_count; index++) {
            string8 error = response.header.errors[index];
            INFO("ERROR: " << error.data);
        }

        // Verify response
        first_pro_proof = response.proof;
        INFO("Signature: " << oxenc::to_hex(
                                      first_pro_proof.sig.data, std::end(first_pro_proof.sig.data))
                           << ", backend pubkey: " << oxenc::to_hex(DEV_BACKEND_PUBKEY)
                           << ", response: " << response_json);
        REQUIRE(session_protocol_pro_proof_verify_signature(
                &first_pro_proof, DEV_BACKEND_PUBKEY.data(), DEV_BACKEND_PUBKEY.size()));
        REQUIRE(std::memcmp(
                        response.proof.rotating_pubkey.data,
                        request.rotating_pkey.data,
                        sizeof(request.rotating_pkey.data)) == 0);
    }

    // Authorise new key
    {
        int64_t now_unix_ts = session::epoch_seconds(session::sysclock_now_s());
        // Build request
        session_pro_backend_master_rotating_signatures pro_sigs =
                session_pro_backend_generate_pro_proof_request_build_sigs(
                        master_privkey.data,
                        sizeof(master_privkey.data),
                        rotating_privkey.data,
                        sizeof(rotating_privkey.data),
                        now_unix_ts);

        session_pro_backend_generate_pro_proof_request request = {};
        request.master_pkey = master_pubkey;
        request.rotating_pkey = rotating_pubkey;
        request.ts = now_unix_ts;
        request.master_sig = pro_sigs.master_sig;
        request.rotating_sig = pro_sigs.rotating_sig;

        session_pro_backend_to_json request_json =
                session_pro_backend_generate_pro_proof_request_to_json(&request);
        scope_exit request_json_free{[&]() { session_pro_backend_to_json_free(&request_json); }};

        // Do CURL request
        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/generate_pro_proof",
                std::string_view(request_json.json.data, request_json.json.size));

        // Parse response
        session_pro_backend_pro_proof_response response =
                session_pro_backend_pro_proof_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{[&]() { session_pro_backend_pro_proof_response_free(&response); }};

        for (size_t index = 0; index < response.header.errors_count; index++) {
            if (index == 0)
                fprintf(stderr, "ERROR: JSON response: %s\n", response_json.c_str());
            string8 error = response.header.errors[index];
            fprintf(stderr, "ERROR: %s\n", error.data);
        }
        REQUIRE(response.header.errors_count == 0);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);

        // Verify response
        session_protocol_pro_proof proof = response.proof;
        REQUIRE(session_protocol_pro_proof_verify_signature(
                &proof, DEV_BACKEND_PUBKEY.data(), DEV_BACKEND_PUBKEY.size()));
        REQUIRE(std::memcmp(
                        response.proof.rotating_pubkey.data,
                        request.rotating_pkey.data,
                        sizeof(request.rotating_pkey.data)) == 0);

        session_pro_backend_to_json_free(&request_json);
        session_pro_backend_pro_proof_response_free(&response);
    }

    // Get pro status
    {
        // Build request
        session_pro_backend_get_pro_details_request request = {};
        request.master_pkey = master_pubkey;
        request.ts = session::epoch_seconds(session::sysclock_now_s());
        request.count = 10'000;

        session_pro_backend_signature sig = session_pro_backend_get_pro_details_request_build_sig(
                master_privkey.data, sizeof(master_privkey.data), request.ts, request.count);
        REQUIRE(sig.success);
        request.master_sig = sig.sig;

        // Do CURL request
        session_pro_backend_to_json request_json =
                session_pro_backend_get_pro_details_request_to_json(&request);
        scope_exit request_json_free{[&]() { session_pro_backend_to_json_free(&request_json); }};

        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/get_pro_details",
                std::string_view(request_json.json.data, request_json.json.size));

        // Parse response
        session_pro_backend_get_pro_details_response response =
                session_pro_backend_get_pro_details_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{
                [&]() { session_pro_backend_get_pro_details_response_free(&response); }};

        // Verify the response
        for (size_t index = 0; index < response.header.errors_count; index++) {
            if (index == 0)
                fprintf(stderr, "ERROR: JSON response: %s\n", response_json.c_str());
            string8 error = response.header.errors[index];
            fprintf(stderr, "ERROR: %s\n", error.data);
        }
        REQUIRE(response.header.errors_count == 0);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(response.status == SESSION_PRO_BACKEND_USER_PRO_STATUS_ACTIVE);
        REQUIRE(response.items_count > 0);
    }

    // Get pro status without history
    {
        // Build request
        session_pro_backend_get_pro_details_request request = {};
        request.master_pkey = master_pubkey;
        request.ts = session::epoch_seconds(session::sysclock_now_s());

        session_pro_backend_signature sig = session_pro_backend_get_pro_details_request_build_sig(
                master_privkey.data, sizeof(master_privkey.data), request.ts, request.count);
        REQUIRE(sig.success);
        request.master_sig = sig.sig;

        // Do CURL request
        session_pro_backend_to_json request_json =
                session_pro_backend_get_pro_details_request_to_json(&request);
        scope_exit request_json_free{[&]() { session_pro_backend_to_json_free(&request_json); }};

        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/get_pro_details",
                std::string_view(request_json.json.data, request_json.json.size));

        // Parse response
        session_pro_backend_get_pro_details_response response =
                session_pro_backend_get_pro_details_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{
                [&]() { session_pro_backend_get_pro_details_response_free(&response); }};

        for (size_t index = 0; index < response.header.errors_count; index++) {
            if (index == 0)
                fprintf(stderr, "ERROR: JSON response: %s\n", response_json.c_str());
            string8 error = response.header.errors[index];
            fprintf(stderr, "ERROR: %s\n", error.data);
        }

        // Verify the response
        REQUIRE(response.header.errors_count == 0);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(response.status == SESSION_PRO_BACKEND_USER_PRO_STATUS_ACTIVE);
        REQUIRE(response.items_count == 0);
    }

    // Add _another_ payment, same details
    session_pro_backend_add_pro_payment_user_transaction another_payment_tx = {};
    {
        std::array<uint8_t, 8> fake_google_payment_token;
        randombytes_buf(fake_google_payment_token.data(), fake_google_payment_token.size());
        std::array<uint8_t, 8> fake_google_order_id;
        randombytes_buf(fake_google_order_id.data(), fake_google_order_id.size());
        std::string fake_payment_id = "DEV." + oxenc::to_hex(fake_google_payment_token) + "|DEV." +
                                      oxenc::to_hex(fake_google_order_id);

        another_payment_tx.provider_code_count =
                sizeof(SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY) - 1;
        std::memcpy(
                another_payment_tx.provider_code,
                SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY,
                sizeof(SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY));
        another_payment_tx.payment_id_count = fake_payment_id.size();
        std::memcpy(
                another_payment_tx.payment_id,
                fake_payment_id.data(),
                another_payment_tx.payment_id_count);

        // Build request
        session_pro_backend_master_rotating_signatures add_pro_sigs =
                session_pro_backend_add_pro_payment_request_build_sigs(
                        master_privkey.data,
                        sizeof(master_privkey.data),
                        rotating_privkey.data,
                        sizeof(rotating_privkey.data),
                        another_payment_tx.provider_code,
                        reinterpret_cast<const uint8_t*>(another_payment_tx.payment_id),
                        another_payment_tx.payment_id_count);

        session_pro_backend_add_pro_payment_request request = {};
        request.master_pkey = master_pubkey;
        request.rotating_pkey = rotating_pubkey;
        request.payment_tx = another_payment_tx;
        request.master_sig = add_pro_sigs.master_sig;
        request.rotating_sig = add_pro_sigs.rotating_sig;

        session_pro_backend_to_json request_json =
                session_pro_backend_add_pro_payment_request_to_json(&request);
        scope_exit request_json_free{[&]() { session_pro_backend_to_json_free(&request_json); }};

        // Do curl request
        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/add_pro_payment",
                std::string_view(request_json.json.data, request_json.json.size));

        // Parse response
        session_pro_backend_pro_proof_response response =
                session_pro_backend_pro_proof_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{[&]() { session_pro_backend_pro_proof_response_free(&response); }};

        // Verify response
        session_protocol_pro_proof proof = response.proof;
        REQUIRE(session_protocol_pro_proof_verify_signature(
                &proof, DEV_BACKEND_PUBKEY.data(), DEV_BACKEND_PUBKEY.size()));
        REQUIRE(std::memcmp(
                        response.proof.rotating_pubkey.data,
                        request.rotating_pkey.data,
                        sizeof(request.rotating_pkey.data)) == 0);
    }

    // Get revocation list
    {
        // Build request
        session_pro_backend_get_pro_revocations_request request = {};

        session_pro_backend_to_json request_json =
                session_pro_backend_get_pro_revocations_request_to_json(&request);
        scope_exit request_json_free{[&]() { session_pro_backend_to_json_free(&request_json); }};

        // Do curl request
        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/get_pro_revocations",
                std::string_view(request_json.json.data, request_json.json.size));

        // Parse response
        session_pro_backend_get_pro_revocations_response response =
                session_pro_backend_get_pro_revocations_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{
                [&]() { session_pro_backend_get_pro_revocations_response_free(&response); }};

        // Verify response
        INFO("ERROR: JSON response: " << response_json.c_str());
        for (size_t index = 0; index < response.header.errors_count; index++) {
            string8 error = response.header.errors[index];
            fprintf(stderr, "ERROR: %s\n", error.data);
        }

        // Verify the response
        REQUIRE(response.header.errors_count == 0);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(response.ticket == 0);
        REQUIRE(response.items_count == 0);
    }

    // Set payment refund requested
    {
        // Build request
        int64_t now_unix_ts = session::epoch_seconds(session::sysclock_now_s());
        session_pro_backend_signature refund_sig =
                session_pro_backend_set_payment_refund_requested_request_build_sigs(
                        master_privkey.data,
                        sizeof(master_privkey.data),
                        /*ts*/ now_unix_ts,
                        /*refund_requested_ts*/ now_unix_ts,
                        another_payment_tx.provider_code,
                        reinterpret_cast<const uint8_t*>(another_payment_tx.payment_id),
                        another_payment_tx.payment_id_count);

        session_pro_backend_set_payment_refund_requested_request request = {};
        request.master_pkey = master_pubkey;
        request.master_sig = refund_sig.sig;
        request.ts = now_unix_ts;
        request.refund_requested_ts = now_unix_ts;
        request.payment_tx = another_payment_tx;

        session_pro_backend_to_json request_json =
                session_pro_backend_set_payment_refund_requested_request_to_json(&request);
        scope_exit request_json_free{[&]() { session_pro_backend_to_json_free(&request_json); }};

        // Do curl request
        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/set_payment_refund_requested",
                std::string_view(request_json.json.data, request_json.json.size));

        // Parse response
        session_pro_backend_set_payment_refund_requested_response response =
                session_pro_backend_set_payment_refund_requested_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{[&]() {
            session_pro_backend_set_payment_refund_requested_response_free(&response);
        }};

        // Verify response
        INFO("ERROR: JSON response: " << response_json.c_str());
        for (size_t index = 0; index < response.header.errors_count; index++) {
            string8 error = response.header.errors[index];
            fprintf(stderr, "ERROR: %s\n", error.data);
        }

        // Verify the response
        REQUIRE(response.header.errors_count == 0);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(response.version == 0);
        REQUIRE(response.updated);
    }
}
#endif
