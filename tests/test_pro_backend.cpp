#include <oxenc/hex.h>
#include <session/pro_backend.h>
#include <sodium.h>

#include <catch2/catch_test_macros.hpp>
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
TEST_CASE("Pro Backend C API", "[pro_backend]") {
    // Setup: Generate keys and payment token hash
    cbytes32 master_pubkey = {};
    cbytes64 master_privkey = {};
    crypto_sign_ed25519_keypair(master_pubkey.data, master_privkey.data);

    cbytes32 rotating_pubkey = {};
    cbytes64 rotating_privkey = {};
    crypto_sign_ed25519_keypair(rotating_pubkey.data, rotating_privkey.data);

    {
        std::array<unsigned char, 8> fake_google_payment_token;
        randombytes_buf(fake_google_payment_token.data(), fake_google_payment_token.size());
        std::array<unsigned char, 8> fake_google_order_id;
        randombytes_buf(fake_google_order_id.data(), fake_google_order_id.size());
        // Google's composite payment_id is "<payment_token>|<order_id>"; libsession treats the
        // whole thing as one opaque value.
        std::string fake_payment_id = "DEV." + oxenc::to_hex(fake_google_payment_token) + "|DEV." +
                                      oxenc::to_hex(fake_google_order_id);

        const char* provider_code = SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY;
        auto payment_id = reinterpret_cast<const uint8_t*>(fake_payment_id.data());
        size_t payment_id_len = fake_payment_id.size();

        int64_t unix_ts = 1698765432;  // Arbitrary timestamp (unix epoch seconds)

        SECTION("session_pro_backend_add_pro_payment_request_build") {
            auto result = session_pro_backend_add_pro_payment_request_build(
                    master_privkey.data,
                    sizeof(master_privkey.data),
                    rotating_privkey.data,
                    sizeof(rotating_privkey.data),
                    provider_code,
                    payment_id,
                    payment_id_len);
            {
                scope_exit result_free{[&]() { session_pro_backend_request_free(&result); }};
                INFO(result.error);
                REQUIRE(result.success);
                REQUIRE(result.data.data != nullptr);
                REQUIRE(result.data.size > 0);

                // Matches the C++ free-function implementation end to end.
                auto cpp = add_payment_request(
                        master_privkey.data,
                        rotating_privkey.data,
                        provider_code,
                        to_byte_span(payment_id, payment_id_len));
                REQUIRE(std::string_view(result.endpoint) == cpp.endpoint);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_ENDPOINT);
                REQUIRE(std::string_view(result.content_type) == cpp.content_type);
                REQUIRE(cpp.content_type == "application/json");
                REQUIRE(string8_equals(result.data, cpp.data));
            }

            // After freeing
            REQUIRE(result.data.data == nullptr);
            REQUIRE(result.data.size == 0);

            // Invalid key size -> failure, no allocation
            result = session_pro_backend_add_pro_payment_request_build(
                    master_privkey.data,
                    sizeof(master_privkey.data) - 1,
                    rotating_privkey.data,
                    sizeof(rotating_privkey.data),
                    provider_code,
                    payment_id,
                    payment_id_len);
            REQUIRE(!result.success);
            REQUIRE(result.error_count > 0);
            REQUIRE(result.data.data == nullptr);
        }

        SECTION("session_pro_backend_generate_pro_proof_request_build") {
            auto result = session_pro_backend_generate_pro_proof_request_build(
                    master_privkey.data,
                    sizeof(master_privkey.data),
                    rotating_privkey.data,
                    sizeof(rotating_privkey.data),
                    unix_ts);
            {
                scope_exit result_free{[&]() { session_pro_backend_request_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.data.size > 0);

                auto cpp = pro_proof_request(
                        master_privkey.data,
                        rotating_privkey.data,
                        session::as_sys_seconds(unix_ts));
                REQUIRE(std::string_view(result.endpoint) == cpp.endpoint);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_GENERATE_PRO_PROOF_ENDPOINT);
                REQUIRE(string8_equals(result.data, cpp.data));
            }
            REQUIRE(result.data.data == nullptr);

            // Invalid rotating key size
            result = session_pro_backend_generate_pro_proof_request_build(
                    master_privkey.data,
                    sizeof(master_privkey.data),
                    rotating_privkey.data,
                    sizeof(rotating_privkey.data) - 1,
                    unix_ts);
            REQUIRE(!result.success);
            REQUIRE(result.error_count > 0);
        }

        SECTION("session_pro_backend_get_pro_revocations_request_build") {
            auto result = session_pro_backend_get_pro_revocations_request_build(123);
            {
                scope_exit result_free{[&]() { session_pro_backend_request_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.data.size > 0);

                auto cpp = revocations_request(123);
                REQUIRE(std::string_view(result.endpoint) == cpp.endpoint);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_GET_PRO_REVOCATIONS_ENDPOINT);
                REQUIRE(string8_equals(result.data, cpp.data));
            }
            REQUIRE(result.data.data == nullptr);
        }

        SECTION("session_pro_backend_get_pro_details_request_build") {
            auto result = session_pro_backend_get_pro_details_request_build(
                    master_privkey.data, sizeof(master_privkey.data), unix_ts, 10'000);
            {
                scope_exit result_free{[&]() { session_pro_backend_request_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.data.size > 0);

                auto cpp = payment_details_request(
                        master_privkey.data, session::as_sys_seconds(unix_ts), 10'000);
                REQUIRE(std::string_view(result.endpoint) == cpp.endpoint);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_GET_PRO_DETAILS_ENDPOINT);
                REQUIRE(string8_equals(result.data, cpp.data));
            }
            REQUIRE(result.data.data == nullptr);

            // Invalid key size
            result = session_pro_backend_get_pro_details_request_build(
                    master_privkey.data, sizeof(master_privkey.data) - 1, unix_ts, 10'000);
            REQUIRE(!result.success);
            REQUIRE(result.error_count > 0);
        }

        SECTION("session_pro_backend_pro_proof_response_parse") {
            b32 fake_revocation_tag;
            randombytes_buf(fake_revocation_tag.data(), fake_revocation_tag.size());

            nlohmann::json j;
            j["status"] = "ok";
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

                if (result.header.error.data)
                    INFO(result.header.error.data);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error.data == nullptr);
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
                        result_cpp.proof.expiry_at.time_since_epoch().count());
                REQUIRE(std::memcmp(
                                result.proof.sig.data,
                                result_cpp.proof.sig.data(),
                                result_cpp.proof.sig.size()) == 0);
            }

            // After freeing
            REQUIRE(result.header.internal_arena_buf_ == nullptr);
            REQUIRE(result.header.error.data == nullptr);
            REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);

            // Invalid JSON
            json = "{invalid}";
            result = session_pro_backend_pro_proof_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_pro_proof_response_free(&result); }};
                REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error_code.data != nullptr);
                REQUIRE(result.header.error_code.data != nullptr);
            }

            // After freeing
            session_pro_backend_pro_proof_response_free(&result);
            REQUIRE(result.header.internal_arena_buf_ == nullptr);

            // Null JSON
            result = session_pro_backend_pro_proof_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
            REQUIRE(result.header.error_code.data != nullptr);
            REQUIRE(result.header.error_code.data != nullptr);

            // No need to free, as errors point to static memory
        }

        SECTION("session_pro_backend_get_pro_revocations_response_parse") {
            nlohmann::json j;
            j["status"] = "ok";
            j["result"]["ticket"] = 123;
            j["result"]["retry_in"] = 3600;
            j["result"]["retain_for"] = 2592000;
            j["result"]["items"] = nlohmann::json::array();

            b32 fake_revocation_tag;
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
                if (result.header.error.data)
                    INFO(result.header.error.data);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error.data == nullptr);
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
                REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error_code.data != nullptr);
                REQUIRE(result.header.error_code.data != nullptr);
            }

            // After freeing
            REQUIRE(result.header.internal_arena_buf_ == nullptr);

            // Null JSON
            result = session_pro_backend_get_pro_revocations_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
            REQUIRE(result.header.error_code.data != nullptr);
            REQUIRE(result.header.error_code.data != nullptr);
        }

        SECTION("session_pro_backend_get_pro_details_response_parse") {
            nlohmann::json j;
            j["status"] = "ok";
            j["result"] = {
                    {"user_status", "expired"},
                    {"error_report",
                     SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_GENERIC_ERROR},
                    {"auto_renewing", true},
                    {"expiry_ts", unix_ts + 2},
                    {"grace_period_duration", 1000},
                    {"refund_requested_ts", unix_ts + 3602},
                    {"payments_total", 3},
                    {"items",
                     nlohmann::json::array(
                             {{{"status", "redeemed"},
                               {"plan", "1m"},
                               {"payment_provider",
                                SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY},
                               {"auto_renewing", false},
                               // purchased_ts/revoked_ts are floats on the wire (sub-second
                               // precision); libsession keeps them as millisecond-precise sys_ms.
                               {"purchased_ts", unix_ts - 3600 + 0.5},
                               {"redeemed_ts", unix_ts - 3600},
                               {"expiry_ts", unix_ts},
                               {"grace_period_duration", 1001},
                               {"platform_refund_expiry_ts", unix_ts + 1},
                               {"revoked_ts", unix_ts + 3600 + 0.75},
                               {"refund_requested_ts", unix_ts + 3601},
                               {"payment_id",
                                std::string(fake_payment_id.data(), fake_payment_id.size())}}})}};
            std::string json = j.dump();

            // Valid Google JSON
            auto result =
                    session_pro_backend_get_pro_details_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_get_pro_details_response_free(&result); }};
                if (result.header.error.data)
                    INFO(result.header.error.data);

                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error.data == nullptr);
                REQUIRE(std::string_view(result.status, result.status_count) == "expired");
                REQUIRE(result.error_report ==
                        SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT_GENERIC_ERROR);
                REQUIRE(result.items_count == 1);
                REQUIRE(result.auto_renewing == true);
                REQUIRE(result.grace_period_duration == 1000);
                REQUIRE(result.expiry_ts == unix_ts + 2);
                REQUIRE(result.refund_requested_ts == unix_ts + 3602);
                REQUIRE(result.payments_total == 3);
                REQUIRE(result.items != nullptr);
                REQUIRE(std::string_view(result.items[0].status, result.items[0].status_count) ==
                        "redeemed");
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
                REQUIRE(result.items[0].payment_id_count == fake_payment_id.size());
                REQUIRE(std::memcmp(
                                result.items[0].payment_id,
                                fake_payment_id.data(),
                                fake_payment_id.size()) == 0);
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
                if (result_rangeproof.header.error.data)
                    INFO(result_rangeproof.header.error.data);

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
                REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error_code.data != nullptr);
                REQUIRE(result.header.error_code.data != nullptr);
            }

            // After freeing
            session_pro_backend_get_pro_details_response_free(&result);
            REQUIRE(result.header.internal_arena_buf_ == nullptr);

            // Null JSON
            result = session_pro_backend_get_pro_details_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
            REQUIRE(result.header.error_code.data != nullptr);
            REQUIRE(result.header.error_code.data != nullptr);
        }

        SECTION("Memory management edge cases") {
            // Test freeing null/empty structs
            session_pro_backend_request to_json = {};
            session_pro_backend_request_free(&to_json);
            REQUIRE(to_json.data.data == nullptr);
            REQUIRE(to_json.data.size == 0);

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

        SECTION("session_pro_backend_set_payment_refund_requested_request_build") {
            auto result = session_pro_backend_set_payment_refund_requested_request_build(
                    master_privkey.data,
                    sizeof(master_privkey.data),
                    unix_ts,
                    unix_ts + 1,
                    provider_code,
                    payment_id,
                    payment_id_len);
            {
                scope_exit result_free{[&]() { session_pro_backend_request_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.data.size > 0);

                auto cpp = refund_request(
                        master_privkey.data,
                        session::as_sys_seconds(unix_ts),
                        session::as_sys_seconds(unix_ts + 1),
                        provider_code,
                        to_byte_span(payment_id, payment_id_len));
                REQUIRE(std::string_view(result.endpoint) == cpp.endpoint);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_SET_PAYMENT_REFUND_REQUESTED_ENDPOINT);
                REQUIRE(string8_equals(result.data, cpp.data));
            }
            REQUIRE(result.data.data == nullptr);

            // Invalid key size
            result = session_pro_backend_set_payment_refund_requested_request_build(
                    master_privkey.data,
                    sizeof(master_privkey.data) - 1,
                    unix_ts,
                    unix_ts + 1,
                    provider_code,
                    payment_id,
                    payment_id_len);
            REQUIRE(!result.success);
            REQUIRE(result.error_count > 0);
        }

        SECTION("session_pro_backend_set_payment_refund_requested_response_parse") {
            nlohmann::json j;
            j["status"] = "ok";
            j["result"]["updated"] = true;
            std::string json = j.dump();

            // Valid JSON
            auto result = session_pro_backend_set_payment_refund_requested_response_parse(
                    json.data(), json.size());
            {
                scope_exit result_free{[&]() {
                    session_pro_backend_set_payment_refund_requested_response_free(&result);
                }};
                if (result.header.error.data)
                    INFO(result.header.error.data);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error.data == nullptr);
                REQUIRE(result.updated);
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
                REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error_code.data != nullptr);
                REQUIRE(result.header.error_code.data != nullptr);
            }

            // After freeing
            REQUIRE(result.header.internal_arena_buf_ == nullptr);

            // Null JSON
            result = session_pro_backend_set_payment_refund_requested_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
            REQUIRE(result.header.error_code.data != nullptr);
            REQUIRE(result.header.error_code.data != nullptr);
        }
    }
}

TEST_CASE("Pro Backend X25519 pubkey matches the converted Ed25519 pubkey", "[pro_backend]") {
    // PUBKEY_X25519 is a hardcoded convenience constant; assert it equals the runtime conversion of
    // the Ed25519 PUBKEY so the two can never silently drift.
    unsigned char converted[32] = {};
    REQUIRE(crypto_sign_ed25519_pk_to_curve25519(
                    converted, reinterpret_cast<const unsigned char*>(PUBKEY.data())) == 0);
    REQUIRE(std::memcmp(converted, PUBKEY_X25519.data(), sizeof(converted)) == 0);
    // The C export points at the same bytes.
    REQUIRE(std::memcmp(
                    SESSION_PRO_BACKEND_PUBKEY_X25519, PUBKEY_X25519.data(), sizeof(converted)) ==
            0);
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
    cbytes32 master_pubkey = {};
    cbytes64 master_privkey = {};
    crypto_sign_ed25519_keypair(master_pubkey.data, master_privkey.data);

    cbytes32 rotating_pubkey = {};
    cbytes64 rotating_privkey = {};
    crypto_sign_ed25519_keypair(rotating_pubkey.data, rotating_privkey.data);

    const auto DEV_BACKEND_PUBKEY =
            "fc947730f49eb01427a66e050733294d9e520e545c7a27125a780634e0860a27"_hex_b;

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

        session_pro_backend_request request_json =
                session_pro_backend_add_pro_payment_request_build(
                        master_privkey.data,
                        sizeof(master_privkey.data),
                        rotating_privkey.data,
                        sizeof(rotating_privkey.data),
                        SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY,
                        reinterpret_cast<const uint8_t*>(fake_payment_id.data()),
                        fake_payment_id.size());
        scope_exit request_json_free{[&]() { session_pro_backend_request_free(&request_json); }};
        REQUIRE(request_json.success);

        // Do curl request
        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/add_pro_payment",
                std::string_view(request_json.data.data, request_json.data.size));

        // Parse response
        session_pro_backend_pro_proof_response response =
                session_pro_backend_pro_proof_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{[&]() { session_pro_backend_pro_proof_response_free(&response); }};

        if (response.header.error.data)
            INFO("ERROR: " << response.header.error.data);

        // Verify response
        first_pro_proof = response.proof;
        INFO("Signature: " << oxenc::to_hex(
                                      first_pro_proof.sig.data, std::end(first_pro_proof.sig.data))
                           << ", backend pubkey: " << oxenc::to_hex(DEV_BACKEND_PUBKEY)
                           << ", response: " << response_json);
        REQUIRE(session_protocol_pro_proof_verify_signature(
                &first_pro_proof,
                reinterpret_cast<const unsigned char*>(DEV_BACKEND_PUBKEY.data()),
                DEV_BACKEND_PUBKEY.size()));
        REQUIRE(std::memcmp(
                        response.proof.rotating_pubkey.data,
                        rotating_pubkey.data,
                        sizeof(rotating_pubkey.data)) == 0);
    }

    // Authorise new key
    {
        int64_t now_unix_ts = session::epoch_seconds(session::clock_now_s());
        session_pro_backend_request request_json =
                session_pro_backend_generate_pro_proof_request_build(
                        master_privkey.data,
                        sizeof(master_privkey.data),
                        rotating_privkey.data,
                        sizeof(rotating_privkey.data),
                        now_unix_ts);
        scope_exit request_json_free{[&]() { session_pro_backend_request_free(&request_json); }};
        REQUIRE(request_json.success);

        // Do CURL request
        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/generate_pro_proof",
                std::string_view(request_json.data.data, request_json.data.size));

        // Parse response
        session_pro_backend_pro_proof_response response =
                session_pro_backend_pro_proof_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{[&]() { session_pro_backend_pro_proof_response_free(&response); }};

        INFO("ERROR: JSON response: " << response_json.c_str());
        if (response.header.error.data)
            UNSCOPED_INFO("ERROR: " << response.header.error.data);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);

        // Verify response
        session_protocol_pro_proof proof = response.proof;
        REQUIRE(session_protocol_pro_proof_verify_signature(
                &proof,
                reinterpret_cast<const unsigned char*>(DEV_BACKEND_PUBKEY.data()),
                DEV_BACKEND_PUBKEY.size()));
        REQUIRE(std::memcmp(
                        response.proof.rotating_pubkey.data,
                        rotating_pubkey.data,
                        sizeof(rotating_pubkey.data)) == 0);
    }

    // Get pro status
    {
        session_pro_backend_request request_json =
                session_pro_backend_get_pro_details_request_build(
                        master_privkey.data,
                        sizeof(master_privkey.data),
                        session::epoch_seconds(session::clock_now_s()),
                        10'000);
        scope_exit request_json_free{[&]() { session_pro_backend_request_free(&request_json); }};
        REQUIRE(request_json.success);

        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/get_pro_details",
                std::string_view(request_json.data.data, request_json.data.size));

        // Parse response
        session_pro_backend_get_pro_details_response response =
                session_pro_backend_get_pro_details_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{
                [&]() { session_pro_backend_get_pro_details_response_free(&response); }};

        INFO("ERROR: JSON response: " << response_json.c_str());
        if (response.header.error.data)
            UNSCOPED_INFO("ERROR: " << response.header.error.data);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
        REQUIRE(std::string_view(response.status, response.status_count) == "active");
        REQUIRE(response.items_count > 0);
    }

    // Get pro status without history
    {
        session_pro_backend_request request_json =
                session_pro_backend_get_pro_details_request_build(
                        master_privkey.data,
                        sizeof(master_privkey.data),
                        session::epoch_seconds(session::clock_now_s()),
                        0);
        scope_exit request_json_free{[&]() { session_pro_backend_request_free(&request_json); }};
        REQUIRE(request_json.success);

        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/get_pro_details",
                std::string_view(request_json.data.data, request_json.data.size));

        // Parse response
        session_pro_backend_get_pro_details_response response =
                session_pro_backend_get_pro_details_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{
                [&]() { session_pro_backend_get_pro_details_response_free(&response); }};

        INFO("ERROR: JSON response: " << response_json.c_str());
        if (response.header.error.data)
            UNSCOPED_INFO("ERROR: " << response.header.error.data);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
        REQUIRE(std::string_view(response.status, response.status_count) == "active");
        REQUIRE(response.items_count == 0);
    }

    // Add _another_ payment, same details
    std::string another_payment_id;
    {
        std::array<uint8_t, 8> fake_google_payment_token;
        randombytes_buf(fake_google_payment_token.data(), fake_google_payment_token.size());
        std::array<uint8_t, 8> fake_google_order_id;
        randombytes_buf(fake_google_order_id.data(), fake_google_order_id.size());
        another_payment_id = "DEV." + oxenc::to_hex(fake_google_payment_token) + "|DEV." +
                             oxenc::to_hex(fake_google_order_id);

        session_pro_backend_request request_json =
                session_pro_backend_add_pro_payment_request_build(
                        master_privkey.data,
                        sizeof(master_privkey.data),
                        rotating_privkey.data,
                        sizeof(rotating_privkey.data),
                        SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY,
                        reinterpret_cast<const uint8_t*>(another_payment_id.data()),
                        another_payment_id.size());
        scope_exit request_json_free{[&]() { session_pro_backend_request_free(&request_json); }};
        REQUIRE(request_json.success);

        // Do curl request
        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/add_pro_payment",
                std::string_view(request_json.data.data, request_json.data.size));

        // Parse response
        session_pro_backend_pro_proof_response response =
                session_pro_backend_pro_proof_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{[&]() { session_pro_backend_pro_proof_response_free(&response); }};

        // Verify response
        session_protocol_pro_proof proof = response.proof;
        REQUIRE(session_protocol_pro_proof_verify_signature(
                &proof,
                reinterpret_cast<const unsigned char*>(DEV_BACKEND_PUBKEY.data()),
                DEV_BACKEND_PUBKEY.size()));
        REQUIRE(std::memcmp(
                        response.proof.rotating_pubkey.data,
                        rotating_pubkey.data,
                        sizeof(rotating_pubkey.data)) == 0);
    }

    // Get revocation list
    {
        session_pro_backend_request request_json =
                session_pro_backend_get_pro_revocations_request_build(0);
        scope_exit request_json_free{[&]() { session_pro_backend_request_free(&request_json); }};
        REQUIRE(request_json.success);

        // Do curl request
        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/get_pro_revocations",
                std::string_view(request_json.data.data, request_json.data.size));

        // Parse response
        session_pro_backend_get_pro_revocations_response response =
                session_pro_backend_get_pro_revocations_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{
                [&]() { session_pro_backend_get_pro_revocations_response_free(&response); }};

        // Verify response
        INFO("ERROR: JSON response: " << response_json.c_str());
        if (response.header.error.data)
            UNSCOPED_INFO("ERROR: " << response.header.error.data);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
        REQUIRE(response.ticket == 0);
        REQUIRE(response.items_count == 0);
    }

    // Set payment refund requested
    {
        int64_t now_unix_ts = session::epoch_seconds(session::clock_now_s());
        session_pro_backend_request request_json =
                session_pro_backend_set_payment_refund_requested_request_build(
                        master_privkey.data,
                        sizeof(master_privkey.data),
                        /*ts*/ now_unix_ts,
                        /*refund_requested_ts*/ now_unix_ts,
                        SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY,
                        reinterpret_cast<const uint8_t*>(another_payment_id.data()),
                        another_payment_id.size());
        scope_exit request_json_free{[&]() { session_pro_backend_request_free(&request_json); }};
        REQUIRE(request_json.success);

        // Do curl request
        std::string response_json = curl_do_basic_blocking_post_request(
                curl,
                curl_headers,
                g_test_pro_backend_dev_server_url + "/set_payment_refund_requested",
                std::string_view(request_json.data.data, request_json.data.size));

        // Parse response
        session_pro_backend_set_payment_refund_requested_response response =
                session_pro_backend_set_payment_refund_requested_response_parse(
                        response_json.data(), response_json.size());
        scope_exit response_free{[&]() {
            session_pro_backend_set_payment_refund_requested_response_free(&response);
        }};

        // Verify response
        INFO("ERROR: JSON response: " << response_json.c_str());
        if (response.header.error.data)
            UNSCOPED_INFO("ERROR: " << response.header.error.data);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
        REQUIRE(response.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
        REQUIRE(response.updated);
    }
}
#endif
