#include <oxenc/hex.h>
#include <session/config/pro.h>
#include <session/pro_backend.h>
#include <sodium.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/pro_backend.hpp>
#include <string>

#include "utils.hpp"

#if defined(TEST_PRO_BACKEND_WITH_DEV_SERVER)
#include <curl/curl.h>
#endif

using namespace session::pro_backend;

static bool string8_equals(string8 s8, std::string_view str) {
    return s8.size == str.size() && std::memcmp(s8.data, str.data(), s8.size) == 0;
}
[[maybe_unused]] static void dump_pro_proof_to_stderr(const pro_proof& proof) {
    fprintf(stderr, "proof.version: %u\n", proof.version);
    fprintf(stderr, "proof.gen_index_hash: %s\n", oxenc::to_hex(proof.gen_index_hash.data).c_str());
    fprintf(stderr,
            "proof.rotating_pubkey: %s\n",
            oxenc::to_hex(proof.rotating_pubkey.data).c_str());
    fprintf(stderr, "proof.expiry_unix_ts_s: %zu\n", proof.expiry_unix_ts_s);
    fprintf(stderr, "proof.sig: %s\n", oxenc::to_hex(proof.sig.data).c_str());
}

[[maybe_unused]] static void dump_pro_payment_item(const session_pro_backend_pro_payment_item& item) {
    fprintf(stderr, "item.activation_unix_ts_s: %zu\n", item.activation_unix_ts_s);
    fprintf(stderr, "item.archive_unix_ts_s: %zu\n", item.archive_unix_ts_s);
    fprintf(stderr, "item.creation_unix_ts_s: %zu\n", item.creation_unix_ts_s);
    fprintf(stderr, "item.subscription_duration: %zu\n", item.subscription_duration);
    fprintf(stderr, "item.payment_token_hash: %s\n", oxenc::to_hex(item.payment_token_hash.data).c_str());
}

size_t curl_perform_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    auto* response_json = static_cast<std::string*>(userp);
    *response_json += std::string_view(static_cast<char*>(contents), total);
    return total;
};

TEST_CASE("Session Pro Backend C API", "[session_pro_backend]") {
    // Setup: Generate keys and payment token hash
    bytes32 master_pubkey = {};
    bytes64 master_privkey = {};
    crypto_sign_ed25519_keypair(master_pubkey.data, master_privkey.data);

    bytes32 rotating_pubkey = {};
    bytes64 rotating_privkey = {};
    crypto_sign_ed25519_keypair(rotating_pubkey.data, rotating_privkey.data);

    bytes32 payment_token_hash;
    randombytes_buf(payment_token_hash.data, sizeof(payment_token_hash.data));
    uint64_t unix_ts_s = 1698765432; // Arbitrary timestamp

    SECTION("session_pro_backend_add_pro_payment_request_build_sigs") {
        // Valid inputs
        session_pro_backend_master_rotating_signatures result =
                session_pro_backend_add_pro_payment_request_build_sigs(
                        /*version*/ 0,
                        master_privkey.data,
                        sizeof(master_privkey),
                        rotating_privkey.data,
                        sizeof(rotating_privkey),
                        payment_token_hash.data,
                        sizeof(payment_token_hash),
                        unix_ts_s);
        REQUIRE(result.success);
        REQUIRE(result.error_count == 0);

        // Verify signatures match C++ implementation
        auto cpp = AddProPaymentRequest::build_sigs(
                0,
                master_privkey.data,
                rotating_privkey.data,
                payment_token_hash.data,
                std::chrono::sys_seconds{std::chrono::seconds{unix_ts_s}});
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
                0,
                master_privkey.data,
                sizeof(master_privkey) - 1,
                rotating_privkey.data,
                sizeof(rotating_privkey),
                payment_token_hash.data,
                sizeof(payment_token_hash.data),
                unix_ts_s);
        REQUIRE(!result.success);
        REQUIRE(result.error_count > 0);

        // Invalid payment token hash size
        result = session_pro_backend_add_pro_payment_request_build_sigs(
                0,
                master_privkey.data,
                sizeof(master_privkey),
                rotating_privkey.data,
                sizeof(rotating_privkey),
                payment_token_hash.data,
                sizeof(payment_token_hash) - 1,
                unix_ts_s);
        REQUIRE(!result.success);
        REQUIRE(result.error_count > 0);
    }

    SECTION("session_pro_backend_get_pro_proof_request_build_sigs") {
        session_pro_backend_master_rotating_signatures result = {};

        // Valid inputs
        result = session_pro_backend_get_pro_proof_request_build_sigs(
                0,
                master_privkey.data,
                sizeof(master_privkey),
                rotating_privkey.data,
                sizeof(rotating_privkey),
                unix_ts_s);
        REQUIRE(result.success);
        REQUIRE(result.error_count == 0);

        // Verify signatures match C++ implementation
        auto cpp_sigs = GetProProofRequest::build_sigs(
                0, master_privkey.data, rotating_privkey.data, std::chrono::seconds{unix_ts_s});
        REQUIRE(std::memcmp(
                        result.master_sig.data,
                        cpp_sigs.master_sig.data(),
                        sizeof(result.master_sig)) == 0);
        REQUIRE(std::memcmp(
                        result.rotating_sig.data,
                        cpp_sigs.rotating_sig.data(),
                        sizeof(result.rotating_sig)) == 0);

        // Invalid rotating key size
        result = session_pro_backend_get_pro_proof_request_build_sigs(
                0,
                master_privkey.data,
                sizeof(master_privkey),
                rotating_privkey.data,
                sizeof(rotating_privkey) - 1,
                unix_ts_s);
        REQUIRE(!result.success);
        REQUIRE(result.error_count > 0);
    }

    SECTION("session_pro_backend_add_pro_payment_request_to_json") {
        session_pro_backend_add_pro_payment_request request = {};
        request.version = 0;
        request.master_pkey = master_pubkey;
        request.rotating_pkey = rotating_pubkey;
        request.payment_token = payment_token_hash;

        // Note just write some junk to the request
        request.master_sig = master_privkey;
        request.rotating_sig = rotating_privkey;

        // Valid request
        auto result = session_pro_backend_add_pro_payment_request_to_json(&request);
        REQUIRE(result.success);
        REQUIRE(result.json.data != nullptr);
        REQUIRE(result.json.size > 0);

        // Verify JSON matches C++ implementation
        AddProPaymentRequest cpp = {};
        cpp.version = request.version;
        std::memcpy(cpp.master_pkey.data(), master_pubkey.data, sizeof(master_pubkey));
        std::memcpy(cpp.rotating_pkey.data(), rotating_pubkey.data, sizeof(rotating_pubkey));
        std::memcpy(cpp.payment_token.data(), payment_token_hash.data, sizeof(payment_token_hash));
        std::memcpy(cpp.master_sig.data(), master_privkey.data, sizeof(master_privkey));
        std::memcpy(cpp.rotating_sig.data(), rotating_privkey.data, sizeof(rotating_privkey));
        std::string cpp_json = cpp.to_json();
        REQUIRE(string8_equals(result.json, cpp_json));

        // Free memory
        session_pro_backend_to_json_free(&result);
        REQUIRE(result.json.data == nullptr);
        REQUIRE(result.json.size == 0);

        // Null request
        result = session_pro_backend_add_pro_payment_request_to_json(nullptr);
        REQUIRE(!result.success);
        REQUIRE(result.json.data == nullptr);
        REQUIRE(result.json.size == 0);
    }

    SECTION("session_pro_backend_get_pro_proof_request_to_json") {
        session_pro_backend_get_pro_proof_request request = {};
        request.version = 0;
        request.master_pkey = master_pubkey;
        request.rotating_pkey = rotating_pubkey;
        request.unix_ts_s = unix_ts_s;

        // Note just write some junk to the request
        request.master_sig = master_privkey;
        request.rotating_sig = rotating_privkey;

        // Valid request
        auto result = session_pro_backend_get_pro_proof_request_to_json(&request);
        REQUIRE(result.success);
        REQUIRE(result.json.data != nullptr);
        REQUIRE(result.json.size > 0);

        // Verify JSON matches C++ implementation
        GetProProofRequest cpp = {};
        cpp.version = request.version;
        std::memcpy(cpp.master_pkey.data(), master_pubkey.data, sizeof(master_pubkey));
        std::memcpy(cpp.rotating_pkey.data(), rotating_pubkey.data, sizeof(rotating_pubkey));
        cpp.unix_ts = std::chrono::seconds{unix_ts_s};
        std::memcpy(cpp.master_sig.data(), master_privkey.data, sizeof(master_privkey));
        std::memcpy(cpp.rotating_sig.data(), rotating_privkey.data, sizeof(rotating_privkey));
        std::string cpp_json = cpp.to_json();
        REQUIRE(string8_equals(result.json, cpp_json));

        // Free memory
        session_pro_backend_to_json_free(&result);
        REQUIRE(result.json.data == nullptr);
        REQUIRE(result.json.size == 0);

        // Null request
        result = session_pro_backend_get_pro_proof_request_to_json(nullptr);
        REQUIRE(!result.success);
        REQUIRE(result.json.data == nullptr);
        REQUIRE(result.json.size == 0);
    }

    SECTION("session_pro_backend_get_pro_revocations_request_to_json") {
        session_pro_backend_get_pro_revocations_request request = {};
        request.version = 0;
        request.ticket = 123;

        // Valid request
        auto result = session_pro_backend_get_pro_revocations_request_to_json(&request);
        REQUIRE(result.success);
        REQUIRE(result.json.data != nullptr);
        REQUIRE(result.json.size > 0);

        // Verify JSON matches C++ implementation
        GetProRevocationsRequest cpp = {};
        cpp.version = request.version;
        cpp.ticket = request.ticket;
        std::string cpp_json = cpp.to_json();
        REQUIRE(string8_equals(result.json, cpp_json));

        // Free memory
        session_pro_backend_to_json_free(&result);
        REQUIRE(result.json.data == nullptr);
        REQUIRE(result.json.size == 0);

        // Null request
        result = session_pro_backend_get_pro_revocations_request_to_json(nullptr);
        REQUIRE(!result.success);
        REQUIRE(result.json.data == nullptr);
        REQUIRE(result.json.size == 0);
    }

    SECTION("session_pro_backend_get_pro_payments_request_to_json") {
        session_pro_backend_get_pro_payments_request request = {};
        request.version = 0;
        request.master_pkey = master_pubkey;
        request.master_sig = master_privkey; // Write some junk
        request.unix_ts_s = unix_ts_s;
        request.page = 1;

        // Valid request
        auto result = session_pro_backend_get_pro_payments_request_to_json(&request);
        REQUIRE(result.success);
        REQUIRE(result.json.data != nullptr);
        REQUIRE(result.json.size > 0);

        // Verify JSON matches C++ implementation
        GetProPaymentsRequest cpp = {};
        cpp.version = 0;
        std::memcpy(cpp.master_pkey.data(), master_pubkey.data, sizeof(master_pubkey));
        std::memcpy(cpp.master_sig.data(), master_privkey.data, sizeof(master_privkey));
        cpp.unix_ts = std::chrono::sys_seconds{std::chrono::seconds{unix_ts_s}};
        cpp.page = request.page;
        std::string cpp_json = cpp.to_json();
        REQUIRE(string8_equals(result.json, cpp_json));

        // Free memory
        session_pro_backend_to_json_free(&result);
        REQUIRE(result.json.data == nullptr);
        REQUIRE(result.json.size == 0);

        // Null request
        result = session_pro_backend_get_pro_payments_request_to_json(nullptr);
        REQUIRE(!result.success);
        REQUIRE(result.json.data == nullptr);
        REQUIRE(result.json.size == 0);
    }

    SECTION("session_pro_backend_add_pro_payment_or_get_pro_proof_response_parse") {
        nlohmann::json j;
        j["status"] = SESSION_PRO_BACKEND_STATUS_SUCCESS;
        j["result"] = {
            {"version", 0},
            {"expiry_unix_ts_s", unix_ts_s},
            {"gen_index_hash", oxenc::to_hex(payment_token_hash.data)},
            {"rotating_pkey", oxenc::to_hex(rotating_pubkey.data)},
            {"sig", oxenc::to_hex(master_privkey.data)}
        };
        std::string json = j.dump();

        // Valid JSON
        auto result = session_pro_backend_add_pro_payment_or_get_pro_proof_response_parse(json.data(), json.size());
        for (size_t index = 0; index < result.header.errors_count; index++)
            INFO(result.header.errors[index].data);
        REQUIRE(result.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(result.header.errors_count == 0);
        REQUIRE(result.header.errors == nullptr);
        REQUIRE(result.expiry_unix_ts_s == unix_ts_s);
        REQUIRE(std::memcmp(result.gen_index_hash.data, payment_token_hash.data, sizeof(payment_token_hash)) == 0);
        REQUIRE(std::memcmp(result.rotating_pkey.data, rotating_pubkey.data, sizeof(rotating_pubkey)) == 0);
        REQUIRE(std::memcmp(result.sig.data, master_privkey.data, sizeof(master_privkey)) == 0);

        // Free memory
        session_pro_backend_add_pro_payment_or_get_pro_proof_response_free(&result);
        REQUIRE(result.header.internal_arena_buf_ == nullptr);
        REQUIRE(result.header.errors == nullptr);
        REQUIRE(result.header.errors_count == 0);

        // Invalid JSON
        json = "{invalid}";
        result = session_pro_backend_add_pro_payment_or_get_pro_proof_response_parse(json.data(), json.size());
        REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(result.header.errors_count > 0);
        REQUIRE(result.header.errors != nullptr);

        // Free memory
        session_pro_backend_add_pro_payment_or_get_pro_proof_response_free(&result);
        REQUIRE(result.header.internal_arena_buf_ == nullptr);

        // Null JSON
        result = session_pro_backend_add_pro_payment_or_get_pro_proof_response_parse(nullptr, 0);
        REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(result.header.errors_count == 1);
        REQUIRE(result.header.errors != nullptr);

        // No need to free, as errors point to static memory
    }

    SECTION("session_pro_backend_get_pro_revocations_response_parse") {
        nlohmann::json j;
        j["status"] = SESSION_PRO_BACKEND_STATUS_SUCCESS;
        j["result"] = {{"ticket", 123}, {"items", nlohmann::json::array()}};

        auto obj = nlohmann::json::object();
        obj["expiry_unix_ts_s"] = unix_ts_s;
        obj["gen_index_hash"] = oxenc::to_hex(payment_token_hash.data);
        j["result"]["items"].push_back(obj);

        std::string json = j.dump();

        // Valid JSON
        auto result = session_pro_backend_get_pro_revocations_response_parse(json.data(), json.size());
        for (size_t index = 0; index < result.header.errors_count; index++)
            INFO(result.header.errors[index].data);
        REQUIRE(result.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(result.header.errors_count == 0);
        REQUIRE(result.header.errors == nullptr);
        REQUIRE(result.ticket == 123);
        REQUIRE(result.items_count == 1);
        REQUIRE(result.items != nullptr);
        REQUIRE(result.items[0].expiry_unix_ts_s == unix_ts_s);
        REQUIRE(std::memcmp(
                        result.items[0].gen_index_hash.data,
                        payment_token_hash.data,
                        sizeof(payment_token_hash)) == 0);

        // Free memory
        session_pro_backend_get_pro_revocations_response_free(&result);
        REQUIRE(result.header.internal_arena_buf_ == nullptr);
        REQUIRE(result.items == nullptr);
        REQUIRE(result.items_count == 0);

        // Invalid JSON
        json = "{invalid}";
        result = session_pro_backend_get_pro_revocations_response_parse(json.data(), json.size());
        REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(result.header.errors_count > 0);
        REQUIRE(result.header.errors != nullptr);

        // Free memory
        session_pro_backend_get_pro_revocations_response_free(&result);
        REQUIRE(result.header.internal_arena_buf_ == nullptr);

        // Null JSON
        result = session_pro_backend_get_pro_revocations_response_parse(nullptr, 0);
        REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(result.header.errors_count == 1);
        REQUIRE(result.header.errors != nullptr);
    }

    SECTION("session_pro_backend_get_pro_payments_response_parse") {
        nlohmann::json j;
        j["status"] = SESSION_PRO_BACKEND_STATUS_SUCCESS;
        j["result"] = {
            {"pages", 2},
            {"payments", 10},
            {"items", nlohmann::json::array({
                {
                    {"activation_unix_ts_s", unix_ts_s},
                    {"archive_unix_ts_s", unix_ts_s + 3600},
                    {"creation_unix_ts_s", unix_ts_s - 3600},
                    {"subscription_duration_s", 86400},
                    {"payment_token_hash", oxenc::to_hex(payment_token_hash.data)}
                }
            })}
        };
        std::string json = j.dump();

        // Valid JSON
        auto result = session_pro_backend_get_pro_payments_response_parse(json.data(), json.size());
        for (size_t index = 0; index < result.header.errors_count; index++)
            INFO(result.header.errors[index].data);
        REQUIRE(result.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(result.header.errors_count == 0);
        REQUIRE(result.header.errors == nullptr);
        REQUIRE(result.pages == 2);
        REQUIRE(result.payments == 10);
        REQUIRE(result.items_count == 1);
        REQUIRE(result.items != nullptr);
        REQUIRE(result.items[0].activation_unix_ts_s == unix_ts_s);
        REQUIRE(result.items[0].archive_unix_ts_s == unix_ts_s + 3600);
        REQUIRE(result.items[0].creation_unix_ts_s == unix_ts_s - 3600);
        REQUIRE(result.items[0].subscription_duration == 86400);
        REQUIRE(std::memcmp(
                        result.items[0].payment_token_hash.data,
                        payment_token_hash.data,
                        sizeof(payment_token_hash)) == 0);

        // Free memory
        session_pro_backend_get_pro_payments_response_free(&result);
        REQUIRE(result.header.internal_arena_buf_ == nullptr);
        REQUIRE(result.items == nullptr);
        REQUIRE(result.items_count == 0);

        // Invalid JSON
        json = "{invalid}";
        result = session_pro_backend_get_pro_payments_response_parse(json.data(), json.size());
        REQUIRE(result.header.status != SESSION_PRO_BACKEND_STATUS_SUCCESS);
        REQUIRE(result.header.errors_count > 0);
        REQUIRE(result.header.errors != nullptr);

        // Free memory
        session_pro_backend_get_pro_payments_response_free(&result);
        REQUIRE(result.header.internal_arena_buf_ == nullptr);

        // Null JSON
        result = session_pro_backend_get_pro_payments_response_parse(nullptr, 0);
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

        session_pro_backend_add_pro_payment_or_get_pro_proof_response proof_response = {};
        session_pro_backend_add_pro_payment_or_get_pro_proof_response_free(&proof_response);
        REQUIRE(proof_response.header.internal_arena_buf_ == nullptr);

        session_pro_backend_get_pro_revocations_response rev_response = {};
        session_pro_backend_get_pro_revocations_response_free(&rev_response);
        REQUIRE(rev_response.header.internal_arena_buf_ == nullptr);

        session_pro_backend_get_pro_payments_response pay_response = {};
        session_pro_backend_get_pro_payments_response_free(&pay_response);
        REQUIRE(pay_response.header.internal_arena_buf_ == nullptr);
    }

#if defined(TEST_PRO_BACKEND_WITH_DEV_SERVER)
    SECTION("Send to local dev server") {
        const auto DEV_BACKEND_PUBKEY =
                "fc947730f49eb01427a66e050733294d9e520e545c7a27125a780634e0860a27"_hexbytes;

        // Setup CURL
        curl_global_init(CURL_GLOBAL_DEFAULT);

        CURL* curl = curl_easy_init();
        REQUIRE(curl);

        struct curl_slist* curl_headers =
                curl_slist_append(curl_headers, "Content-Type: application/json");
        REQUIRE(curl_headers);

        // Add pro payment
        {
            // Build request
            session_pro_backend_master_rotating_signatures add_pro_sigs =
                    session_pro_backend_add_pro_payment_request_build_sigs(
                            /*version*/ 0,
                            master_privkey.data,
                            sizeof(master_privkey),
                            rotating_privkey.data,
                            sizeof(rotating_privkey),
                            payment_token_hash.data,
                            sizeof(payment_token_hash),
                            unix_ts_s);

            session_pro_backend_add_pro_payment_request request = {};
            request.version = 0;
            request.master_pkey = master_pubkey;
            request.rotating_pkey = rotating_pubkey;
            request.payment_token = payment_token_hash;
            request.master_sig = add_pro_sigs.master_sig;
            request.rotating_sig = add_pro_sigs.rotating_sig;

            session_pro_backend_to_json request_json =
                    session_pro_backend_add_pro_payment_request_to_json(&request);

            // Build CURL request
            std::string response_json = {};
            curl_easy_reset(curl);
            curl_easy_setopt(curl, CURLOPT_POST, request_json.json.size);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_perform_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_json);
            curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:5000/add_pro_payment");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_json.json.data);

            // Dispatch
            CURLcode res = curl_easy_perform(curl);
            REQUIRE(res == CURLE_OK);

            // Parse response
            session_pro_backend_add_pro_payment_or_get_pro_proof_response response =
                    session_pro_backend_add_pro_payment_or_get_pro_proof_response_parse(
                            response_json.data(), response_json.size());
            for (size_t index = 0; index < response.header.errors_count; index++) {
                string8 error = response.header.errors[index];
                INFO("error: " << error.data);
            }

            // Verify response
            pro_proof proof = {};
            proof.version = response.version;
            proof.gen_index_hash = response.gen_index_hash;
            proof.rotating_pubkey = response.rotating_pkey;
            proof.expiry_unix_ts_s = response.expiry_unix_ts_s;
            proof.sig = response.sig;

            REQUIRE(pro_proof_verify_signature(
                    &proof, DEV_BACKEND_PUBKEY.data(), DEV_BACKEND_PUBKEY.size()));
            REQUIRE(std::memcmp(
                            response.rotating_pkey.data,
                            request.rotating_pkey.data,
                            sizeof(request.rotating_pkey)) == 0);

            session_pro_backend_to_json_free(&request_json);
            session_pro_backend_add_pro_payment_or_get_pro_proof_response_free(&response);
        }

        // Authorise new key
        {
            uint64_t now_unix_ts_s = time(nullptr);
            // Build request
            session_pro_backend_master_rotating_signatures pro_sigs =
                    session_pro_backend_get_pro_proof_request_build_sigs(
                            /*version*/ 0,
                            master_privkey.data,
                            sizeof(master_privkey),
                            rotating_privkey.data,
                            sizeof(rotating_privkey),
                            now_unix_ts_s);

            session_pro_backend_get_pro_proof_request request = {};
            request.version = 0;
            request.master_pkey = master_pubkey;
            request.rotating_pkey = rotating_pubkey;
            request.unix_ts_s = now_unix_ts_s;
            request.master_sig = pro_sigs.master_sig;
            request.rotating_sig = pro_sigs.rotating_sig;

            session_pro_backend_to_json request_json =
                    session_pro_backend_get_pro_proof_request_to_json(&request);

            // Build CURL request
            std::string response_json = {};
            curl_easy_reset(curl);
            curl_easy_setopt(curl, CURLOPT_POST, request_json.json.size);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_perform_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_json);
            curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:5000/get_pro_proof");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_json.json.data);

            // Dispatch
            CURLcode res = curl_easy_perform(curl);
            REQUIRE(res == CURLE_OK);

            // Parse response
            session_pro_backend_add_pro_payment_or_get_pro_proof_response response =
                    session_pro_backend_add_pro_payment_or_get_pro_proof_response_parse(
                            response_json.data(), response_json.size());
            for (size_t index = 0; index < response.header.errors_count; index++) {
                string8 error = response.header.errors[index];
                fprintf(stderr, "error: %s\n", error.data);
            }
            REQUIRE(response.header.errors_count == 0);
            REQUIRE(response.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);

            // Verify response
            pro_proof proof = {};
            proof.version = response.version;
            proof.gen_index_hash = response.gen_index_hash;
            proof.rotating_pubkey = response.rotating_pkey;
            proof.expiry_unix_ts_s = response.expiry_unix_ts_s;
            proof.sig = response.sig;

            REQUIRE(pro_proof_verify_signature(
                    &proof, DEV_BACKEND_PUBKEY.data(), DEV_BACKEND_PUBKEY.size()));
            REQUIRE(std::memcmp(
                            response.rotating_pkey.data,
                            request.rotating_pkey.data,
                            sizeof(request.rotating_pkey)) == 0);

            session_pro_backend_to_json_free(&request_json);
            session_pro_backend_add_pro_payment_or_get_pro_proof_response_free(&response);
        }

        // Get payment history
        {
            uint64_t now_unix_ts_s = time(nullptr);

            // Build request
            session_pro_backend_get_pro_payments_request request = {};
            request.version = 0;
            request.master_pkey = master_pubkey;
            request.unix_ts_s = now_unix_ts_s;
            request.page = 0;

            session_pro_backend_signature sig =
                    session_pro_backend_get_pro_payments_request_build_sig(
                            request.version,
                            master_privkey.data,
                            sizeof(master_privkey.data),
                            request.unix_ts_s,
                            request.page);
            REQUIRE(sig.success);

            request.master_sig = sig.sig;

            session_pro_backend_to_json request_json =
                    session_pro_backend_get_pro_payments_request_to_json(&request);

            // Build CURL request
            std::string response_json = {};
            curl_easy_reset(curl);
            curl_easy_setopt(curl, CURLOPT_POST, request_json.json.size);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_perform_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_json);
            curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:5000/get_pro_payments");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_json.json.data);

            // Dispatch
            CURLcode res = curl_easy_perform(curl);
            REQUIRE(res == CURLE_OK);

            // Parse response
            session_pro_backend_get_pro_payments_response response =
                    session_pro_backend_get_pro_payments_response_parse(
                            response_json.data(), response_json.size());
            for (size_t index = 0; index < response.header.errors_count; index++) {
                string8 error = response.header.errors[index];
                fprintf(stderr, "error: %s\n", error.data);
            }

            // Verify the response
            REQUIRE(response.header.errors_count == 0);
            REQUIRE(response.header.status == SESSION_PRO_BACKEND_STATUS_SUCCESS);
            REQUIRE(response.pages == 0);
            REQUIRE(response.payments > 0);
            REQUIRE(response.items_count > 0);
            for (size_t index = 0; index < response.items_count; index++) {
                const session_pro_backend_pro_payment_item& payment = response.items[index];
                dump_pro_payment_item(payment);
            }

            session_pro_backend_to_json_free(&request_json);
            session_pro_backend_get_pro_payments_response_free(&response);
        }

        // Cleanup CURL
        curl_slist_free_all(curl_headers);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
    }
#endif
}
