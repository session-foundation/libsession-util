#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/session_encrypt.hpp>
#include <session/session_protocol.hpp>
#include <session/random.hpp>
#include <session/config/pro.hpp>
#include <session/pro_backend.hpp>
#include "SessionProtos.pb.h"

#include "utils.hpp"

using namespace session;

TEST_CASE("Session protocol helpers", "[session-protocol][helpers]") {

    using namespace session;
    TestKeys keys = get_deterministic_test_keys();

    // Tuesday, 12 August 2025 03:58:21 UTC
    const std::chrono::milliseconds timestamp_ms = std::chrono::seconds(1754971101);
    const std::string_view data_body = "hello";

    SECTION("Encrypt with and w/o pro sig produce same payload size") {
        // Same payload size because the encrypt function should put in a dummy signature if one
        // wasn't specific to make pro and non-pro envelopes indistinguishable.

        session::Destination dest = {};
        dest.type = DestinationType::Contact;
        dest.sent_timestamp_ms = timestamp_ms;
        dest.recipient_pubkey = keys.session_pk1;

        // Withhold the pro signature
        dest.pro_sig = std::nullopt;
        EncryptedForDestination encrypt_without_pro_sig = encrypt_for_destination(
                to_span(data_body), keys.ed_sk0, dest, config::Namespace::Default);

        // Set the pro signature
        dest.pro_sig.emplace();
        EncryptedForDestination encrypt_with_pro_sig = encrypt_for_destination(
                to_span(data_body), keys.ed_sk0, dest, config::Namespace::Default);

        REQUIRE(encrypt_without_pro_sig.encrypted);
        REQUIRE(encrypt_with_pro_sig.encrypted);

        // Should have the same payload size
        REQUIRE(encrypt_without_pro_sig.ciphertext.size() == encrypt_with_pro_sig.ciphertext.size());
    }

    SECTION("Encrypt/decrypt for contact in default namespace") {
        // Build content
        std::string plaintext;
        {
            SessionProtos::Content content = {};
            SessionProtos::DataMessage* data = content.mutable_datamessage();
            data->set_body(std::string(data_body));
            plaintext = content.SerializeAsString();
            REQUIRE(plaintext.size() > data_body.size());
        }

        // Encrypt
        EncryptedForDestination encrypt_result = {};
        {
            session::Destination dest = {};
            dest.type = DestinationType::Contact;
            dest.sent_timestamp_ms = timestamp_ms;
            REQUIRE(dest.recipient_pubkey.size() == keys.session_pk1.size());
            std::memcpy(dest.recipient_pubkey.data(), keys.session_pk1.data(), keys.session_pk1.size());

            encrypt_result = session::encrypt_for_destination(
                    to_span(plaintext), keys.ed_sk0, dest, config::Namespace::Default);
            REQUIRE(encrypt_result.encrypted);
        }

        // Decrypt envelope
        DecryptedEnvelope decrypt_result = session::decrypt_envelope(
                keys.ed_sk1,
                encrypt_result.ciphertext,
                std::chrono::sys_seconds(
                        std::chrono::duration_cast<std::chrono::seconds>(timestamp_ms)), pro_backend::PUBKEY);

        // Verify pro
        config::ProProof nil_proof = {};
        REQUIRE(decrypt_result.pro_status == ProStatus::Nil); // Pro was not attached
        REQUIRE(decrypt_result.pro_features == PRO_FEATURES_NIL);
        REQUIRE(decrypt_result.pro_proof.hash() == nil_proof.hash());

        // Verify it is decryptable
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data(), decrypt_result.content_plaintext.size()));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == data_body);
    }

    SECTION("Ensure get pro fetaures detects large message") {
        // Try a message below the size threshold
        PRO_FEATURES features = get_pro_features_for_msg(
                PRO_STANDARD_CHARACTER_LIMIT,
                PRO_EXTRA_FEATURES_PRO_BADGE | PRO_EXTRA_FEATURES_ANIMATED_AVATAR);
        REQUIRE(features == (PRO_FEATURES_PRO_BADGE | PRO_FEATURES_ANIMATED_AVATAR));

        // Try a message exceeding the size threshold
        features = get_pro_features_for_msg(
                PRO_STANDARD_CHARACTER_LIMIT + 1,
                PRO_EXTRA_FEATURES_PRO_BADGE | PRO_EXTRA_FEATURES_ANIMATED_AVATAR);
        REQUIRE(features == (PRO_FEATURES_10K_CHARACTER_LIMIT | PRO_FEATURES_PRO_BADGE |
                             PRO_FEATURES_ANIMATED_AVATAR));

        // Try asking for just one extra feature
        features = get_pro_features_for_msg(100, PRO_EXTRA_FEATURES_PRO_BADGE);
        REQUIRE(features == PRO_FEATURES_PRO_BADGE);
    }

    // Prepare a Session Pro proof
    // We reuse test key 1 as the "Session Pro" backend key that signs the proofs as it
    // doesn't matter what key really, just that we have one for signing.
    const array_uc64& pro_backend_ed_sk = keys.ed_sk1;
    const array_uc32& pro_backend_ed_pk = keys.ed_pk1;

    // Generate the user's Session Pro rotating key for testing encrypted payloads with Session
    // Pro metadata
    const auto user_pro_seed =
            "0123456789abcdef0123456789abcdeff00baa00000000000000000000000000"_hexbytes;
    array_uc32 user_pro_ed_pk;
    array_uc64 user_pro_ed_sk;
    crypto_sign_ed25519_seed_keypair(
            user_pro_ed_pk.data(), user_pro_ed_sk.data(), user_pro_seed.data());

    // Build protobuf `Content` message, serialise to `plaintext` and get it signed by the user's
    // "Session Pro" key into `sig_over_plaintext_with_user_pro_key`
    std::string plaintext;
    array_uc64 sig_over_plaintext_with_user_pro_key = {};
    array_uc32 pro_proof_hash = {};
    {
        SessionProtos::Content content = {};

        // Create protobuf `Content.dataMessage`
        SessionProtos::DataMessage* data = content.mutable_datamessage();
        data->set_body(std::string(data_body));

        // Generate a dummy proof
        config::ProProof proof = {};
        proof.rotating_pubkey = user_pro_ed_pk;
        proof.expiry_unix_ts = std::chrono::sys_seconds(
                std::chrono::duration_cast<std::chrono::seconds>(timestamp_ms));

        // Sign the proof by the dummy "Session Pro Backend" key
        pro_proof_hash = proof.hash();
        crypto_sign_ed25519_detached(
                proof.sig.data(),
                nullptr,
                pro_proof_hash.data(),
                pro_proof_hash.size(),
                pro_backend_ed_sk.data());

        // Create protobuf `Content.proMessage`
        SessionProtos::ProMessage *pro = content.mutable_promessage();
        pro->set_flags(PRO_FEATURES_NIL);

        // Create protobuf `Content.proMessage.proof`
        SessionProtos::ProProof *proto_proof = pro->mutable_proof();
        proto_proof->set_version(proof.version);
        proto_proof->set_genindexhash(proof.gen_index_hash.data(), proof.gen_index_hash.size());
        proto_proof->set_rotatingpublickey(proof.rotating_pubkey.data(), proof.rotating_pubkey.size());
        proto_proof->set_expiryunixts(proof.expiry_unix_ts.time_since_epoch().count());
        proto_proof->set_sig(proof.sig.data(), proof.sig.size());

        // Generate the plaintext
        plaintext = content.SerializeAsString();
        REQUIRE(plaintext.size() > data_body.size());

        // Sign the plaintext with the user's pro key
        crypto_sign_ed25519_detached(
                sig_over_plaintext_with_user_pro_key.data(),
                nullptr,
                reinterpret_cast<uint8_t*>(plaintext.data()),
                plaintext.size(),
                user_pro_ed_sk.data());
    }

    SECTION("Encrypt/decrypt for contact in default namespace with Pro") {
        // Build content
        std::string plaintext;
        array_uc64 sig_over_plaintext_with_user_pro_key = {};
        array_uc32 pro_proof_hash = {};
        {
            SessionProtos::Content content = {};

            // Create protobuf `Content.dataMessage`
            SessionProtos::DataMessage* data = content.mutable_datamessage();
            data->set_body(std::string(data_body));

            // Generate a dummy proof
            config::ProProof proof = {};
            proof.rotating_pubkey = user_pro_ed_pk;
            proof.expiry_unix_ts = std::chrono::sys_seconds(
                    std::chrono::duration_cast<std::chrono::seconds>(timestamp_ms));

            // Sign the proof by the dummy "Session Pro Backend" key
            pro_proof_hash = proof.hash();
            crypto_sign_ed25519_detached(
                    proof.sig.data(),
                    nullptr,
                    pro_proof_hash.data(),
                    pro_proof_hash.size(),
                    pro_backend_ed_sk.data());

            // Create protobuf `Content.proMessage`
            SessionProtos::ProMessage *pro = content.mutable_promessage();
            pro->set_flags(PRO_FEATURES_NIL);

            // Create protobuf `Content.proMessage.proof`
            SessionProtos::ProProof *proto_proof = pro->mutable_proof();
            proto_proof->set_version(proof.version);
            proto_proof->set_genindexhash(proof.gen_index_hash.data(), proof.gen_index_hash.size());
            proto_proof->set_rotatingpublickey(proof.rotating_pubkey.data(), proof.rotating_pubkey.size());
            proto_proof->set_expiryunixts(proof.expiry_unix_ts.time_since_epoch().count());
            proto_proof->set_sig(proof.sig.data(), proof.sig.size());

            // Generate the plaintext
            plaintext = content.SerializeAsString();
            REQUIRE(plaintext.size() > data_body.size());

            // Sign the plaintext with the user's pro key
            crypto_sign_ed25519_detached(
                    sig_over_plaintext_with_user_pro_key.data(),
                    nullptr,
                    reinterpret_cast<uint8_t*>(plaintext.data()),
                    plaintext.size(),
                    user_pro_ed_sk.data());
        }

        // Encrypt
        EncryptedForDestination encrypt_result = {};
        {
            session::Destination dest = {};
            dest.type = DestinationType::Contact;
            dest.sent_timestamp_ms = timestamp_ms;
            dest.pro_sig = sig_over_plaintext_with_user_pro_key;
            REQUIRE(dest.recipient_pubkey.size() == keys.session_pk1.size());
            std::memcpy(dest.recipient_pubkey.data(), keys.session_pk1.data(), keys.session_pk1.size());

            encrypt_result = session::encrypt_for_destination(
                    to_span(plaintext), keys.ed_sk0, dest, config::Namespace::Default);
            REQUIRE(encrypt_result.encrypted);
        }

        // Decrypt envelope
        DecryptedEnvelope decrypt_result = session::decrypt_envelope(
                keys.ed_sk1,
                encrypt_result.ciphertext,
                std::chrono::sys_seconds(
                        std::chrono::duration_cast<std::chrono::seconds>(timestamp_ms)),
                pro_backend_ed_pk);

        // Verify pro
        REQUIRE(decrypt_result.pro_status == ProStatus::Valid); // Pro was attached
        REQUIRE(decrypt_result.pro_proof.hash() == pro_proof_hash);
        REQUIRE(decrypt_result.pro_features == PRO_FEATURES_NIL); // No features requested

        // Verify it is decryptable
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data(), decrypt_result.content_plaintext.size()));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == data_body);
    }

    SECTION("Check non-encryptable messages produce plaintext") {
        auto dest_list = {
                DestinationType::OpenGroup,
                DestinationType::OpenGroupInbox,
                DestinationType::Contact};

        for (auto dest_type : dest_list) {
            if (dest_type == DestinationType::OpenGroup)
                INFO("Trying open groups");
            else if (dest_type == DestinationType::OpenGroupInbox)
                INFO("Trying open group inbox");
            else
                INFO("Trying contacts to non-default namespace");

            session::Destination dest = {};
            dest.type = dest_type;
            dest.sent_timestamp_ms = timestamp_ms;
            dest.pro_sig = sig_over_plaintext_with_user_pro_key;
            REQUIRE(dest.recipient_pubkey.size() == keys.session_pk1.size());
            std::memcpy(
                    dest.recipient_pubkey.data(), keys.session_pk1.data(), keys.session_pk1.size());

            config::Namespace space = config::Namespace::Default;
            if (dest_type == DestinationType::Contact) {
                space = config::Namespace::Contacts;
                dest.recipient_pubkey[0] = 0x15;
            }

            EncryptedForDestination encrypt_result =
                    session::encrypt_for_destination(to_span(plaintext), keys.ed_sk0, dest, space);
            REQUIRE_FALSE(encrypt_result.encrypted);
            REQUIRE(encrypt_result.ciphertext.empty());
        }
    }


    SECTION("Encrypt/decrypt for legacy closed group (w/ encrypted envelope, plaintext content) "
            "with Pro") {

        // Encrypt
        EncryptedForDestination encrypt_result = {};
        {
            session::Destination dest = {};
            dest.type = DestinationType::ClosedGroup;
            dest.sent_timestamp_ms = timestamp_ms;
            dest.pro_sig = sig_over_plaintext_with_user_pro_key;
            REQUIRE(dest.recipient_pubkey.size() == keys.session_pk1.size());
            std::memcpy(dest.recipient_pubkey.data(), keys.session_pk1.data(), keys.session_pk1.size());

            encrypt_result = session::encrypt_for_destination(
                    to_span(plaintext), keys.ed_sk0, dest, config::Namespace::Default);
            REQUIRE(encrypt_result.encrypted);
        }

        // Decrypt envelope
        DecryptedEnvelope decrypt_result = session::decrypt_envelope(
                keys.ed_sk1,
                encrypt_result.ciphertext,
                std::chrono::sys_seconds(
                        std::chrono::duration_cast<std::chrono::seconds>(timestamp_ms)),
                pro_backend_ed_pk);

        // Verify pro
        REQUIRE(decrypt_result.pro_status == ProStatus::Valid); // Pro was attached
        REQUIRE(decrypt_result.pro_proof.hash() == pro_proof_hash);
        REQUIRE(decrypt_result.pro_features == PRO_FEATURES_NIL); // No features requested

        // Verify it is decryptable
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data(), decrypt_result.content_plaintext.size()));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == data_body);
    }

    SECTION("Encrypt/decrypt for sync messages with Pro") {

        // Encrypt
        EncryptedForDestination encrypt_result = {};
        {
            session::Destination dest = {};
            dest.type = DestinationType::SyncMessage;
            dest.sent_timestamp_ms = timestamp_ms;
            dest.pro_sig = sig_over_plaintext_with_user_pro_key;
            REQUIRE(dest.recipient_pubkey.size() == keys.session_pk1.size());
            std::memcpy(dest.recipient_pubkey.data(), keys.session_pk1.data(), keys.session_pk1.size());

            encrypt_result = session::encrypt_for_destination(
                    to_span(plaintext), keys.ed_sk0, dest, config::Namespace::Default);
            REQUIRE(encrypt_result.encrypted);
        }

        // Decrypt envelope
        DecryptedEnvelope decrypt_result = session::decrypt_envelope(
                keys.ed_sk1,
                encrypt_result.ciphertext,
                std::chrono::sys_seconds(
                        std::chrono::duration_cast<std::chrono::seconds>(timestamp_ms)),
                pro_backend_ed_pk);

        // Verify pro
        REQUIRE(decrypt_result.pro_status == ProStatus::Valid); // Pro was attached
        REQUIRE(decrypt_result.pro_proof.hash() == pro_proof_hash);
        REQUIRE(decrypt_result.pro_features == PRO_FEATURES_NIL); // No features requested

        // Verify it is decryptable
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data(), decrypt_result.content_plaintext.size()));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == data_body);
    }
}
