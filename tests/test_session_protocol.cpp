#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/blinding.hpp>
#include <session/config/groups/info.hpp>
#include <session/config/groups/keys.hpp>
#include <session/config/groups/members.hpp>
#include <session/config/pro.hpp>
#include <session/pro_backend.hpp>
#include <session/random.hpp>
#include <session/session_encrypt.hpp>
#include <session/session_protocol.hpp>

#include "SessionProtos.pb.h"
#include "WebSocketResources.pb.h"
#include "utils.hpp"

using namespace session;

struct SerialisedProtobufContentWithProForTesting {
    config::ProProof proof;
    std::string plaintext;
    array_uc64 sig_over_plaintext_with_user_pro_key;
    array_uc32 pro_proof_hash;
};

static SerialisedProtobufContentWithProForTesting build_protobuf_content_with_session_pro(
        std::string_view data_body,
        const array_uc64& user_rotating_privkey,
        const array_uc64& pro_backend_privkey,
        std::chrono::sys_seconds pro_expiry_unix_ts,
        PRO_FEATURES features) {
    SerialisedProtobufContentWithProForTesting result = {};

    // Create protobuf `Content.dataMessage`
    SessionProtos::Content content = {};
    SessionProtos::DataMessage* data = content.mutable_datamessage();
    data->set_body(std::string(data_body));

    // Generate a dummy proof
    crypto_sign_ed25519_sk_to_pk(result.proof.rotating_pubkey.data(), user_rotating_privkey.data());
    result.proof.expiry_unix_ts = pro_expiry_unix_ts;

    // Sign the proof by the dummy "Session Pro Backend" key
    result.pro_proof_hash = result.proof.hash();
    crypto_sign_ed25519_detached(
            result.proof.sig.data(),
            nullptr,
            result.pro_proof_hash.data(),
            result.pro_proof_hash.size(),
            pro_backend_privkey.data());

    // Create protobuf `Content.proMessage`
    SessionProtos::ProMessage* pro = content.mutable_promessage();
    pro->set_features(features);

    // Create protobuf `Content.proMessage.proof`
    SessionProtos::ProProof* proto_proof = pro->mutable_proof();
    proto_proof->set_version(result.proof.version);
    proto_proof->set_genindexhash(
            result.proof.gen_index_hash.data(), result.proof.gen_index_hash.size());
    proto_proof->set_rotatingpublickey(
            result.proof.rotating_pubkey.data(), result.proof.rotating_pubkey.size());
    proto_proof->set_expiryunixts(result.proof.expiry_unix_ts.time_since_epoch().count());
    proto_proof->set_sig(result.proof.sig.data(), result.proof.sig.size());

    // Generate the plaintext
    result.plaintext = content.SerializeAsString();
    REQUIRE(result.plaintext.size() > data_body.size());

    // Sign the plaintext with the user's pro key
    crypto_sign_ed25519_detached(
            result.sig_over_plaintext_with_user_pro_key.data(),
            nullptr,
            reinterpret_cast<uint8_t*>(result.plaintext.data()),
            result.plaintext.size(),
            user_rotating_privkey.data());

    return result;
}

TEST_CASE("Session protocol helpers", "[session-protocol][helpers]") {

    // Do tests that require no setup
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

    // Tests that require some setup code
    using namespace session;
    TestKeys keys = get_deterministic_test_keys();

    // Tuesday, 12 August 2025 03:58:21 UTC
    const std::chrono::milliseconds timestamp_ms = std::chrono::seconds(1754971101);
    const std::chrono::sys_seconds timestamp_s = std::chrono::sys_seconds(
            std::chrono::duration_cast<std::chrono::seconds>(timestamp_ms));
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
        REQUIRE(encrypt_without_pro_sig.ciphertext.size() ==
                encrypt_with_pro_sig.ciphertext.size());
    }

    // Setup a dummy "Session Pro Backend" key
    // We reuse test key 1 as the "Session Pro" backend key that signs the proofs as it
    // doesn't matter what key really, just that we have one available for signing.
    const array_uc64& pro_backend_ed_sk = keys.ed_sk1;
    const array_uc32& pro_backend_ed_pk = keys.ed_pk1;

    SECTION("Encrypt/decrypt for contact in default namespace w/o pro attached") {
        // Build content without pro attached
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
            std::memcpy(
                    dest.recipient_pubkey.data(), keys.session_pk1.data(), keys.session_pk1.size());

            encrypt_result = session::encrypt_for_destination(
                    to_span(plaintext), keys.ed_sk0, dest, config::Namespace::Default);
            REQUIRE(encrypt_result.encrypted);
        }

        // Decrypt envelope
        std::span<const uint8_t> key = keys.ed_sk1;
        DecryptEnvelopeKey decrypt_keys = {};
        decrypt_keys.ed25519_privkeys = {&key, 1};
        DecryptedEnvelope decrypt_result = session::decrypt_envelope(
                decrypt_keys, encrypt_result.ciphertext, timestamp_s, pro_backend_ed_pk);

        // Verify pro
        config::ProProof nil_proof = {};
        REQUIRE(decrypt_result.pro_status == ProStatus::Nil);  // Pro was not attached
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
    SerialisedProtobufContentWithProForTesting protobuf_content_with_pro =
            build_protobuf_content_with_session_pro(
                    /*data_body*/ data_body,
                    /*user_rotating_privkey*/ user_pro_ed_sk,
                    /*pro_backend_privkey*/ pro_backend_ed_sk,
                    /*pro_expiry_unix_ts*/ timestamp_s,
                    PRO_FEATURES_NIL);

    // Setup base destination object with the pro signature w/ Session pubkey 1 as the recipient
    session::Destination base_dest = {};
    base_dest.sent_timestamp_ms = timestamp_ms;
    base_dest.pro_sig = protobuf_content_with_pro.sig_over_plaintext_with_user_pro_key;
    REQUIRE(base_dest.recipient_pubkey.size() == keys.session_pk1.size());
    std::memcpy(
            base_dest.recipient_pubkey.data(), keys.session_pk1.data(), keys.session_pk1.size());

    SECTION("Check non-encryptable messages produce only plaintext") {
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

            session::Destination dest = base_dest;
            dest.type = dest_type;

            config::Namespace space = config::Namespace::Default;
            if (dest_type == DestinationType::Contact) {
                space = config::Namespace::Contacts;
            } else if (dest_type == DestinationType::OpenGroupInbox) {
                auto [blind15_pk, blind15_sk] = session::blind15_key_pair(
                        keys.ed_sk1, keys.ed_pk1, /*blind factor*/ nullptr);
                dest.recipient_pubkey[0] = 0x15;
                std::memcpy(dest.recipient_pubkey.data() + 1, blind15_pk.data(), blind15_pk.size());
            }

            EncryptedForDestination encrypt_result = session::encrypt_for_destination(
                    to_span(protobuf_content_with_pro.plaintext), keys.ed_sk0, dest, space);

            if (dest_type == DestinationType::OpenGroupInbox) {
                REQUIRE(encrypt_result.encrypted);
                REQUIRE(encrypt_result.ciphertext.size());
            } else {
                REQUIRE_FALSE(encrypt_result.encrypted);
                REQUIRE(encrypt_result.ciphertext.empty());
            }
        }
    }

    SECTION("Encrypt/decrypt for contact in default namespace with Pro") {
        // Encrypt content
        EncryptedForDestination encrypt_result = {};
        {
            session::Destination dest = base_dest;
            dest.type = DestinationType::Contact;
            encrypt_result = session::encrypt_for_destination(
                    to_span(protobuf_content_with_pro.plaintext),
                    keys.ed_sk0,
                    dest,
                    config::Namespace::Default);
            REQUIRE(encrypt_result.encrypted);
        }

        // Decrypt envelope
        std::span<const uint8_t> key = keys.ed_sk1;
        DecryptEnvelopeKey decrypt_keys = {};
        decrypt_keys.ed25519_privkeys = {&key, 1};
        DecryptedEnvelope decrypt_result = session::decrypt_envelope(
                decrypt_keys, encrypt_result.ciphertext, timestamp_s, pro_backend_ed_pk);

        // Verify pro
        REQUIRE(decrypt_result.pro_status == ProStatus::Valid);  // Pro was attached
        REQUIRE(decrypt_result.pro_proof.hash() == protobuf_content_with_pro.pro_proof_hash);
        REQUIRE(decrypt_result.pro_features == PRO_FEATURES_NIL);  // No features requested

        // Verify the content can be parsed w/ protobufs
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data(), decrypt_result.content_plaintext.size()));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == data_body);
    }

    SECTION("Encrypt/decrypt for contact in default namespace with Pro + features") {

        std::string large_message;
        large_message.resize(PRO_STANDARD_CHARACTER_LIMIT + 1);

        PRO_FEATURES features =
                get_pro_features_for_msg(large_message.size(), PRO_EXTRA_FEATURES_PRO_BADGE);
        REQUIRE(features == (PRO_FEATURES_10K_CHARACTER_LIMIT | PRO_FEATURES_PRO_BADGE));

        SerialisedProtobufContentWithProForTesting protobuf_content_with_pro_and_features =
                build_protobuf_content_with_session_pro(
                        /*data_body*/ large_message,
                        /*user_rotating_privkey*/ user_pro_ed_sk,
                        /*pro_backend_privkey*/ pro_backend_ed_sk,
                        /*pro_expiry_unix_ts*/ timestamp_s,
                        features);

        // Encrypt content
        EncryptedForDestination encrypt_result = {};
        {
            session::Destination dest = base_dest;
            dest.type = DestinationType::Contact;
            dest.pro_sig =
                    protobuf_content_with_pro_and_features.sig_over_plaintext_with_user_pro_key;
            encrypt_result = session::encrypt_for_destination(
                    to_span(protobuf_content_with_pro_and_features.plaintext),
                    keys.ed_sk0,
                    dest,
                    config::Namespace::Default);
            REQUIRE(encrypt_result.encrypted);
        }

        // Decrypt envelope
        std::span<const uint8_t> key = keys.ed_sk1;
        DecryptEnvelopeKey decrypt_keys = {};
        decrypt_keys.ed25519_privkeys = {&key, 1};
        DecryptedEnvelope decrypt_result = session::decrypt_envelope(
                decrypt_keys, encrypt_result.ciphertext, timestamp_s, pro_backend_ed_pk);

        // Verify pro
        REQUIRE(decrypt_result.pro_status == ProStatus::Valid);  // Pro was attached
        REQUIRE(decrypt_result.pro_proof.hash() ==
                protobuf_content_with_pro_and_features.pro_proof_hash);
        REQUIRE(decrypt_result.pro_features ==
                (PRO_FEATURES_10K_CHARACTER_LIMIT | PRO_FEATURES_PRO_BADGE));

        // Verify the content can be parsed w/ protobufs
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data(), decrypt_result.content_plaintext.size()));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == large_message);
    }

    SECTION("Encrypt/decrypt for legacy groups (w/ encrypted envelope, plaintext content) with "
            "Pro") {
        // Encrypt
        EncryptedForDestination encrypt_result = {};
        {
            Destination dest = base_dest;
            dest.type = DestinationType::ClosedGroup;
            assert(dest.recipient_pubkey[0] == 0x05);

            encrypt_result = session::encrypt_for_destination(
                    to_span(protobuf_content_with_pro.plaintext),
                    keys.ed_sk0,
                    dest,
                    config::Namespace::Default);
            REQUIRE(encrypt_result.encrypted);
        }

        // Legacy groups wrap in websocket message
        WebSocketProtos::WebSocketMessage ws_msg;
        REQUIRE(ws_msg.ParseFromArray(
                encrypt_result.ciphertext.data(), encrypt_result.ciphertext.size()));
        REQUIRE(ws_msg.has_request());
        REQUIRE(ws_msg.request().has_body());

        // Decrypt envelope
        std::span<const uint8_t> key = keys.ed_sk1;
        DecryptEnvelopeKey decrypt_keys = {};
        decrypt_keys.ed25519_privkeys = {&key, 1};
        DecryptedEnvelope decrypt_result = session::decrypt_envelope(
                decrypt_keys, to_span(ws_msg.request().body()), timestamp_s, pro_backend_ed_pk);

        // Verify pro
        REQUIRE(decrypt_result.pro_status == ProStatus::Valid);  // Pro was attached
        REQUIRE(decrypt_result.pro_proof.hash() == protobuf_content_with_pro.pro_proof_hash);
        REQUIRE(decrypt_result.pro_features == PRO_FEATURES_NIL);  // No features requested

        // Verify the content can be parsed w/ protobufs
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data(), decrypt_result.content_plaintext.size()));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == data_body);
    }

    SECTION("Encrypt/decrypt for groups v2 (w/ encrypted envelope, plaintext content) with Pro") {
        // TODO: Finish setting up a fake group
        const auto group_v2_seed =
                "0123456789abcdef0123456789abcdeff00baadeadb33f000000000000000000"_hexbytes;
        array_uc64 group_v2_sk = {};
        array_uc32 group_v2_pk = {};
        crypto_sign_ed25519_seed_keypair(
                group_v2_pk.data(), group_v2_sk.data(), group_v2_seed.data());

        auto group_v2_info = config::groups::Info(group_v2_pk, group_v2_sk, std::nullopt);
        auto group_v2_members = config::groups::Members(group_v2_pk, group_v2_sk, std::nullopt);
        auto group_v2_keys = config::groups::Keys(
                keys.ed_sk0,
                group_v2_pk,
                group_v2_sk,
                std::nullopt,
                group_v2_info,
                group_v2_members);

        // Encrypt
#if 0
        EncryptedForDestination encrypt_result = {};
        {
            Destination dest = base_dest;
            dest.type = DestinationType::ClosedGroup;
            dest.closed_group_pubkey[0] = 0x03;
            std::memcpy(dest.closed_group_pubkey.data() + 1, group_v2_pk.data(), group_v2_pk.size());
            dest.closed_group_keys = &group_v2_keys;

            encrypt_result = session::encrypt_for_destination(
                    to_span(protobuf_content_with_pro.plaintext),
                    keys.ed_sk0,
                    dest,
                    config::Namespace::GroupMessages);
            REQUIRE(encrypt_result.encrypted);
        }

        // Decrypt envelope
        DecryptEnvelopeKey decrypt_keys = {};
        decrypt_keys.use_group_keys = true;
        decrypt_keys.group_keys = &group_v2_keys;

        // TODO: Finish setting up a group so we can check the decrypted result for now this will
        // throw because the keys aren't setup correctly.
        CHECK_THROWS(session::decrypt_envelope(
                decrypt_keys, encrypt_result.ciphertext, timestamp_s, pro_backend_ed_pk));
#endif
    }

    SECTION("Encrypt/decrypt for sync messages with Pro") {
        // Encrypt
        EncryptedForDestination encrypt_result = {};
        {
            session::Destination dest = base_dest;
            dest.type = DestinationType::SyncMessage;
            encrypt_result = session::encrypt_for_destination(
                    to_span(protobuf_content_with_pro.plaintext),
                    keys.ed_sk0,
                    dest,
                    config::Namespace::Default);
            REQUIRE(encrypt_result.encrypted);
        }

        // Decrypt envelope
        std::span<const uint8_t> key = keys.ed_sk1;
        DecryptEnvelopeKey decrypt_keys = {};
        decrypt_keys.ed25519_privkeys = {&key, 1};
        DecryptedEnvelope decrypt_result = session::decrypt_envelope(
                decrypt_keys, encrypt_result.ciphertext, timestamp_s, pro_backend_ed_pk);

        // Verify pro
        REQUIRE(decrypt_result.pro_status == ProStatus::Valid);  // Pro was attached
        REQUIRE(decrypt_result.pro_proof.hash() == protobuf_content_with_pro.pro_proof_hash);
        REQUIRE(decrypt_result.pro_features == PRO_FEATURES_NIL);  // No features requested

        // Verify the content can be parsed w/ protobufs
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data(), decrypt_result.content_plaintext.size()));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == data_body);

        // Try decrypt with a timestamp past the pro proof expiry date
        DecryptedEnvelope decrypt_result_again = session::decrypt_envelope(
                decrypt_keys,
                encrypt_result.ciphertext,
                protobuf_content_with_pro.proof.expiry_unix_ts + std::chrono::seconds(1),
                pro_backend_ed_pk);
        REQUIRE(decrypt_result_again.pro_status == ProStatus::Expired);

        // Try decrypt with a bad backend key
        array_uc32 bad_pro_backend_ed_pk = pro_backend_ed_pk;
        bad_pro_backend_ed_pk[0] ^= 1;
        decrypt_result_again = session::decrypt_envelope(
                decrypt_keys,
                encrypt_result.ciphertext,
                protobuf_content_with_pro.proof.expiry_unix_ts,
                bad_pro_backend_ed_pk);
        REQUIRE(decrypt_result_again.pro_status == ProStatus::InvalidProBackendSig);

        // Try decrypt with bad key (ed_sk0 which was the sender; ed_sk1 the recipient)
        std::span<const uint8_t> bad_key = keys.ed_sk0;
        DecryptEnvelopeKey bad_decrypt_keys = {};
        decrypt_keys.ed25519_privkeys = {&bad_key, 1};
        REQUIRE_THROWS(
                session::decrypt_envelope(
                        bad_decrypt_keys,
                        encrypt_result.ciphertext,
                        protobuf_content_with_pro.proof.expiry_unix_ts,
                        pro_backend_ed_pk));

        // Try decrypt with multiple keys, 1 bad, 1 good key
        auto key_list = std::array{bad_key, key};
        DecryptEnvelopeKey multi_decrypt_keys = {};
        multi_decrypt_keys.ed25519_privkeys = key_list;
        decrypt_result_again = session::decrypt_envelope(
                multi_decrypt_keys,
                encrypt_result.ciphertext,
                protobuf_content_with_pro.proof.expiry_unix_ts,
                pro_backend_ed_pk);
        REQUIRE(decrypt_result_again.pro_status == ProStatus::Valid);
    }

    SECTION("Encrypt/decrypt for sync messages with Pro and bad rotating signature") {
        EncryptedForDestination encrypt_result = {};
        {
            session::Destination dest = base_dest;
            dest.type = DestinationType::SyncMessage;
            (*dest.pro_sig)[0] ^= 1;  // Break the sig by flipping a bit
            encrypt_result = session::encrypt_for_destination(
                    to_span(protobuf_content_with_pro.plaintext),
                    keys.ed_sk0,
                    dest,
                    config::Namespace::Default);
            REQUIRE(encrypt_result.encrypted);
        }

        std::span<const uint8_t> key = keys.ed_sk1;
        DecryptEnvelopeKey decrypt_keys = {};
        decrypt_keys.ed25519_privkeys = {&key, 1};
        DecryptedEnvelope decrypt_result = session::decrypt_envelope(
                decrypt_keys, encrypt_result.ciphertext, timestamp_s, pro_backend_ed_pk);
        REQUIRE(decrypt_result.pro_status == ProStatus::InvalidUserSig);
    }
}
