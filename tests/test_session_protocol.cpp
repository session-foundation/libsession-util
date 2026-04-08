#include <session/blinding.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/blinding.hpp>
#include <session/pro_backend.hpp>
#include <session/random.hpp>
#include <session/session_encrypt.hpp>
#include <session/session_protocol.hpp>

#include "SessionProtos.pb.h"
#include "utils.hpp"

using namespace session;

struct SerialisedProtobufContentWithProForTesting {
    ProProof proof;
    std::string plaintext;
    std::vector<std::byte> plaintext_padded;
    b64 sig_over_plaintext_with_user_pro_key;
    b64 sig_over_plaintext_padded_with_user_pro_key;
    b32 pro_proof_hash;
    cbytes64 sig_over_plaintext_with_user_pro_key_c;
    cbytes32 pro_proof_hash_c;
};

static SerialisedProtobufContentWithProForTesting build_protobuf_content_with_session_pro(
        std::string_view data_body,
        const ed25519::PrivKeySpan& user_rotating_privkey,
        const ed25519::PrivKeySpan& pro_backend_privkey,
        std::chrono::sys_seconds content_unix_ts,
        std::chrono::sys_seconds pro_expiry_unix_ts,
        session_protocol_pro_message_bitset msg_bitset,
        session_protocol_pro_profile_bitset profile_bitset) {
    SerialisedProtobufContentWithProForTesting result = {};

    // Create protobuf `Content.dataMessage`
    SessionProtos::Content content = {};
    content.set_sigtimestamp(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     content_unix_ts.time_since_epoch())
                                     .count());

    SessionProtos::DataMessage* data = content.mutable_datamessage();
    data->set_body(std::string(data_body));

    // Generate a dummy proof
    std::ranges::copy(user_rotating_privkey.pubkey(), result.proof.rotating_pubkey.begin());
    result.proof.expiry_unix_ts = pro_expiry_unix_ts;

    // Sign the proof by the dummy "Session Pro Backend" key
    result.pro_proof_hash = result.proof.hash();
    result.proof.sig = ed25519::sign(pro_backend_privkey, result.pro_proof_hash);

    // Create protobuf `Content.proMessage`
    SessionProtos::ProMessage* pro = content.mutable_promessage();
    pro->set_profilebitset(profile_bitset.data);
    pro->set_msgbitset(msg_bitset.data);

    // Create protobuf `Content.proMessage.proof`
    SessionProtos::ProProof* proto_proof = pro->mutable_proof();
    proto_proof->set_version(result.proof.version);
    proto_proof->set_genindexhash(
            result.proof.gen_index_hash.data(), result.proof.gen_index_hash.size());
    proto_proof->set_rotatingpublickey(
            result.proof.rotating_pubkey.data(), result.proof.rotating_pubkey.size());
    proto_proof->set_expiryunixts(std::chrono::duration_cast<std::chrono::milliseconds>(
                                          result.proof.expiry_unix_ts.time_since_epoch())
                                          .count());
    proto_proof->set_sig(result.proof.sig.data(), result.proof.sig.size());

    // Generate the plaintext
    result.plaintext = content.SerializeAsString();
    result.plaintext_padded = session::pad_message(to_span(result.plaintext));
    REQUIRE(result.plaintext.size() > data_body.size());
    REQUIRE(result.plaintext_padded.size() % SESSION_PROTOCOL_COMMUNITY_OR_1O1_MSG_PADDING == 0);

    // Sign the plaintext with the user's pro key
    result.sig_over_plaintext_with_user_pro_key =
            ed25519::sign(user_rotating_privkey, to_span(result.plaintext));
    result.sig_over_plaintext_padded_with_user_pro_key =
            ed25519::sign(user_rotating_privkey, result.plaintext_padded);

    // Setup the C versions for convenience
    std::memcpy(
            result.sig_over_plaintext_with_user_pro_key_c.data,
            result.sig_over_plaintext_with_user_pro_key.data(),
            sizeof(result.sig_over_plaintext_with_user_pro_key_c.data));
    std::memcpy(
            result.pro_proof_hash_c.data,
            result.pro_proof_hash.data(),
            sizeof(result.pro_proof_hash_c.data));
    return result;
}

TEST_CASE("Session protocol helpers C API", "[session-protocol][helpers]") {

    // Do tests that require no setup
    SECTION("Ensure get pro fetaures detects large message") {
        // Try a message below the size threshold
        {
            auto msg = std::string(SESSION_PROTOCOL_PRO_STANDARD_CHARACTER_LIMIT, 'a');
            session_protocol_pro_features_for_msg pro_msg =
                    session_protocol_pro_features_for_utf8(msg.data(), msg.size());
            REQUIRE(pro_msg.status == SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_SUCCESS);
            REQUIRE(pro_msg.bitset.data == 0);
            REQUIRE(pro_msg.codepoint_count == msg.size());
        }

        // Try an invalid message
        {
            std::string_view msg = "\xFF";
            session_protocol_pro_features_for_msg pro_msg =
                    session_protocol_pro_features_for_utf8(msg.data(), msg.size());
            REQUIRE(pro_msg.status ==
                    SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_UTF_DECODING_ERROR);
            REQUIRE(pro_msg.error.size);
        }

        // Try a message exceeding the standard size threshold
        {
            auto msg = std::string(SESSION_PROTOCOL_PRO_STANDARD_CHARACTER_LIMIT + 1, 'a');
            session_protocol_pro_features_for_msg pro_msg =
                    session_protocol_pro_features_for_utf8(msg.data(), msg.size());
            REQUIRE(pro_msg.status == SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_SUCCESS);
            REQUIRE(session_protocol_pro_message_bitset_is_set(
                    pro_msg.bitset, SESSION_PROTOCOL_PRO_MESSAGE_FEATURES_10K_CHARACTER_LIMIT));
            REQUIRE(pro_msg.codepoint_count == msg.size());
        }

        // Try a message at the max size threshold
        {
            auto msg = std::string(SESSION_PROTOCOL_PRO_HIGHER_CHARACTER_LIMIT, 'a');
            session_protocol_pro_features_for_msg pro_msg =
                    session_protocol_pro_features_for_utf8(msg.data(), msg.size());
            REQUIRE(pro_msg.status == SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_SUCCESS);
            REQUIRE(session_protocol_pro_message_bitset_is_set(
                    pro_msg.bitset, SESSION_PROTOCOL_PRO_MESSAGE_FEATURES_10K_CHARACTER_LIMIT));
            REQUIRE(pro_msg.codepoint_count == msg.size());
        }

        // Try a message at the (max size + 1) threshold
        {
            auto msg = std::string(SESSION_PROTOCOL_PRO_HIGHER_CHARACTER_LIMIT + 1, 'a');
            session_protocol_pro_features_for_msg pro_msg =
                    session_protocol_pro_features_for_utf8(msg.data(), msg.size());
            REQUIRE(pro_msg.status ==
                    SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_EXCEEDS_CHARACTER_LIMIT);
            REQUIRE(pro_msg.bitset.data == 0);
            REQUIRE(pro_msg.codepoint_count == msg.size());
        }
    }

    // Tests that require some setup code
    using namespace session;
    TestKeys keys = get_deterministic_test_keys();

    // Tuesday, 12 August 2025 03:58:21 UTC
    const std::chrono::sys_seconds timestamp_s =
            std::chrono::sys_seconds(std::chrono::seconds(1754971101));
    const std::chrono::sys_time<std::chrono::milliseconds> timestamp_ms = timestamp_s;
    const std::string_view data_body = "hello";

    // Generate the user's Session Pro rotating key for testing encrypted payloads with Session
    // Pro metadata
    const auto user_pro_seed =
            "0123456789abcdef0123456789abcdeff00baa00000000000000000000000000"_hex_b;
    auto [user_pro_ed_pk, user_pro_ed_sk] = ed25519::keypair(user_pro_seed);

    SECTION("Encrypt with and w/o pro sig produce same payload size") {
        // Same payload size because the encrypt function should put in a dummy signature if one
        // wasn't specific to make pro and non-pro envelopes indistinguishable.
        cbytes33 recipient_pubkey = {};
        std::memcpy(recipient_pubkey.data, keys.session_pk1.data(), sizeof(recipient_pubkey.data));

        // Withhold the pro signature
        char error[256];
        session_protocol_encoded_for_destination encrypt_without_pro_sig =
                session_protocol_encode_dm_v1(
                        data_body.data(),
                        data_body.size(),
                        keys.ed_sk0.data(),
                        keys.ed_sk0.size(),
                        timestamp_ms.time_since_epoch().count(),
                        &recipient_pubkey,
                        nullptr,
                        0,
                        error,
                        sizeof(error));
        INFO(error);
        REQUIRE(encrypt_without_pro_sig.error_len_incl_null_terminator == 0);

        // Set the pro signature
        session_protocol_encoded_for_destination encrypt_with_pro_sig =
                session_protocol_encode_dm_v1(
                        data_body.data(),
                        data_body.size(),
                        keys.ed_sk0.data(),
                        keys.ed_sk0.size(),
                        timestamp_ms.time_since_epoch().count(),
                        &recipient_pubkey,
                        keys.ed_sk0.data(),  // Use random key, doesn't matter, we're checking size
                        keys.ed_sk0.size(),
                        error,
                        sizeof(error));
        REQUIRE(encrypt_with_pro_sig.error_len_incl_null_terminator == 0);

        // Should have the same payload size
        REQUIRE(encrypt_without_pro_sig.ciphertext.size == encrypt_with_pro_sig.ciphertext.size);
        session_protocol_encode_for_destination_free(&encrypt_without_pro_sig);
        session_protocol_encode_for_destination_free(&encrypt_with_pro_sig);
    }

    // Setup a dummy "Session Pro Backend" key
    // We reuse test key 1 as the "Session Pro" backend key that signs the proofs as it
    // doesn't matter what key really, just that we have one available for signing.
    char error[256];

    SECTION("Encrypt/decrypt for contact in default namespace w/o pro attached") {
        // Build content without pro attached
        std::string plaintext;
        {
            SessionProtos::Content content = {};
            content.set_sigtimestamp(timestamp_ms.time_since_epoch().count());

            SessionProtos::DataMessage* data = content.mutable_datamessage();
            data->set_body(std::string(data_body));
            plaintext = content.SerializeAsString();
            REQUIRE(plaintext.size() > data_body.size());
        }

        // Encrypt
        session_protocol_encoded_for_destination encrypt_result = {};
        {
            cbytes33 recipient_pubkey = {};
            std::memcpy(recipient_pubkey.data, keys.session_pk1.data(), keys.session_pk1.size());
            encrypt_result = session_protocol_encode_dm_v1(
                    plaintext.data(),
                    plaintext.size(),
                    keys.ed_sk0.data(),
                    keys.ed_sk0.size(),
                    timestamp_ms.time_since_epoch().count(),
                    &recipient_pubkey,
                    nullptr,
                    0,
                    error,
                    sizeof(error));
            REQUIRE(encrypt_result.error_len_incl_null_terminator == 0);
        }

        // Decrypt envelope
        span_u8 key = {keys.ed_sk1.data(), keys.ed_sk1.size()};
        session_protocol_decode_envelope_keys decrypt_keys = {};
        decrypt_keys.decrypt_keys = &key;
        decrypt_keys.decrypt_keys_len = 1;
        session_protocol_decoded_envelope decrypt_result = session_protocol_decode_envelope(
                &decrypt_keys,
                encrypt_result.ciphertext.data,
                encrypt_result.ciphertext.size,
                keys.ed_pk1.data(),
                keys.ed_pk1.size(),
                error,
                sizeof(error));
        INFO("ERROR: " << error);
        REQUIRE(decrypt_result.success);
        REQUIRE(decrypt_result.error_len_incl_null_terminator == 0);
        session_protocol_encode_for_destination_free(&encrypt_result);

        // Verify pro
        ProProof nil_proof = {};
        b32 nil_hash = nil_proof.hash();
        cbytes32 decrypt_result_pro_hash =
                session_protocol_pro_proof_hash(&decrypt_result.pro.proof);
        REQUIRE(decrypt_result.pro.status ==
                SESSION_PROTOCOL_PRO_STATUS_NIL);  // Pro was not attached
        REQUIRE(decrypt_result.pro.msg_bitset.data == 0);
        REQUIRE(decrypt_result.pro.profile_bitset.data == 0);
        REQUIRE(std::memcmp(
                        decrypt_result_pro_hash.data,
                        nil_hash.data(),
                        sizeof(decrypt_result_pro_hash.data)) == 0);

        // Verify it is decryptable
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data, decrypt_result.content_plaintext.size));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == data_body);
        session_protocol_decode_envelope_free(&decrypt_result);
    }

    // Build protobuf `Content` message, serialise to `plaintext` and get it signed by the user's
    // "Session Pro" key into `sig_over_plaintext_with_user_pro_key`
    SerialisedProtobufContentWithProForTesting protobuf_content =
            build_protobuf_content_with_session_pro(
                    /*data_body*/ data_body,
                    /*user_rotating_privkey*/ user_pro_ed_sk,
                    /*pro_backend_privkey*/ keys.ed_sk1,
                    /*content_unix_ts=*/timestamp_s,
                    /*pro_expiry_unix_ts*/ timestamp_s,
                    /*msg_bitset*/ {},
                    /*profile_bitset*/ {});

    // Setup base destination object with the pro signature w/ Session pubkey 1 as the recipient
    cbytes64 base_pro_sig = {};
    std::memcpy(
            base_pro_sig.data,
            protobuf_content.sig_over_plaintext_with_user_pro_key.data(),
            sizeof(base_pro_sig.data));

    uint64_t base_sent_timestamp_ms = timestamp_ms.time_since_epoch().count();
    cbytes33 base_recipient_pubkey = {};
    REQUIRE(sizeof(base_recipient_pubkey.data) == keys.session_pk1.size());
    std::memcpy(base_recipient_pubkey.data, keys.session_pk1.data(), keys.session_pk1.size());

    SECTION("Check non-encryptable messages produce only plaintext") {
        SECTION("Community inbox") {
            auto [blind15_pk, blind15_sk] =
                    session::blind15_key_pair(keys.ed_sk1, to_byte_span<32>(keys.ed_pk1.data()), /*blind factor*/ nullptr);
            cbytes33 blind15_recipient = {};
            blind15_recipient.data[0] = 0x15;
            std::memcpy(blind15_recipient.data + 1, blind15_pk.data(), blind15_pk.size());
            cbytes32 community_pubkey = {};

            session_protocol_encoded_for_destination encrypt_result =
                    session_protocol_encode_for_community_inbox(
                            protobuf_content.plaintext.data(),
                            protobuf_content.plaintext.size(),
                            keys.ed_sk0.data(),
                            keys.ed_sk0.size(),
                            base_sent_timestamp_ms,
                            &blind15_recipient,
                            &community_pubkey,
                            user_pro_ed_sk.data(),
                            user_pro_ed_sk.size(),
                            error,
                            sizeof(error));
            INFO("ERROR: " << error);
            REQUIRE(encrypt_result.ciphertext.size > 0);
            REQUIRE(encrypt_result.error_len_incl_null_terminator == 0);
            session_protocol_encode_for_destination_free(&encrypt_result);
        }

        SECTION("Contact in non-default namespace") {
            session_protocol_encoded_for_destination encrypt_result = session_protocol_encode_dm_v1(
                    protobuf_content.plaintext.data(),
                    protobuf_content.plaintext.size(),
                    keys.ed_sk0.data(),
                    keys.ed_sk0.size(),
                    base_sent_timestamp_ms,
                    &base_recipient_pubkey,
                    user_pro_ed_sk.data(),
                    user_pro_ed_sk.size(),
                    error,
                    sizeof(error));
            INFO("ERROR: " << error);
            REQUIRE(encrypt_result.ciphertext.size > 0);
            REQUIRE(encrypt_result.error_len_incl_null_terminator == 0);
            session_protocol_encode_for_destination_free(&encrypt_result);
        }
    }

    SECTION("Encrypt/decrypt for contact in default namespace with Pro") {
        // Encrypt content
        session_protocol_encoded_for_destination encrypt_result = session_protocol_encode_dm_v1(
                protobuf_content.plaintext.data(),
                protobuf_content.plaintext.size(),
                keys.ed_sk0.data(),
                keys.ed_sk0.size(),
                base_sent_timestamp_ms,
                &base_recipient_pubkey,
                user_pro_ed_sk.data(),
                user_pro_ed_sk.size(),
                error,
                sizeof(error));
        REQUIRE(encrypt_result.error_len_incl_null_terminator == 0);

        // Decrypt envelope
        span_u8 key = {keys.ed_sk1.data(), keys.ed_sk1.size()};
        session_protocol_decode_envelope_keys decrypt_keys = {};
        decrypt_keys.decrypt_keys = &key;
        decrypt_keys.decrypt_keys_len = 1;
        session_protocol_decoded_envelope decrypt_result = session_protocol_decode_envelope(
                &decrypt_keys,
                encrypt_result.ciphertext.data,
                encrypt_result.ciphertext.size,
                keys.ed_pk1.data(),
                keys.ed_pk1.size(),
                error,
                sizeof(error));
        REQUIRE(decrypt_result.success);
        REQUIRE(decrypt_result.error_len_incl_null_terminator == 0);
        session_protocol_encode_for_destination_free(&encrypt_result);

        // Verify pro
        REQUIRE(decrypt_result.pro.status ==
                SESSION_PROTOCOL_PRO_STATUS_VALID);  // Pro was attached
        cbytes32 hash = session_protocol_pro_proof_hash(&decrypt_result.pro.proof);
        REQUIRE(std::memcmp(hash.data, protobuf_content.pro_proof_hash.data(), sizeof(hash.data)) ==
                0);
        REQUIRE(decrypt_result.pro.msg_bitset.data == 0);      // No features requested
        REQUIRE(decrypt_result.pro.profile_bitset.data == 0);  // No features requested

        // Verify the content can be parsed w/ protobufs
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data, decrypt_result.content_plaintext.size));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == data_body);
        session_protocol_decode_envelope_free(&decrypt_result);
    }

    SECTION("Encrypt/decrypt for contact in default namespace with Pro + features") {
        std::string large_message;
        large_message.resize(SESSION_PROTOCOL_PRO_STANDARD_CHARACTER_LIMIT + 1);

        session_protocol_pro_features_for_msg pro_msg =
                session_protocol_pro_features_for_utf8(large_message.data(), large_message.size());
        REQUIRE(session_protocol_pro_message_bitset_is_set(
                pro_msg.bitset, SESSION_PROTOCOL_PRO_MESSAGE_FEATURES_10K_CHARACTER_LIMIT));

        session_protocol_pro_profile_bitset profile_bitset = {};
        session_protocol_pro_profile_bitset_set(
                &profile_bitset, SESSION_PROTOCOL_PRO_PROFILE_FEATURES_PRO_BADGE);

        SerialisedProtobufContentWithProForTesting protobuf_content_with_pro_and_features =
                build_protobuf_content_with_session_pro(
                        /*data_body*/ large_message,
                        /*user_rotating_privkey*/ user_pro_ed_sk,
                        /*pro_backend_privkey*/ keys.ed_sk1,
                        /*content_unix_ts*/ timestamp_s,
                        /*pro_expiry_unix_ts*/ timestamp_s,
                        /*msg_bitset*/ pro_msg.bitset,
                        /*proilfe_bitset*/ profile_bitset);

        // Encrypt content
        session_protocol_encoded_for_destination encrypt_result = session_protocol_encode_dm_v1(
                protobuf_content_with_pro_and_features.plaintext.data(),
                protobuf_content_with_pro_and_features.plaintext.size(),
                keys.ed_sk0.data(),
                keys.ed_sk0.size(),
                base_sent_timestamp_ms,
                &base_recipient_pubkey,
                user_pro_ed_sk.data(),
                user_pro_ed_sk.size(),
                error,
                sizeof(error));
        INFO("ERROR: " << error);
        REQUIRE(encrypt_result.error_len_incl_null_terminator == 0);

        // Decrypt envelope
        span_u8 key = {keys.ed_sk1.data(), keys.ed_sk1.size()};
        session_protocol_decode_envelope_keys decrypt_keys = {};
        decrypt_keys.decrypt_keys = &key;
        decrypt_keys.decrypt_keys_len = 1;
        session_protocol_decoded_envelope decrypt_result = session_protocol_decode_envelope(
                &decrypt_keys,
                encrypt_result.ciphertext.data,
                encrypt_result.ciphertext.size,
                keys.ed_pk1.data(),
                keys.ed_pk1.size(),
                error,
                sizeof(error));
        INFO("ERROR: " << error);
        REQUIRE(decrypt_result.success);
        REQUIRE(decrypt_result.error_len_incl_null_terminator == 0);
        REQUIRE(decrypt_result.envelope.timestamp_ms == base_sent_timestamp_ms);
        session_protocol_encode_for_destination_free(&encrypt_result);

        // Verify pro
        REQUIRE(decrypt_result.pro.status ==
                SESSION_PROTOCOL_PRO_STATUS_VALID);  // Pro was attached
        cbytes32 hash = session_protocol_pro_proof_hash(&decrypt_result.pro.proof);
        REQUIRE(std::memcmp(hash.data, protobuf_content.pro_proof_hash.data(), sizeof(hash.data)) ==
                0);
        REQUIRE(session_protocol_pro_profile_bitset_is_set(
                decrypt_result.pro.profile_bitset,
                SESSION_PROTOCOL_PRO_PROFILE_FEATURES_PRO_BADGE));
        REQUIRE(session_protocol_pro_message_bitset_is_set(
                decrypt_result.pro.msg_bitset,
                SESSION_PROTOCOL_PRO_MESSAGE_FEATURES_10K_CHARACTER_LIMIT));

        // Verify the content can be parsed w/ protobufs
        SessionProtos::Content decrypt_content = {};
        REQUIRE(decrypt_content.ParseFromArray(
                decrypt_result.content_plaintext.data, decrypt_result.content_plaintext.size));
        REQUIRE(decrypt_content.has_datamessage());
        const SessionProtos::DataMessage& data = decrypt_content.datamessage();
        REQUIRE(data.body() == large_message);
        session_protocol_decode_envelope_free(&decrypt_result);
    }

    SECTION("Encrypt/decrypt for legacy groups is rejected") {
        CHECK(base_recipient_pubkey.data[0] == 0x05);
        cbytes32 group_enc_key = {};

        session_protocol_encoded_for_destination encrypt_result = session_protocol_encode_for_group(
                protobuf_content.plaintext.data(),
                protobuf_content.plaintext.size(),
                keys.ed_sk0.data(),
                keys.ed_sk0.size(),
                base_sent_timestamp_ms,
                &base_recipient_pubkey,
                &group_enc_key,
                nullptr,
                0,
                error,
                sizeof(error));
        REQUIRE(encrypt_result.error_len_incl_null_terminator > 0);
        REQUIRE(encrypt_result.error_len_incl_null_terminator <= sizeof(error));
        REQUIRE(!encrypt_result.success);
        session_protocol_encode_for_destination_free(&encrypt_result);
    }

    SECTION("Encrypt/decrypt for groups v2 (w/ encrypted envelope, plaintext content) with Pro") {
        // TODO: Finish setting up a fake group
        const auto group_v2_seed =
                "0123456789abcdef0123456789abcdeff00baadeadb33f000000000000000000"_hex_b;
        auto [group_v2_pk, group_v2_sk] = ed25519::keypair(group_v2_seed);

        // Encrypt
        session_protocol_encoded_for_destination encrypt_result = {};
        {
            cbytes33 group_v2_session_pk = {};
            cbytes32 group_v2_session_sk = {};
            group_v2_session_pk.data[0] = 0x03;
            std::memcpy(group_v2_session_pk.data + 1, to_unsigned(group_v2_pk.data()), group_v2_pk.size());
            std::memcpy(
                    group_v2_session_sk.data, to_unsigned(group_v2_sk.data()), sizeof(group_v2_session_sk.data));

            encrypt_result = session_protocol_encode_for_group(
                    protobuf_content.plaintext.data(),
                    protobuf_content.plaintext.size(),
                    keys.ed_sk0.data(),
                    keys.ed_sk0.size(),
                    base_sent_timestamp_ms,
                    &group_v2_session_pk,
                    &group_v2_session_sk,
                    user_pro_ed_sk.data(),
                    user_pro_ed_sk.size(),
                    error,
                    sizeof(error));
            INFO("Encrypt for group error: " << error);
            REQUIRE(encrypt_result.success);
            REQUIRE(encrypt_result.error_len_incl_null_terminator == 0);
        }

        // Decrypt envelope
        span_u8 key = {to_unsigned(group_v2_sk.data()), group_v2_sk.size()};
        session_protocol_decode_envelope_keys decrypt_keys = {};
        decrypt_keys.group_ed25519_pubkey = {to_unsigned(group_v2_pk.data()), group_v2_pk.size()};
        decrypt_keys.decrypt_keys = &key;
        decrypt_keys.decrypt_keys_len = 1;

        // TODO: Finish setting up a group so we can check the decrypted result for now this will
        // throw because the keys aren't setup correctly.
        session_protocol_decoded_envelope decrypt_result = session_protocol_decode_envelope(
                &decrypt_keys,
                encrypt_result.ciphertext.data,
                encrypt_result.ciphertext.size,
                keys.ed_pk1.data(),
                keys.ed_pk1.size(),
                error,
                sizeof(error));
        INFO("Decrypt for group error: " << error);
        REQUIRE(decrypt_result.success);
        REQUIRE(decrypt_result.pro.status == SESSION_PROTOCOL_PRO_STATUS_VALID);
        REQUIRE(decrypt_result.error_len_incl_null_terminator == 0);
        static_assert(
                sizeof(decrypt_result.sender_x25519_pubkey.data) == keys.curve_pk0.max_size());
        REQUIRE(memcmp(decrypt_result.sender_x25519_pubkey.data,
                       keys.curve_pk0.data(),
                       keys.curve_pk0.size()) == 0);

        session_protocol_encode_for_destination_free(&encrypt_result);
        session_protocol_decode_envelope_free(&decrypt_result);
    }

    SECTION("Encrypt/decrypt for sync messages with Pro") {
        // Encrypt
        session_protocol_encoded_for_destination encrypt_result = session_protocol_encode_dm_v1(
                protobuf_content.plaintext.data(),
                protobuf_content.plaintext.size(),
                keys.ed_sk0.data(),
                keys.ed_sk0.size(),
                base_sent_timestamp_ms,
                &base_recipient_pubkey,
                user_pro_ed_sk.data(),
                user_pro_ed_sk.size(),
                error,
                sizeof(error));
        REQUIRE(encrypt_result.error_len_incl_null_terminator == 0);

        // Decrypt
        span_u8 key = {keys.ed_sk1.data(), keys.ed_sk1.size()};
        session_protocol_decode_envelope_keys decrypt_keys = {};
        decrypt_keys.decrypt_keys = &key;
        decrypt_keys.decrypt_keys_len = 1;
        {
            session_protocol_decoded_envelope decrypt_result = session_protocol_decode_envelope(
                    &decrypt_keys,
                    encrypt_result.ciphertext.data,
                    encrypt_result.ciphertext.size,
                    keys.ed_pk1.data(),
                    keys.ed_pk1.size(),
                    error,
                    sizeof(error));
            REQUIRE(decrypt_result.error_len_incl_null_terminator == 0);
            REQUIRE(decrypt_result.success);

            // Verify pro
            REQUIRE(decrypt_result.pro.status ==
                    SESSION_PROTOCOL_PRO_STATUS_VALID);  // Pro was attached
            cbytes32 hash = session_protocol_pro_proof_hash(&decrypt_result.pro.proof);
            REQUIRE(std::memcmp(
                            hash.data, protobuf_content.pro_proof_hash.data(), sizeof(hash.data)) ==
                    0);
            REQUIRE(decrypt_result.pro.msg_bitset.data == 0);      // No features requested
            REQUIRE(decrypt_result.pro.profile_bitset.data == 0);  // No features requested

            // Verify the content can be parsed w/ protobufs
            SessionProtos::Content decrypt_content = {};
            REQUIRE(decrypt_content.ParseFromArray(
                    decrypt_result.content_plaintext.data, decrypt_result.content_plaintext.size));
            REQUIRE(decrypt_content.has_datamessage());
            const SessionProtos::DataMessage& data = decrypt_content.datamessage();
            REQUIRE(data.body() == data_body);
            session_protocol_decode_envelope_free(&decrypt_result);
        }

        // Try decrypt with a timestamp past the pro proof expiry date
        {
            // Build protobuf `Content` message, serialise to `plaintext` and get it signed by the
            // user's "Session Pro" key into `sig_over_plaintext_with_user_pro_key`
            std::chrono::milliseconds bad_timestamp_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                            protobuf_content.proof.expiry_unix_ts.time_since_epoch()) +
                    std::chrono::seconds(1);

            SerialisedProtobufContentWithProForTesting bad_protobuf_content =
                    build_protobuf_content_with_session_pro(
                            /*data_body*/ data_body,
                            /*user_rotating_privkey*/ user_pro_ed_sk,
                            /*pro_backend_privkey*/ keys.ed_sk1,
                            /*content_unix_ts=*/
                            std::chrono::sys_seconds(
                                    std::chrono::duration_cast<std::chrono::seconds>(
                                            bad_timestamp_ms)),
                            /*pro_expiry_unix_ts*/ timestamp_s,
                            /*msg_bitset*/ {},
                            /*profile_bitset*/ {});

            session_protocol_encoded_for_destination encrypt_bad_result =
                    session_protocol_encode_dm_v1(
                            bad_protobuf_content.plaintext.data(),
                            bad_protobuf_content.plaintext.size(),
                            keys.ed_sk0.data(),
                            keys.ed_sk0.size(),
                            bad_timestamp_ms.count(),
                            &base_recipient_pubkey,
                            user_pro_ed_sk.data(),
                            user_pro_ed_sk.size(),
                            error,
                            sizeof(error));
            REQUIRE(encrypt_bad_result.error_len_incl_null_terminator == 0);

            session_protocol_decoded_envelope decrypt_result = session_protocol_decode_envelope(
                    &decrypt_keys,
                    encrypt_bad_result.ciphertext.data,
                    encrypt_bad_result.ciphertext.size,
                    keys.ed_pk1.data(),
                    keys.ed_pk1.size(),
                    error,
                    sizeof(error));
            REQUIRE(decrypt_result.success);
            REQUIRE(decrypt_result.pro.status == SESSION_PROTOCOL_PRO_STATUS_EXPIRED);
            REQUIRE(decrypt_result.error_len_incl_null_terminator == 0);
            session_protocol_decode_envelope_free(&decrypt_result);
        }

        // Try decrypt with a bad backend key
        {
            uc32 bad_pro_ed_pk = keys.ed_pk1;
            bad_pro_ed_pk[0] ^= 1;
            session_protocol_decoded_envelope decrypt_result = session_protocol_decode_envelope(
                    &decrypt_keys,
                    encrypt_result.ciphertext.data,
                    encrypt_result.ciphertext.size,
                    bad_pro_ed_pk.data(),
                    bad_pro_ed_pk.size(),
                    error,
                    sizeof(error));
            REQUIRE(decrypt_result.success);
            REQUIRE(decrypt_result.pro.status ==
                    SESSION_PROTOCOL_PRO_STATUS_INVALID_PRO_BACKEND_SIG);
            REQUIRE(decrypt_result.error_len_incl_null_terminator == 0);
            session_protocol_decode_envelope_free(&decrypt_result);
        }

        // Try decrypt with bad key (ed_sk0 which was the sender; ed_sk1 the recipient)
        span_u8 bad_key = {keys.ed_sk0.data(), keys.ed_sk0.size()};
        {
            session_protocol_decode_envelope_keys bad_decrypt_keys = {};
            bad_decrypt_keys.decrypt_keys = &bad_key;
            bad_decrypt_keys.decrypt_keys_len = 1;
            session_protocol_decoded_envelope decrypt_result = session_protocol_decode_envelope(
                    &bad_decrypt_keys,
                    encrypt_result.ciphertext.data,
                    encrypt_result.ciphertext.size,
                    keys.ed_pk1.data(),
                    keys.ed_pk1.size(),
                    error,
                    sizeof(error));
            INFO("Checking error from bad envelope decryption: " << std::string_view(
                         error, decrypt_result.error_len_incl_null_terminator - 1));
            REQUIRE(!decrypt_result.success);
            REQUIRE(decrypt_result.error_len_incl_null_terminator > 0);
            REQUIRE(decrypt_result.error_len_incl_null_terminator <= sizeof(error));
            session_protocol_decode_envelope_free(&decrypt_result);
        }

        // Try decrypt with multiple keys, 1 bad, 1 good key
        {
            auto key_list = std::array{bad_key, key};
            session_protocol_decode_envelope_keys multi_decrypt_keys = {};
            multi_decrypt_keys.decrypt_keys = key_list.data();
            multi_decrypt_keys.decrypt_keys_len = key_list.size();
            session_protocol_decoded_envelope decrypt_result = session_protocol_decode_envelope(
                    &multi_decrypt_keys,
                    encrypt_result.ciphertext.data,
                    encrypt_result.ciphertext.size,
                    keys.ed_pk1.data(),
                    keys.ed_pk1.size(),
                    error,
                    sizeof(error));
            REQUIRE(decrypt_result.success);
            REQUIRE(decrypt_result.pro.status == SESSION_PROTOCOL_PRO_STATUS_VALID);
            REQUIRE(decrypt_result.error_len_incl_null_terminator == 0);
            session_protocol_decode_envelope_free(&decrypt_result);
        }
        session_protocol_encode_for_destination_free(&encrypt_result);
    }

    SECTION("Encode/decode for community (content message)") {
        session_protocol_encoded_for_destination encoded = session_protocol_encode_for_community(
                protobuf_content.plaintext.data(),
                protobuf_content.plaintext.size(),
                nullptr,
                0,
                error,
                sizeof(error));
        scope_exit encoded_free{[&]() { session_protocol_encode_for_destination_free(&encoded); }};
        REQUIRE(encoded.ciphertext.size % SESSION_PROTOCOL_COMMUNITY_OR_1O1_MSG_PADDING == 0);

        session_protocol_decoded_community_message decoded = session_protocol_decode_for_community(
                encoded.ciphertext.data,
                encoded.ciphertext.size,
                timestamp_ms.time_since_epoch().count(),
                keys.ed_pk1.data(),
                keys.ed_pk1.size(),
                error,
                sizeof(error));
        scope_exit decoded_free{[&]() { session_protocol_decode_for_community_free(&decoded); }};
        REQUIRE(!decoded.has_pro);
    }

    SECTION("Encode/decode for community (content message+pro)") {
        session_protocol_encoded_for_destination encoded = session_protocol_encode_for_community(
                protobuf_content.plaintext.data(),
                protobuf_content.plaintext.size(),
                user_pro_ed_sk.data(),
                user_pro_ed_sk.size(),
                error,
                sizeof(error));
        scope_exit encoded_free{[&]() { session_protocol_encode_for_destination_free(&encoded); }};
        REQUIRE(encoded.ciphertext.size % SESSION_PROTOCOL_COMMUNITY_OR_1O1_MSG_PADDING == 0);

        session_protocol_decoded_community_message decoded = session_protocol_decode_for_community(
                encoded.ciphertext.data,
                encoded.ciphertext.size,
                timestamp_ms.time_since_epoch().count(),
                keys.ed_pk1.data(),
                keys.ed_pk1.size(),
                error,
                sizeof(error));
        scope_exit decoded_free{[&]() { session_protocol_decode_for_community_free(&decoded); }};
        REQUIRE(decoded.has_pro);
        REQUIRE(decoded.pro.status == SESSION_PROTOCOL_PRO_STATUS_VALID);
    }

    SECTION("Decode for community (envelope)") {
        SessionProtos::Envelope envelope;
        envelope.set_type(SessionProtos::Envelope_Type_SESSION_MESSAGE);
        envelope.set_timestamp(timestamp_ms.time_since_epoch().count());
        envelope.set_content(
                protobuf_content.plaintext_padded.data(), protobuf_content.plaintext_padded.size());
        std::string envelope_plaintext = envelope.SerializeAsString();

        session_protocol_decoded_community_message decoded = session_protocol_decode_for_community(
                envelope_plaintext.data(),
                envelope_plaintext.size(),
                timestamp_ms.time_since_epoch().count(),
                keys.ed_pk1.data(),
                keys.ed_pk1.size(),
                error,
                sizeof(error));
        scope_exit decoded_free{[&]() { session_protocol_decode_for_community_free(&decoded); }};
        REQUIRE(decoded.has_envelope);
        REQUIRE(!decoded.has_pro);
    }

    SECTION("Decode for community (envelope+pro)") {
        SessionProtos::Envelope envelope;
        envelope.set_type(SessionProtos::Envelope_Type_SESSION_MESSAGE);
        envelope.set_timestamp(timestamp_ms.time_since_epoch().count());
        envelope.set_content(
                protobuf_content.plaintext_padded.data(), protobuf_content.plaintext_padded.size());
        envelope.set_prosig(
                protobuf_content.sig_over_plaintext_padded_with_user_pro_key.data(),
                protobuf_content.sig_over_plaintext_padded_with_user_pro_key.size());
        std::string envelope_plaintext = envelope.SerializeAsString();

        session_protocol_decoded_community_message decoded = session_protocol_decode_for_community(
                envelope_plaintext.data(),
                envelope_plaintext.size(),
                timestamp_ms.time_since_epoch().count(),
                keys.ed_pk1.data(),
                keys.ed_pk1.size(),
                error,
                sizeof(error));
        scope_exit decoded_free{[&]() { session_protocol_decode_for_community_free(&decoded); }};
        REQUIRE(decoded.has_envelope);
        REQUIRE(decoded.has_pro);
        REQUIRE(decoded.pro.status == SESSION_PROTOCOL_PRO_STATUS_VALID);
    }

    SECTION("Encode/decode for community inbox (content message)") {
        const auto community_seed =
                "0123456789abcdef0123456789abcdeff00baadeadb33f000000000000000000"_hex_b;
        auto [community_pk, community_sk] = ed25519::keypair(community_seed);

        cbytes32 session_blind15_sk0 = {};
        cbytes33 session_blind15_pk0 = {};
        session_blind15_pk0.data[0] = 0x15;
        session_blind15_key_pair(
                keys.ed_sk0.data(),
                to_unsigned(community_pk.data()),
                session_blind15_pk0.data + 1,
                session_blind15_sk0.data);

        cbytes32 session_blind15_sk1 = {};
        cbytes33 session_blind15_pk1 = {};
        session_blind15_pk1.data[0] = 0x15;
        session_blind15_key_pair(
                keys.ed_sk1.data(),
                to_unsigned(community_pk.data()),
                session_blind15_pk1.data + 1,
                session_blind15_sk1.data);

        cbytes33 recipient_pubkey = session_blind15_pk1;
        cbytes32 community_pubkey = {};
        std::memcpy(community_pubkey.data, community_pk.data(), community_pk.size());

        session_protocol_encoded_for_destination encoded =
                session_protocol_encode_for_community_inbox(
                        protobuf_content.plaintext.data(),
                        protobuf_content.plaintext.size(),
                        keys.ed_sk0.data(),
                        keys.ed_sk0.size(),
                        timestamp_ms.time_since_epoch().count(),
                        &recipient_pubkey,
                        &community_pubkey,
                        nullptr,
                        0,
                        error,
                        sizeof(error));
        scope_exit encoded_free{[&]() { session_protocol_encode_for_destination_free(&encoded); }};

        auto [decrypted_cipher, sender_id] = session::decrypt_from_blinded_recipient(
                keys.ed_sk1,
                community_pk,
                to_byte_span(session_blind15_pk0.data),
                to_byte_span(session_blind15_pk1.data),
                to_byte_span(encoded.ciphertext.data, encoded.ciphertext.size));

        session_protocol_decoded_community_message decoded = session_protocol_decode_for_community(
                decrypted_cipher.data(),
                decrypted_cipher.size(),
                timestamp_ms.time_since_epoch().count(),
                keys.ed_pk1.data(),
                keys.ed_pk1.size(),
                error,
                sizeof(error));
        scope_exit decoded_free{[&]() { session_protocol_decode_for_community_free(&decoded); }};
        REQUIRE(!decoded.has_pro);
    }
}
