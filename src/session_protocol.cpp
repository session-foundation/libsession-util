#include <sodium/crypto_sign_ed25519.h>
#include <fmt/core.h>

#include <session/config/groups/keys.hpp>
#include <session/config/namespaces.hpp>
#include <session/config/pro.hpp>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/session_protocol.hpp>

#include "SessionProtos.pb.h"
#include "WebSocketResources.pb.h"

namespace session {

ProFeatures get_pro_features_for_msg(std::span<const unsigned char> msg, ProExtraFeatures extra) {
    ProFeatures result = session_pro_features_nil;
    if (msg.size() >= SESSION_PRO_10k_CHARACTER_LIMIT)
        result |= session_pro_features_10k_character_limit;
    if (extra & session_pro_extra_features_animated_avatar)
        result |= session_pro_features_animated_avatar;
    if (extra & session_pro_extra_features_pro_badge)
        result |= session_pro_features_pro_badge;
    return result;
}

array_uc64 sign_msg_for_pro(std::span<const unsigned char> msg, const array_uc64& rotating_priv_key) {
    // Sign the msg with the rotating public pro key and the pro proof if given
    array_uc64 result = {};
    static_assert(result.max_size() == crypto_sign_ed25519_BYTES);
    crypto_sign_ed25519_detached(result.data(), nullptr, msg.data(), msg.size(), rotating_priv_key.data());
    return result;
}

std::vector<uint8_t> encrypt_for_namespaced_destination(
        std::span<const unsigned char> plaintext,
        std::span<const unsigned char> ed25519_privkey,
        const Destination& dest,
        config::Namespace space) {

    enum class Mode {
        Envelope,
        Plaintext,
        EncryptForBlindedRecipient,
    };

    enum class AfterEnvelope {
        Nil,
        EnvelopeIsCipherText,
        WrapInWSMessage,
        KeysEncryptMessage,
    };

    struct EncodeContext {
        Mode mode;

        // Parameters for BuildMode => Envelope
        bool before_envelope_encrypt_for_recipient_deterministic;
        std::vector<uint8_t> before_envelope_ciphertext;
        std::optional<std::span<const uint8_t>> envelope_src;
        std::optional<SessionProtos::Envelope_Type> envelope_type;
        AfterEnvelope after_envelope;
    };

    // Figure out how to encrypt the message based on the destination and setup the encoding context
    EncodeContext enc = {};
    switch (dest.type) {
        case DestinationType::ClosedGroup: {
            bool has_03_prefix =
                    dest.closed_group_pubkey[0] == static_cast<uint8_t>(SessionIDPrefix::group);
            if (has_03_prefix) {
                if (space == config::Namespace::GroupMessages) {
                    if (!dest.closed_group_keys)
                        throw std::runtime_error(
                                "API misuse: Sending to a closed group into the group messages "
                                "namespace requires the closed group keys to be set");
                    enc.mode = Mode::Envelope;
                    enc.after_envelope = AfterEnvelope::KeysEncryptMessage;
                    enc.envelope_type =
                            SessionProtos::Envelope_Type::Envelope_Type_CLOSED_GROUP_MESSAGE;
                } else if (space == config::Namespace::RevokedRetrievableGroupMessages) {
                    enc.mode = Mode::Plaintext;
                } else {
                    // Config messages should be sent directly rather than via this method (just
                    // return plaintext and no-op). See:
                    // https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Sending%20%26%20Receiving/MessageSender.swift#L494
                    enc.mode = Mode::Plaintext;
                }
            } else {
                enc.mode = Mode::Envelope;
                enc.before_envelope_encrypt_for_recipient_deterministic = true;
                enc.envelope_type =
                        SessionProtos::Envelope_Type::Envelope_Type_CLOSED_GROUP_MESSAGE;
                enc.after_envelope = AfterEnvelope::WrapInWSMessage;

                if (!dest.closed_group_swarm_public_key)
                    throw std::runtime_error(
                            "API misuse: Closed group swarm public key must be set on non 0x03 "
                            "prefixed group keys");
                enc.envelope_src = *dest.closed_group_swarm_public_key;
            }
        } break;

        case DestinationType::Contact: {
            if (space == config::Namespace::Default) {
                enc.mode = Mode::Envelope;
                enc.before_envelope_encrypt_for_recipient_deterministic = true;
                enc.envelope_type = SessionProtos::Envelope_Type::Envelope_Type_SESSION_MESSAGE;
                enc.after_envelope = AfterEnvelope::EnvelopeIsCipherText;
            } else {
                // Config messages should be sent directly rather than via this method (return just
                // the plaintext and no-op) See:
                // https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Sending%20%26%20Receiving/MessageSender.swift#L498
                enc.mode = Mode::Plaintext;
            }
        } break;

        case DestinationType::SyncMessage: {
            enc.mode = Mode::Envelope;
            enc.before_envelope_encrypt_for_recipient_deterministic = true;
            enc.envelope_type = SessionProtos::Envelope_Type::Envelope_Type_SESSION_MESSAGE;
            enc.after_envelope = AfterEnvelope::EnvelopeIsCipherText;
        } break;

        case DestinationType::OpenGroup: {
            enc.mode = Mode::Plaintext;
        } break;

        case DestinationType::OpenGroupInbox: {
            enc.mode = Mode::EncryptForBlindedRecipient;
        } break;
    }

    // Do the encryption work
    std::vector<uint8_t> result;
    switch (enc.mode) {
        case Mode::Envelope: {
            assert(enc.envelope_type.has_value());
            std::span<const uint8_t> src_text = plaintext;
            if (enc.before_envelope_encrypt_for_recipient_deterministic) {
                enc.before_envelope_ciphertext = session::encrypt_for_recipient_deterministic(
                        ed25519_privkey, dest.recipient_pubkey, plaintext);
                src_text = enc.before_envelope_ciphertext;
            }

            // Create envelope
            // Set sourcedevice to 1 as per:
            // https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Utilities/MessageWrapper.swift#L57
            SessionProtos::Envelope envelope = {};
            envelope.set_type(*enc.envelope_type);
            envelope.set_sourcedevice(1);
            envelope.set_timestamp(dest.sent_timestamp_ms.count());
            envelope.set_content(src_text.data(), src_text.size());
            if (enc.envelope_src)
                envelope.set_source(reinterpret_cast<const char*>(enc.envelope_src->data()), enc.envelope_src->size());
            if (dest.pro_sig)
                envelope.set_prosig(reinterpret_cast<const char*>(dest.pro_sig->data()), dest.pro_sig->size());

            switch (enc.after_envelope) {
                case AfterEnvelope::Nil:
                    assert(false && "Dev error, after envelope action was not set");
                    break;

                case AfterEnvelope::WrapInWSMessage: {
                    // Make request
                    WebSocketProtos::WebSocketRequestMessage req_msg = {};
                    req_msg.set_body(envelope.SerializeAsString());

                    // Put into message
                    WebSocketProtos::WebSocketMessage msg = {};
                    msg.set_type(
                            WebSocketProtos::WebSocketMessage_Type::WebSocketMessage_Type_REQUEST);
                    msg.set_allocated_request(&req_msg);

                    // Write message as ciphertext
                    result.resize(msg.ByteSizeLong());
                    msg.SerializeToArray(result.data(), result.size());
                } break;

                case AfterEnvelope::KeysEncryptMessage: {
                    assert(dest.closed_group_keys &&
                           "Dev error, API miuse was not detected. We should throw an exception "
                           "when this happens");

                    std::string bytes = envelope.SerializeAsString();
                    result = dest.closed_group_keys->encrypt_message(
                            std::span<uint8_t>(
                                    reinterpret_cast<uint8_t*>(bytes.data()), bytes.size()));
                } break;

                case AfterEnvelope::EnvelopeIsCipherText: {
                    result.resize(envelope.ByteSizeLong());
                    envelope.SerializeToArray(result.data(), result.size());
                } break;
            }
        } break;

        case Mode::Plaintext: {
            result = std::vector<uint8_t>(plaintext.begin(), plaintext.end());
        } break;

        case Mode::EncryptForBlindedRecipient: {
            result = encrypt_for_blinded_recipient(
                    ed25519_privkey,
                    dest.open_group_inbox_server_pubkey,
                    dest.recipient_pubkey,  // recipient blinded pubkey
                    plaintext);
        } break;
    }

    return result;
}

DecryptedEnvelope decrypt_envelope(
        std::span<const unsigned char> ed25519_privkey,
        std::span<const unsigned char> envelope_plaintext,
        std::chrono::sys_seconds unix_ts) {
    DecryptedEnvelope result = {};
    SessionProtos::Envelope envelope = {};
    if (!envelope.ParseFromArray(envelope_plaintext.data(), envelope_plaintext.size()))
        throw std::runtime_error{"Parse envelope from ciphertext failed"};

    // Parse type (unconditionallty)
    if (!envelope.has_type())
        throw std::runtime_error("Parse envelope failed, missing type");

    switch (envelope.type()) {
        case SessionProtos::Envelope_Type_SESSION_MESSAGE:
            result.envelope.type = EnvelopeType::SessionMessage;
            break;

        case SessionProtos::Envelope_Type_CLOSED_GROUP_MESSAGE:
            result.envelope.type = EnvelopeType::ClosedGroupMessage;
            break;
    }

    // Parse source (optional)
    if (envelope.has_source()) {
        // Libsession is now responsible for creating the envelope. The only data that we send in
        // the source is a Session public key (see: encrypt_for_namespaced_destination)
        const std::string& source = envelope.source();
        if (source.size() != result.envelope.source.max_size())
            throw std::runtime_error(
                    fmt::format(
                            "Parse envelope failed, source had unexpected size ({} bytes)",
                            source.size()));
        std::memcpy(result.envelope.source.data(), source.data(), source.size());
        result.envelope.flags |= EnvelopeFlags_Source;
    }

    // Parse source device (optional)
    if (envelope.has_sourcedevice()) {
        result.envelope.source_device = envelope.sourcedevice();
        result.envelope.flags |= EnvelopeFlags_SourceDevice;
    }

    // Parse server timestamp (optional)
    if (envelope.has_servertimestamp()) {
        result.envelope.server_timestamp = envelope.servertimestamp();
        result.envelope.flags |= EnvelopeFlags_ServerTimestamp;
    }

    // Parse content (unconditionallty)
    if (!envelope.has_content())
        throw std::runtime_error{"Parse decrypted message failed, missing content"};

    const std::string& content_str = envelope.content();
    auto content_span = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(content_str.data()), content_str.size());
    std::tie(result.content_plaintext, result.sender_ed25519_pubkey) =
            session::decrypt_incoming(ed25519_privkey, content_span);

    SessionProtos::Content content = {};
    if (!envelope.ParseFromArray(result.content_plaintext.data(), result.content_plaintext.size()))
        throw std::runtime_error{"Parse content from envelope failed"};

    if (content.has_promessage()) {
        // Parse the signature from the envelope if the content had a pro component to it
        if (!envelope.has_prosig())
            throw std::runtime_error("Parse envelope failed, pro message is missing signature");

        const std::string& pro_sig = envelope.prosig();
        if (pro_sig.size() != crypto_sign_ed25519_BYTES)
            throw std::runtime_error("Parse envelope failed, pro signature has wrong size");

        static_assert(sizeof(result.envelope.pro_sig) == crypto_sign_ed25519_BYTES);
        std::memcpy(result.envelope.pro_sig.data(), pro_sig.data(), pro_sig.size());
        result.envelope.flags |= EnvelopeFlags_ProSig;

        SessionProtos::ProMessage pro_msg = content.promessage();
        if (!pro_msg.has_proof())
            throw std::runtime_error("Parse decrypted message failed, pro config missing proof");
        if (!pro_msg.has_flags())
            throw std::runtime_error("Parse decrypted message failed, pro config missing flags");

        const SessionProtos::ProProof& proto_proof = pro_msg.proof();
        std::uint32_t proto_flags = pro_msg.flags();

        // Parse the proof from protobufs
        session::config::ProProof& proof = result.pro_proof;
        // clang-format off
        size_t proof_errors = 0;
        proof_errors += !proto_proof.has_version()           || proto_proof.version() != static_cast<std::uint32_t>(session::config::ProProofVersion_v0);
        proof_errors += !proto_proof.has_genindexhash()      || proto_proof.genindexhash().size() != proof.gen_index_hash.max_size();
        proof_errors += !proto_proof.has_rotatingpublickey() || proto_proof.rotatingpublickey().size() != proof.rotating_pubkey.max_size();
        proof_errors += !proto_proof.has_expiryunixts();
        proof_errors += !proto_proof.has_sig()               || proto_proof.sig().size() != proof.sig.max_size();
        // clang-format on
        if (proof_errors)
            throw std::runtime_error("Parse decrypted message failed, pro metadata was malformed");

        // Verify the sig since we have extracted the rotating public key from the embedded proof
        int verify_result = crypto_sign_ed25519_verify_detached(
                reinterpret_cast<const unsigned char*>(pro_sig.data()),
                reinterpret_cast<const unsigned char*>(content_str.data()),
                content_str.size(),
                reinterpret_cast<const unsigned char*>(proto_proof.rotatingpublickey().data()));
        if (verify_result != 0)
            throw std::runtime_error("Parse decrypted message failed, pro signature is invalid");

        // Fill out the resulting proof structure, we have parsed successfully
        result.pro_flags = proto_flags;
        std::memcpy(result.pro_sig.data(), pro_sig.data(), pro_sig.size());

        std::memcpy(
                proof.gen_index_hash.data(),
                proto_proof.genindexhash().data(),
                proto_proof.genindexhash().size());
        std::memcpy(
                proof.rotating_pubkey.data(),
                proto_proof.rotatingpublickey().data(),
                proto_proof.rotatingpublickey().size());
        proof.expiry_unix_ts =
                std::chrono::sys_seconds(std::chrono::seconds(proto_proof.expiryunixts()));
        std::memcpy(proof.sig.data(), proto_proof.sig().data(), proto_proof.sig().size());

        // Verify the at the proof is verified by the Session Pro Backend key (e.g.: It has been
        // authorised by the backend as having a valid backing payment).
        if (proof.verify(session::pro_backend::PUBKEY))
            result.pro_status = ProStatus::Valid;

        // Check if the proof has expired
        if (result.pro_status == ProStatus::Valid) {
            if (unix_ts >= result.pro_proof.expiry_unix_ts)
                result.pro_status = ProStatus::Expired;
        }
    }
    return result;
}
}  // namespace session
