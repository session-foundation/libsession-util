#include <fmt/core.h>
#include <session/config/groups/keys.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>

#include <session/config/groups/keys.hpp>
#include <session/config/namespaces.hpp>
#include <session/config/pro.hpp>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/session_protocol.hpp>

#include "SessionProtos.pb.h"
#include "WebSocketResources.pb.h"
#include "session/export.h"

namespace session {

PRO_FEATURES get_pro_features_for_msg(std::span<const uint8_t> msg, PRO_EXTRA_FEATURES extra) {
    PRO_FEATURES result = PRO_FEATURES_NIL;

    if (msg.size() >= PRO_STANDARD_CHARACTER_LIMIT)
        result |= PRO_FEATURES_10K_CHARACTER_LIMIT;

    if (extra & PRO_EXTRA_FEATURES_ANIMATED_AVATAR)
        result |= PRO_FEATURES_ANIMATED_AVATAR;

    if (extra & PRO_EXTRA_FEATURES_PRO_BADGE)
        result |= PRO_FEATURES_PRO_BADGE;

    assert((result & ~PRO_FEATURES_ALL) == 0);
    return result;
}

// Interop between the C and CPP API. The C api will request malloc which writes to `ciphertext_c`.
// This pointer is taken verbatim and avoids requiring a copy from the CPP vector. The CPP api will
// steal the contents from `ciphertext_cpp`.
struct EncryptedForDestinationInternal {
    bool encrypted;
    std::vector<uint8_t> ciphertext_cpp;
    span_u8 ciphertext_c;
};

enum class UseMalloc { No, Yes };
static EncryptedForDestinationInternal encrypt_for_destination_internal(
        const std::span<const uint8_t> plaintext,
        const std::span<const uint8_t> ed25519_privkey,
        DestinationType dest_type,
        const uint8_t* dest_pro_sig,
        const uint8_t* dest_recipient_pubkey,
        std::chrono::milliseconds dest_sent_timestamp_ms,
        const uint8_t* dest_open_group_inbox_server_pubkey,
        const uint8_t* dest_closed_group_pubkey,
        const config::groups::Keys* dest_closed_group_keys,
        const uint8_t* dest_closed_group_public_key,
        config::Namespace space,
        UseMalloc use_malloc) {

    // All incoming arguments are passed in from typed, fixed-sized arrays so we do not check
    // the pointer lengths of those arguments.
    EncryptedForDestinationInternal result = {};
    enum class Mode {
        Envelope,
        Plaintext,
        EncryptForBlindedRecipient,
    };

    // The step to partake after enveloping the content payload
    enum class AfterEnvelope {
        Nil,
        EnvelopeIsCipherText,  // No extra bit-mangling required after enveloping
        WrapInWSMessage,       // Wrap in the protobuf websocket message after enveloping
        KeysEncryptMessage,    // Encrypt with the closed group keys after ennveloping
    };

    struct EncodeContext {
        Mode mode;
        // Parameters for BuildMode => Envelope
        bool before_envelope_encrypt_for_recipient_deterministic;

        // Ciphertext storing the result of encrypt for recipient deterministic, if it was necessary
        // to encrypt before enveloping.
        std::vector<uint8_t> before_envelope_ciphertext;

        // Payload to set the envelope source if necessary.
        std::optional<std::span<const uint8_t>> envelope_src;

        // Type of message to mark the enevelope as
        std::optional<SessionProtos::Envelope_Type> envelope_type;
        AfterEnvelope after_envelope;
    };

    // Figure out how to encrypt the message based on the destination and setup the encoding context
    EncodeContext enc = {};
    switch (dest_type) {
        case DestinationType::ClosedGroup: {
            bool has_03_prefix =
                    dest_closed_group_pubkey[0] == static_cast<uint8_t>(SessionIDPrefix::group);
            if (has_03_prefix) {
                if (space == config::Namespace::GroupMessages) {
                    if (!dest_closed_group_keys)
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
                // Legacy closed groups which have a 05 prefixed key
                enc.mode = Mode::Envelope;
                enc.before_envelope_encrypt_for_recipient_deterministic = true;
                enc.envelope_type =
                        SessionProtos::Envelope_Type::Envelope_Type_CLOSED_GROUP_MESSAGE;
                enc.after_envelope = AfterEnvelope::WrapInWSMessage;

                if (!dest_closed_group_public_key)
                    throw std::runtime_error(
                            "API misuse: Closed group public key must be set on non 0x03 prefixed "
                            "group keys");
                enc.envelope_src = {dest_closed_group_public_key, sizeof(array_uc33)};
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
    switch (enc.mode) {
        case Mode::Envelope: {
            assert(enc.envelope_type.has_value());
            std::span<const uint8_t> src_text = plaintext;
            if (enc.before_envelope_encrypt_for_recipient_deterministic) {
                enc.before_envelope_ciphertext = session::encrypt_for_recipient_deterministic(
                        ed25519_privkey, {dest_recipient_pubkey, sizeof(array_uc32)}, src_text);
                src_text = enc.before_envelope_ciphertext;
            }

            // Create envelope
            // Set sourcedevice to 1 as per:
            // https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Utilities/MessageWrapper.swift#L57
            SessionProtos::Envelope envelope = {};
            envelope.set_type(*enc.envelope_type);
            envelope.set_sourcedevice(1);
            envelope.set_timestamp(dest_sent_timestamp_ms.count());
            envelope.set_content(src_text.data(), src_text.size());
            if (enc.envelope_src)
                envelope.set_source(
                        reinterpret_cast<const char*>(enc.envelope_src->data()),
                        enc.envelope_src->size());

            if (dest_pro_sig) {
                envelope.set_prosig(
                        reinterpret_cast<const char*>(dest_pro_sig), sizeof(array_uc64));
            } else {
                // If there's no pro signature specified, we still fill out the pro signature with a
                // dummy 64 byte stream. This is to make pro and non-pro messages indistinguishable.
                std::string *pro_sig = envelope.mutable_prosig();
                pro_sig->resize(sizeof(array_uc64));
                randombytes_buf(pro_sig->data(), pro_sig->size());
            }

            result.encrypted = true;
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
                    void* dest = nullptr;
                    if (use_malloc == UseMalloc::Yes) {
                        result.ciphertext_c = span_u8_alloc_or_throw(envelope.ByteSizeLong());
                        msg.SerializeToArray(result.ciphertext_c.data, result.ciphertext_c.size);
                    } else {
                        result.ciphertext_cpp.resize(msg.ByteSizeLong());
                        msg.SerializeToArray(
                                result.ciphertext_cpp.data(), result.ciphertext_cpp.size());
                    }
                } break;

                case AfterEnvelope::KeysEncryptMessage: {
                    assert(dest_closed_group_keys &&
                           "Dev error, API miuse was not detected. We should throw an exception "
                           "when this happens earlier");

                    std::string bytes = envelope.SerializeAsString();
                    std::vector<uint8_t> ciphertext = dest_closed_group_keys->encrypt_message(
                            {reinterpret_cast<uint8_t*>(bytes.data()), bytes.size()});
                    if (use_malloc == UseMalloc::Yes) {
                        result.ciphertext_c =
                                span_u8_copy_or_throw(ciphertext.data(), ciphertext.size());
                    } else {
                        result.ciphertext_cpp = std::move(ciphertext);
                    }
                } break;

                case AfterEnvelope::EnvelopeIsCipherText: {
                    if (use_malloc == UseMalloc::Yes) {
                        result.ciphertext_c = span_u8_alloc_or_throw(envelope.ByteSizeLong());
                        envelope.SerializeToArray(
                                result.ciphertext_c.data, result.ciphertext_c.size);
                    } else {
                        result.ciphertext_cpp.resize(envelope.ByteSizeLong());
                        envelope.SerializeToArray(
                                result.ciphertext_cpp.data(), result.ciphertext_cpp.size());
                    }
                } break;
            }

        } break;

        case Mode::Plaintext: {
            // No-op. We do not populate the ciphertext because there was no encryption.
        } break;

        case Mode::EncryptForBlindedRecipient: {
            result.encrypted = true;
            std::vector<uint8_t> ciphertext = encrypt_for_blinded_recipient(
                    ed25519_privkey,
                    {dest_open_group_inbox_server_pubkey, sizeof(array_uc32)},
                    {dest_recipient_pubkey, sizeof(array_uc32)},  // recipient blinded pubkey
                    plaintext);

            if (use_malloc == UseMalloc::Yes) {
                result.ciphertext_c = span_u8_copy_or_throw(ciphertext.data(), ciphertext.size());
            } else {
                result.ciphertext_cpp = std::move(ciphertext);
            }
        } break;
    }

    return result;
}

EncryptedForDestination encrypt_for_destination(
        std::span<const unsigned char> plaintext,
        std::span<const unsigned char> ed25519_privkey,
        const Destination& dest,
        config::Namespace space) {

    EncryptedForDestinationInternal result_internal = encrypt_for_destination_internal(
            /*plaintext=*/plaintext,
            /*ed25519_privkey=*/ed25519_privkey,
            /*dest_type=*/dest.type,
            /*dest_pro_sig=*/dest.pro_sig ? dest.pro_sig->data() : nullptr,
            /*dest_recipient_pubkey=*/dest.recipient_pubkey.data(),
            /*dest_sent_timestamp_ms=*/dest.sent_timestamp_ms,
            /*dest_open_group_inbox_server_pubkey=*/dest.open_group_inbox_server_pubkey.data(),
            /*dest_closed_group_pubkey=*/dest.closed_group_pubkey.data(),
            /*dest_closed_group_keys=*/dest.closed_group_keys,
            /*dest_closed_group_swarm_public_key=*/dest.closed_group_public_key
                    ? dest.closed_group_public_key->data()
                    : nullptr,
            /*space=*/space,
            /*use_malloc=*/UseMalloc::No);

    EncryptedForDestination result = {
            .encrypted = result_internal.encrypted,
            .ciphertext = std::move(result_internal.ciphertext_cpp),
    };
    return result;
}

struct DecryptedEnvelopeInternal {
    Envelope envelope;
    std::vector<uint8_t> content_plaintext;
    std::vector<uint8_t> sender_ed25519_pubkey;
    ProStatus pro_status;
    config::ProProof pro_proof;
    PRO_FEATURES pro_features;
};

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
        // the source is a Session public key (see: encrypt_for_destination)
        const std::string& source = envelope.source();
        if (source.size() != result.envelope.source.max_size())
            throw std::runtime_error(
                    fmt::format(
                            "Parse envelope failed, source had unexpected size ({} bytes)",
                            source.size()));
        std::memcpy(result.envelope.source.data(), source.data(), source.size());
        result.envelope.flags |= ENVELOPE_FLAGS_SOURCE;
    }

    // Parse source device (optional)
    if (envelope.has_sourcedevice()) {
        result.envelope.source_device = envelope.sourcedevice();
        result.envelope.flags |= ENVELOPE_FLAGS_SOURCE_DEVICE;
    }

    // Parse server timestamp (optional)
    if (envelope.has_servertimestamp()) {
        result.envelope.server_timestamp = envelope.servertimestamp();
        result.envelope.flags |= ENVELOPE_FLAGS_SERVER_TIMESTAMP;
    }

    // Parse content
    if (!envelope.has_content())
        throw std::runtime_error{"Parse decrypted message failed, missing content"};

    // Decrypt content
    const std::string& content_str = envelope.content();
    auto content_span = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(content_str.data()), content_str.size());
    auto [content_plaintext, sender_ed25519_pubkey] =
            session::decrypt_incoming(ed25519_privkey, content_span);
    assert(result.sender_ed25519_pubkey.size() == crypto_sign_ed25519_PUBLICKEYBYTES);

    result.content_plaintext = std::move(content_plaintext);
    std::memcpy(
            result.sender_ed25519_pubkey.data(),
            sender_ed25519_pubkey.data(),
            result.sender_ed25519_pubkey.size());

    // TODO: We parse the content in libsession to extract pro metadata but we return the unparsed
    // blob back to the caller. This is temporary, eventually we will return a proxy structure for
    // the protobuf Content type to the user. We avoid returning the direct protobuf type to keep
    // the interface simple and avoid leaking protobuf implementation detail into the libsession
    // interface.
    SessionProtos::Content content = {};
    if (!envelope.ParseFromArray(result.content_plaintext.data(), result.content_plaintext.size()))
        throw std::runtime_error{"Parse content from envelope failed"};

    // A signature must always be present on the envelope. This is to make a pro and non-pro
    // envelope indistinguishable. If the message does not have pro then this signature must still
    // be set but will be ignored. So in all instances a signature must be attached (real or
    // dummy).
    if (!envelope.has_prosig())
        throw std::runtime_error("Parse envelope failed, pro message is missing signature");

    const std::string& pro_sig = envelope.prosig();
    if (pro_sig.size() != crypto_sign_ed25519_BYTES)
        throw std::runtime_error("Parse envelope failed, pro signature has wrong size");
    static_assert(sizeof(result.envelope.pro_sig) == crypto_sign_ed25519_BYTES);

    std::memcpy(result.envelope.pro_sig.data(), pro_sig.data(), pro_sig.size());

    if (content.has_promessage()) {
        // Mark the envelope as having a pro signature that the caller can use.
        result.envelope.flags |= ENVELOPE_FLAGS_PRO_SIG;

        // Extract the pro message
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
        result.pro_status = verify_result == 0 ? ProStatus::Valid : ProStatus::Invalid;

        // Fill out the resulting proof structure, we have parsed successfully
        result.pro_features = proto_flags;
        std::memcpy(result.envelope.pro_sig.data(), pro_sig.data(), pro_sig.size());

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

        if (result.pro_status == ProStatus::Valid) {
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
    }
    return result;
}
}  // namespace session

using namespace session;

LIBSESSION_EXPORT
PRO_FEATURES session_protocol_get_pro_features_for_msg(const span_u8 msg, PRO_FEATURES flags) {
    PRO_FEATURES result = get_pro_features_for_msg({msg.data, msg.size}, flags);
    return result;
}

LIBSESSION_EXPORT session_protocol_encrypted_for_destination
session_protocol_encrypt_for_destination(
        const span_u8 plaintext,
        const span_u8 ed25519_privkey,
        const session_protocol_destination* dest,
        NAMESPACE space) {
    session_protocol_encrypted_for_destination result = {};
    try {
        EncryptedForDestinationInternal result_internal = encrypt_for_destination_internal(
                /*plaintext=*/{plaintext.data, plaintext.size},
                /*ed25519_privkey=*/{ed25519_privkey.data, ed25519_privkey.size},
                /*dest_type=*/static_cast<DestinationType>(dest->type),
                /*dest_pro_sig=*/dest->has_pro_sig ? dest->pro_sig : nullptr,
                /*dest_recipient_pubkey=*/dest->recipient_pubkey,
                /*dest_sent_timestamp_ms=*/std::chrono::milliseconds(dest->sent_timestamp_ms),
                /*dest_open_group_inbox_server_pubkey=*/dest->open_group_inbox_server_pubkey,
                /*dest_closed_group_pubkey=*/dest->closed_group_pubkey,
                /*dest_closed_group_keys=*/
                static_cast<const config::groups::Keys*>(dest->closed_group_keys->internals),
                /*dest_closed_group_swarm_public_key=*/dest->has_closed_group_public_key
                        ? dest->closed_group_public_key
                        : nullptr,
                /*space=*/static_cast<config::Namespace>(space),
                /*use_malloc=*/UseMalloc::Yes);

        result = {
                .success = true,
                .encrypted = result_internal.encrypted,
                .ciphertext = result_internal.ciphertext_c,
        };
    } catch (...) {
    }

    return result;
}

LIBSESSION_EXPORT
session_protocol_decrypted_envelope session_protocol_decrypt_envelope(
        const span_u8 ed25519_privkey, const span_u8 envelope_plaintext, uint64_t unix_ts) {
    session_protocol_decrypted_envelope result = {};
    try {
        DecryptedEnvelope result_cpp = decrypt_envelope(
                {ed25519_privkey.data, ed25519_privkey.size},
                {envelope_plaintext.data, envelope_plaintext.size},
                std::chrono::sys_seconds(std::chrono::seconds(unix_ts)));

        // Marshall into c type
        result = {
                .success = false,
                .envelope =
                        {
                                .flags = result_cpp.envelope.flags,
                                .type = static_cast<ENVELOPE_TYPE>(result_cpp.envelope.type),
                                .timestamp_ms = static_cast<uint64_t>(
                                        result_cpp.envelope.timestamp.count()),
                                .source = {},
                                .source_device = result_cpp.envelope.source_device,
                                .server_timestamp = result_cpp.envelope.server_timestamp,
                                .pro_sig = {},
                        },
                .content_plaintext = {},
                .sender_ed25519_pubkey = {},
                .pro_status = static_cast<PRO_STATUS>(result_cpp.pro_status),
                .pro_proof =
                        {
                                .version = result_cpp.pro_proof.version,
                                .gen_index_hash = {},
                                .rotating_pubkey = {},
                                .expiry_unix_ts = static_cast<uint64_t>(
                                        result_cpp.pro_proof.expiry_unix_ts.time_since_epoch()
                                                .count()),
                                .sig = {},
                        },
                .pro_features = result_cpp.pro_features};

        std::memcpy(
                result.envelope.source,
                result_cpp.envelope.source.data(),
                sizeof(result.envelope.source));
        std::memcpy(
                result.envelope.pro_sig,
                result_cpp.envelope.pro_sig.data(),
                sizeof(result.envelope.pro_sig));

        result.content_plaintext = span_u8_copy_or_throw(
                result_cpp.content_plaintext.data(), result_cpp.content_plaintext.size());
        std::memcpy(
                result.sender_ed25519_pubkey,
                result_cpp.sender_ed25519_pubkey.data(),
                sizeof(result.sender_ed25519_pubkey));

        std::memcpy(
                result.pro_proof.gen_index_hash,
                result_cpp.pro_proof.gen_index_hash.data(),
                sizeof(result.pro_proof.gen_index_hash));
        std::memcpy(
                result.pro_proof.rotating_pubkey,
                result_cpp.pro_proof.rotating_pubkey.data(),
                sizeof(result.pro_proof.rotating_pubkey));
        std::memcpy(
                result.pro_proof.sig,
                result_cpp.pro_proof.sig.data(),
                sizeof(result.pro_proof.sig));

        result.success = true;
    } catch (...) {
    }

    return result;
}
