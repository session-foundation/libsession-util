#include <fmt/core.h>
#include <oxenc/hex.h>
#include <session/config/groups/keys.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>

#include <session/config/groups/keys.hpp>
#include <session/config/namespaces.hpp>
#include <session/config/pro.hpp>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/session_protocol.hpp>
#include <session/util.hpp>

#include "SessionProtos.pb.h"
#include "WebSocketResources.pb.h"
#include "session/export.h"

namespace session {

PRO_FEATURES get_pro_features_for_msg(size_t msg_size, PRO_EXTRA_FEATURES extra) {
    PRO_FEATURES result = PRO_FEATURES_NIL;

    if (msg_size > PRO_STANDARD_CHARACTER_LIMIT)
        result |= PRO_FEATURES_10K_CHARACTER_LIMIT;

    if (extra & PRO_EXTRA_FEATURES_ANIMATED_AVATAR)
        result |= PRO_FEATURES_ANIMATED_AVATAR;

    if (extra & PRO_EXTRA_FEATURES_PRO_BADGE)
        result |= PRO_FEATURES_PRO_BADGE;

    assert((result & ~PRO_FEATURES_ALL) == 0);
    return result;
}

std::vector<uint8_t> encrypt_for_1o1(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        const array_uc33& recipient_pubkey,
        const std::optional<array_uc64>& pro_sig) {
    Destination dest = {};
    dest.type = DestinationType::ContactOrSyncMessage;
    dest.pro_sig = pro_sig;
    dest.sent_timestamp_ms = sent_timestamp;
    dest.recipient_pubkey = recipient_pubkey;
    std::vector<uint8_t> result = encrypt_for_destination(plaintext, ed25519_privkey, dest);
    return result;
}

std::vector<uint8_t> encrypt_for_community_inbox(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        const array_uc33& recipient_pubkey,
        const array_uc32& community_pubkey,
        const std::optional<array_uc64>& pro_sig) {
    Destination dest = {};
    dest.type = DestinationType::CommunityInbox;
    dest.pro_sig = pro_sig;
    dest.sent_timestamp_ms = sent_timestamp;
    dest.recipient_pubkey = recipient_pubkey;
    dest.community_inbox_server_pubkey = community_pubkey;
    std::vector<uint8_t> result = encrypt_for_destination(plaintext, ed25519_privkey, dest);
    return result;
}

std::vector<uint8_t> encrypt_for_group(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        const array_uc33& group_ed25519_pubkey,
        const cleared_uc32& group_ed25519_privkey,
        const std::optional<array_uc64>& pro_sig) {
    Destination dest = {};
    dest.type = DestinationType::Group;
    dest.pro_sig = pro_sig;
    dest.sent_timestamp_ms = sent_timestamp;
    dest.group_ed25519_pubkey = group_ed25519_pubkey;
    dest.group_ed25519_privkey = group_ed25519_privkey;
    std::vector<uint8_t> result = encrypt_for_destination(plaintext, ed25519_privkey, dest);
    return result;
}

// Interop between the C and CPP API. The C api will request malloc which writes to `ciphertext_c`.
// This pointer is taken verbatim and avoids requiring a copy from the CPP vector. The CPP api will
// steal the contents from `ciphertext_cpp`.
struct EncryptedForDestinationInternal {
    std::vector<uint8_t> ciphertext_cpp;
    span_u8 ciphertext_c;
};

enum class UseMalloc { No, Yes };
static EncryptedForDestinationInternal encrypt_for_destination_internal(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        DestinationType dest_type,
        std::span<const uint8_t> dest_pro_sig,
        std::span<const uint8_t> dest_recipient_pubkey,
        std::chrono::milliseconds dest_sent_timestamp_ms,
        std::span<const uint8_t> dest_community_inbox_server_pubkey,
        std::span<const uint8_t> dest_group_ed25519_pubkey,
        std::span<const uint8_t> dest_group_ed25519_privkey,
        UseMalloc use_malloc) {

    assert(dest_pro_sig.empty() || dest_pro_sig.size() == crypto_sign_ed25519_BYTES);
    assert(dest_recipient_pubkey.size() == 1 + crypto_sign_ed25519_PUBLICKEYBYTES);
    assert(dest_community_inbox_server_pubkey.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
    assert(dest_group_ed25519_pubkey.size() == 1 + crypto_sign_ed25519_PUBLICKEYBYTES);
    assert(dest_group_ed25519_privkey.size() == 32 || dest_group_ed25519_privkey.size() == 64);

    // All incoming arguments are passed in from typed, fixed-sized arrays so we do not need to
    // throw if these sizes are wrong. It being wrong would be a development error.

    EncryptedForDestinationInternal result = {};
    enum class Mode {
        Envelope,
        EncryptForBlindedRecipient,
    };

    // The step to partake after enveloping the content payload
    enum class AfterEnvelope {
        Nil,
        EnvelopeIsCipherText,  // No extra bit-mangling required after enveloping
        WrapInWSMessage,       // Wrap in the protobuf websocket message after enveloping
        KeysEncryptMessage,    // Encrypt with the group keys after ennveloping
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

        // Action to take after generating the envelope (e.g.: further encryption/wrapping)
        AfterEnvelope after_envelope;
    };

    // Figure out how to encrypt the message based on the destination and setup the encoding context
    EncodeContext enc = {};
    switch (dest_type) {
        case DestinationType::Group: {
            bool has_03_prefix =
                    dest_group_ed25519_pubkey[0] == static_cast<uint8_t>(SessionIDPrefix::group);
            if (has_03_prefix) {
                enc.mode = Mode::Envelope;
                enc.before_envelope_encrypt_for_recipient_deterministic = false;
                enc.after_envelope = AfterEnvelope::KeysEncryptMessage;
                enc.envelope_type =
                        SessionProtos::Envelope_Type::Envelope_Type_CLOSED_GROUP_MESSAGE;
            } else {
                // Legacy groups which have a 05 prefixed key
                throw std::runtime_error{
                        "Unsupported configuration, encrypting for a legacy group (0x05 prefix) is "
                        "no longer supported"};
            }
        } break;

        case DestinationType::ContactOrSyncMessage: {
            enc.mode = Mode::Envelope;
            enc.before_envelope_encrypt_for_recipient_deterministic = true;
            enc.envelope_type = SessionProtos::Envelope_Type::Envelope_Type_SESSION_MESSAGE;
            enc.after_envelope = AfterEnvelope::WrapInWSMessage;
        } break;

        case DestinationType::CommunityInbox: {
            enc.mode = Mode::EncryptForBlindedRecipient;
        } break;
    }

    // Do the encryption work
    switch (enc.mode) {
        case Mode::Envelope: {
            assert(enc.envelope_type.has_value());
            std::span<const uint8_t> content = plaintext;
            if (enc.before_envelope_encrypt_for_recipient_deterministic) {
                enc.before_envelope_ciphertext = session::encrypt_for_recipient_deterministic(
                        ed25519_privkey, dest_recipient_pubkey, content);
                content = enc.before_envelope_ciphertext;
            }

            // Create envelope
            // Set sourcedevice to 1 as per:
            // https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Utilities/MessageWrapper.swift#L57
            SessionProtos::Envelope envelope = {};
            envelope.set_type(*enc.envelope_type);
            envelope.set_sourcedevice(1);
            envelope.set_timestamp(dest_sent_timestamp_ms.count());
            envelope.set_content(content.data(), content.size());
            if (enc.envelope_src)
                envelope.set_source(
                        reinterpret_cast<const char*>(enc.envelope_src->data()),
                        enc.envelope_src->size());

            if (dest_pro_sig.empty()) {
                // If there's no pro signature specified, we still fill out the pro signature with a
                // dummy 64 byte stream. This is to make pro and non-pro messages indistinguishable.
                std::string* pro_sig = envelope.mutable_prosig();
                pro_sig->resize(sizeof(array_uc64));
                randombytes_buf(pro_sig->data(), pro_sig->size());
            } else {
                envelope.set_prosig(dest_pro_sig.data(), dest_pro_sig.size());
            }

            switch (enc.after_envelope) {
                case AfterEnvelope::Nil:
                    assert(false && "Dev error, after envelope action was not set");
                    break;

                case AfterEnvelope::KeysEncryptMessage: {
                    std::string bytes = envelope.SerializeAsString();
                    if (dest_group_ed25519_pubkey.size() == crypto_sign_ed25519_PUBLICKEYBYTES + 1)
                        dest_group_ed25519_pubkey = dest_group_ed25519_pubkey.subspan(1);

                    std::vector<uint8_t> ciphertext = encrypt_for_group(
                            ed25519_privkey,
                            dest_group_ed25519_pubkey,
                            dest_group_ed25519_privkey,
                            to_span(bytes),
                            /*compress*/ true,
                            /*padding*/ 256);

                    if (use_malloc == UseMalloc::Yes) {
                        result.ciphertext_c =
                                span_u8_copy_or_throw(ciphertext.data(), ciphertext.size());
                    } else {
                        result.ciphertext_cpp = std::move(ciphertext);
                    }
                } break;

                case AfterEnvelope::WrapInWSMessage: {
                    // Setup message
                    WebSocketProtos::WebSocketMessage msg = {};
                    msg.set_type(
                            WebSocketProtos::WebSocketMessage_Type::WebSocketMessage_Type_REQUEST);

                    // Make request
                    WebSocketProtos::WebSocketRequestMessage* req_msg = msg.mutable_request();
                    req_msg->set_body(envelope.SerializeAsString());

                    // Write message as ciphertext
                    [[maybe_unused]] bool serialized = false;
                    if (use_malloc == UseMalloc::Yes) {
                        result.ciphertext_c = span_u8_alloc_or_throw(msg.ByteSizeLong());
                        serialized = msg.SerializeToArray(
                                result.ciphertext_c.data, result.ciphertext_c.size);
                    } else {
                        result.ciphertext_cpp.resize(msg.ByteSizeLong());
                        serialized = msg.SerializeToArray(
                                result.ciphertext_cpp.data(), result.ciphertext_cpp.size());
                    }
                    assert(serialized);
                } break;

                case AfterEnvelope::EnvelopeIsCipherText: {
                    [[maybe_unused]] bool serialized = false;
                    if (use_malloc == UseMalloc::Yes) {
                        result.ciphertext_c = span_u8_alloc_or_throw(envelope.ByteSizeLong());
                        serialized = envelope.SerializeToArray(
                                result.ciphertext_c.data, result.ciphertext_c.size);
                    } else {
                        result.ciphertext_cpp.resize(envelope.ByteSizeLong());
                        serialized = envelope.SerializeToArray(
                                result.ciphertext_cpp.data(), result.ciphertext_cpp.size());
                    }
                    assert(serialized);
                } break;
            }

        } break;

        case Mode::EncryptForBlindedRecipient: {
            std::vector<uint8_t> ciphertext = encrypt_for_blinded_recipient(
                    ed25519_privkey,
                    dest_community_inbox_server_pubkey,
                    dest_recipient_pubkey,  // recipient blinded pubkey
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

std::vector<uint8_t> encrypt_for_destination(
        std::span<const unsigned char> plaintext,
        std::span<const unsigned char> ed25519_privkey,
        const Destination& dest) {

    EncryptedForDestinationInternal result_internal = encrypt_for_destination_internal(
            /*plaintext=*/plaintext,
            /*ed25519_privkey=*/ed25519_privkey,
            /*dest_type=*/dest.type,
            /*dest_pro_sig=*/dest.pro_sig ? *dest.pro_sig : std::span<const uint8_t>(),
            /*dest_recipient_pubkey=*/dest.recipient_pubkey,
            /*dest_sent_timestamp_ms=*/dest.sent_timestamp_ms,
            /*dest_community_inbox_server_pubkey=*/dest.community_inbox_server_pubkey,
            /*dest_group_ed25519_pubkey=*/dest.group_ed25519_pubkey,
            /*dest_group_ed25519_privkey=*/dest.group_ed25519_privkey,
            /*use_malloc=*/UseMalloc::No);

    std::vector<uint8_t> result = std::move(result_internal.ciphertext_cpp);
    return result;
}

DecryptedEnvelope decrypt_envelope(
        const DecryptEnvelopeKey& keys,
        std::span<const uint8_t> envelope_payload,
        std::chrono::sys_seconds unix_ts,
        const array_uc32& pro_backend_pubkey) {
    DecryptedEnvelope result = {};
    SessionProtos::Envelope envelope = {};
    std::span<const uint8_t> envelope_plaintext = envelope_payload;

    // The caller is indicating that the envelope_payload is encrypted, if the group keys are
    // provided. We will decrypt the payload to get the plaintext. In all other cases, the envelope
    // is assumed to be websocket wrapped
    std::vector<uint8_t> envelope_from_decrypted_groups;
    std::string envelope_from_websocket_message;
    if (keys.group_ed25519_pubkey) {
        // Decrypt using the keys
        DecryptGroupMessage decrypt = decrypt_group_message(
                keys.ed25519_privkeys, *keys.group_ed25519_pubkey, envelope_plaintext);

        if (decrypt.session_id.size() != ((crypto_sign_ed25519_PUBLICKEYBYTES + 1) * 2))
            throw std::runtime_error{fmt::format(
                    "Parse encrypted envelope failed, extracted session ID was wrong size: "
                    "{}",
                    decrypt.session_id.size())};

        // Update the plaintext to use the decrypted envelope
        envelope_from_decrypted_groups = std::move(decrypt.plaintext);
        envelope_plaintext = envelope_from_decrypted_groups;

        // Copy keys out
        assert(decrypt.session_id.starts_with("05"));
        oxenc::from_hex(
                decrypt.session_id.begin() + 2,
                decrypt.session_id.end() - 2,
                result.sender_x25519_pubkey.begin());
    } else {
        // Assumed to be a 1o1/sync message which is wrapped in a websocket message
        WebSocketProtos::WebSocketMessage ws_msg;
        if (!ws_msg.ParseFromArray(envelope_plaintext.data(), envelope_plaintext.size()))
            throw std::runtime_error{fmt::format(
                    "Parse websocket wrapped envelope from payload failed: {}",
                    envelope_plaintext.size())};

        if (!ws_msg.has_request())
            throw std::runtime_error{"Parse websocket wrapped envelope failed, missing request"};

        if (!ws_msg.request().has_body())
            throw std::runtime_error{
                    "Parse websocket wrapped envelope failed, missing request body"};

        WebSocketProtos::WebSocketRequestMessage* request = ws_msg.mutable_request();
        std::string* body = request->mutable_body();
        envelope_from_websocket_message = std::move(*body);
        envelope_plaintext = to_span(envelope_from_websocket_message);
    }

    if (!envelope.ParseFromArray(envelope_plaintext.data(), envelope_plaintext.size()))
        throw std::runtime_error{"Parse envelope from plaintext failed"};

    // TODO: We do not parse the envelop type anymore, we infer the type from
    // the namespace. Deciding whether or not we decrypt the envelope vs the content depends on
    // whether or not the group keys were passed in so we don't care about the type anymore.
    //
    // When the type is removed, we can remove this TODO. This is just a reminder as to why we skip
    // over that field but it's still in the schema and still being set on the sending side.

    // Parse source (optional)
    if (envelope.has_source()) {
        // Libsession is now responsible for creating the envelope. The only data that we send in
        // the source is a Session public key (see: encrypt_for_destination)
        const std::string& source = envelope.source();
        if (source.size() != result.envelope.source.max_size())
            throw std::runtime_error(fmt::format(
                    "Parse envelope failed, source had unexpected size ({} bytes)", source.size()));
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
    // The envelope is encrypted in GroupsV2, contents unencrypted. In 1o1 and legacy groups, the
    // envelope is encrypted, contents is encrypted.
    if (keys.group_ed25519_pubkey) {
        result.content_plaintext.resize(envelope.content().size());
        std::memcpy(
                result.content_plaintext.data(),
                envelope.content().data(),
                envelope.content().size());
    } else {
        const std::string& content = envelope.content();
        bool decrypt_success = false;
        std::vector<uint8_t> content_plaintext;
        std::vector<uint8_t> sender_ed25519_pubkey;
        for (const auto& privkey_it : keys.ed25519_privkeys) {
            try {
                std::tie(content_plaintext, sender_ed25519_pubkey) =
                        session::decrypt_incoming(privkey_it, to_span(content));
                assert(result.sender_ed25519_pubkey.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
                decrypt_success = true;
                break;
            } catch (...) {
            }
        }

        if (!decrypt_success) {
            throw std::runtime_error{fmt::format(
                    "Envelope content decryption failed, tried {} key(s)",
                    keys.ed25519_privkeys.size())};
        }

        result.content_plaintext = std::move(content_plaintext);
        std::memcpy(
                result.sender_ed25519_pubkey.data(),
                sender_ed25519_pubkey.data(),
                result.sender_ed25519_pubkey.size());

        if (crypto_sign_ed25519_pk_to_curve25519(
                    result.sender_x25519_pubkey.data(), result.sender_ed25519_pubkey.data()) != 0)
            throw std::runtime_error(
                    "Parse content failed, ed25519 public key could not be converted to x25519 "
                    "key.");
    }

    // TODO: We parse the content in libsession to extract pro metadata but we return the unparsed
    // blob back to the caller. This is temporary, eventually we will return a proxy structure for
    // the protobuf Content type to the user. We avoid returning the direct protobuf type to keep
    // the interface simple and avoid leaking protobuf implementation detail into the libsession
    // interface.
    SessionProtos::Content content = {};
    if (!content.ParseFromArray(result.content_plaintext.data(), result.content_plaintext.size()))
        throw std::runtime_error{fmt::format(
                "Parse content from envelope failed: {}", result.content_plaintext.size())};

    // A signature must always be present on the envelope. This is to make a pro and non-pro
    // envelope indistinguishable. If the message does not have pro then this signature must still
    // be set but will be ignored. So in all instances a signature must be attached (real or
    // dummy).
    //
    // TODO: However for backwards compatibility, so old client's sending their envelopes to new
    // clients won't have the pro signature set. We have to allow these for now until we
    // deprecate the supporting of messages from those clients. For forwards compatibility, the new
    // clients will send the message with the pro signature attached. The old clients will ignore
    // the new fields.
    //
    // This should be deprecated in about 1-2yrs from this message. 2025-08-18 doyle
    if (envelope.has_prosig()) {
        // Copy (maybe dummy) pro signature into our result struct
        const std::string& pro_sig = envelope.prosig();
        if (pro_sig.size() != crypto_sign_ed25519_BYTES)
            throw std::runtime_error("Parse envelope failed, pro signature has wrong size");
        static_assert(sizeof(result.envelope.pro_sig) == crypto_sign_ed25519_BYTES);
        std::memcpy(result.envelope.pro_sig.data(), pro_sig.data(), pro_sig.size());

        if (content.has_promessage()) {
            // Mark the envelope as having a pro signature that the caller can use.
            result.envelope.flags |= ENVELOPE_FLAGS_PRO_SIG;
            DecryptedPro& pro = result.pro.emplace();

            // Extract the pro message
            const SessionProtos::ProMessage& pro_msg = content.promessage();
            if (!pro_msg.has_proof())
                throw std::runtime_error(
                        "Parse decrypted message failed, pro config missing proof");
            if (!pro_msg.has_features())
                throw std::runtime_error(
                        "Parse decrypted message failed, pro config missing features");

            // Parse the proof from protobufs
            const SessionProtos::ProProof& proto_proof = pro_msg.proof();
            session::config::ProProof& proof = pro.proof;
            // clang-format off
            size_t proof_errors = 0;
            proof_errors += !proto_proof.has_version()           || proto_proof.version()                  != static_cast<std::uint32_t>(session::config::ProProofVersion_v0);
            proof_errors += !proto_proof.has_genindexhash()      || proto_proof.genindexhash().size()      != proof.gen_index_hash.max_size();
            proof_errors += !proto_proof.has_rotatingpublickey() || proto_proof.rotatingpublickey().size() != proof.rotating_pubkey.max_size();
            proof_errors += !proto_proof.has_expiryunixts();
            proof_errors += !proto_proof.has_sig()               || proto_proof.sig().size() != proof.sig.max_size();
            // clang-format on
            if (proof_errors)
                throw std::runtime_error(
                        "Parse decrypted message failed, pro metadata was malformed");

            // Fill out the resulting proof structure, we have parsed successfully
            pro.features = pro_msg.features();
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

            // Evaluate the pro status given the extracted components (was it signed, is it expired,
            // was the message signed validly?)
            config::ProSignedMessage signed_msg = {};
            signed_msg.sig = to_span(pro_sig);
            signed_msg.msg = result.content_plaintext;
            pro.status = proof.status(pro_backend_pubkey, unix_ts, signed_msg);
        }
    }
    return result;
}
}  // namespace session

using namespace session;

LIBSESSION_C_API
PRO_FEATURES session_protocol_get_pro_features_for_msg(size_t msg_size, PRO_EXTRA_FEATURES flags) {
    PRO_FEATURES result = get_pro_features_for_msg(msg_size, flags);
    return result;
}

LIBSESSION_C_API
session_protocol_encrypted_for_destination session_protocol_encrypt_for_1o1(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const bytes33* recipient_pubkey,
        const bytes64* pro_sig,
        char* error,
        size_t error_len) {

    session_protocol_destination dest = {};
    dest.type = DESTINATION_TYPE_CONTACT_OR_SYNC_MESSAGE;
    dest.pro_sig = pro_sig;
    dest.recipient_pubkey = *recipient_pubkey;
    dest.sent_timestamp_ms = sent_timestamp_ms;

    session_protocol_encrypted_for_destination result = session_protocol_encrypt_for_destination(
            plaintext,
            plaintext_len,
            ed25519_privkey,
            ed25519_privkey_len,
            &dest,
            error,
            error_len);
    return result;
}

LIBSESSION_C_API
session_protocol_encrypted_for_destination session_protocol_encrypt_for_community_inbox(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const bytes33* recipient_pubkey,
        const bytes32* community_pubkey,
        const bytes64* pro_sig,
        char* error,
        size_t error_len) {

    session_protocol_destination dest = {};
    dest.type = DESTINATION_TYPE_COMMUNITY_INBOX;
    dest.pro_sig = pro_sig;
    dest.sent_timestamp_ms = sent_timestamp_ms;
    dest.recipient_pubkey = *recipient_pubkey;
    dest.community_inbox_server_pubkey = *community_pubkey;

    session_protocol_encrypted_for_destination result = session_protocol_encrypt_for_destination(
            plaintext,
            plaintext_len,
            ed25519_privkey,
            ed25519_privkey_len,
            &dest,
            error,
            error_len);
    return result;
}

LIBSESSION_C_API
session_protocol_encrypted_for_destination session_protocol_encrypt_for_group(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const bytes33* group_ed25519_pubkey,
        const bytes32* group_ed25519_privkey,
        const bytes64* pro_sig,
        char* error,
        size_t error_len) {

    session_protocol_destination dest = {};
    dest.type = DESTINATION_TYPE_GROUP;
    dest.pro_sig = pro_sig;
    dest.group_ed25519_pubkey = *group_ed25519_pubkey;
    dest.group_ed25519_privkey = *group_ed25519_privkey;
    dest.sent_timestamp_ms = sent_timestamp_ms;

    session_protocol_encrypted_for_destination result = session_protocol_encrypt_for_destination(
            plaintext,
            plaintext_len,
            ed25519_privkey,
            ed25519_privkey_len,
            &dest,
            error,
            error_len);
    return result;
}

LIBSESSION_C_API session_protocol_encrypted_for_destination
session_protocol_encrypt_for_destination(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        const session_protocol_destination* dest,
        char* error,
        size_t error_len) {
    session_protocol_encrypted_for_destination result = {};
    try {
        EncryptedForDestinationInternal result_internal = encrypt_for_destination_internal(
                /*plaintext=*/{static_cast<const uint8_t*>(plaintext), plaintext_len},
                /*ed25519_privkey=*/
                {static_cast<const uint8_t*>(ed25519_privkey), ed25519_privkey_len},
                /*dest_type=*/static_cast<DestinationType>(dest->type),
                /*dest_pro_sig=*/dest->pro_sig ? dest->pro_sig->data : std::span<const uint8_t>(),
                /*dest_recipient_pubkey=*/dest->recipient_pubkey.data,
                /*dest_sent_timestamp_ms=*/std::chrono::milliseconds(dest->sent_timestamp_ms),
                /*dest_community_inbox_server_pubkey=*/dest->community_inbox_server_pubkey.data,
                /*dest_group_ed25519_pubkey=*/dest->group_ed25519_pubkey.data,
                /*dest_group_ed25519_privkey=*/dest->group_ed25519_privkey.data,
                /*use_malloc=*/UseMalloc::Yes);

        result = {
                .success = true,
                .ciphertext = result_internal.ciphertext_c,
        };
    } catch (const std::exception& e) {
        std::string error_cpp = e.what();
        result.error_len_incl_null_terminator = snprintf_bytes_written_clamped(
                                                        error,
                                                        error_len,
                                                        "%.*s",
                                                        static_cast<int>(error_cpp.size()),
                                                        error_cpp.data()) +
                                                1;
    }

    return result;
}

LIBSESSION_C_API void session_protocol_encrypt_for_destination_free(
        session_protocol_encrypted_for_destination* encrypt) {
    if (encrypt) {
        free(encrypt->ciphertext.data);
        *encrypt = {};
    }
}

LIBSESSION_C_API
session_protocol_decrypted_envelope session_protocol_decrypt_envelope(
        const session_protocol_decrypt_envelope_keys* keys,
        const void* envelope_plaintext,
        size_t envelope_plaintext_len,
        uint64_t unix_ts,
        const void* pro_backend_pubkey,
        size_t pro_backend_pubkey_len,
        char* error,
        size_t error_len) {
    session_protocol_decrypted_envelope result = {};

    // Setup the pro backend pubkey
    array_uc32 pro_backend_pubkey_cpp = {};
    if (pro_backend_pubkey) {
        if (pro_backend_pubkey_len != sizeof(pro_backend_pubkey_cpp)) {
            result.error_len_incl_null_terminator = snprintf_bytes_written_clamped(
                                                            error,
                                                            error_len,
                                                            "Invalid pro_backend_pubkey: Key was "
                                                            "set but was not 32 bytes, was: %zu",
                                                            pro_backend_pubkey_len) +
                                                    1;
            return result;
        }
        std::memcpy(pro_backend_pubkey_cpp.data(), pro_backend_pubkey, pro_backend_pubkey_len);
    }

    // Setup decryption keys and decrypt
    DecryptEnvelopeKey keys_cpp = {};
    if (keys->group_ed25519_pubkey.size) {
        keys_cpp.group_ed25519_pubkey = std::span<const uint8_t>(
                keys->group_ed25519_pubkey.data, keys->group_ed25519_pubkey.size);
    }

    DecryptedEnvelope result_cpp = {};
    for (size_t index = 0; index < keys->ed25519_privkeys_len; index++) {
        std::span<const uint8_t> key = {
                keys->ed25519_privkeys[index].data, keys->ed25519_privkeys[index].size};
        keys_cpp.ed25519_privkeys = {&key, 1};
        try {
            result_cpp = decrypt_envelope(
                    keys_cpp,
                    {static_cast<const uint8_t*>(envelope_plaintext), envelope_plaintext_len},
                    std::chrono::sys_seconds(std::chrono::seconds(unix_ts)),
                    pro_backend_pubkey_cpp);
            result.success = true;
            break;
        } catch (const std::exception& e) {
            std::string error_cpp = e.what();
            result.error_len_incl_null_terminator = snprintf_bytes_written_clamped(
                                                            error,
                                                            error_len,
                                                            "%.*s",
                                                            static_cast<int>(error_cpp.size()),
                                                            error_cpp.data()) +
                                                    1;
        }
    }

    if (keys->ed25519_privkeys_len == 0) {
        result.error_len_incl_null_terminator =
                snprintf_bytes_written_clamped(
                        error, error_len, "No keys ed25519_privkeys were provided") +
                1;
    }

    // Marshall into c type
    try {
        result.content_plaintext = span_u8_copy_or_throw(
                result_cpp.content_plaintext.data(), result_cpp.content_plaintext.size());
    } catch (const std::exception& e) {
        std::string error_cpp = e.what();
        result.success = false;
        result.error_len_incl_null_terminator = snprintf_bytes_written_clamped(
                                                        error,
                                                        error_len,
                                                        "%.*s",
                                                        static_cast<int>(error_cpp.size()),
                                                        error_cpp.data()) +
                                                1;
    }

    result.envelope.flags = result_cpp.envelope.flags;
    result.envelope.timestamp_ms = static_cast<uint64_t>(result_cpp.envelope.timestamp.count());
    result.envelope.source_device = result_cpp.envelope.source_device;
    result.envelope.server_timestamp = result_cpp.envelope.server_timestamp;

    if (result_cpp.pro) {
        const DecryptedPro& pro = *result_cpp.pro;
        result.pro_status = static_cast<PRO_STATUS>(pro.status);
        result.pro_proof.version = pro.proof.version;
        result.pro_proof.expiry_unix_ts =
                static_cast<uint64_t>(pro.proof.expiry_unix_ts.time_since_epoch().count());
        result.pro_features = pro.features;

        std::memcpy(
                result.pro_proof.gen_index_hash,
                pro.proof.gen_index_hash.data(),
                sizeof(result.pro_proof.gen_index_hash));
        std::memcpy(
                result.pro_proof.rotating_pubkey,
                pro.proof.rotating_pubkey.data(),
                sizeof(result.pro_proof.rotating_pubkey));
        std::memcpy(result.pro_proof.sig, pro.proof.sig.data(), sizeof(pro.proof.sig));
    }

    // Since we support multiple keys, if some of the keys failed but one of them succeeded, we will
    // zero out the error buffer to avoid conflating one of the failures when the function actually
    // succeeded.
    if (result.success)
        result.error_len_incl_null_terminator = 0;

    std::memcpy(
            result.envelope.source.data,
            result_cpp.envelope.source.data(),
            sizeof(result.envelope.source.data));
    std::memcpy(
            result.envelope.pro_sig.data,
            result_cpp.envelope.pro_sig.data(),
            sizeof(result.envelope.pro_sig.data));

    std::memcpy(
            result.sender_ed25519_pubkey.data,
            result_cpp.sender_ed25519_pubkey.data(),
            sizeof(result.sender_ed25519_pubkey.data));
    std::memcpy(
            result.sender_x25519_pubkey.data,
            result_cpp.sender_x25519_pubkey.data(),
            sizeof(result.sender_x25519_pubkey.data));

    return result;
}

LIBSESSION_C_API
void session_protocol_decrypt_envelope_free(session_protocol_decrypted_envelope* envelope) {
    if (envelope) {
        free(envelope->content_plaintext.data);
        *envelope = {};
    }
}
