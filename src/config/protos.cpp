#include "session/config/protos.hpp"

#include <oxen/log.hpp>
#include <oxenc/hex.h>

#include <array>
#include <stdexcept>
#include <vector>

#include "SessionProtos.pb.h"
#include "WebSocketResources.pb.h"
#include "session/session_encrypt.hpp"
#include "session/util.hpp"

namespace session::config::protos {

namespace {

    SessionProtos::SharedConfigMessage_Kind encode_namespace(session::config::Namespace t) {
        switch (t) {
            case session::config::Namespace::UserProfile:
                return SessionProtos::SharedConfigMessage_Kind_USER_PROFILE;
            case session::config::Namespace::Contacts:
                return SessionProtos::SharedConfigMessage_Kind_CONTACTS;
            case session::config::Namespace::ConvoInfoVolatile:
                return SessionProtos::SharedConfigMessage_Kind_CONVO_INFO_VOLATILE;
            case session::config::Namespace::UserGroups:
                return SessionProtos::SharedConfigMessage_Kind_USER_GROUPS;
            default:
                throw std::invalid_argument{
                        "Error: cannot encode invalid SharedConfigMessage type"};
        }
    }

}  // namespace

std::vector<std::byte> wrap_config(
        const ed25519::PrivKeySpan& ed25519_sk,
        std::span<const std::byte> data,
        int64_t seqno,
        config::Namespace t) {
    auto my_xpk = ed25519::pk_to_x25519(ed25519_sk.pubkey());

    if (static_cast<int16_t>(t) > 5)
        throw std::invalid_argument{"Error: received invalid outgoing SharedConfigMessage type"};

    // Wrap in a SharedConfigMessage inside a Content
    SessionProtos::Content config{};
    auto& shconf = *config.mutable_sharedconfigmessage();
    shconf.set_kind(encode_namespace(t));
    shconf.set_seqno(seqno);
    *shconf.mutable_data() = to_string_view(data);

    // Then we serialize that, pad it, and encrypt it.  Copying this relevant comment from the
    // Session codebase (the comment itself git blames to Signal):
    // NOTE: This is dumb.
    auto shared_conf = config.SerializeAsString();
    // Okay now let's talk about padding.  Remember, though:
    // NOTE: This is dumb.
    // Okay so to be more specific, padding adds a 0x80 byte followed by any number (including 0) of
    // 0x00 bytes.  The 0x80 byte, however, is always required (so there is always at least one
    // padding byte); for DMs, this gets pushed up to the next multiple of 160, hence the final
    // padded length we want, mathematically, is ⌈(x+1)/160⌉ * 160.  With integer division,
    // ceil(a/b) is (a+b-1)/b, so for a=x+1 we get: (x+1+b-1)/b*b = (x+b)/b*b = (x/b + 1)*b.
    //
#if 0
    const size_t unpadded_size = shared_conf.size();
    const size_t padded_size = (unpadded_size / 160 + 1) * 160;
    assert(padded_size > shared_conf.size());
    shared_conf.resize(padded_size);
    shared_conf[unpadded_size] = 0x80;
#else
    // But this is all moot for a config message which is *already* padded to a multiple of 256, so
    // just tack on the 0x80 and no 0x00s rather than making it bigger still.
    shared_conf += '\x80';
#endif

    // Now we encrypt using the session protocol encryption, but with sender == recipient ==
    // ourself.  This is unnecessary because the inner content is already encrypted with a value
    // derived from our private key, but old Session clients expect this.
    // NOTE: This is dumb.
    auto enc_shared_conf = encrypt_for_recipient_deterministic(
            ed25519_sk, my_xpk, to_span<std::byte>(shared_conf));

    // This is the point in session client code where this value got base64-encoded, passed to
    // another function, which then base64-decoded that value to put into the envelope.  We're going
    // to skip that step here: fingers crossed!!!
    // enc_shared_conf = oxenc::from_base64(oxenc::to_base64(enc_shared_conf));
    // NOTE: This is dumb.

    // Now we just keep on trucking with more protobuf:
    auto envelope = SessionProtos::Envelope();
    *envelope.mutable_content() = to_string_view(enc_shared_conf);
    envelope.set_timestamp(1);  // Old session clients with their own unwrapping require this > 0
    envelope.set_type(SessionProtos::Envelope_Type::Envelope_Type_SESSION_MESSAGE);

    // And more protobuf (even though this no one cares about anything other than the body in this
    // one):
    // NOTE: This is dumb.
    auto webreq = WebSocketProtos::WebSocketRequestMessage();
    webreq.set_verb("");
    webreq.set_path("");
    webreq.set_requestid(0);
    *webreq.mutable_body() = envelope.SerializeAsString();

    // And then yet more protobuf (even though this no one cares about anything other than the body
    // in this one, again):
    // NOTE: This is dumb.
    auto msg = WebSocketProtos::WebSocketMessage();
    msg.set_type(WebSocketProtos::WebSocketMessage_Type_REQUEST);
    *msg.mutable_request() = webreq;

    return to_vector<std::byte>(msg.SerializeAsString());
}

std::vector<std::byte> unwrap_config(
        const ed25519::PrivKeySpan& ed25519_sk,
        std::span<const std::byte> data,
        config::Namespace ns) {
    // Hurray, we get to undo everything from the above!

    auto ed25519_pk = ed25519_sk.pubkey();

    WebSocketProtos::WebSocketMessage req{};

    if (!req.ParseFromArray(data.data(), data.size()))
        throw std::runtime_error{"Failed to parse WebSocketMessage"};

    if (req.type() != WebSocketProtos::WebSocketMessage_Type_REQUEST)
        throw std::runtime_error{"Error: received invalid WebSocketRequest"};

    SessionProtos::Envelope envelope{};
    if (!envelope.ParseFromString(req.request().body()))
        throw std::runtime_error{"Failed to parse Envelope"};

    auto [content, sender] = decrypt_incoming(ed25519_sk, to_span<std::byte>(envelope.content()));
    if (to_string_view(sender) != to_string_view(ed25519_pk))
        throw std::runtime_error{"Incoming config data was not from us; ignoring"};

    if (content.empty())
        throw std::runtime_error{"Incoming config data decrypted to empty string"};

    if (!(content.back() == std::byte{0x00} || content.back() == std::byte{0x80}))
        throw std::runtime_error{"Incoming config data doesn't have required padding"};

    if (auto it = std::find_if(
                content.rbegin(), content.rend(), [](std::byte c) { return c != std::byte{0}; });
        it != content.rend() && *it == std::byte{0x80})
        content.resize(content.size() - std::distance(content.rbegin(), it) - 1);
    else
        throw std::runtime_error{"Incoming config data has invalid padding"};

    SessionProtos::Content config{};
    if (!config.ParseFromArray(content.data(), content.size()))
        throw std::runtime_error{"Failed to parse SharedConfig"};

    if (!config.has_sharedconfigmessage())
        throw std::runtime_error{"Content is missing a SharedConfigMessage"};
    auto& shconf = config.sharedconfigmessage();
    if (shconf.kind() != encode_namespace(ns))
        throw std::runtime_error{"SharedConfig has wrong kind for config namespace"};

    // if ParseFromString fails, we have a raw (not protobuf encoded) message
    return to_vector<std::byte>(shconf.data());
}

}  // namespace session::config::protos
