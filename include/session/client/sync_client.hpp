#pragma once

#include <session/client.hpp>

namespace session::client {

/// A Client whose entry points block, for callers that have nothing better to be doing: tests,
/// scripts, single-threaded tools.
///
/// Sugar, and nothing more: every one of these is `Client`'s own call with `wait` supplied.  It
/// guarantees nothing — a `Conversation` obtained from one of these carries both forms, as it does
/// however you came by it, so holding this class rather than a `Client` does not stop anything from
/// blocking or make anything block that would not have.
///
/// It used to mean more than that.  Before the operations moved onto `Conversation` this hid
/// `Client`'s asynchronous methods so that choosing the class chose the style for everything, which
/// was worth having; that is no longer possible to enforce and so no longer claimed.  `wait_t` is
/// what marks a blocking call now, and it does it where the call is rather than where the variable
/// was declared.
///
/// **What is synchronous is the call, not the operation.**  `send_message` returns once the message
/// is stored, which is before it has reached anyone — and, with attachments, before anything has
/// even been uploaded.  Delivery is still reported through `callbacks` afterwards, so a caller
/// waiting on one of these has not waited for the send; it has waited to be told the send began.
class SyncClient : public Client {
  public:
    using Client::Client;

    std::vector<AnyConversation> conversations() { return Client::conversations(wait); }
    std::vector<AnyConversation> message_requests() { return Client::message_requests(wait); }

    std::optional<AnyConversation> conversation(const ConversationId& id) {
        return Client::conversation(id, wait);
    }
    std::optional<DM> dm(const ConversationId& id) { return Client::dm(id, wait); }
    DM open_dm(const ConversationId& id) { return Client::open_dm(id, wait); }

    std::optional<Message> message(int64_t id) { return Client::message(id, wait); }

    int64_t send_message(const ConversationId& id, std::string_view body) {
        return Client::send_message(id, body, wait);
    }
    int64_t send_message(
            const ConversationId& id,
            std::string_view body,
            std::vector<OutgoingAttachment> attachments,
            Conversation::upload_progress on_upload = nullptr) {
        return Client::send_message(id, body, std::move(attachments), std::move(on_upload), wait);
    }

    bool retry_send(int64_t message_id, Conversation::upload_progress on_upload = nullptr) {
        bool ok = false;
        std::optional<std::string> error;
        core.loop().call_get([&] {
            Client::retry_send(message_id, std::move(on_upload), [&](auto err, bool r) {
                error = std::move(err);
                ok = r;
            });
            return 0;
        });
        if (error)
            throw std::runtime_error{*error};
        return ok;
    }
};

}  // namespace session::client
