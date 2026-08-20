#pragma once

#include <future>
#include <oxen/quic/loop.hpp>
#include <session/client.hpp>

namespace session::client {

/// A Client whose calls block until they have an answer, for callers that have nothing better to
/// be doing: tests, scripts, single-threaded tools.
///
/// This is a convenience, not the intended interface.  Client's methods hand their work to Core's
/// event loop and report through callbacks because that is what the work actually is; blocking on
/// them is a caller admitting it has no other thread to be useful on.  A UI must not do that — it
/// would stall its render thread against the network — which is why these are kept out of Client
/// rather than sitting alongside the asynchronous forms where they would be the easier thing to
/// reach for.
///
/// The wrappers deliberately hide the base class's versions rather than overloading them, so that
/// picking this class means picking it for everything.  Mixing the two is the worst of both: the
/// code reads as though it is asynchronous while blocking wherever it is convenient.  Anything
/// genuinely needing both can still qualify explicitly (`Client::send_message(...)`), which is
/// deliberately more effort than it looks.
///
/// **What is synchronous is the call, not the operation.**  `send_message` returns once the message
/// is stored, which is before it has reached anyone — and, with attachments, before anything has
/// even been uploaded.  Delivery is still reported through `callbacks` afterwards, so a caller
/// waiting on one of these has not waited for the send; it has waited to be told the send began.
class SyncClient : public Client {
  public:
    using Client::Client;

    std::vector<Conversation> conversations() {
        return core.loop().call_get([this] { return _conversations(); });
    }

    std::optional<Conversation> conversation(const ConversationId& id) {
        return core.loop().call_get([&] { return _conversation(id); });
    }

    Conversation create_conversation(const ConversationId& id) {
        _require_dm("create_conversation", id);
        return core.loop().call_get([&] { return _create_conversation(id); });
    }

    void mark_read(const ConversationId& id, std::optional<sys_ms> up_to = std::nullopt) {
        core.loop().call_get([&] { _mark_read(id, up_to); });
    }

    void set_priority(const ConversationId& id, int priority) {
        core.loop().call_get([&] { _set_priority(id, priority); });
    }

    void set_blocked(const ConversationId& id, bool blocked) {
        _require_dm("set_blocked", id);
        core.loop().call_get([&] { _set_blocked(id, blocked); });
    }

    void clear_messages(const ConversationId& id) {
        _require_dm("clear_messages", id);
        core.loop().call_get([&] { _clear_messages(id); });
    }

    void delete_conversation(const ConversationId& id, bool keep_messages = false) {
        _require_dm("delete_conversation", id);
        core.loop().call_get([&] { _delete_conversation(id, keep_messages); });
    }

    void delete_contact(const ConversationId& id) {
        _require_dm("delete_contact", id);
        core.loop().call_get([&] { _delete_contact(id); });
    }

    std::vector<Message> messages(
            const ConversationId& id,
            int limit = 50,
            std::optional<MessageCursor> before = std::nullopt) {
        return core.loop().call_get([&] { return _messages(id, limit, before); });
    }

    std::optional<Message> message(int64_t id) {
        return core.loop().call_get([&] { return _message(id); });
    }

    int64_t send_message(const ConversationId& id, std::string_view body) {
        _require_dm("send_message", id);
        return core.loop().call_get([&] { return _send_message(id, body); });
    }

    int64_t send_message(
            const ConversationId& id,
            std::string_view body,
            std::vector<OutgoingAttachment> attachments,
            std::function<
                    void(size_t index, int64_t sent, int64_t total, std::optional<int> result)>
                    on_upload = nullptr) {
        _require_dm("send_message", id);
        _require_readable(attachments);
        return core.loop().call_get(
                [&] { return _send_message(id, body, attachments, std::move(on_upload)); });
    }

    bool retry_send(
            int64_t message_id,
            std::function<
                    void(size_t index, int64_t sent, int64_t total, std::optional<int> result)>
                    on_upload = nullptr) {
        return core.loop().call_get([&] { return _retry_send(message_id, std::move(on_upload)); });
    }

    /// Unlike the rest of these, this waits for the whole operation and not merely its start: a
    /// save that returned as soon as the download began would tell a synchronous caller nothing
    /// they could use.  It returns when the file is on disk, and throws if it did not get there.
    ///
    /// Note this is the one wrapper that waits on the *callback* rather than on Core's loop, so it
    /// deadlocks if a dispatcher is set that posts back to this thread.  Not a combination that
    /// arises in practice -- an application with its own loop wants the asynchronous form -- but
    /// SyncClient with a dispatcher is a thing that can be typed.
    void save_attachment(
            int64_t message_id,
            size_t index,
            std::filesystem::path dest,
            std::function<
                    void(size_t index, int64_t done, int64_t total, std::optional<int> result)>
                    on_progress = nullptr,
            bool notify_sender = true) {
        std::promise<std::optional<std::string>> done;
        auto waiter = done.get_future();
        Client::save_attachment(
                message_id,
                index,
                std::move(dest),
                std::move(on_progress),
                [&done](std::optional<std::string> error) { done.set_value(std::move(error)); },
                notify_sender);
        if (auto error = waiter.get())
            throw std::runtime_error{*error};
    }
};

}  // namespace session::client
