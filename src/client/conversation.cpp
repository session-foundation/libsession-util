#include <session/client.hpp>

// Every operation here is one line of dispatch onto a `_`-form on Client: the work itself lives
// there, next to the rest of what touches the database, and this file is only about which thread it
// happens on and who is told.  The pairing is mechanical -- a handler form hands the work to
// `_async`, a waiting form hands it to the loop and lets it throw -- which is why they are together
// rather than split by direction.
//
// **A handler form must not capture `this`.**  It returns before the work runs, and the caller is
// under no obligation to keep this object alive until then: the natural way to write any of these is
// on a temporary (`client.conversation(id, …)` hands one to a handler, and
// `*client.conversation(id, wait)` is a temporary outright), and a list element dies whenever the
// list is replaced.  So each captures the two things the work needs -- the Client, which outlives
// everything here, and the id, which is a value -- and nothing else.  Capturing `this` reads the id
// out of freed memory, which surfaces as a `ConversationId::Type` outside the enum and an
// "unhandled conversation kind" from a long way away.
//
// The waiting forms are exempt: `call_get` runs the work before returning, inline when it is already
// the loop's thread, so there is no window in which the object could have gone.  That asymmetry is
// also why tests written entirely in the waiting form prove nothing about the handler form.

namespace session::client {

// -- Reading ------------------------------------------------------------------------------------

void Conversation::messages(failable_function<void(std::vector<Message>)> cb) const {
    messages(50, std::nullopt, std::move(cb));
}
void Conversation::messages(int limit, failable_function<void(std::vector<Message>)> cb) const {
    messages(limit, std::nullopt, std::move(cb));
}
void Conversation::messages(
        int limit,
        std::optional<MessageCursor> before,
        failable_function<void(std::vector<Message>)> cb) const {
    messages(limit, before, false, std::move(cb));
}
void Conversation::messages(
        int limit,
        std::optional<MessageCursor> before,
        bool include_deleted,
        failable_function<void(std::vector<Message>)> cb) const {
    _client->_async(
            [c = _client, id = id, limit, before, include_deleted] {
                return c->_messages(id, limit, before, include_deleted);
            },
            std::move(cb));
}

std::vector<Message> Conversation::messages(wait_t) const {
    return messages(50, std::nullopt, wait);
}
std::vector<Message> Conversation::messages(int limit, wait_t) const {
    return messages(limit, std::nullopt, wait);
}
std::vector<Message> Conversation::messages(
        int limit, std::optional<MessageCursor> before, wait_t) const {
    return messages(limit, before, false, wait);
}
std::vector<Message> Conversation::messages(
        int limit, std::optional<MessageCursor> before, bool include_deleted, wait_t) const {
    return _client->loop.call_get([this, limit, before, include_deleted] {
        return _client->_messages(id, limit, before, include_deleted);
    });
}

void Conversation::purge_deleted(failable_function<void(size_t)> cb) {
    _client->_require_dm("purge_deleted", id);
    _client->_async([c = _client, id = id] { return c->_purge_deleted(id); }, std::move(cb));
}
size_t Conversation::purge_deleted(wait_t) {
    _client->_require_dm("purge_deleted", id);
    return _client->loop.call_get([this] { return _client->_purge_deleted(id); });
}

// -- Read state ---------------------------------------------------------------------------------

void Conversation::mark_read(failable_function<void()> cb) {
    mark_read(std::nullopt, std::move(cb));
}
void Conversation::mark_read(std::optional<sys_ms> up_to, failable_function<void()> cb) {
    _client->_async([c = _client, id = id, up_to] { c->_mark_read(id, up_to); }, std::move(cb));
}
void Conversation::mark_read(wait_t) {
    mark_read(std::nullopt, wait);
}
void Conversation::mark_read(std::optional<sys_ms> up_to, wait_t) {
    _client->loop.call_get([this, up_to] { _client->_mark_read(id, up_to); });
}

void Conversation::set_marked_unread(bool unread, failable_function<void()> cb) {
    _client->_async(
            [c = _client, id = id, unread] { c->_set_marked_unread(id, unread); }, std::move(cb));
}
void Conversation::set_marked_unread(bool unread, wait_t) {
    _client->loop.call_get([this, unread] { _client->_set_marked_unread(id, unread); });
}

// -- Settings -----------------------------------------------------------------------------------

void Conversation::set_priority(int priority, failable_function<void()> cb) {
    _client->_async(
            [c = _client, id = id, priority] { c->_set_priority(id, priority); }, std::move(cb));
}
void Conversation::set_priority(int priority, wait_t) {
    _client->loop.call_get([this, priority] { _client->_set_priority(id, priority); });
}

void Conversation::set_notifications(config::notify_mode mode, failable_function<void()> cb) {
    _client->_async([c = _client, id = id, mode] { c->_set_notifications(id, mode); },
                    std::move(cb));
}
void Conversation::set_notifications(config::notify_mode mode, wait_t) {
    _client->loop.call_get([this, mode] { _client->_set_notifications(id, mode); });
}

void Conversation::set_mute_until(std::chrono::sys_seconds until, failable_function<void()> cb) {
    _client->_async([c = _client, id = id, until] { c->_set_mute_until(id, until); },
                    std::move(cb));
}
void Conversation::set_mute_until(std::chrono::sys_seconds until, wait_t) {
    _client->loop.call_get([this, until] { _client->_set_mute_until(id, until); });
}

void Conversation::set_expiry(
        config::expiration_mode mode, std::chrono::seconds timer, failable_function<void()> cb) {
    _client->_async([c = _client, id = id, mode, timer] { c->_set_expiry(id, mode, timer); },
                    std::move(cb));
}
void Conversation::set_expiry(config::expiration_mode mode, std::chrono::seconds timer, wait_t) {
    _client->loop.call_get([this, mode, timer] { _client->_set_expiry(id, mode, timer); });
}

void Conversation::set_auto_download(AutoDownload mode, failable_function<void()> cb) {
    _client->_async([c = _client, id = id, mode] { c->_set_auto_download(id, mode); },
                    std::move(cb));
}
void Conversation::set_auto_download(AutoDownload mode, wait_t) {
    _client->loop.call_get([this, mode] { _client->_set_auto_download(id, mode); });
}

// -- Sending ------------------------------------------------------------------------------------

void Conversation::send_message(
        std::string_view body, failable_function<void(int64_t message_id)> cb) {
    _client->_require_dm("send_message", id);
    _client->_async(
            [c = _client, id = id, body = std::string{body}] { return c->_send_message(id, body); },
            std::move(cb));
}
int64_t Conversation::send_message(std::string_view body, wait_t) {
    _client->_require_dm("send_message", id);
    return _client->loop.call_get([this, body] { return _client->_send_message(id, body); });
}

void Conversation::send_message(
        std::string_view body,
        std::vector<OutgoingAttachment> attachments,
        upload_progress on_upload,
        failable_function<void(int64_t message_id)> cb) {
    _client->_require_dm("send_message", id);
    _client->_require_readable(attachments);
    _client->_async(
            [c = _client,
             id = id,
             body = std::string{body},
             attachments = std::move(attachments),
             on_upload = std::move(on_upload)] {
                return c->_send_message(id, body, attachments, on_upload);
            },
            std::move(cb));
}
int64_t Conversation::send_message(
        std::string_view body, std::vector<OutgoingAttachment> attachments, wait_t) {
    return send_message(body, std::move(attachments), nullptr, wait);
}
int64_t Conversation::send_message(
        std::string_view body,
        std::vector<OutgoingAttachment> attachments,
        upload_progress on_upload,
        wait_t) {
    _client->_require_dm("send_message", id);
    _client->_require_readable(attachments);
    return _client->loop.call_get([&] {
        return _client->_send_message(id, body, attachments, std::move(on_upload));
    });
}

// -- Destroying ---------------------------------------------------------------------------------

void Conversation::clear_messages(failable_function<void()> cb) {
    _client->_require_dm("clear_messages", id);
    _client->_async([c = _client, id = id] { c->_clear_messages(id); }, std::move(cb));
}
void Conversation::clear_messages(wait_t) {
    _client->_require_dm("clear_messages", id);
    _client->loop.call_get([this] { _client->_clear_messages(id); });
}

void Conversation::delete_conversation(failable_function<void()> cb) {
    delete_conversation(false, std::move(cb));
}
void Conversation::delete_conversation(bool keep_messages, failable_function<void()> cb) {
    _client->_require_dm("delete_conversation", id);
    _client->_async(
            [c = _client, id = id, keep_messages] { c->_delete_conversation(id, keep_messages); },
            std::move(cb));
}
void Conversation::delete_conversation(wait_t) {
    delete_conversation(false, wait);
}
void Conversation::delete_conversation(bool keep_messages, wait_t) {
    _client->_require_dm("delete_conversation", id);
    _client->loop.call_get([this, keep_messages] {
        _client->_delete_conversation(id, keep_messages);
    });
}

// -- One-to-one only ----------------------------------------------------------------------------

void DM::set_blocked(bool blocked, failable_function<void()> cb) {
    _client->_require_contact("set_blocked", id);
    _client->_async([c = _client, id = id, blocked] { c->_set_blocked(id, blocked); },
                    std::move(cb));
}
void DM::set_blocked(bool blocked, wait_t) {
    _client->_require_contact("set_blocked", id);
    _client->loop.call_get([this, blocked] { _client->_set_blocked(id, blocked); });
}

void DM::set_nickname(std::string_view nickname, failable_function<void()> cb) {
    _client->_require_contact("set_nickname", id);
    _client->_async(
            [c = _client, id = id, nickname = std::string{nickname}] { c->_set_nickname(id, nickname); },
            std::move(cb));
}
void DM::set_nickname(std::string_view nickname, wait_t) {
    _client->_require_contact("set_nickname", id);
    _client->loop.call_get([this, nickname] { _client->_set_nickname(id, nickname); });
}

void DM::delete_contact(failable_function<void()> cb) {
    _client->_require_contact("delete_contact", id);
    _client->_async([c = _client, id = id] { c->_delete_contact(id); }, std::move(cb));
}
void DM::delete_contact(wait_t) {
    _client->_require_contact("delete_contact", id);
    _client->loop.call_get([this] { _client->_delete_contact(id); });
}

}  // namespace session::client
