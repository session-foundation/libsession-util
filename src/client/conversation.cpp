#include <session/client.hpp>

// Every operation here is one line of dispatch onto a `_`-form on Client: the work itself lives
// there, next to the rest of what touches the database, and this file is only about which thread it
// happens on and who is told.  The pairing is mechanical -- a handler form hands the work to
// `_async`, a waiting form hands it to the loop and lets it throw -- which is why they are together
// rather than split by direction.

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
    _client->_async([this, limit, before] { return _client->_messages(id, limit, before); },
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
    return _client->loop.call_get([this, limit, before] {
        return _client->_messages(id, limit, before);
    });
}

// -- Read state ---------------------------------------------------------------------------------

void Conversation::mark_read(failable_function<void()> cb) {
    mark_read(std::nullopt, std::move(cb));
}
void Conversation::mark_read(std::optional<sys_ms> up_to, failable_function<void()> cb) {
    _client->_async([this, up_to] { _client->_mark_read(id, up_to); }, std::move(cb));
}
void Conversation::mark_read(wait_t) {
    mark_read(std::nullopt, wait);
}
void Conversation::mark_read(std::optional<sys_ms> up_to, wait_t) {
    _client->loop.call_get([this, up_to] { _client->_mark_read(id, up_to); });
}

void Conversation::set_marked_unread(bool unread, failable_function<void()> cb) {
    _client->_async([this, unread] { _client->_set_marked_unread(id, unread); }, std::move(cb));
}
void Conversation::set_marked_unread(bool unread, wait_t) {
    _client->loop.call_get([this, unread] { _client->_set_marked_unread(id, unread); });
}

// -- Settings -----------------------------------------------------------------------------------

void Conversation::set_priority(int priority, failable_function<void()> cb) {
    _client->_async([this, priority] { _client->_set_priority(id, priority); }, std::move(cb));
}
void Conversation::set_priority(int priority, wait_t) {
    _client->loop.call_get([this, priority] { _client->_set_priority(id, priority); });
}

// -- Sending ------------------------------------------------------------------------------------

void Conversation::send_message(
        std::string_view body, failable_function<void(int64_t message_id)> cb) {
    _client->_require_dm("send_message", id);
    _client->_async([this, body = std::string{body}] { return _client->_send_message(id, body); },
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
            [this,
             body = std::string{body},
             attachments = std::move(attachments),
             on_upload = std::move(on_upload)] {
                return _client->_send_message(id, body, attachments, on_upload);
            },
            std::move(cb));
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
    _client->_async([this] { _client->_clear_messages(id); }, std::move(cb));
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
    _client->_async([this, keep_messages] { _client->_delete_conversation(id, keep_messages); },
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
    _client->_async([this, blocked] { _client->_set_blocked(id, blocked); }, std::move(cb));
}
void DM::set_blocked(bool blocked, wait_t) {
    _client->_require_contact("set_blocked", id);
    _client->loop.call_get([this, blocked] { _client->_set_blocked(id, blocked); });
}

void DM::delete_contact(failable_function<void()> cb) {
    _client->_require_contact("delete_contact", id);
    _client->_async([this] { _client->_delete_contact(id); }, std::move(cb));
}
void DM::delete_contact(wait_t) {
    _client->_require_contact("delete_contact", id);
    _client->loop.call_get([this] { _client->_delete_contact(id); });
}

}  // namespace session::client
