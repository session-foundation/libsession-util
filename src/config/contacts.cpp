#include "session/config/contacts.hpp"

#include <fmt/format.h>
#include <fmt/ranges.h>
#include <oxenc/hex.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <variant>

#include "internal.hpp"
#include "session/blinding.hpp"
#include "session/config/contacts.h"
#include "session/config/error.h"
#include "session/export.h"
#include "session/types.hpp"
#include "session/util.hpp"

using namespace std::literals;
using namespace session::config;
using namespace oxen::log::literals;

// Check for agreement between various C/C++ types
static_assert(sizeof(contacts_contact::name) == contact_info::MAX_NAME_LENGTH + 1);
static_assert(sizeof(contacts_contact::nickname) == contact_info::MAX_NAME_LENGTH + 1);
static_assert(sizeof(user_profile_pic::url) == profile_pic::MAX_URL_LENGTH + 1);
static_assert(CONVO_EXPIRATION_NONE == static_cast<int>(expiration_mode::none));
static_assert(CONVO_EXPIRATION_AFTER_SEND == static_cast<int>(expiration_mode::after_send));
static_assert(CONVO_EXPIRATION_AFTER_READ == static_cast<int>(expiration_mode::after_read));
static_assert(CONVO_NOTIFY_DEFAULT == static_cast<int>(notify_mode::defaulted));
static_assert(CONVO_NOTIFY_ALL == static_cast<int>(notify_mode::all));
static_assert(CONVO_NOTIFY_DISABLED == static_cast<int>(notify_mode::disabled));
static_assert(CONVO_NOTIFY_MENTIONS_ONLY == static_cast<int>(notify_mode::mentions_only));

LIBSESSION_C_API bool session_id_is_valid(const char* session_id) {
    return std::strlen(session_id) == 66 && oxenc::is_hex(session_id, session_id + 66);
}

contact_info::contact_info(std::string sid) : session_id{std::move(sid)} {
    check_session_id(session_id);
}

void contact_info::set_name(std::string n) {
    if (n.size() > MAX_NAME_LENGTH)
        name = utf8_truncate(std::move(n), MAX_NAME_LENGTH);
    else
        name = std::move(n);
}

void contact_info::set_nickname(std::string n) {
    if (n.size() > MAX_NAME_LENGTH)
        throw std::invalid_argument{"Invalid contact nickname: exceeds maximum length"};
    nickname = std::move(n);
}

void contact_info::set_nickname_truncated(std::string n) {
    set_nickname(utf8_truncate(std::move(n), MAX_NAME_LENGTH));
}

Contacts::Contacts(
        std::span<const unsigned char> ed25519_secretkey,
        std::optional<std::span<const unsigned char>> dumped) {
    init(dumped, std::nullopt, std::nullopt);
    load_key(ed25519_secretkey);
}

void contact_info::load(const dict& info_dict) {
    name = string_or_empty(info_dict, "n");
    nickname = string_or_empty(info_dict, "N");

    auto url = maybe_string(info_dict, "p");
    auto key = maybe_vector(info_dict, "q");
    if (url && key && !url->empty() && key->size() == 32) {
        profile_picture.url = std::move(*url);
        profile_picture.key = std::move(*key);
    } else {
        profile_picture.clear();
    }

    profile_updated = ts_or_epoch(info_dict, "t");
    approved = int_or_0(info_dict, "a");
    approved_me = int_or_0(info_dict, "A");
    blocked = int_or_0(info_dict, "b");

    priority = int_or_0(info_dict, "+");

    int notify = int_or_0(info_dict, "@");
    if (notify >= 0 && notify <= 3) {
        notifications = static_cast<notify_mode>(notify);
        if (notifications == notify_mode::mentions_only)
            notifications = notify_mode::all;
    } else {
        notifications = notify_mode::defaulted;
    }
    mute_until = to_epoch_seconds(int_or_0(info_dict, "!"));

    int exp_mode_ = int_or_0(info_dict, "e");
    if (exp_mode_ >= static_cast<int>(expiration_mode::none) &&
        exp_mode_ <= static_cast<int>(expiration_mode::after_read))
        exp_mode = static_cast<expiration_mode>(exp_mode_);
    else
        exp_mode = expiration_mode::none;

    if (exp_mode == expiration_mode::none)
        exp_timer = 0s;
    else {
        int secs = int_or_0(info_dict, "E");
        if (secs <= 0) {
            exp_mode = expiration_mode::none;
            exp_timer = 0s;
        } else {
            exp_timer = std::chrono::seconds{secs};
        }
    }

    created = to_epoch_seconds(int_or_0(info_dict, "j"));

    const session::config::set* profile_bitset_set = maybe_set(info_dict, "f");
    if (profile_bitset_set)
        profile_bitset.data = bitset_from_set_of_int64_or_0(*profile_bitset_set);
}

void contact_info::into(contacts_contact& c) const {
    std::memcpy(c.session_id, session_id.data(), 67);
    copy_c_str(c.name, name);
    copy_c_str(c.nickname, nickname);
    if (profile_picture) {
        copy_c_str(c.profile_pic.url, profile_picture.url);
        std::memcpy(c.profile_pic.key, profile_picture.key.data(), 32);
    } else {
        copy_c_str(c.profile_pic.url, "");
    }
    c.profile_updated = epoch_seconds(profile_updated);
    c.approved = approved;
    c.approved_me = approved_me;
    c.blocked = blocked;
    c.priority = priority;
    c.notifications = static_cast<CONVO_NOTIFY_MODE>(notifications);
    c.mute_until = to_epoch_seconds(mute_until);
    c.exp_mode = static_cast<CONVO_EXPIRATION_MODE>(exp_mode);
    c.exp_seconds = exp_timer.count();
    if (c.exp_seconds <= 0 && c.exp_mode != CONVO_EXPIRATION_NONE)
        c.exp_mode = CONVO_EXPIRATION_NONE;
    c.created = to_epoch_seconds(created);
    c.profile_bitset.data = profile_bitset.data;
}

contact_info::contact_info(const contacts_contact& c) : session_id{c.session_id, 66} {
    assert(std::strlen(c.name) <= MAX_NAME_LENGTH);
    name = c.name;
    assert(std::strlen(c.nickname) <= MAX_NAME_LENGTH);
    nickname = c.nickname;
    assert(std::strlen(c.profile_pic.url) <= profile_pic::MAX_URL_LENGTH);
    if (std::strlen(c.profile_pic.url)) {
        profile_picture.url = c.profile_pic.url;
        profile_picture.key.assign(c.profile_pic.key, c.profile_pic.key + 32);
    }
    profile_updated = to_sys_seconds(c.profile_updated);
    approved = c.approved;
    approved_me = c.approved_me;
    blocked = c.blocked;
    priority = c.priority;
    notifications = static_cast<notify_mode>(c.notifications);
    mute_until = to_epoch_seconds(c.mute_until);
    exp_mode = static_cast<expiration_mode>(c.exp_mode);
    exp_timer = exp_mode == expiration_mode::none ? 0s : std::chrono::seconds{c.exp_seconds};
    if (exp_timer <= 0s && exp_mode != expiration_mode::none)
        exp_mode = expiration_mode::none;
    created = to_epoch_seconds(c.created);
    profile_bitset.data = c.profile_bitset.data;
}

std::optional<contact_info> Contacts::get(std::string_view pubkey_hex) const {
    std::string pubkey = session_id_to_bytes(pubkey_hex);

    auto* info_dict = data["c"][pubkey].dict();
    if (!info_dict)
        return std::nullopt;

    auto result = std::make_optional<contact_info>(std::string{pubkey_hex});
    result->load(*info_dict);
    return result;
}

contact_info Contacts::get_or_construct(std::string_view pubkey_hex) const {
    if (auto maybe = get(pubkey_hex))
        return *std::move(maybe);

    return contact_info{std::string{pubkey_hex}};
}

void Contacts::set(const contact_info& contact) {
    std::string pk = session_id_to_bytes(contact.session_id);
    auto info = data["c"][pk];

    // Always set the name, even if empty, to keep the dict from getting pruned if there are no
    // other entries.
    info["n"] = contact.name.substr(0, contact_info::MAX_NAME_LENGTH);
    set_nonempty_str(info["N"], contact.nickname.substr(0, contact_info::MAX_NAME_LENGTH));

    set_pair_if(
            contact.profile_picture,
            info["p"],
            contact.profile_picture.url,
            info["q"],
            contact.profile_picture.key);

    set_ts(info["t"], contact.profile_updated);

    set_flag(info["a"], contact.approved);
    set_flag(info["A"], contact.approved_me);
    set_flag(info["b"], contact.blocked);

    set_nonzero_int(info["+"], contact.priority);

    auto notify = contact.notifications;
    if (notify == notify_mode::mentions_only)
        notify = notify_mode::all;
    set_positive_int(info["@"], static_cast<int>(notify));
    set_positive_int(info["!"], to_epoch_seconds(contact.mute_until));

    set_pair_if(
            contact.exp_mode != expiration_mode::none && contact.exp_timer > 0s,
            info["e"],
            static_cast<int8_t>(contact.exp_mode),
            info["E"],
            contact.exp_timer.count());

    set_positive_int(info["j"], to_epoch_seconds(contact.created));
    set_int64_set_from_bitset(info["f"], contact.profile_bitset.data);
}

void Contacts::set_name(std::string_view session_id, std::string name) {
    auto c = get_or_construct(session_id);
    c.set_name(std::move(name));
    set(c);
}
void Contacts::set_nickname(std::string_view session_id, std::string nickname) {
    auto c = get_or_construct(session_id);
    c.set_nickname(std::move(nickname));
    set(c);
}
void Contacts::set_nickname_truncated(std::string_view session_id, std::string nickname) {
    auto c = get_or_construct(session_id);
    c.set_nickname_truncated(std::move(nickname));
    set(c);
}
void Contacts::set_profile_pic(std::string_view session_id, profile_pic pic) {
    auto c = get_or_construct(session_id);
    c.profile_picture = std::move(pic);
    set(c);
}
void Contacts::set_profile_updated(
        std::string_view session_id, std::chrono::sys_seconds profile_updated) {
    auto c = get_or_construct(session_id);
    c.profile_updated = profile_updated;
    set(c);
}
void Contacts::set_approved(std::string_view session_id, bool approved) {
    auto c = get_or_construct(session_id);
    c.approved = approved;
    set(c);
}
void Contacts::set_approved_me(std::string_view session_id, bool approved_me) {
    auto c = get_or_construct(session_id);
    c.approved_me = approved_me;
    set(c);
}
void Contacts::set_blocked(std::string_view session_id, bool blocked) {
    auto c = get_or_construct(session_id);
    c.blocked = blocked;
    set(c);
}

void Contacts::set_priority(std::string_view session_id, int priority) {
    auto c = get_or_construct(session_id);
    c.priority = priority;
    set(c);
}

void Contacts::set_notifications(std::string_view session_id, notify_mode notifications) {
    auto c = get_or_construct(session_id);
    c.notifications = notifications;
    set(c);
}

void Contacts::set_expiry(
        std::string_view session_id, expiration_mode mode, std::chrono::seconds timer) {
    auto c = get_or_construct(session_id);
    c.exp_mode = mode;
    c.exp_timer = c.exp_mode == expiration_mode::none ? 0s : timer;
    set(c);
}

void Contacts::set_created(std::string_view session_id, int64_t timestamp) {
    auto c = get_or_construct(session_id);
    c.created = to_epoch_seconds(timestamp);
    set(c);
}

void Contacts::set_pro_features(std::string_view session_id, ProProfileBitset features) {
    auto c = get_or_construct(session_id);
    c.profile_bitset = features;
    set(c);
}

bool Contacts::erase(std::string_view session_id) {
    std::string pk = session_id_to_bytes(session_id);
    auto info = data["c"][pk];
    bool ret = info.exists();
    info.erase();
    return ret;
}

size_t Contacts::size() const {
    if (auto* c = data["c"].dict())
        return c->size();
    return 0;
}

blinded_contact_info::blinded_contact_info(
        std::string_view community_base_url,
        std::span<const unsigned char> community_pubkey,
        std::string_view blinded_id) :
        comm{community(
                std::move(community_base_url), blinded_id.substr(2), std::move(community_pubkey))} {
    auto prefix = get_session_id_prefix(blinded_id);
    legacy_blinding = (prefix == session::SessionIDPrefix::community_blinded_legacy);

    if (prefix != session::SessionIDPrefix::community_blinded &&
        prefix != session::SessionIDPrefix::community_blinded_legacy)
        throw std::invalid_argument{
                "Invalid blinded ID: Expected '15' or '25' prefix; got " + std::string{blinded_id}};
}

void blinded_contact_info::load(const dict& info_dict) {
    name = string_or_empty(info_dict, "n");

    auto url = maybe_string(info_dict, "p");
    auto key = maybe_vector(info_dict, "q");
    if (url && key && !url->empty() && key->size() == 32) {
        profile_picture.url = std::move(*url);
        profile_picture.key = std::move(*key);
    } else {
        profile_picture.clear();
    }
    profile_updated = ts_or_epoch(info_dict, "t");
    priority = int_or_0(info_dict, "+");
    legacy_blinding = int_or_0(info_dict, "y");
    created = ts_or_epoch(info_dict, "j");
    auto it = info_dict.find("f");
    if (it != info_dict.end()) {
        if (auto* set = std::get_if<session::config::set>(&it->second))
            profile_bitset.data = bitset_from_set_of_int64_or_0(*set);
    }
}

void blinded_contact_info::into(contacts_blinded_contact& c) const {
    copy_c_str(c.base_url, comm.base_url());
    c.session_id[0] = (legacy_blinding ? '1' : '2');
    c.session_id[1] = '5';
    std::memcpy(c.session_id + 2, session_id().data(), 64);
    c.session_id[66] = '\0';
    std::memcpy(c.pubkey, comm.pubkey().data(), 32);
    copy_c_str(c.name, name);
    if (profile_picture) {
        copy_c_str(c.profile_pic.url, profile_picture.url);
        std::memcpy(c.profile_pic.key, profile_picture.key.data(), 32);
    } else {
        copy_c_str(c.profile_pic.url, "");
    }
    c.profile_updated = epoch_seconds(profile_updated);
    c.priority = priority;
    c.legacy_blinding = legacy_blinding;
    c.created = epoch_seconds(created);
    c.profile_bitset.data = profile_bitset.data;
}

blinded_contact_info::blinded_contact_info(const contacts_blinded_contact& c) {
    comm = community(c.base_url, {c.session_id + 2, 64}, c.pubkey);
    assert(std::strlen(c.name) <= contact_info::MAX_NAME_LENGTH);
    name = c.name;
    assert(std::strlen(c.profile_pic.url) <= profile_pic::MAX_URL_LENGTH);
    if (std::strlen(c.profile_pic.url)) {
        profile_picture.url = c.profile_pic.url;
        profile_picture.key.assign(c.profile_pic.key, c.profile_pic.key + 32);
    }
    profile_updated = to_sys_seconds(c.profile_updated);
    priority = c.priority;
    legacy_blinding = c.legacy_blinding;
    created = to_sys_seconds(c.created);
    profile_bitset.data = c.profile_bitset.data;
}

const std::string blinded_contact_info::session_id() const {
    return "{}{}"_format(legacy_blinding ? "15" : "25", comm.room());
}

void blinded_contact_info::set_name(std::string n) {
    if (n.size() > contact_info::MAX_NAME_LENGTH)
        name = utf8_truncate(std::move(n), contact_info::MAX_NAME_LENGTH);
    else
        name = std::move(n);
}

void blinded_contact_info::set_base_url(std::string_view base_url) {
    comm.set_base_url(base_url);
}

void blinded_contact_info::set_room(std::string_view room) {
    if (room.size() != 64 || !oxenc::is_hex(room))
        throw std::invalid_argument{
                fmt::format("Invalid room: expected 64 hex digits; got {}", room)};

    comm.set_room(room);
}

void blinded_contact_info::set_pubkey(std::span<const unsigned char> pubkey) {
    comm.set_pubkey(pubkey);
}

void blinded_contact_info::set_pubkey(std::string_view pubkey) {
    comm.set_pubkey(pubkey);
}

ConfigBase::DictFieldProxy Contacts::blinded_contact_field(
        const blinded_contact_info& bc, std::span<const unsigned char>* get_pubkey) const {
    auto record = data["b"][bc.comm.base_url()];
    if (get_pubkey) {
        auto pkrec = record["#"];
        if (auto pk = pkrec.string_view_or(""); pk.size() == 32)
            *get_pubkey = std::span<const unsigned char>{
                    reinterpret_cast<const unsigned char*>(pk.data()), pk.size()};
    }
    return record["R"][bc.comm.room()];  // The `room` value is the blinded id without the prefix
}

using any_blinded_contact = std::variant<blinded_contact_info>;

std::optional<blinded_contact_info> Contacts::get_blinded(std::string_view blinded_id_hex) const {
    get_session_id_prefix(blinded_id_hex);

    if (auto* b = data["b"].dict()) {
        auto comm = comm_iterator_helper{b->begin(), b->end()};
        std::shared_ptr<any_blinded_contact> val;

        while (!comm.done()) {
            if (comm.load<blinded_contact_info>(val))
                if (auto* ptr = std::get_if<blinded_contact_info>(val.get());
                    ptr && ptr->session_id() == blinded_id_hex)
                    return *ptr;
            comm.advance();
        }
    }

    return std::nullopt;
}

blinded_contact_info Contacts::get_or_construct_blinded(
        std::string_view community_base_url,
        std::string_view community_pubkey_hex,
        std::string_view blinded_id_hex) {
    if (auto maybe = get_blinded(blinded_id_hex))
        return *std::move(maybe);

    return blinded_contact_info{
            community_base_url, to_span(oxenc::from_hex(community_pubkey_hex)), blinded_id_hex};
}

std::vector<blinded_contact_info> Contacts::blinded() const {
    std::vector<blinded_contact_info> ret;

    if (auto* b = data["b"].dict()) {
        auto comm = comm_iterator_helper{b->begin(), b->end()};
        std::shared_ptr<any_blinded_contact> val;

        while (!comm.done()) {
            if (comm.load<blinded_contact_info>(val))
                if (auto* ptr = std::get_if<blinded_contact_info>(val.get()))
                    ret.emplace_back(*ptr);
            comm.advance();
        }
    }

    return ret;
}

void Contacts::set_blinded(const blinded_contact_info& bc) {
    data["b"][bc.comm.base_url()]["#"] = bc.comm.pubkey();
    auto info = blinded_contact_field(bc);  // data["b"][base]["R"][bc_session_id_without_prefix]

    // Always set the name, even if empty, to keep the dict from getting pruned if there are no
    // other entries.
    info["n"] = bc.name.substr(0, contact_info::MAX_NAME_LENGTH);

    set_pair_if(
            bc.profile_picture,
            info["p"],
            bc.profile_picture.url,
            info["q"],
            bc.profile_picture.key);
    set_ts(info["t"], bc.profile_updated);
    set_nonzero_int(info["+"], bc.priority);
    set_positive_int(info["y"], bc.legacy_blinding);
    set_ts(info["j"], bc.created);
    set_int64_set_from_bitset(info["f"], bc.profile_bitset.data);
}

bool Contacts::erase_blinded(std::string_view base_url_, std::string_view blinded_id) {
    auto prefix = get_session_id_prefix(blinded_id);

    if (prefix != session::SessionIDPrefix::community_blinded &&
        prefix != session::SessionIDPrefix::community_blinded_legacy)
        throw std::invalid_argument{
                "Invalid blinded ID: Expected '15' or '25' prefix; got " + std::string{blinded_id}};

    auto base_url = community::canonical_url(base_url_);
    auto pk = std::string(blinded_id.substr(2));
    auto info = data["b"][base_url]["R"][pk];
    bool ret = info.exists();
    info.erase();
    return ret;
}

/// Load _val from the current iterator position; if it is invalid, skip to the next key until we
/// find one that is valid (or hit the end).
void Contacts::iterator::_load_info() {
    while (_it != _contacts->end()) {
        if (_it->first.size() == 33) {
            if (auto* info_dict = std::get_if<dict>(&_it->second)) {
                _val = std::make_shared<contact_info>(oxenc::to_hex(_it->first));
                _val->load(*info_dict);
                return;
            }
        }

        // We found something we don't understand (wrong pubkey size, or not a dict value) so skip
        // it.
        ++_it;
    }
}

bool Contacts::iterator::operator==(const iterator& other) const {
    if (!_contacts && !other._contacts)
        return true;  // Both are end tombstones
    if (!other._contacts)
        // other is an "end" tombstone: return whether we are at the end
        return _it == _contacts->end();
    if (!_contacts)
        // we are an "end" tombstone: return whether the other one is at the end
        return other._it == other._contacts->end();
    return _it == other._it;
}

bool Contacts::iterator::done() const {
    return !_contacts || _it == _contacts->end();
}

Contacts::iterator& Contacts::iterator::operator++() {
    ++_it;
    _load_info();
    return *this;
}

extern "C" {

LIBSESSION_C_API const size_t CONTACT_MAX_NAME_LENGTH = contact_info::MAX_NAME_LENGTH;

LIBSESSION_C_API int contacts_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey_bytes,
        const unsigned char* dumpstr,
        size_t dumplen,
        char* error) {
    return c_wrapper_init<Contacts>(conf, ed25519_secretkey_bytes, dumpstr, dumplen, error);
}

LIBSESSION_C_API bool contacts_get(
        config_object* conf, contacts_contact* contact, const char* session_id) {
    return wrap_exceptions(
            conf,
            [&] {
                if (auto c = unbox<Contacts>(conf)->get(session_id)) {
                    c->into(*contact);
                    return true;
                }
                return false;
            },
            false);
}

LIBSESSION_C_API bool contacts_get_or_construct(
        config_object* conf, contacts_contact* contact, const char* session_id) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<Contacts>(conf)->get_or_construct(session_id).into(*contact);
                return true;
            },
            false);
}

LIBSESSION_C_API bool contacts_set(config_object* conf, const contacts_contact* contact) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<Contacts>(conf)->set(contact_info{*contact});
                return true;
            },
            false);
}

LIBSESSION_C_API bool contacts_erase(config_object* conf, const char* session_id) {
    try {
        return unbox<Contacts>(conf)->erase(session_id);
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API size_t contacts_size(const config_object* conf) {
    return unbox<Contacts>(conf)->size();
}

LIBSESSION_C_API bool contacts_get_blinded(
        config_object* conf, const char* blinded_id, contacts_blinded_contact* blinded_contact) {
    return wrap_exceptions(
            conf,
            [&] {
                if (auto bc = unbox<Contacts>(conf)->get_blinded(blinded_id)) {
                    bc->into(*blinded_contact);
                    return true;
                }
                return false;
            },
            false);
}

LIBSESSION_C_API bool contacts_get_or_construct_blinded(
        config_object* conf,
        const char* community_base_url,
        const char* community_pubkey_hex,
        const char* blinded_id,
        contacts_blinded_contact* blinded_contact) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<Contacts>(conf)
                        ->get_or_construct_blinded(
                                community_base_url, community_pubkey_hex, blinded_id)
                        .into(*blinded_contact);
                return true;
            },
            false);
}

LIBSESSION_C_API contacts_blinded_contact_list* contacts_blinded(const config_object* conf) {
    try {
        auto cpp_contacts = unbox<Contacts>(conf)->blinded();

        if (cpp_contacts.empty())
            return nullptr;

        // We malloc space for the contacts_blinded_contact_list struct itself, plus the required
        // number of contacts_blinded_contact pointers to store its records, and the space to
        // actually contain a copy of the data. When we're done, the malloced memory we grab is
        // going to look like this:
        //
        // {contacts_blinded_contact_list}
        // {pointer1}{pointer2}...
        // {contacts_blinded_contact data 1\0}{contacts_blinded_contact data 2\0}...
        //
        // where contacts_blinded_contact.value points at the beginning of {pointer1}, and each
        // pointerN points at the beginning of the {contacts_blinded_contact data N\0} struct.
        //
        // Since we malloc it all at once, when the user frees it, they also free the entire thing.
        size_t sz = sizeof(contacts_blinded_contact_list) +
                    (cpp_contacts.size() * sizeof(contacts_blinded_contact*)) +
                    (cpp_contacts.size() * sizeof(contacts_blinded_contact));
        auto* ret = static_cast<contacts_blinded_contact_list*>(std::malloc(sz));
        ret->len = cpp_contacts.size();

        // value points at the space immediately after the struct itself, which is the first element
        // in the array of contacts_blinded_contact pointers.
        ret->value = reinterpret_cast<contacts_blinded_contact**>(ret + 1);
        contacts_blinded_contact* next_struct =
                reinterpret_cast<contacts_blinded_contact*>(ret->value + ret->len);

        for (size_t i = 0; i < cpp_contacts.size(); ++i) {
            ret->value[i] = next_struct;
            cpp_contacts[i].into(*next_struct);
            next_struct++;
        }

        return ret;
    } catch (...) {
        return nullptr;
    }
}

LIBSESSION_C_API bool contacts_set_blinded(
        config_object* conf, const contacts_blinded_contact* bc) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<Contacts>(conf)->set_blinded(blinded_contact_info{*bc});
                return true;
            },
            false);
}

LIBSESSION_C_API bool contacts_erase_blinded(
        config_object* conf, const char* community_base_url, const char* blinded_id) {
    try {
        return unbox<Contacts>(conf)->erase_blinded(community_base_url, blinded_id);
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API contacts_iterator* contacts_iterator_new(const config_object* conf) {
    auto* it = new contacts_iterator{};
    it->_internals = new Contacts::iterator{unbox<Contacts>(conf)->begin()};
    return it;
}

LIBSESSION_C_API void contacts_iterator_free(contacts_iterator* it) {
    delete static_cast<Contacts::iterator*>(it->_internals);
    delete it;
}

LIBSESSION_C_API bool contacts_iterator_done(contacts_iterator* it, contacts_contact* c) {
    auto& real = *static_cast<Contacts::iterator*>(it->_internals);
    if (real.done())
        return true;
    real->into(*c);
    return false;
}

LIBSESSION_C_API void contacts_iterator_advance(contacts_iterator* it) {
    ++*static_cast<Contacts::iterator*>(it->_internals);
}

}  // extern "C"
