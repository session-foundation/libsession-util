#include "session/config/convo_info_volatile.hpp"

#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <charconv>
#include <iterator>
#include <map>
#include <stdexcept>
#include <variant>

#include "internal.hpp"
#include "session/config/convo_info_volatile.h"
#include "session/config/error.h"
#include "session/export.h"
#include "session/types.hpp"
#include "session/util.hpp"
using namespace std::literals;

namespace session::config {

namespace convo {

    one_to_one::one_to_one(std::string&& sid) : session_id{std::move(sid)} {
        check_session_id(session_id);
    }
    one_to_one::one_to_one(std::string_view sid) : session_id{sid} {
        check_session_id(session_id);
    }
    one_to_one::one_to_one(const convo_info_volatile_1to1& c) :
            pro_base(c.last_read, c.unread), session_id{c.session_id, 66} {
        if (c.has_pro_gen_index_hash) {
            pro_gen_index_hash.emplace();
            std::memcpy(
                    pro_gen_index_hash->data(),
                    c.pro_gen_index_hash.data,
                    pro_gen_index_hash->size());
            pro_expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                    std::chrono::milliseconds(c.pro_expiry_unix_ts_ms));
        }
    }

    void one_to_one::into(convo_info_volatile_1to1& c) const {
        std::memcpy(c.session_id, session_id.data(), 67);
        c.last_read = last_read;
        c.unread = unread;

        if (pro_gen_index_hash) {
            c.has_pro_gen_index_hash = true;
            std::memcpy(
                    c.pro_gen_index_hash.data,
                    pro_gen_index_hash->data(),
                    pro_gen_index_hash->size());

            c.pro_expiry_unix_ts_ms = pro_expiry_unix_ts.time_since_epoch().count();
        } else {
            c.has_pro_gen_index_hash = false;
            c.pro_expiry_unix_ts_ms = 0;
        }
    }

    community::community(const convo_info_volatile_community& c) :
            config::community{c.base_url, c.room, std::span<const unsigned char>{c.pubkey, 32}},
            base(c.last_read, c.unread) {}

    void community::into(convo_info_volatile_community& c) const {
        static_assert(sizeof(c.base_url) == BASE_URL_MAX_LENGTH + 1);
        static_assert(sizeof(c.room) == ROOM_MAX_LENGTH + 1);
        copy_c_str(c.base_url, base_url());
        copy_c_str(c.room, room_norm());
        std::memcpy(c.pubkey, pubkey().data(), 32);
        c.last_read = last_read;
        c.unread = unread;
    }

    group::group(std::string&& cgid) : id{std::move(cgid)} {
        check_session_id(id, "03");
    }
    group::group(std::string_view cgid) : id{cgid} {
        check_session_id(id, "03");
    }
    group::group(const convo_info_volatile_group& c) :
            base(c.last_read, c.unread), id{c.group_id, 66} {}

    void group::into(convo_info_volatile_group& c) const {
        std::memcpy(c.group_id, id.c_str(), 67);
        c.last_read = last_read;
        c.unread = unread;
    }

    legacy_group::legacy_group(std::string&& cgid) : id{std::move(cgid)} {
        check_session_id(id);
    }
    legacy_group::legacy_group(std::string_view cgid) : id{cgid} {
        check_session_id(id);
    }
    legacy_group::legacy_group(const convo_info_volatile_legacy_group& c) :
            base(c.last_read, c.unread), id{c.group_id, 66} {}

    void legacy_group::into(convo_info_volatile_legacy_group& c) const {
        std::memcpy(c.group_id, id.data(), 67);
        c.last_read = last_read;
        c.unread = unread;
    }

    blinded_one_to_one::blinded_one_to_one(std::string&& sid) : blinded_session_id{std::move(sid)} {
        auto prefix = get_session_id_prefix(blinded_session_id);
        legacy_blinding = (prefix == session::SessionIDPrefix::community_blinded_legacy);

        if (prefix != session::SessionIDPrefix::community_blinded &&
            prefix != session::SessionIDPrefix::community_blinded_legacy)
            throw std::invalid_argument{
                    "Invalid blinded ID: Expected '15' or '25' prefix; got " + blinded_session_id};
    }
    blinded_one_to_one::blinded_one_to_one(std::string_view sid) : blinded_session_id{sid} {
        auto prefix = get_session_id_prefix(blinded_session_id);
        legacy_blinding = (prefix == session::SessionIDPrefix::community_blinded_legacy);

        if (prefix != session::SessionIDPrefix::community_blinded &&
            prefix != session::SessionIDPrefix::community_blinded_legacy)
            throw std::invalid_argument{
                    "Invalid blinded ID: Expected '15' or '25' prefix; got " + blinded_session_id};
    }
    blinded_one_to_one::blinded_one_to_one(const convo_info_volatile_blinded_1to1& c) :
            pro_base(c.last_read, c.unread),
            blinded_session_id{c.blinded_session_id, 66},
            legacy_blinding{c.legacy_blinding} {
        if (c.has_pro_gen_index_hash) {
            pro_gen_index_hash.emplace();
            std::memcpy(
                    pro_gen_index_hash->data(),
                    c.pro_gen_index_hash.data,
                    pro_gen_index_hash->size());
            pro_expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                    std::chrono::milliseconds(c.pro_expiry_unix_ts_ms));
        }
    }

    void blinded_one_to_one::into(convo_info_volatile_blinded_1to1& c) const {
        std::memcpy(c.blinded_session_id, blinded_session_id.data(), 67);
        c.last_read = last_read;
        c.unread = unread;
        c.legacy_blinding = legacy_blinding;

        if (pro_gen_index_hash) {
            c.has_pro_gen_index_hash = true;
            std::memcpy(
                    c.pro_gen_index_hash.data,
                    pro_gen_index_hash->data(),
                    pro_gen_index_hash->size());
            c.pro_expiry_unix_ts_ms = pro_expiry_unix_ts.time_since_epoch().count();
        } else {
            c.has_pro_gen_index_hash = false;
            c.pro_expiry_unix_ts_ms = 0;
        }
    }

    void pro_base::load(const dict& info_dict) {
        base::load(info_dict);

        auto pro_expiry = int_or_0(info_dict, "e");
        std::optional<std::vector<unsigned char>> maybe_pro_gen_index_hash =
                maybe_vector(info_dict, "g");
        if (pro_expiry > 0 && maybe_pro_gen_index_hash && maybe_pro_gen_index_hash->size() == 32) {
            pro_expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                    std::chrono::milliseconds(pro_expiry));
            pro_gen_index_hash.emplace();
            std::memcpy(
                    pro_gen_index_hash->data(),
                    maybe_pro_gen_index_hash->data(),
                    pro_gen_index_hash->size());
        }
    }

    void base::load(const dict& info_dict) {
        last_read = int_or_0(info_dict, "r");
        unread = (bool)int_or_0(info_dict, "u");
    }

}  // namespace convo

ConvoInfoVolatile::ConvoInfoVolatile(
        std::span<const unsigned char> ed25519_secretkey,
        std::optional<std::span<const unsigned char>> dumped) {
    init(dumped, std::nullopt, std::nullopt);
    load_key(ed25519_secretkey);
}

std::optional<convo::one_to_one> ConvoInfoVolatile::get_1to1(
        std::string_view pubkey_hex, bool include_archived) const {
    std::string pubkey = session_id_to_bytes(pubkey_hex);

    auto* info_dict = data["1"][pubkey].dict();
    if (!info_dict) {
        if (include_archived)
            if (auto it = _arch_1to1.find(pubkey); it != _arch_1to1.end())
                return it->second;
        return std::nullopt;
    }

    auto result = std::make_optional<convo::one_to_one>(std::string{pubkey_hex});
    result->load(*info_dict);
    return result;
}

convo::one_to_one ConvoInfoVolatile::get_or_construct_1to1(std::string_view pubkey_hex) const {
    if (auto maybe = get_1to1(pubkey_hex))
        return *std::move(maybe);

    return convo::one_to_one{std::string{pubkey_hex}};
}

ConfigBase::DictFieldProxy ConvoInfoVolatile::community_field(
        const convo::community& comm, std::span<const unsigned char>* get_pubkey) const {
    auto record = data["o"][comm.base_url()];
    if (get_pubkey) {
        auto pkrec = record["#"];
        if (auto pk = pkrec.string_view_or(""); pk.size() == 32)
            *get_pubkey = to_span(pk);
    }
    return record["R"][comm.room_norm()];
}

std::optional<convo::community> ConvoInfoVolatile::get_community(
        std::string_view base_url, std::string_view room, bool include_archived) const {
    convo::community og{base_url, community::canonical_room(room)};

    std::span<const unsigned char> pubkey;
    if (auto* info_dict = community_field(og, &pubkey).dict()) {
        og.load(*info_dict);
        if (!pubkey.empty())
            og.set_pubkey(pubkey);
        return og;
    }
    if (include_archived)
        if (auto s = _arch_comm.find(og.base_url()); s != _arch_comm.end())
            if (auto r = s->second.find(og.room_norm()); r != s->second.end())
                return r->second;
    return std::nullopt;
}

std::optional<convo::community> ConvoInfoVolatile::get_community(
        std::string_view partial_url, bool include_archived) const {
    auto [base, room, pubkey] = community::parse_partial_url(partial_url);
    return get_community(base, room, include_archived);
}

convo::community ConvoInfoVolatile::get_or_construct_community(
        std::string_view base_url,
        std::string_view room,
        std::span<const unsigned char> pubkey) const {
    convo::community result{base_url, community::canonical_room(room), pubkey};

    if (auto* info_dict = community_field(result).dict())
        result.load(*info_dict);
    else if (auto s = _arch_comm.find(result.base_url()); s != _arch_comm.end())
        if (auto r = s->second.find(result.room_norm()); r != s->second.end()) {
            result.last_read = r->second.last_read;
            result.unread = r->second.unread;
        }

    return result;
}

convo::community ConvoInfoVolatile::get_or_construct_community(std::string_view full_url) const {
    auto [base, room, pubkey] = community::parse_full_url(full_url);
    return get_or_construct_community(base, room, pubkey);
}

convo::community ConvoInfoVolatile::get_or_construct_community(
        std::string_view base_url, std::string_view room, std::string_view pubkey_hex) const {
    convo::community result{base_url, room, pubkey_hex};

    if (auto* info_dict = community_field(result).dict())
        result.load(*info_dict);
    else if (auto s = _arch_comm.find(result.base_url()); s != _arch_comm.end())
        if (auto r = s->second.find(result.room_norm()); r != s->second.end()) {
            result.last_read = r->second.last_read;
            result.unread = r->second.unread;
        }

    return result;
}

std::optional<convo::group> ConvoInfoVolatile::get_group(
        std::string_view pubkey_hex, bool include_archived) const {
    std::string pubkey = session_id_to_bytes(pubkey_hex, "03");

    auto* info_dict = data["g"][pubkey].dict();
    if (!info_dict) {
        if (include_archived)
            if (auto it = _arch_group.find(pubkey); it != _arch_group.end())
                return it->second;
        return std::nullopt;
    }

    auto result = std::make_optional<convo::group>(std::string{pubkey_hex});
    result->load(*info_dict);
    return result;
}

convo::group ConvoInfoVolatile::get_or_construct_group(std::string_view pubkey_hex) const {
    if (auto maybe = get_group(pubkey_hex))
        return *std::move(maybe);

    return convo::group{std::string{pubkey_hex}};
}

std::optional<convo::legacy_group> ConvoInfoVolatile::get_legacy_group(
        std::string_view pubkey_hex, bool include_archived) const {
    std::string pubkey = session_id_to_bytes(pubkey_hex);

    auto* info_dict = data["C"][pubkey].dict();
    if (!info_dict) {
        if (include_archived)
            if (auto it = _arch_legacy.find(pubkey); it != _arch_legacy.end())
                return it->second;
        return std::nullopt;
    }

    auto result = std::make_optional<convo::legacy_group>(std::string{pubkey_hex});
    result->load(*info_dict);
    return result;
}

convo::legacy_group ConvoInfoVolatile::get_or_construct_legacy_group(
        std::string_view pubkey_hex) const {
    if (auto maybe = get_legacy_group(pubkey_hex))
        return *std::move(maybe);

    return convo::legacy_group{std::string{pubkey_hex}};
}

std::optional<convo::blinded_one_to_one> ConvoInfoVolatile::get_blinded_1to1(
        std::string_view pubkey_hex, bool include_archived) const {
    auto prefix = get_session_id_prefix(pubkey_hex);

    if (prefix != session::SessionIDPrefix::community_blinded &&
        prefix != session::SessionIDPrefix::community_blinded_legacy)
        throw std::invalid_argument{
                "Invalid blinded ID: Expected '15' or '25' prefix; got " + std::string{pubkey_hex}};

    std::string pubkey = session_id_to_bytes(pubkey_hex, to_string(prefix));

    auto* info_dict = data["b"][pubkey].dict();
    if (!info_dict) {
        if (include_archived)
            if (auto it = _arch_blinded.find(pubkey); it != _arch_blinded.end())
                return it->second;
        return std::nullopt;
    }

    auto result = std::make_optional<convo::blinded_one_to_one>(std::string{pubkey_hex});
    result->load(*info_dict);
    return result;
}

convo::blinded_one_to_one ConvoInfoVolatile::get_or_construct_blinded_1to1(
        std::string_view pubkey_hex) const {
    if (auto maybe = get_blinded_1to1(pubkey_hex))
        return *std::move(maybe);

    return convo::blinded_one_to_one{std::string{pubkey_hex}};
}

void ConvoInfoVolatile::set(const convo::one_to_one& c) {
    auto key = session_id_to_bytes(c.session_id);
    auto info = data["1"][key];
    if (set_or_archive(c, info, key, _arch_1to1)) {
        set_nonzero_int(info["e"], c.pro_expiry_unix_ts.time_since_epoch().count());
        if (c.pro_gen_index_hash)
            info["g"] = *c.pro_gen_index_hash;
    }
}

bool ConvoInfoVolatile::set_base(const convo::base& c, DictFieldProxy& info) {
    std::chrono::system_clock::time_point last_read{std::chrono::milliseconds{c.last_read}};
    if (last_read <= std::chrono::system_clock::now() - ARCHIVE_AFTER)
        return false;  // Stale — caller should route to archive

    info["r"] = c.last_read;
    set_flag(info["u"], c.unread);
    return true;
}

template <std::derived_from<convo::base> C>
static bool is_stale(const C& c, int64_t cutoff_ms) {
    if (c.unread)
        return false;
    if constexpr (std::derived_from<C, convo::pro_base>)
        if (c.pro_gen_index_hash.has_value() &&
            c.pro_expiry_unix_ts.time_since_epoch().count() >= cutoff_ms)
            return false;
    return c.last_read < cutoff_ms;
}

void ConvoInfoVolatile::archive_stale() {

    const int64_t cutoff =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                    (std::chrono::system_clock::now() - ARCHIVE_AFTER).time_since_epoch())
                    .count();

    // For each stale entry found: snapshot it, then erase it.  The erase() overloads also remove
    // any existing archive entry for the same ID (deduplication), so after the erase we push_back
    // the fresh snapshot.  This order (snapshot → erase → archive) avoids the erase undoing the
    // archive addition that would happen if we archived before erasing.
    // Only examine active (non-archived) entries
    std::vector<std::string> stale;
    for (auto it = begin_1to1(false); !it.done(); ++it)
        if (is_stale(*it, cutoff))
            stale.push_back(it->session_id);
    for (const auto& sid : stale) {
        auto c = get_1to1(sid);
        erase_1to1(sid);
        if (c)
            _arch_1to1.insert_or_assign(session_id_to_bytes(c->session_id), std::move(*c));
    }

    stale.clear();
    for (auto it = begin_legacy_groups(false); !it.done(); ++it)
        if (is_stale(*it, cutoff))
            stale.push_back(it->id);
    for (const auto& id : stale) {
        auto c = get_legacy_group(id);
        erase_legacy_group(id);
        if (c)
            _arch_legacy.insert_or_assign(session_id_to_bytes(c->id), std::move(*c));
    }

    stale.clear();
    for (auto it = begin_blinded_1to1(false); !it.done(); ++it)
        if (is_stale(*it, cutoff))
            stale.push_back(it->blinded_session_id);
    for (const auto& id : stale) {
        auto c = get_blinded_1to1(id);
        erase_blinded_1to1(id);
        if (c)
            _arch_blinded.insert_or_assign(
                    session_id_to_bytes(c->blinded_session_id, c->legacy_blinding ? "15" : "25"),
                    std::move(*c));
    }

    stale.clear();
    for (auto it = begin_groups(false); !it.done(); ++it)
        if (is_stale(*it, cutoff))
            stale.push_back(it->id);
    for (const auto& id : stale) {
        auto c = get_group(id);
        erase_group(id);
        if (c)
            _arch_group.insert_or_assign(session_id_to_bytes(c->id, "03"), std::move(*c));
    }

    std::vector<std::pair<std::string, std::string>> stale_comms;
    for (auto it = begin_communities(false); !it.done(); ++it)
        if (is_stale(*it, cutoff))
            stale_comms.emplace_back(it->base_url(), it->room());
    for (const auto& [base, room] : stale_comms) {
        auto c = get_community(base, room);
        erase_community(base, room);
        if (c)
            _arch_comm[c->base_url()].insert_or_assign(c->room_norm(), std::move(*c));
    }
}

std::tuple<seqno_t, std::vector<std::vector<unsigned char>>, std::vector<std::string>>
ConvoInfoVolatile::push() {
    // Archive any conversations with last_read timestamps more than ARCHIVE_AFTER ago (unless they
    // also have a `unread` flag set, in which case we keep them indefinitely).
    archive_stale();

    return ConfigBase::push();
}

void ConvoInfoVolatile::after_merge() {
    // After a config merge the active dict may contain entries that are also sitting in one of
    // the local-only archive maps (e.g. a peer's config re-activated a conversation that had
    // been archived locally). Remove any such duplicates from the archives so that iteration always
    // yields each entry exactly once.
    // Note: manually adding entries to the active dict will still create duplicates.
    // A call to push will eventually archive those that needs to be archived.

    auto cleanup = [](auto& arch, const dict* active) {
        if (!active)
            return;
        for (auto it = arch.begin(); it != arch.end();)
            it = active->count(it->first) ? arch.erase(it) : std::next(it);
    };

    cleanup(_arch_1to1, data["1"].dict());
    cleanup(_arch_legacy, data["C"].dict());
    cleanup(_arch_blinded, data["b"].dict());
    cleanup(_arch_group, data["g"].dict());

    // Communities are nested: base_url → room_norm.
    for (auto sit = _arch_comm.begin(); sit != _arch_comm.end();) {
        auto& [base_url, rooms] = *sit;
        if (auto* rd = data["o"][base_url]["R"].dict())
            for (auto rit = rooms.begin(); rit != rooms.end();)
                rit = rd->count(rit->first) ? rooms.erase(rit) : std::next(rit);
        sit = rooms.empty() ? _arch_comm.erase(sit) : std::next(sit);
    }

    this->archive_stale();
}

void ConvoInfoVolatile::extra_data(oxenc::bt_dict_producer&& extra) const {
    // Maps are already sorted by binary key; iterate directly.
    // Top-level bencode key order: "1"(49) < "C"(67) < "b"(98) < "g"(103) < "o"(111)

    // "1": one_to_one — entry fields sorted: "e" < "g" < "r" < "u"
    if (!_arch_1to1.empty()) {
        auto section = extra.append_dict("1");
        for (const auto& [key, c] : _arch_1to1) {
            auto val = section.append_dict(key);
            auto pro_expiry = c.pro_expiry_unix_ts.time_since_epoch().count();
            if (pro_expiry > 0 && c.pro_gen_index_hash) {
                val.append("e", pro_expiry);
                val.append(
                        "g",
                        std::span<const unsigned char>{
                                c.pro_gen_index_hash->data(), c.pro_gen_index_hash->size()});
            }
            val.append("r", c.last_read);
            if (c.unread)
                val.append("u", 1);
        }
    }

    // "C": legacy_group — entry fields sorted: "r" < "u"
    if (!_arch_legacy.empty()) {
        auto section = extra.append_dict("C");
        for (const auto& [key, c] : _arch_legacy) {
            auto val = section.append_dict(key);
            val.append("r", c.last_read);
            if (c.unread)
                val.append("u", 1);
        }
    }

    // "b": blinded_one_to_one — entry fields sorted: "e" < "g" < "r" < "u" < "y"
    if (!_arch_blinded.empty()) {
        auto section = extra.append_dict("b");
        for (const auto& [key, c] : _arch_blinded) {
            auto val = section.append_dict(key);
            auto pro_expiry = c.pro_expiry_unix_ts.time_since_epoch().count();
            if (pro_expiry > 0 && c.pro_gen_index_hash) {
                val.append("e", pro_expiry);
                val.append(
                        "g",
                        std::span<const unsigned char>{
                                c.pro_gen_index_hash->data(), c.pro_gen_index_hash->size()});
            }
            val.append("r", c.last_read);
            if (c.unread)
                val.append("u", 1);
            if (c.legacy_blinding)
                val.append("y", 1);
        }
    }

    // "g": group — entry fields sorted: "r" < "u"
    if (!_arch_group.empty()) {
        auto section = extra.append_dict("g");
        for (const auto& [key, c] : _arch_group) {
            auto val = section.append_dict(key);
            val.append("r", c.last_read);
            if (c.unread)
                val.append("u", 1);
        }
    }

    // "o": community — server dict keys sorted: "#"(35) < "R"(82); room dict: "r" < "u"
    if (!_arch_comm.empty()) {
        auto section = extra.append_dict("o");
        for (const auto& [base_url, rooms] : _arch_comm) {
            if (rooms.empty())
                continue;
            auto server = section.append_dict(base_url);
            const auto& any_comm = rooms.begin()->second;
            server.append(
                    "#",
                    std::span<const unsigned char>{
                            any_comm.pubkey().data(), any_comm.pubkey().size()});
            auto rooms_dict = server.append_dict("R");
            for (const auto& [room, c] : rooms) {
                auto room_val = rooms_dict.append_dict(room);
                room_val.append("r", c.last_read);
                if (c.unread)
                    room_val.append("u", 1);
            }
        }
    }
}

void ConvoInfoVolatile::load_extra_data(oxenc::bt_dict_consumer&& extra) {
    // "1": one_to_one — skip if already in active config (handles re-activation)
    if (extra.skip_until("1")) {
        auto section = extra.consume_dict_consumer();
        while (!section.is_finished()) {
            auto [key, val] = section.next_dict_consumer();
            if (key.size() != 33)
                continue;
            if (data["1"][std::string{key}].dict())
                continue;
            convo::one_to_one c{oxenc::to_hex(key)};
            if (val.skip_until("e")) {
                c.pro_expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                        std::chrono::milliseconds(val.consume_integer<int64_t>()));
            }
            if (val.skip_until("g")) {
                auto g = val.consume_string_view();
                if (g.size() == 32) {
                    c.pro_gen_index_hash.emplace();
                    std::memcpy(c.pro_gen_index_hash->data(), g.data(), 32);
                }
            }
            if (val.skip_until("r"))
                c.last_read = val.consume_integer<int64_t>();
            if (val.skip_until("u"))
                c.unread = (bool)val.consume_integer<int>();
            _arch_1to1.insert_or_assign(std::string{key}, std::move(c));
        }
    }

    // "C": legacy_group
    if (extra.skip_until("C")) {
        auto section = extra.consume_dict_consumer();
        while (!section.is_finished()) {
            auto [key, val] = section.next_dict_consumer();
            if (key.size() != 33)
                continue;
            if (data["C"][std::string{key}].dict())
                continue;
            convo::legacy_group c{oxenc::to_hex(key)};
            if (val.skip_until("r"))
                c.last_read = val.consume_integer<int64_t>();
            if (val.skip_until("u"))
                c.unread = (bool)val.consume_integer<int>();
            _arch_legacy.insert_or_assign(std::string{key}, std::move(c));
        }
    }

    // "b": blinded_one_to_one
    if (extra.skip_until("b")) {
        auto section = extra.consume_dict_consumer();
        while (!section.is_finished()) {
            auto [key, val] = section.next_dict_consumer();
            if (key.size() != 33)
                continue;
            if (data["b"][std::string{key}].dict())
                continue;
            try {
                convo::blinded_one_to_one c{oxenc::to_hex(key)};
                if (val.skip_until("e")) {
                    c.pro_expiry_unix_ts = std::chrono::sys_time<std::chrono::milliseconds>(
                            std::chrono::milliseconds(val.consume_integer<int64_t>()));
                }
                if (val.skip_until("g")) {
                    auto g = val.consume_string_view();
                    if (g.size() == 32) {
                        c.pro_gen_index_hash.emplace();
                        std::memcpy(c.pro_gen_index_hash->data(), g.data(), 32);
                    }
                }
                if (val.skip_until("r"))
                    c.last_read = val.consume_integer<int64_t>();
                if (val.skip_until("u"))
                    c.unread = (bool)val.consume_integer<int>();
                // "y" (legacy_blinding) is derivable from the ID prefix; no need to parse
                _arch_blinded.insert_or_assign(std::string{key}, std::move(c));
            } catch (...) { /* invalid blinded ID — skip */
            }
        }
    }

    // "g": group
    if (extra.skip_until("g")) {
        auto section = extra.consume_dict_consumer();
        while (!section.is_finished()) {
            auto [key, val] = section.next_dict_consumer();
            if (key.size() != 33)
                continue;
            if (data["g"][std::string{key}].dict())
                continue;
            try {
                convo::group c{oxenc::to_hex(key)};
                if (val.skip_until("r"))
                    c.last_read = val.consume_integer<int64_t>();
                if (val.skip_until("u"))
                    c.unread = (bool)val.consume_integer<int>();
                _arch_group.insert_or_assign(std::string{key}, std::move(c));
            } catch (...) { /* invalid group ID — skip */
            }
        }
    }

    // "o": community
    if (extra.skip_until("o")) {
        auto section = extra.consume_dict_consumer();
        while (!section.is_finished()) {
            auto [base_url_sv, server_val] = section.next_dict_consumer();
            std::string base_url{base_url_sv};
            if (!server_val.skip_until("#"))
                continue;
            auto pk_sv = server_val.consume_string_view();
            if (pk_sv.size() != 32)
                continue;
            std::span<const unsigned char> pubkey{
                    reinterpret_cast<const unsigned char*>(pk_sv.data()), 32};
            if (!server_val.skip_until("R"))
                continue;
            auto rooms_val = server_val.consume_dict_consumer();
            while (!rooms_val.is_finished()) {
                auto [room_sv, room_val] = rooms_val.next_dict_consumer();
                std::string room{room_sv};
                if (data["o"][base_url]["R"][room].dict())
                    continue;
                try {
                    convo::community c{base_url, room, pubkey};
                    if (room_val.skip_until("r"))
                        c.last_read = room_val.consume_integer<int64_t>();
                    if (room_val.skip_until("u"))
                        c.unread = (bool)room_val.consume_integer<int>();
                    _arch_comm[base_url].insert_or_assign(c.room_norm(), std::move(c));
                } catch (...) { /* invalid url/room format — skip */
                }
            }
        }
    }
}

void ConvoInfoVolatile::set(const convo::community& c) {
    auto info = community_field(c);
    if (set_base(c, info)) {
        if (auto s = _arch_comm.find(c.base_url()); s != _arch_comm.end())
            if (s->second.erase(c.room_norm()) && s->second.empty())
                _arch_comm.erase(s);
        data["o"][c.base_url()]["#"] = c.pubkey();
    } else {
        info.erase();  // remove from active dict if present
        _arch_comm[c.base_url()].insert_or_assign(c.room_norm(), c);
        _needs_dump = true;
    }
}

void ConvoInfoVolatile::set(const convo::group& c) {
    auto key = session_id_to_bytes(c.id, "03");
    auto info = data["g"][key];
    set_or_archive(c, info, key, _arch_group);
}

void ConvoInfoVolatile::set(const convo::legacy_group& c) {
    auto key = session_id_to_bytes(c.id);
    auto info = data["C"][key];
    set_or_archive(c, info, key, _arch_legacy);
}

void ConvoInfoVolatile::set(const convo::blinded_one_to_one& c) {
    auto key = session_id_to_bytes(c.blinded_session_id, c.legacy_blinding ? "15" : "25");
    auto info = data["b"][key];
    if (set_or_archive(c, info, key, _arch_blinded)) {
        set_nonzero_int(info["e"], c.pro_expiry_unix_ts.time_since_epoch().count());
        if (c.pro_gen_index_hash)
            info["g"] = *c.pro_gen_index_hash;
        set_nonzero_int(info["y"], c.legacy_blinding);
    }
}

template <typename Field>
static bool erase_impl(Field convo) {
    bool ret = convo.exists();
    convo.erase();
    return ret;
}

bool ConvoInfoVolatile::erase(const convo::one_to_one& c) {
    auto key = session_id_to_bytes(c.session_id);
    return erase_from_both(data["1"][key], key, _arch_1to1);
}
bool ConvoInfoVolatile::erase(const convo::community& c) {
    if (auto s = _arch_comm.find(c.base_url()); s != _arch_comm.end()) {
        if (s->second.erase(c.room_norm())) {
            if (s->second.empty())
                _arch_comm.erase(s);
            _needs_dump = true;
        }
    }
    bool gone = erase_impl(community_field(c));
    if (gone) {
        // If this was the last room on the server, also remove the server
        auto server_info = data["o"][c.base_url()];
        auto rooms = server_info["R"];
        if (auto* rd = rooms.dict(); !rd || rd->empty()) {
            rooms.erase();
            server_info.erase();
        }
    }
    return gone;
}
bool ConvoInfoVolatile::erase(const convo::group& c) {
    auto key = session_id_to_bytes(c.id, "03");
    return erase_from_both(data["g"][key], key, _arch_group);
}
bool ConvoInfoVolatile::erase(const convo::legacy_group& c) {
    auto key = session_id_to_bytes(c.id);
    return erase_from_both(data["C"][key], key, _arch_legacy);
}
bool ConvoInfoVolatile::erase(const convo::blinded_one_to_one& c) {
    auto key = session_id_to_bytes(c.blinded_session_id, c.legacy_blinding ? "15" : "25");
    return erase_from_both(data["b"][key], key, _arch_blinded);
}

bool ConvoInfoVolatile::erase(const convo::any& c) {
    return std::visit([this](const auto& c) { return erase(c); }, c);
}
bool ConvoInfoVolatile::erase_1to1(std::string_view session_id) {
    return erase(convo::one_to_one{session_id});
}
bool ConvoInfoVolatile::erase_community(std::string_view base_url, std::string_view room) {
    return erase(convo::community{base_url, room});
}
bool ConvoInfoVolatile::erase_group(std::string_view id) {
    return erase(convo::group{id});
}
bool ConvoInfoVolatile::erase_legacy_group(std::string_view id) {
    return erase(convo::legacy_group{id});
}
bool ConvoInfoVolatile::erase_blinded_1to1(std::string_view blinded_session_id) {
    return erase(convo::blinded_one_to_one{blinded_session_id});
}

size_t ConvoInfoVolatile::size_1to1() const {
    if (auto* d = data["1"].dict())
        return d->size();
    return 0;
}

size_t ConvoInfoVolatile::size_communities() const {
    size_t count = 0;
    auto og = data["o"];
    if (auto* servers = og.dict()) {
        for (const auto& [baseurl, info] : *servers) {
            auto server = og[baseurl];
            if (!server["#"].exists<std::string>())
                continue;
            auto rooms = server["R"];
            if (auto* rd = rooms.dict())
                count += rd->size();
        }
    }
    return count;
}

size_t ConvoInfoVolatile::size_groups() const {
    if (auto* d = data["g"].dict())
        return d->size();
    return 0;
}

size_t ConvoInfoVolatile::size_legacy_groups() const {
    if (auto* d = data["C"].dict())
        return d->size();
    return 0;
}

size_t ConvoInfoVolatile::size_blinded_1to1() const {
    if (auto* d = data["b"].dict())
        return d->size();
    return 0;
}

size_t ConvoInfoVolatile::size_1to1_archived() const {
    return _arch_1to1.size();
}

size_t ConvoInfoVolatile::size_communities_archived() const {
    size_t n = 0;
    for (const auto& [_, rooms] : _arch_comm)
        n += rooms.size();
    return n;
}

size_t ConvoInfoVolatile::size_groups_archived() const {
    return _arch_group.size();
}

size_t ConvoInfoVolatile::size_legacy_groups_archived() const {
    return _arch_legacy.size();
}

size_t ConvoInfoVolatile::size_blinded_1to1_archived() const {
    return _arch_blinded.size();
}

size_t ConvoInfoVolatile::size() const {
    return size_1to1() + size_communities() + size_legacy_groups() + size_groups() +
           size_blinded_1to1();
}

size_t ConvoInfoVolatile::size_archived() const {
    return size_1to1_archived() + size_communities_archived() + size_legacy_groups_archived() +
           size_groups_archived() + size_blinded_1to1_archived();
}

ConvoInfoVolatile::iterator::iterator(
        const DictFieldRoot& data,
        bool oneto1,
        bool communities,
        bool groups,
        bool legacy_groups,
        bool blinded_1to1,
        const ConvoInfoVolatile::arch_1to1_map_t* arch_1to1,
        const ConvoInfoVolatile::arch_legacy_map_t* arch_legacy,
        const ConvoInfoVolatile::arch_blinded_map_t* arch_blinded,
        const ConvoInfoVolatile::arch_group_map_t* arch_group,
        const ConvoInfoVolatile::arch_comm_map_t* arch_comm) {
    _arch_1to1 = (arch_1to1 && !arch_1to1->empty()) ? arch_1to1 : nullptr;
    _arch_legacy = (arch_legacy && !arch_legacy->empty()) ? arch_legacy : nullptr;
    _arch_blinded = (arch_blinded && !arch_blinded->empty()) ? arch_blinded : nullptr;
    _arch_group = (arch_group && !arch_group->empty()) ? arch_group : nullptr;
    _arch_comm = (arch_comm && !arch_comm->empty()) ? arch_comm : nullptr;
    _arch_section = (_arch_1to1 || _arch_legacy || _arch_blinded || _arch_group || _arch_comm)
                          ? ArchPhase::s_1to1
                          : ArchPhase::done;
    // Initialise all archive map iterators to begin() upfront; only the one matching
    // _arch_section is used at any given time, but pre-initialising avoids lazy init in _load_val.
    if (_arch_1to1)
        _arch_1to1_it = _arch_1to1->begin();
    if (_arch_group)
        _arch_group_it = _arch_group->begin();
    if (_arch_comm) {
        _arch_comm_it = _arch_comm->begin();
        if (_arch_comm_it != _arch_comm->end())
            _arch_comm_room_it = _arch_comm_it->second.begin();
    }
    if (_arch_legacy)
        _arch_legacy_it = _arch_legacy->begin();
    if (_arch_blinded)
        _arch_blinded_it = _arch_blinded->begin();
    if (oneto1)
        if (auto* d = data["1"].dict()) {
            _it_11 = d->begin();
            _end_11 = d->end();
        }
    if (communities)
        if (auto* d = data["o"].dict())
            _it_comm.emplace(d->begin(), d->end());
    if (groups)
        if (auto* d = data["g"].dict()) {
            _it_group = d->begin();
            _end_group = d->end();
        }
    if (legacy_groups)
        if (auto* d = data["C"].dict()) {
            _it_lgroup = d->begin();
            _end_lgroup = d->end();
        }
    if (blinded_1to1)
        if (auto* d = data["b"].dict()) {
            _it_b11 = d->begin();
            _end_b11 = d->end();
        }
    _load_val();
}

class val_loader {
  public:
    template <typename ConvoType>
    static bool load(
            std::shared_ptr<convo::any>& val,
            std::optional<dict::const_iterator>& it,
            std::optional<dict::const_iterator>& end,
            char prefix,
            std::optional<char> legacy_prefix = std::nullopt) {
        while (it) {
            if (*it == *end) {
                it.reset();
                end.reset();
                return false;
            }

            auto& [k, v] = **it;

            if (k.size() == 33 && (k[0] == prefix || (legacy_prefix && k[0] == *legacy_prefix))) {
                if (auto* info_dict = std::get_if<dict>(&v)) {
                    val = std::make_shared<convo::any>(ConvoType{oxenc::to_hex(k)});
                    std::get<ConvoType>(*val).load(*info_dict);
                    return true;
                }
            }
            ++*it;
        }
        return false;
    }
};

/// Load _val from the current iterator position; if it is invalid, skip to the next key until we
/// find one that is valid (or hit the end).  We also span across four different iterators: we
/// exhaust, in order: _it_11, _it_group, _it_comm, _it_lgroup, _it_b11.
///
/// We *always* call this after incrementing the iterator (and after iterator initialization), and
/// this is responsible for making sure that _it_11, _it_group, etc. are only set to non-nullopt if
/// the respective sub-iterator is *not* at the end (and resetting them when we hit the end).  Thus,
/// after calling this, our "end" condition will be simply that all of the three iterators are
/// nullopt.
void ConvoInfoVolatile::iterator::_load_val() {
    if (val_loader::load<convo::one_to_one>(_val, _it_11, _end_11, 0x05))
        return;

    if (val_loader::load<convo::group>(_val, _it_group, _end_group, 0x03))
        return;

    if (_it_comm) {
        if (_it_comm->load<convo::community>(_val))
            return;
        else
            _it_comm.reset();
    }

    if (val_loader::load<convo::legacy_group>(_val, _it_lgroup, _end_lgroup, 0x05))
        return;

    if (val_loader::load<convo::blinded_one_to_one>(_val, _it_b11, _end_b11, 0x25, 0x15))
        return;

    // Dict phase exhausted — scan typed archive sections in extra_data key order
    // ("1"<"C"<"b"<"g"<"o").
    while (_arch_section != ArchPhase::done) {
        switch (_arch_section) {
            case ArchPhase::s_1to1:
                if (_arch_1to1 && _arch_1to1_it != _arch_1to1->end()) {
                    _val = std::make_shared<convo::any>(_arch_1to1_it->second);
                    ++_arch_1to1_it;
                    return;
                }
                break;
            case ArchPhase::s_legacy:
                if (_arch_legacy && _arch_legacy_it != _arch_legacy->end()) {
                    _val = std::make_shared<convo::any>(_arch_legacy_it->second);
                    ++_arch_legacy_it;
                    return;
                }
                break;
            case ArchPhase::s_blinded:
                if (_arch_blinded && _arch_blinded_it != _arch_blinded->end()) {
                    _val = std::make_shared<convo::any>(_arch_blinded_it->second);
                    ++_arch_blinded_it;
                    return;
                }
                break;
            case ArchPhase::s_group:
                if (_arch_group && _arch_group_it != _arch_group->end()) {
                    _val = std::make_shared<convo::any>(_arch_group_it->second);
                    ++_arch_group_it;
                    return;
                }
                break;
            case ArchPhase::s_comm:
                if (_arch_comm) {
                    while (_arch_comm_it != _arch_comm->end()) {
                        if (_arch_comm_room_it != _arch_comm_it->second.end()) {
                            _val = std::make_shared<convo::any>(_arch_comm_room_it->second);
                            ++_arch_comm_room_it;
                            return;
                        }
                        ++_arch_comm_it;
                        if (_arch_comm_it != _arch_comm->end())
                            _arch_comm_room_it = _arch_comm_it->second.begin();
                    }
                }
                break;
            case ArchPhase::done: break;
        }
        _arch_section = static_cast<ArchPhase>(static_cast<uint8_t>(_arch_section) + 1);
    }
}

bool ConvoInfoVolatile::iterator::operator==(const iterator& other) const {
    if (_it_11 != other._it_11 || _it_group != other._it_group || _it_comm != other._it_comm ||
        _it_lgroup != other._it_lgroup || _it_b11 != other._it_b11)
        return false;
    if (_arch_section != other._arch_section)
        return false;
    switch (_arch_section) {
        case ArchPhase::s_1to1: return _arch_1to1_it == other._arch_1to1_it;
        case ArchPhase::s_legacy: return _arch_legacy_it == other._arch_legacy_it;
        case ArchPhase::s_blinded: return _arch_blinded_it == other._arch_blinded_it;
        case ArchPhase::s_group: return _arch_group_it == other._arch_group_it;
        case ArchPhase::s_comm:
            if (_arch_comm_it != other._arch_comm_it)
                return false;
            if (_arch_comm && _arch_comm_it != _arch_comm->end())
                return _arch_comm_room_it == other._arch_comm_room_it;
            return true;
        default: return true;  // ArchPhase::done — both exhausted
    }
}

bool ConvoInfoVolatile::iterator::done() const {
    return !_it_11 && !_it_group && (!_it_comm || _it_comm->done()) && !_it_lgroup && !_it_b11 &&
           _arch_section == ArchPhase::done;
}

ConvoInfoVolatile::iterator& ConvoInfoVolatile::iterator::operator++() {
    if (_it_11)
        ++*_it_11;
    else if (_it_group)
        ++*_it_group;
    else if (_it_comm && !_it_comm->done())
        _it_comm->advance();
    else if (_it_lgroup)
        ++*_it_lgroup;
    else if (_it_b11)
        ++*_it_b11;
    // else: archive phase — _load_val() advances the map iterator
    _load_val();
    return *this;
}

}  // namespace session::config

using namespace session::config;

extern "C" {
struct convo_info_volatile_iterator {
    void* _internals;
};
}

LIBSESSION_C_API
int convo_info_volatile_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey_bytes,
        const unsigned char* dumpstr,
        size_t dumplen,
        char* error) {
    return c_wrapper_init<ConvoInfoVolatile>(
            conf, ed25519_secretkey_bytes, dumpstr, dumplen, error);
}

LIBSESSION_C_API bool convo_info_volatile_get_1to1(
        config_object* conf, convo_info_volatile_1to1* convo, const char* session_id) {
    return wrap_exceptions(
            conf,
            [&] {
                if (auto c = unbox<ConvoInfoVolatile>(conf)->get_1to1(session_id)) {
                    c->into(*convo);
                    return true;
                }
                return false;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_get_or_construct_1to1(
        config_object* conf, convo_info_volatile_1to1* convo, const char* session_id) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<ConvoInfoVolatile>(conf)->get_or_construct_1to1(session_id).into(*convo);
                return true;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_get_community(
        config_object* conf,
        convo_info_volatile_community* og,
        const char* base_url,
        const char* room) {
    return wrap_exceptions(
            conf,
            [&] {
                if (auto c = unbox<ConvoInfoVolatile>(conf)->get_community(base_url, room)) {
                    c->into(*og);
                    return true;
                }
                return false;
            },
            false);
}
LIBSESSION_C_API bool convo_info_volatile_get_or_construct_community(
        config_object* conf,
        convo_info_volatile_community* convo,
        const char* base_url,
        const char* room,
        unsigned const char* pubkey) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<ConvoInfoVolatile>(conf)
                        ->get_or_construct_community(
                                base_url, room, std::span<const unsigned char>{pubkey, 32})
                        .into(*convo);
                return true;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_get_group(
        config_object* conf, convo_info_volatile_group* convo, const char* id) {
    return wrap_exceptions(
            conf,
            [&] {
                if (auto c = unbox<ConvoInfoVolatile>(conf)->get_group(id)) {
                    c->into(*convo);
                    return true;
                }
                return false;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_get_or_construct_group(
        config_object* conf, convo_info_volatile_group* convo, const char* id) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<ConvoInfoVolatile>(conf)->get_or_construct_group(id).into(*convo);
                return true;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_get_legacy_group(
        config_object* conf, convo_info_volatile_legacy_group* convo, const char* id) {
    return wrap_exceptions(
            conf,
            [&] {
                if (auto c = unbox<ConvoInfoVolatile>(conf)->get_legacy_group(id)) {
                    c->into(*convo);
                    return true;
                }
                return false;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_get_or_construct_legacy_group(
        config_object* conf, convo_info_volatile_legacy_group* convo, const char* id) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<ConvoInfoVolatile>(conf)->get_or_construct_legacy_group(id).into(*convo);
                return true;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_get_blinded_1to1(
        config_object* conf,
        convo_info_volatile_blinded_1to1* convo,
        const char* blinded_session_id) {
    return wrap_exceptions(
            conf,
            [&] {
                if (auto c = unbox<ConvoInfoVolatile>(conf)->get_blinded_1to1(blinded_session_id)) {
                    c->into(*convo);
                    return true;
                }
                return false;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_get_or_construct_blinded_1to1(
        config_object* conf,
        convo_info_volatile_blinded_1to1* convo,
        const char* blinded_session_id) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<ConvoInfoVolatile>(conf)
                        ->get_or_construct_blinded_1to1(blinded_session_id)
                        .into(*convo);
                return true;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_set_1to1(
        config_object* conf, const convo_info_volatile_1to1* convo) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<ConvoInfoVolatile>(conf)->set(convo::one_to_one{*convo});
                return true;
            },
            false);
}
LIBSESSION_C_API bool convo_info_volatile_set_community(
        config_object* conf, const convo_info_volatile_community* convo) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<ConvoInfoVolatile>(conf)->set(convo::community{*convo});
                return true;
            },
            false);
}
LIBSESSION_C_API bool convo_info_volatile_set_group(
        config_object* conf, const convo_info_volatile_group* convo) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<ConvoInfoVolatile>(conf)->set(convo::group{*convo});
                return true;
            },
            false);
}
LIBSESSION_C_API bool convo_info_volatile_set_legacy_group(
        config_object* conf, const convo_info_volatile_legacy_group* convo) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<ConvoInfoVolatile>(conf)->set(convo::legacy_group{*convo});
                return true;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_set_blinded_1to1(
        config_object* conf, const convo_info_volatile_blinded_1to1* convo) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<ConvoInfoVolatile>(conf)->set(convo::blinded_one_to_one{*convo});
                return true;
            },
            false);
}

LIBSESSION_C_API bool convo_info_volatile_erase_1to1(config_object* conf, const char* session_id) {
    return wrap_exceptions(
            conf, [&] { return unbox<ConvoInfoVolatile>(conf)->erase_1to1(session_id); }, false);
}
LIBSESSION_C_API bool convo_info_volatile_erase_community(
        config_object* conf, const char* base_url, const char* room) {
    return wrap_exceptions(
            conf,
            [&] { return unbox<ConvoInfoVolatile>(conf)->erase_community(base_url, room); },
            false);
}
LIBSESSION_C_API bool convo_info_volatile_erase_group(config_object* conf, const char* group_id) {
    return wrap_exceptions(
            conf, [&] { return unbox<ConvoInfoVolatile>(conf)->erase_group(group_id); }, false);
}
LIBSESSION_C_API bool convo_info_volatile_erase_legacy_group(
        config_object* conf, const char* group_id) {
    return wrap_exceptions(
            conf,
            [&] { return unbox<ConvoInfoVolatile>(conf)->erase_legacy_group(group_id); },
            false);
}
LIBSESSION_C_API bool convo_info_volatile_erase_blinded_1to1(
        config_object* conf, const char* blinded_session_id) {
    return wrap_exceptions(
            conf,
            [&] { return unbox<ConvoInfoVolatile>(conf)->erase_blinded_1to1(blinded_session_id); },
            false);
}

LIBSESSION_C_API size_t convo_info_volatile_size(const config_object* conf) {
    return unbox<ConvoInfoVolatile>(conf)->size();
}
LIBSESSION_C_API size_t convo_info_volatile_size_1to1(const config_object* conf) {
    return unbox<ConvoInfoVolatile>(conf)->size_1to1();
}
LIBSESSION_C_API size_t convo_info_volatile_size_communities(const config_object* conf) {
    return unbox<ConvoInfoVolatile>(conf)->size_communities();
}
LIBSESSION_C_API size_t convo_info_volatile_size_groups(const config_object* conf) {
    return unbox<ConvoInfoVolatile>(conf)->size_groups();
}
LIBSESSION_C_API size_t convo_info_volatile_size_legacy_groups(const config_object* conf) {
    return unbox<ConvoInfoVolatile>(conf)->size_legacy_groups();
}
LIBSESSION_C_API size_t convo_info_volatile_size_blinded_1to1(const config_object* conf) {
    return unbox<ConvoInfoVolatile>(conf)->size_blinded_1to1();
}

LIBSESSION_C_API convo_info_volatile_iterator* convo_info_volatile_iterator_new(
        const config_object* conf) {
    auto* it = new convo_info_volatile_iterator{};
    it->_internals = new ConvoInfoVolatile::iterator{unbox<ConvoInfoVolatile>(conf)->begin()};
    return it;
}

LIBSESSION_C_API convo_info_volatile_iterator* convo_info_volatile_iterator_new_1to1(
        const config_object* conf) {
    auto* it = new convo_info_volatile_iterator{};
    it->_internals = new ConvoInfoVolatile::iterator{unbox<ConvoInfoVolatile>(conf)->begin_1to1()};
    return it;
}
LIBSESSION_C_API convo_info_volatile_iterator* convo_info_volatile_iterator_new_communities(
        const config_object* conf) {
    auto* it = new convo_info_volatile_iterator{};
    it->_internals =
            new ConvoInfoVolatile::iterator{unbox<ConvoInfoVolatile>(conf)->begin_communities()};
    return it;
}
LIBSESSION_C_API convo_info_volatile_iterator* convo_info_volatile_iterator_new_groups(
        const config_object* conf) {
    auto* it = new convo_info_volatile_iterator{};
    it->_internals =
            new ConvoInfoVolatile::iterator{unbox<ConvoInfoVolatile>(conf)->begin_groups()};
    return it;
}
LIBSESSION_C_API convo_info_volatile_iterator* convo_info_volatile_iterator_new_legacy_groups(
        const config_object* conf) {
    auto* it = new convo_info_volatile_iterator{};
    it->_internals =
            new ConvoInfoVolatile::iterator{unbox<ConvoInfoVolatile>(conf)->begin_legacy_groups()};
    return it;
}
LIBSESSION_C_API convo_info_volatile_iterator* convo_info_volatile_iterator_new_blinded_1to1(
        const config_object* conf) {
    auto* it = new convo_info_volatile_iterator{};
    it->_internals =
            new ConvoInfoVolatile::iterator{unbox<ConvoInfoVolatile>(conf)->begin_blinded_1to1()};
    return it;
}

LIBSESSION_C_API void convo_info_volatile_iterator_free(convo_info_volatile_iterator* it) {
    delete static_cast<ConvoInfoVolatile::iterator*>(it->_internals);
    delete it;
}

LIBSESSION_C_API bool convo_info_volatile_iterator_done(convo_info_volatile_iterator* it) {
    auto& real = *static_cast<ConvoInfoVolatile::iterator*>(it->_internals);
    return real.done();
}

LIBSESSION_C_API void convo_info_volatile_iterator_advance(convo_info_volatile_iterator* it) {
    ++*static_cast<ConvoInfoVolatile::iterator*>(it->_internals);
}

namespace {
template <typename Cpp, typename C>
bool convo_info_volatile_it_is_impl(convo_info_volatile_iterator* it, C* c) {
    auto& convo = **static_cast<ConvoInfoVolatile::iterator*>(it->_internals);
    if (auto* d = std::get_if<Cpp>(&convo)) {
        d->into(*c);
        return true;
    }
    return false;
}
}  // namespace

LIBSESSION_C_API bool convo_info_volatile_it_is_1to1(
        convo_info_volatile_iterator* it, convo_info_volatile_1to1* c) {
    return convo_info_volatile_it_is_impl<convo::one_to_one>(it, c);
}

LIBSESSION_C_API bool convo_info_volatile_it_is_community(
        convo_info_volatile_iterator* it, convo_info_volatile_community* c) {
    return convo_info_volatile_it_is_impl<convo::community>(it, c);
}

LIBSESSION_C_API bool convo_info_volatile_it_is_group(
        convo_info_volatile_iterator* it, convo_info_volatile_group* c) {
    return convo_info_volatile_it_is_impl<convo::group>(it, c);
}

LIBSESSION_C_API bool convo_info_volatile_it_is_legacy_group(
        convo_info_volatile_iterator* it, convo_info_volatile_legacy_group* c) {
    return convo_info_volatile_it_is_impl<convo::legacy_group>(it, c);
}

LIBSESSION_C_API bool convo_info_volatile_it_is_blinded_1to1(
        convo_info_volatile_iterator* it, convo_info_volatile_blinded_1to1* c) {
    return convo_info_volatile_it_is_impl<convo::blinded_one_to_one>(it, c);
}
