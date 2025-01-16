#include "session/config/base.hpp"

#include <fmt/format.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_value_producer.h>
#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/utils.h>

#include <chrono>
#include <iterator>
#include <oxen/log/format.hpp>
#include <stdexcept>
#include <string>
#include <vector>

#include "internal.hpp"
#include "oxenc/bt_serialize.h"
#include "session/config/base.h"
#include "session/config/encrypt.hpp"
#include "session/config/protos.hpp"
#include "session/export.h"
#include "session/util.hpp"

using namespace std::literals;
using namespace oxen::log::literals;

namespace session::config {

void ConfigBase::set_state(ConfigState s) {
    if (s == ConfigState::Dirty && is_readonly())
        throw std::runtime_error{"Unable to make changes to a read-only config object"};

    if (_state == ConfigState::Clean && !_curr_hashes.empty()) {
        _old_hashes.insert(
                std::make_move_iterator(_curr_hashes.begin()),
                std::make_move_iterator(_curr_hashes.end()));
        _curr_hashes.clear();
    }
    _state = s;
    _needs_dump = true;
}

MutableConfigMessage& ConfigBase::dirty() {
    if (_state != ConfigState::Dirty) {
        set_state(ConfigState::Dirty);
        _config = std::make_unique<MutableConfigMessage>(*_config, increment_seqno);
    } else {
        _needs_dump = true;
    }

    if (auto* mut = dynamic_cast<MutableConfigMessage*>(_config.get()))
        return *mut;
    throw std::runtime_error{"Internal error: unexpected dirty but non-mutable ConfigMessage"};
}

template <typename... Args>
std::unique_ptr<ConfigMessage> make_config_message(bool from_dirty, Args&&... args) {
    if (from_dirty)
        return std::make_unique<MutableConfigMessage>(std::forward<Args>(args)...);
    return std::make_unique<ConfigMessage>(std::forward<Args>(args)...);
}

std::unordered_set<std::string> ConfigBase::merge(
        const std::vector<std::pair<std::string, ustring>>& configs) {
    std::vector<std::pair<std::string, ustring_view>> config_views;
    config_views.reserve(configs.size());
    for (auto& [hash, data] : configs)
        config_views.emplace_back(hash, data);
    return merge(config_views);
}

std::unordered_set<std::string> ConfigBase::merge(
        const std::vector<std::pair<std::string, ustring_view>>& configs) {
    if (accepts_protobuf() && !_keys.empty()) {
        std::list<ustring> keep_alive;
        std::vector<std::pair<std::string, ustring_view>> parsed;
        parsed.reserve(configs.size());

        for (auto& [h, c] : configs) {
            try {
                auto unwrapped = protos::unwrap_config(
                        ustring_view{_keys.front().data(), _keys.front().size()},
                        c,
                        storage_namespace());

                // There was a release of one of the clients which resulted in double-wrapped
                // config messages so we now need to try to double-unwrap in order to better
                // support multi-device for users running those old versions
                try {
                    auto unwrapped2 = protos::unwrap_config(
                            ustring_view{_keys.front().data(), _keys.front().size()},
                            unwrapped,
                            storage_namespace());
                    parsed.emplace_back(h, keep_alive.emplace_back(std::move(unwrapped2)));
                } catch (...) {
                    parsed.emplace_back(h, keep_alive.emplace_back(std::move(unwrapped)));
                }
            } catch (...) {
                parsed.emplace_back(h, c);
            }
        }

        return _merge(parsed);
    }

    return _merge(configs);
}

std::pair<bool, std::optional<std::pair<std::list<std::string>, ustring>>>
ConfigBase::_handle_multipart(std::string_view msg_id, std::span<const unsigned char> message) {
    assert(!message.empty() && message[0] == 'm');

    // Handle multipart messages.  Each part of a multipart message starts with `m` and then is
    // immediately followed by a bt_list where:
    //   - element 0 is the hash of the final, uncompressed, re-assembled message.
    //   - element 1 is the numeric sequence number of the message, starting from 0.
    //   - element 2 is the total number of messages in the sequence.
    //   - element 3 is a chunk of the data.
    // (and no trailing bt_list elements are allowed).

    try {
        if (message.size() > MAX_MESSAGE_SIZE)
            throw std::runtime_error{
                    "Invalid multi-part message: message part exceeds max message size"};

        oxenc::bt_list_consumer c{message.subspan<1>()};

        auto h = c.consume<ustring_view>();
        hash_t final_hash;
        if (h.size() != final_hash.size())
            throw std::runtime_error{"Invalid multi-part final message hash"};
        std::copy(h.begin(), h.end(), final_hash.begin());

        auto index_bytes = c.consume_span<uint8_t>();
        auto size_bytes = c.consume_span<uint8_t>();
        if (index_bytes.size() != 1 || size_bytes.size() != 1)
            throw std::runtime_error{"Invalid multi-part message part number encoding"};
        auto index = index_bytes[0];
        auto num_parts = size_bytes[0];
        if (num_parts <= 1 || index >= num_parts)
            throw std::runtime_error{"Invalid multi-part message part numbering ({} of {})"_format(
                    index, num_parts)};

        auto data = c.consume_span<unsigned char>();
        if (data.empty())
            throw std::runtime_error{"Invalid multi-part message with empty data"};

        if (!c.is_finished())
            throw std::runtime_error{"Invalid multi-part message with post-data elements"};

        auto& parts = _multiparts[final_hash];
        if (parts.done) {
            log(LogLevel::debug,
                "message {} is a duplicate part {} of {} of an already-processed multipart "
                "message; ignoring",
                msg_id,
                index,
                num_parts);
            return {true, std::nullopt};
        }
        if (parts.parts.empty()) {
            parts.size = num_parts;
        } else {
            if (num_parts != parts.size)
                throw std::runtime_error{
                        "message size ({}) does not match previous parts ({})"_format(
                                num_parts, parts.size)};
        }

        auto it = parts.parts.begin();
        while (it != parts.parts.end() && it->index < index)
            ++it;
        if (it != parts.parts.end() && it->index == index) {
            log(LogLevel::debug,
                "message {} is an already-seen multipart message ({} of {}); ignoring",
                msg_id,
                index,
                num_parts);
            return {true, std::nullopt};
        }
        parts.parts.emplace(it, index, msg_id, data);
        _needs_dump = true;

        if (parts.parts.size() == parts.size) {
            // We've completed a set of multiparts!

            std::pair<std::list<std::string>, ustring> result{};
            auto& [msgids, recombined] = result;

            size_t final_size = 0;
            for (const auto& p : parts.parts)
                final_size += p.data.size();
            recombined.reserve(final_size);
            for (const auto& p : parts.parts) {
                msgids.emplace_back(std::move(p.message_id));
                recombined.insert(recombined.end(), p.data.begin(), p.data.end());
            }

            {
                hash_t actual_hash;
                hash::hash(actual_hash, recombined);
                if (actual_hash != final_hash)
                    throw std::runtime_error{
                            "recombined message hash ({}) does not match part hash ({})"_format(
                                    oxenc::to_hex(actual_hash.begin(), actual_hash.end()),
                                    oxenc::to_hex(final_hash.begin(), final_hash.end()))};
            }

            log(LogLevel::debug,
                "message {} (part {} of {}) completed a multipart set (hash {}), {}B data",
                msg_id,
                index,
                parts.size,
                oxenc::to_hex(final_hash.begin(), final_hash.end()),
                final_size);

            parts.finish(MULTIPART_MAX_REMEMBER);

            // Remove prefix padding of the recombined message:
            if (auto p = recombined.find_first_not_of((unsigned char)0);
                p > 0 && p != std::string::npos) {
                std::memmove(recombined.data(), recombined.data() + p, recombined.size() - p);
                recombined.resize(recombined.size() - p);
            }

            if (recombined.starts_with((unsigned char)'z')) {
                if (auto decompressed = zstd_decompress(recombined.substr(1));
                    decompressed && !decompressed->empty()) {
                    log(LogLevel::debug,
                        "multipart message {} inflated to {}B plaintext from {}B compressed",
                        oxenc::to_hex(final_hash.begin(), final_hash.end()),
                        decompressed->size(),
                        recombined.size());
                    recombined = std::move(*decompressed);
                } else
                    throw std::runtime_error{
                            "Invalid recombined data (hash {}): decompression failed"_format(
                                    oxenc::to_hex(final_hash.begin(), final_hash.end()), msg_id)};
            }

            if (recombined.empty())
                throw std::runtime_error{"recombined data is empty"};

            if (!recombined.starts_with((unsigned char)'d'))
                throw std::runtime_error{"Recombined data has invalid/unsupported type {:?}"_format(
                        static_cast<const char>(recombined[0]))};

            return {true, std::move(result)};
        } else {
            parts.expiry = std::chrono::system_clock::now() + MULTIPART_MAX_WAIT;
            log(LogLevel::debug,
                "message {} (part {} of {}) stored without completing a multipart set for {}",
                msg_id,
                index,
                parts.size,
                oxenc::to_hex(final_hash.begin(), final_hash.end()));
            return {true, std::nullopt};
        }

    } catch (const std::exception& e) {
        log(LogLevel::error, "invalid multi-part config message {}: {}", msg_id, e.what());
        return {false, std::nullopt};
    }
}

void ConfigBase::_expire_multiparts() {
    auto now = std::chrono::system_clock::now();
    for (auto it = _multiparts.begin(); it != _multiparts.end();) {
        auto& [hash, parts] = *it;
        if (parts.expiry < now)
            it = _multiparts.erase(it);
        else
            ++it;
    }
}

void ConfigBase::_dump_multiparts(oxenc::bt_dict_producer&& multi) const {
    auto now = std::chrono::system_clock::now();
    for (const auto& [fhash, parts] : _multiparts) {
        if (parts.expiry < now)
            continue;
        auto pdata = multi.append_dict(from_unsigned_sv(fhash));
        pdata.append("#", parts.done ? 0 : parts.size);
        pdata.append(
                "T",
                std::chrono::duration_cast<std::chrono::milliseconds>(
                        parts.expiry.time_since_epoch())
                        .count());
        if (!parts.done) {
            auto parts_list = pdata.append_list("p");
            for (const auto& part : parts.parts) {
                auto pd = parts_list.append_dict();
                pd.append("#", part.index);
                pd.append("M", part.message_id);
                pd.append("d", std::span{part.data});
            }
        }
    }
}

void ConfigBase::_load_multiparts(oxenc::bt_dict_consumer&& multi) {
    auto now = std::chrono::system_clock::now();
    while (!multi.is_finished()) {
        auto [k, pdata] = multi.next_dict_consumer();
        if (k.size() != sizeof(hash_t)) {
            log(LogLevel::warning,
                "Invalid multipart key in config: expected {} bytes, but key is {} bytes",
                sizeof(hash_t),
                k.size());
            continue;
        }
        int size = pdata.require<int>("#");
        auto exp = std::chrono::system_clock::time_point{
                std::chrono::milliseconds{pdata.require<int64_t>("T")}};
        if (exp < now) {
            log(LogLevel::debug, "Not loading expired multipart data");
            // We *could* set _needs_dump to true here to instruct a client to store it again, but
            // there's no real need to force a re-dump as what we have is perfectly usable, and if
            // this is the *only* thing that needs it then we just force rewriting the entire dump
            // just to do a little cleanup which seems unnecessary.
            //
            // _needs_dump = true;
            continue;
        }

        hash_t key;
        std::memcpy(key.data(), k.data(), k.size());
        PartialMessages pm;
        pm.size = size;
        pm.expiry = exp;
        if (pm.size > 0) {
            auto parts_list = pdata.require<oxenc::bt_list_consumer>("p");
            while (!parts_list.is_finished()) {
                auto pd = parts_list.consume_dict_consumer();
                auto index = pd.consume_integer<int>();
                auto msgid = pd.consume_string_view();
                auto chunk = pd.consume_span<unsigned char>();
                pm.parts.emplace_back(index, msgid, chunk);
            }
        }
        _multiparts[key] = std::move(pm);
    }
}

std::unordered_set<std::string> ConfigBase::_merge(
        std::span<const std::pair<std::string, ustring_view>> configs) {

    if (_keys.empty())
        throw std::logic_error{"Cannot merge configs without any decryption keys"};

    const auto old_seqno = _config->seqno();
    std::vector<std::list<std::string>> all_hashes;  // >1 hashes for multipart configs
    std::vector<ustring_view> all_confs;
    all_hashes.reserve(configs.size() + 1);
    all_confs.reserve(configs.size() + 1);

    // We serialize our current config and include it in the list of configs to be merged, as if it
    // had already been pushed to the server (so that this code will be identical whether or not the
    // value was pushed).
    //
    // (We skip this for seqno=0, but that's just a default-constructed, nothing-in-the-config case
    // for which we also can't have or produce a signature, so there's no point in even trying to
    // merge it).

    ustring mine;
    if (old_seqno != 0 || is_dirty()) {
        mine = _config->serialize();
        all_hashes.emplace_back(_curr_hashes.begin(), _curr_hashes.end());
        all_confs.emplace_back(mine);
    }

    std::vector<std::pair<std::string_view, ustring>> plaintexts;

    std::unordered_set<std::string> good_hashes;

    for (size_t ci = 0; ci < configs.size(); ci++) {
        auto& [hash, conf] = configs[ci];
        bool decrypted = false;
        for (size_t i = 0; !decrypted && i < _keys.size(); i++) {
            try {
                plaintexts.emplace_back(hash, decrypt(conf, key(i), encryption_domain()));
                decrypted = true;
            } catch (const decrypt_error&) {
                log(LogLevel::debug, "Failed to decrypt message {} using key {}", ci, i);
            }
        }
        if (!decrypted)
            log(LogLevel::warning, "Failed to decrypt message {}", ci);
    }
    log(LogLevel::debug,
        "successfully decrypted {} of {} incoming messages",
        plaintexts.size(),
        configs.size());

    for (auto& [hash, plain] : plaintexts) {
        // Remove prefix padding:
        if (auto p = plain.find_first_not_of((unsigned char)0); p > 0 && p != std::string::npos) {
            std::memmove(plain.data(), plain.data() + p, plain.size() - p);
            plain.resize(plain.size() - p);
        }
        if (plain.empty()) {
            log(LogLevel::error, "Invalid config message: contains no data");
            continue;
        }

        if (plain[0] == 'm') {
            // Multipart message

            auto [accepted, completed] = _handle_multipart(hash, plain);
            if (accepted)
                good_hashes.emplace(hash);

            if (completed) {
                all_hashes.push_back(std::move(completed->first));
                plain = std::move(completed->second);
                all_confs.emplace_back(plain);
            }
            // else we didn't complete a set so nothing to do yet

            continue;
        }

        // Single-part message

        if (plain[0] == 'z') {  // zstd-compressed data
            if (auto decompressed = zstd_decompress({plain.data() + 1, plain.size() - 1});
                decompressed && !decompressed->empty())
                plain = std::move(*decompressed);
            else {
                log(LogLevel::warning, "Invalid config message: decompression failed");
                continue;
            }
        }

        if (plain[0] != 'd') {
            log(LogLevel::error,
                "invalid/unsupported config message with type {:?}",
                static_cast<const char>(plain[0]));
            continue;
        }

        good_hashes.emplace(hash);
        all_hashes.emplace_back().emplace_back(hash);
        all_confs.emplace_back(plain);
    }

    _expire_multiparts();

    // This is only really possible when merging to a brand-new config object, but it *can* happen
    // for instance if we only have some incomplete set of multiparts to load at the moment.
    if (all_hashes.empty())
        return good_hashes;

    std::set<size_t> bad_confs;

    auto new_conf = make_config_message(
            _state == ConfigState::Dirty,
            all_confs,
            _config->verifier,
            _config->signer,
            config_lags(),
            [&](size_t i, const config_error& e) {
                log(LogLevel::warning, "{}", e.what());
                assert(i > 0);  // i == 0 would mean we can't deserialize our own serialization
                bad_confs.insert(i);
            });

    // All the given config msgs are stale except for:
    // - the message we used, if we found and used a single config that includes all configs.  (This
    //   might be our current config, or might be one single one of the new incoming messages).
    // - confs that failed to parse (we can't understand them, so leave them behind as they may be
    //   some future message).
    int superconf = new_conf->unmerged_index();  // -1 if we had to merge
    for (int i = 0; i < static_cast<int>(all_hashes.size()); i++) {
        if (i != superconf && !bad_confs.count(i) && !all_hashes[i].empty())
            _old_hashes.insert(all_hashes[i].begin(), all_hashes[i].end());
    }

    if (new_conf->seqno() != old_seqno) {
        if (new_conf->merged()) {
            if (_state != ConfigState::Dirty) {
                // Merging resulted in a merge conflict resolution message, but won't currently be
                // mutable (because we weren't dirty to start with).  Convert into a Mutable message
                // and mark ourselves dirty so that we'll get pushed.
                _config =
                        std::make_unique<MutableConfigMessage>(std::move(*new_conf), retain_seqno);
            } else {
                _config = std::move(new_conf);
            }
            set_state(ConfigState::Dirty);
        } else if (
                _state == ConfigState::Dirty && new_conf->unmerged_index() == 0 &&
                new_conf->seqno() == old_seqno + 1) {
            // Constructing a new MutableConfigMessage always increments the seqno (by design) but
            // in this case nothing changed: every other config got ignored and we didn't change
            // anything, so we can ignore the new config and just keep our current one, despite the
            // seqno increment.
            /* do nothing */
        } else {
            _config = std::move(new_conf);
            assert(((old_seqno == 0 && mine.empty()) || _config->unmerged_index() >= 1) &&
                   _config->unmerged_index() < all_hashes.size());
            set_state(ConfigState::Clean);
            _curr_hashes.clear();
            auto& hashes = all_hashes[_config->unmerged_index()];
            _curr_hashes.insert(hashes.begin(), hashes.end());
        }
    } else {
        // the merging affect nothing (if it had seqno would have been incremented), so don't
        // pointlessly replace the inner config object.
        assert(new_conf->unmerged_index() == 0);

        // The for loop above can end up adding our _curr_hashes into _old_hashes if given the
        // *current* active config to merge a second time, so make sure we didn't do so by cleaning
        // _curr_hashes out of _old_hashes just in case:
        for (const auto& c : _curr_hashes)
            _old_hashes.erase(c);
    }

    for (size_t i = mine.empty() ? 0 : 1; i < all_hashes.size(); i++)
        if (bad_confs.count(i))
            for (const auto& h : all_hashes[i])
                good_hashes.erase(h);

    return good_hashes;
}

const std::unordered_set<std::string>& ConfigBase::curr_hashes() const {
    return _curr_hashes;
}

std::unordered_set<std::string> ConfigBase::active_hashes() const {
    // First copy any hashes that make up the currently active config:
    std::unordered_set<std::string> hashes{_curr_hashes};

    auto now = std::chrono::system_clock::now();
    // Add include any pending partial configs that *might* be newer:
    for (const auto& [_, part] : _multiparts)
        if (!part.done && part.expiry > now)
            for (const auto& p : part.parts)
                hashes.insert(p.message_id);

    return hashes;
}

bool ConfigBase::needs_push() const {
    return !is_clean();
}

// Tries to compresses the message; if the compressed version (including the 'z' prefix tag) is
// smaller than the source message then we modify `msg` to contain the 'z'-prefixed compressed
// message, otherwise we leave it as-is.  Returns true if compression was beneficial and `msg` has
// been compressed; false if compression did not reduce the size and msg was left as-is.
void compress_message(ustring& msg, int level) {
    if (!level)
        return;
    // "z" is our zstd compression marker prefix byte
    ustring compressed = zstd_compress(msg, level, to_unsigned_sv("z"sv));
    if (compressed.size() < msg.size())
        msg = std::move(compressed);
}

std::tuple<seqno_t, std::vector<ustring>, std::vector<std::string>> ConfigBase::push() {
    if (_keys.empty())
        throw std::logic_error{"Cannot push data without an encryption key!"};

    auto s = _config->seqno();

    std::tuple<seqno_t, std::vector<ustring>, std::vector<std::string>> ret{s, {}, {}};
    auto& [seqno, msgs, obs] = ret;

    auto msg = _config->serialize();

    if (auto lvl = compression_level())
        compress_message(msg, *lvl);

    pad_message(msg);  // Prefix pad with nulls

    if (msg.size() > MAX_MULTIPART_SIZE)
        throw std::length_error{
                "Config data is insanely large ({}B), even for multipart"_format(msg.size())};

    if (msg.size() + ENCRYPT_DATA_OVERHEAD > MAX_MESSAGE_SIZE) {
        // Multipart handling: if the above gives us a msg that exceeds the storage server limit
        // then we need to split it up into multipart config messages, and then encrypt each piece.
        // Each one (before encryption) starts with `m` and consists of a 4-element bt list:
        //   - element 0 is the hash of the recombined message (i.e. what we have right now in
        //   `msg`)
        //   - element 1 is the index of the message within the set, starting from 0, encoded as a
        //     fixed length 1-byte string (0-254).
        //   - element 2 is the size of the message parts, and must be at least 2 (2-255).
        //   - element 3 is the chunk of data (and so, when ordered by sequence number, each data
        //   chunk
        //     concatenated together gives us the `msg` value we have right now in this function).
        hash_t final_hash;
        hash::hash(final_hash, msg);

        constexpr size_t ENCODE_OVERHEAD =
                1         // The `m` prefix indicating a multipart message part
                + 2       // the `l` and `e` encoding around the list
                + 3 + 32  // '32:' followed by final_hash 32 bytes
                + 2 + 1   // '1:x' part index (x is the uint8_t part index encoded as a byte)
                + 2 + 1   // '1:y' num parts (y is the uint8_t parts count encoded as a byte)
                + 6;      // '76543:' data length prefix; just under 76800 for all but the last part

        constexpr size_t MAX_CHUNK_SIZE =
                MAX_MESSAGE_SIZE - ENCODE_OVERHEAD - ENCRYPT_DATA_OVERHEAD;

        static_assert(MAX_CHUNK_SIZE < MAX_MESSAGE_SIZE);
        static_assert(
                (MAX_MULTIPART_SIZE + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE <= 255,
                "MAX_MULTIPART_SIZE is too large: more than 255 parts could result");

        const uint8_t num_parts = (msg.size() + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
        msgs.reserve(num_parts);

        log(LogLevel::debug,
            "splitting large config message ({}B, hash {}) into {} parts",
            msg.size(),
            oxenc::to_hex(final_hash.begin(), final_hash.end()),
            num_parts);

        ucspan remaining{msg};
        for (uint8_t index = 0; !remaining.empty(); ++index) {
            auto& out = msgs.emplace_back();
            auto chunk = remaining.subspan(0, std::min(MAX_CHUNK_SIZE, remaining.size()));
            remaining = remaining.subspan(chunk.size());
            out.reserve(chunk.size() + ENCODE_OVERHEAD + ENCRYPT_DATA_OVERHEAD);
            out.resize(chunk.size() + ENCODE_OVERHEAD);
            out[0] = 'm';
            {
                oxenc::bt_list_producer lp{reinterpret_cast<char*>(out.data() + 1), out.size() - 1};
                lp.append(std::span{final_hash});
                lp.append(std::span{&index, 1});
                lp.append(std::span{&num_parts, 1});
                lp.append(chunk);

                // We should have filled the buffer exactly, except for the last part which, due to
                // the variable length data prefix ("76543:" in the ENCODE_OVERHEAD comment above),
                // could be up to 4 chars shorter (for example: "9:abcdefghi").
                assert(static_cast<size_t>(
                               reinterpret_cast<const char*>(out.data() + out.size()) - lp.end()) <=
                       (remaining.empty() ? 4 : 0));
            }

            encrypt_inplace(out, key(), encryption_domain());

            _multiparts[final_hash].finish(MULTIPART_MAX_REMEMBER);
        }
        assert(msgs.size() > 1 && msgs.size() <= 255);

    } else {
        encrypt_inplace(msg, key(), encryption_domain());

        if (accepts_protobuf() && !_keys.empty()) {
            auto pbwrapped = protos::wrap_config(
                    ustring_view{_keys.front().data(), _keys.front().size()},
                    msg,
                    s,
                    storage_namespace());
            // If protobuf wrapping would push us *over* the max message size then we just skip the
            // protobuf wrapping because older clients (that need protobuf) also don't support
            // multipart anyway, so we can't produce a message they will accept no matter what.
            if (pbwrapped.size() <= MAX_MESSAGE_SIZE)
                msg = std::move(pbwrapped);
        }

        assert(msg.size() <= MAX_MESSAGE_SIZE);

        msgs.push_back(std::move(msg));
    }

    if (is_dirty())
        set_state(ConfigState::Waiting);

    if (!is_readonly())
        for (auto& old : _old_hashes)
            obs.push_back(std::move(old));
    _old_hashes.clear();

    return ret;
}

void ConfigBase::confirm_pushed(seqno_t seqno, std::unordered_set<std::string> msg_hashes) {
    // Make sure seqno hasn't changed; if it has then that means we set some other data *after* the
    // caller got the last data to push, and so we don't care about this confirmation.
    if (_state == ConfigState::Waiting && seqno == _config->seqno()) {
        set_state(ConfigState::Clean);
        _curr_hashes = std::move(msg_hashes);
        _needs_dump = true;
    }
}

ustring ConfigBase::dump() {
    if (is_readonly())
        _old_hashes.clear();

    _expire_multiparts();

    auto d = make_dump();
    _needs_dump = false;
    return d;
}

ustring ConfigBase::make_dump() const {
    auto data = _config->serialize(false /* disable signing for local storage */);
    auto data_sv = from_unsigned_sv(data);
    oxenc::bt_list old_hashes;

    oxenc::bt_dict_producer d;
    d.append("!", static_cast<int>(_state));
    d.append("$", data_sv);
    d.append_list("(", _curr_hashes);

    d.append_list(")").extend(_old_hashes.begin(), _old_hashes.end());

    _dump_multiparts(d.append_dict("*"));

    extra_data(d.append_dict("+"));

    return ustring{to_unsigned_sv(d.view())};
}

ConfigBase::ConfigBase(
        std::optional<ustring_view> dump,
        std::optional<ustring_view> ed25519_pubkey,
        std::optional<ustring_view> ed25519_secretkey) {

    if (sodium_init() == -1)
        throw std::runtime_error{"libsodium initialization failed!"};

    init(dump, ed25519_pubkey, ed25519_secretkey);
}

void ConfigSig::init_sig_keys(
        std::optional<ustring_view> ed25519_pubkey, std::optional<ustring_view> ed25519_secretkey) {
    if (ed25519_secretkey) {
        if (ed25519_pubkey && *ed25519_pubkey != ed25519_secretkey->substr(32))
            throw std::invalid_argument{"Invalid signing keys: secret key and pubkey do not match"};
        set_sig_keys(*ed25519_secretkey);
    } else if (ed25519_pubkey) {
        set_sig_pubkey(*ed25519_pubkey);
    } else {
        clear_sig_keys();
    }
}

void ConfigBase::init(
        std::optional<ustring_view> dump,
        std::optional<ustring_view> ed25519_pubkey,
        std::optional<ustring_view> ed25519_secretkey) {
    if (!dump) {
        _state = ConfigState::Clean;
        _config = std::make_unique<ConfigMessage>();
    } else {

        oxenc::bt_dict_consumer d{from_unsigned_sv(*dump)};
        if (!d.skip_until("!"))
            throw std::runtime_error{
                    "Unable to parse dumped config data: did not find '!' state key"};
        _state = static_cast<ConfigState>(d.consume_integer<int>());

        if (!d.skip_until("$"))
            throw std::runtime_error{
                    "Unable to parse dumped config data: did not find '$' data key"};
        auto data = to_unsigned_sv(d.consume_string_view());
        if (_state == ConfigState::Dirty)
            // If we dumped dirty data then we need to reload it as a mutable config message so that
            // the seqno gets incremented.  This "wastes" one seqno value (since we didn't send the
            // old one), but that's minor and easier than extracting and restoring all the fields we
            // set and is a little more robust against failure if we actually sent it but got killed
            // before we could store a dump.
            _config = std::make_unique<MutableConfigMessage>(
                    data,
                    nullptr,  // We omit verifier and signer for now because we don't want this dump
                              // to
                    nullptr,  // be signed (since it's just a dump).
                    config_lags());
        else
            _config = std::make_unique<ConfigMessage>(
                    data,
                    nullptr,
                    nullptr,
                    config_lags(),
                    /*trust_signature=*/true);

        _curr_hashes.clear();
        if (d.skip_until("(")) {
            if (d.is_list())
                _curr_hashes = d.consume<std::unordered_set<std::string>>();
            else if (d.is_string()) {
                // Backwards compatibility with a dump created before multipart configs:
                if (auto hash = d.consume_string_view(); !hash.empty())
                    _curr_hashes.emplace(hash);
            } else {
                throw std::runtime_error{
                        "Invalid dumped config data: expected '(' containing list or string"};
            }
            if (!d.skip_until(")"))
                throw std::runtime_error{"Unable to parse dumped config data: found '(' without ')'"};
            for (auto old = d.consume_list_consumer(); !old.is_finished();)
                _old_hashes.insert(old.consume_string());
        }

        if (d.skip_until("*"))
            _load_multiparts(d.consume_dict_consumer());

        if (d.skip_until("+"))
            load_extra_data(d.consume_dict_consumer());
    }

    init_sig_keys(ed25519_pubkey, ed25519_secretkey);
}

int ConfigBase::key_count() const {
    return _keys.size();
}

bool ConfigBase::has_key(ustring_view key) const {
    if (key.size() != 32)
        throw std::invalid_argument{"invalid key given to has_key(): not 32-bytes"};

    auto* keyptr = key.data();
    for (const auto& key : _keys)
        if (sodium_memcmp(keyptr, key.data(), KEY_SIZE) == 0)
            return true;
    return false;
}

std::vector<ustring_view> ConfigBase::get_keys() const {
    std::vector<ustring_view> ret;
    ret.reserve(_keys.size());
    for (const auto& key : _keys)
        ret.emplace_back(key.data(), key.size());
    return ret;
}

void ConfigBase::add_key(ustring_view key, bool high_priority, bool dirty_config) {
    static_assert(
            sizeof(Key) == KEY_SIZE, "std::array appears to have some overhead which seems bad");

    if (key.size() != KEY_SIZE)
        throw std::invalid_argument{"add_key failed: key size must be 32 bytes"};

    if (!_keys.empty() && sodium_memcmp(_keys.front().data(), key.data(), KEY_SIZE) == 0)
        return;
    else if (!high_priority && has_key(key))
        return;

    if (_keys.capacity() == 0)
        // There's not a lot of point in starting this off really small: sodium is likely going to
        // use at least a page size anyway.
        _keys.reserve(64);

    if (high_priority)
        remove_key(key, 1);

    auto& newkey = *_keys.emplace(high_priority ? _keys.begin() : _keys.end());
    std::memcpy(newkey.data(), key.data(), KEY_SIZE);

    if (dirty_config && !is_readonly() && (_keys.size() == 1 || high_priority))
        dirty();
}

int ConfigBase::clear_keys(bool dirty_config) {
    int ret = _keys.size();
    _keys.clear();
    _keys.shrink_to_fit();

    if (dirty_config && !is_readonly() && ret > 0)
        dirty();

    return ret;
}

void ConfigBase::replace_keys(const std::vector<ustring_view>& new_keys, bool dirty_config) {
    if (new_keys.empty()) {
        if (_keys.empty())
            return;
        clear_keys(dirty_config);
        return;
    }

    for (auto& k : new_keys)
        if (k.size() != KEY_SIZE)
            throw std::invalid_argument{"replace_keys failed: keys must be 32 bytes"};

    dirty_config = dirty_config && !is_readonly() &&
                   (_keys.empty() ||
                    sodium_memcmp(_keys.front().data(), new_keys.front().data(), KEY_SIZE) != 0);

    _keys.clear();
    for (auto& k : new_keys)
        add_key(k, /*high_priority=*/false);  // The first key gets the high priority spot even
                                              // with `false` since we just emptied the list

    if (dirty_config)
        dirty();
}

bool ConfigBase::remove_key(ustring_view key, size_t from, bool dirty_config) {
    auto starting_size = _keys.size();
    if (from >= starting_size)
        return false;

    dirty_config = dirty_config && !is_readonly() &&
                   sodium_memcmp(key.data(), _keys.front().data(), KEY_SIZE) == 0;

    _keys.erase(
            std::remove_if(
                    _keys.begin() + from,
                    _keys.end(),
                    [&key](const auto& k) {
                        return sodium_memcmp(key.data(), k.data(), KEY_SIZE) == 0;
                    }),
            _keys.end());

    if (dirty_config)
        dirty();

    return _keys.size() < starting_size;
}

void ConfigBase::load_key(ustring_view ed25519_secretkey) {
    if (!(ed25519_secretkey.size() == 64 || ed25519_secretkey.size() == 32))
        throw std::invalid_argument{
                encryption_domain() + " requires an Ed25519 64-byte secret key or 32-byte seed"s};

    add_key(ed25519_secretkey.substr(0, 32));
}

void ConfigSig::set_sig_keys(ustring_view secret) {
    if (secret.size() != 64)
        throw std::invalid_argument{"Invalid sodium secret: expected 64 bytes"};
    clear_sig_keys();
    _sign_sk.reset(64);
    std::memcpy(_sign_sk.data(), secret.data(), secret.size());
    _sign_pk.emplace();
    crypto_sign_ed25519_sk_to_pk(_sign_pk->data(), _sign_sk.data());

    set_verifier([this](ustring_view data, ustring_view sig) {
        return 0 == crypto_sign_ed25519_verify_detached(
                            sig.data(), data.data(), data.size(), _sign_pk->data());
    });
    set_signer([this](ustring_view data) {
        ustring sig;
        sig.resize(64);
        if (0 != crypto_sign_ed25519_detached(
                         sig.data(), nullptr, data.data(), data.size(), _sign_sk.data()))
            throw std::runtime_error{"Internal error: config signing failed!"};
        return sig;
    });
}

void ConfigSig::set_sig_pubkey(ustring_view pubkey) {
    if (pubkey.size() != 32)
        throw std::invalid_argument{"Invalid pubkey: expected 32 bytes"};
    _sign_pk.emplace();
    std::memcpy(_sign_pk->data(), pubkey.data(), 32);

    set_verifier([this](ustring_view data, ustring_view sig) {
        return 0 == crypto_sign_ed25519_verify_detached(
                            sig.data(), data.data(), data.size(), _sign_pk->data());
    });
}

void ConfigSig::clear_sig_keys() {
    _sign_pk.reset();
    _sign_sk.reset();
    set_signer(nullptr);
    set_verifier(nullptr);
}

void ConfigBase::set_verifier(ConfigMessage::verify_callable v) {
    _config->verifier = std::move(v);
}

void ConfigBase::set_signer(ConfigMessage::sign_callable s) {
    _config->signer = std::move(s);
}

std::array<unsigned char, 32> ConfigSig::seed_hash(std::string_view key) const {
    if (!_sign_sk)
        throw std::runtime_error{"Cannot make a seed hash without a signing secret key"};
    std::array<unsigned char, 32> out;
    crypto_generichash_blake2b(
            out.data(),
            out.size(),
            _sign_sk.data(),
            32,  // Just the seed part of the value, not the last half (which is just the pubkey)
            reinterpret_cast<const unsigned char*>(key.data()),
            std::min<size_t>(key.size(), 64));
    return out;
}

void set_error(config_object* conf, std::string e) {
    auto& error = unbox(conf).error;
    error = std::move(e);
    conf->last_error = error.c_str();
}

}  // namespace session::config

extern "C" {

using namespace session;
using namespace session::config;

LIBSESSION_EXPORT void config_free(config_object* conf) {
    delete static_cast<internals<>*>(conf->internals);
    delete conf;
}

LIBSESSION_EXPORT int16_t config_storage_namespace(const config_object* conf) {
    return static_cast<int16_t>(unbox(conf)->storage_namespace());
}

LIBSESSION_EXPORT config_string_list* config_merge(
        config_object* conf,
        const char** msg_hashes,
        const unsigned char** configs,
        const size_t* lengths,
        size_t count) {
    auto& config = *unbox(conf);
    std::vector<std::pair<std::string, ustring_view>> confs;
    confs.reserve(count);
    for (size_t i = 0; i < count; i++)
        confs.emplace_back(msg_hashes[i], ustring_view{configs[i], lengths[i]});

    return make_string_list(config.merge(confs));
}

LIBSESSION_EXPORT bool config_needs_push(const config_object* conf) {
    return unbox(conf)->needs_push();
}

LIBSESSION_EXPORT config_push_data* config_push(config_object* conf) {
    auto& config = *unbox(conf);
    auto [seqno, data, obs] = config.push();

    // We need to do one alloc here that holds everything.  We pack it as follows:
    // - the returned struct
    // - data pointers: [*configdata1][*configdata2]...  <-- `config` points to the beginning of
    // this
    // - size_t [size1][size2]... <-- `config_lens` points to the beginning of this
    // - obsolete hash pointers: [*obs1][*obs2]...  <-- `obsolete` points to the beginning of this
    // - data: [configdata1][configdata2]...[obs1\0][obs2\0]...
    static_assert(alignof(config_push_data) >= alignof(char*));
    static_assert(sizeof(config_push_data) % alignof(char*) == 0);
    static_assert(alignof(char*) == alignof(size_t*));
    static_assert(alignof(size_t) == alignof(char*));
    size_t buffer_size = sizeof(config_push_data)      // struct data
                       + data.size() * sizeof(char**)  // data pointer array
                       + data.size() * sizeof(size_t)  // data sizes
                       + obs.size() * sizeof(char**); // obsolete pointer array

    // + configdata array data:
    for (auto& d : data)
        buffer_size += d.size();
    // + obsolete hash data (including null terminator for each):
    for (auto& o : obs)
        buffer_size += o.size() + 1;

    auto* ret = static_cast<config_push_data*>(std::malloc(buffer_size));
    if (!ret) {
        // TODO: uncomment this when we start using oxen-logging:
        // log::critical(logcat, "Memory allocation failed in config_push!");
        return nullptr;
    }

    ret->seqno = seqno;
    ret->config = reinterpret_cast<unsigned char**>(ret + 1);
    ret->config_lens = reinterpret_cast<size_t*>(ret->config + 1);
    ret->n_configs = data.size();
    ret->obsolete = reinterpret_cast<char**>(ret->config_lens + 1);
    ret->obsolete_len = obs.size();

    unsigned char* pos = reinterpret_cast<unsigned char*>(ret->obsolete + ret->obsolete_len);
    for (size_t i = 0; i < data.size(); i++) {
        std::memcpy(pos, data[i].data(), data[i].size());
        ret->config[i] = pos;
        pos += (ret->config_lens[i] = data[i].size());
    }
    for (size_t i = 0; i < obs.size(); i++) {
        auto cstr_len = obs[i].size() + 1 /*NUL terminator*/;
        std::memcpy(pos, obs[i].c_str(), cstr_len);
        ret->obsolete[i] = reinterpret_cast<char*>(pos);
        pos += cstr_len;
    }
    assert(pos - reinterpret_cast<unsigned char*>(ret) == buffer_size);

    return ret;
}

LIBSESSION_EXPORT void config_confirm_pushed(
        config_object* conf, seqno_t seqno, const char* const* msg_hashes, size_t hashes_len) {
    std::unordered_set<std::string> hashes;
    for (size_t i = 0; i < hashes_len; i++)
        hashes.emplace(msg_hashes[i]);

    unbox(conf)->confirm_pushed(seqno, std::move(hashes));
}

LIBSESSION_EXPORT void config_dump(config_object* conf, unsigned char** out, size_t* outlen) {
    assert(out && outlen);
    auto data = unbox(conf)->dump();
    *outlen = data.size();
    *out = static_cast<unsigned char*>(std::malloc(data.size()));
    std::memcpy(*out, data.data(), data.size());
}

LIBSESSION_EXPORT bool config_needs_dump(const config_object* conf) {
    return unbox(conf)->needs_dump();
}

LIBSESSION_EXPORT config_string_list* config_curr_hashes(const config_object* conf) {
    return make_string_list(unbox(conf)->curr_hashes());
}

LIBSESSION_EXPORT config_string_list* config_active_hashes(const config_object* conf) {
    return make_string_list(unbox(conf)->active_hashes());
}

LIBSESSION_EXPORT unsigned char* config_get_keys(const config_object* conf, size_t* len) {
    const auto keys = unbox(conf)->get_keys();
    assert(std::count_if(keys.begin(), keys.end(), [](const auto& k) { return k.size() == 32; }) ==
           keys.size());
    assert(len);
    *len = keys.size();
    if (keys.empty())
        return nullptr;
    auto* buf = static_cast<unsigned char*>(std::malloc(32 * keys.size()));
    auto* cur = buf;
    for (const auto& k : keys) {
        std::memcpy(cur, k.data(), 32);
        cur += 32;
    }

    return buf;
}

LIBSESSION_EXPORT void config_add_key(config_object* conf, const unsigned char* key) {
    unbox(conf)->add_key({key, 32});
}
LIBSESSION_EXPORT void config_add_key_low_prio(config_object* conf, const unsigned char* key) {
    unbox(conf)->add_key({key, 32}, /*high_priority=*/false);
}
LIBSESSION_EXPORT int config_clear_keys(config_object* conf) {
    return unbox(conf)->clear_keys();
}
LIBSESSION_EXPORT bool config_remove_key(config_object* conf, const unsigned char* key) {
    return unbox(conf)->remove_key({key, 32});
}
LIBSESSION_EXPORT int config_key_count(const config_object* conf) {
    return unbox(conf)->key_count();
}
LIBSESSION_EXPORT bool config_has_key(const config_object* conf, const unsigned char* key) {
    return unbox(conf)->has_key({key, 32});
}
LIBSESSION_EXPORT const unsigned char* config_key(const config_object* conf, size_t i) {
    return unbox(conf)->key(i).data();
}

LIBSESSION_EXPORT const char* config_encryption_domain(const config_object* conf) {
    return unbox(conf)->encryption_domain();
}

LIBSESSION_EXPORT void config_set_sig_keys(config_object* conf, const unsigned char* secret) {
    unbox(conf)->set_sig_keys({secret, 64});
}

LIBSESSION_EXPORT void config_set_sig_pubkey(config_object* conf, const unsigned char* pubkey) {
    unbox(conf)->set_sig_pubkey({pubkey, 32});
}

LIBSESSION_EXPORT const unsigned char* config_get_sig_pubkey(const config_object* conf) {
    const auto& pk = unbox(conf)->get_sig_pubkey();
    if (pk)
        return pk->data();
    return nullptr;
}

LIBSESSION_EXPORT void config_clear_sig_keys(config_object* conf) {
    unbox(conf)->clear_sig_keys();
}

LIBSESSION_EXPORT void config_set_logger(
        config_object* conf, void (*callback)(config_log_level, const char*, void*), void* ctx) {
    if (!callback)
        unbox(conf)->logger = nullptr;
    else
        unbox(conf)->logger = [callback, ctx](LogLevel lvl, std::string msg) {
            callback(static_cast<config_log_level>(static_cast<int>(lvl)), msg.c_str(), ctx);
        };
}

}  // extern "C"
