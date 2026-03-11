#include <fmt/ranges.h>
#include <mlkem_native.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/crypto_stream_xchacha20.h>
#include <sodium/crypto_xof_turboshake256.h>
#include <sodium/utils.h>

#include <chrono>
#include <concepts>
#include <iterator>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <ranges>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/hash.hpp>
#include <session/random.hpp>
#include <session/sqlite.hpp>
#include <session/types.hpp>
#include <session/util.hpp>
#include <stdexcept>

namespace session::core {

using namespace oxen::log::literals;

namespace log = oxen::log;
static auto cat = log::Cat("core.dev");

static constexpr auto dev_key = "device_unique_id"sv;

void Devices::init() {
    if (core.globals.get_blob_to(dev_key, self_id))
        log::info(cat, "Loaded existing unique device id: {}", oxenc::to_hex(self_id));
    else {
        random::fill(self_id);
        core.globals.set(dev_key, self_id);
        log::info(cat, "Generated new unique device id: {}", oxenc::to_hex(self_id));
    }
}

std::string Devices::device_id() const {
    return oxenc::to_hex(self_id.begin(), self_id.end());
}

template <typename T>
consteval unsigned char KEY_DOMAIN() = delete;
template <>
consteval unsigned char KEY_DOMAIN<Devices::DeviceKeys>() {
    return static_cast<unsigned char>('D');
}
template <>
consteval unsigned char KEY_DOMAIN<Devices::AccountKeys>() {
    return static_cast<unsigned char>('A');
}

template <std::derived_from<Devices::XWingKeys> Keys>
static Keys keys_from_seed(std::span<const std::byte, 32> seed) {
    Keys keys;
    auto& [x_sec, x_pub, ml_sec, ml_pub] = static_cast<Devices::XWingKeys&>(keys);

    crypto_xof_turboshake256_state st;
    crypto_xof_turboshake256_init_with_domain(&st, KEY_DOMAIN<Keys>());
    crypto_xof_turboshake256_update(
            &st, reinterpret_cast<const unsigned char*>(seed.data()), seed.size());
    crypto_xof_turboshake256_squeeze(&st, x_sec.data(), x_sec.size());
    crypto_scalarmult_curve25519_base(x_pub.data(), x_pub.data());

    static_assert(MLKEM768_PUBLICKEYBYTES == sizeof(ml_pub));
    static_assert(MLKEM768_SECRETKEYBYTES == sizeof(ml_sec));

    cleared_array<unsigned char, 2 * MLKEM_SYMBYTES> ml_seed;
    crypto_xof_turboshake256_squeeze(&st, ml_seed.data(), ml_seed.size());

    if (0 != sr_mlkem768_keypair_derand(ml_pub.data(), ml_sec.data(), ml_seed.data()))
        throw std::runtime_error{"ML-KEM-768 keygen failed!"};

    return keys;
}

Devices::DeviceKeys Devices::rotate_device_keys() {
    // We store just one single seed value, then use TurboSHAKE256 to expand it into separate X25519
    // (32B) and MLKEM-768 (64B) seeds.
    cleared_b32 seed;
    random::fill(seed);

    // Call this mainly to ensure that we can successfully produce keys from this seed.
    auto keys = keys_from_seed<DeviceKeys>(seed);

    auto c = conn();
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch());
    c.prepared_exec("INSERT INTO device_privkeys (created, seed) VALUES (?, ?)", now.count(), seed);

    log::info(
            cat,
            "New rotating device keys generated: X25519[{}…{}], MLKEM768[{}…{}]",
            oxenc::to_hex(keys.x25519_pub.begin(), keys.x25519_pub.begin() + 2),
            oxenc::to_hex(keys.x25519_pub.end() - 2, keys.x25519_pub.end()),
            oxenc::to_hex(keys.mlkem768_pub.begin(), keys.mlkem768_pub.begin() + 2),
            oxenc::to_hex(keys.mlkem768_pub.end() - 2, keys.mlkem768_pub.end()));

    return keys;
}

std::vector<Devices::DeviceKeys> Devices::active_device_keys() {
    std::vector<DeviceKeys> keys;
    auto c = conn();
    SQLite::Transaction tx{c.sql};
    bool have_active = false;
    for (auto [seed, active] : c.prepared_results<sqlite::blobn<32>, int>(
                 "SELECT seed, rotated IS NULL FROM device_privkeys"
                 " ORDER BY rotated DESC NULLS FIRST, created DESC")) {
        keys.push_back(keys_from_seed<DeviceKeys>(seed));
        if (active)
            have_active = true;
    }

    if (!have_active) {
        log::info(cat, "No currently active device keys; generating a new one");
        keys.insert(keys.begin(), rotate_device_keys());
    }

    return keys;
}

std::vector<Devices::AccountKeys> Devices::active_account_keys() {
    std::vector<AccountKeys> keys;

    auto rotation_cutoff = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch()) -
                           16 * 24h;

    auto c = conn();
    SQLite::Transaction tx{c.sql};
    c.prepared_exec("DELETE FROM device_group_keys WHERE rotated < ?", rotation_cutoff.count());
    for (auto [id, created, rotated, seed, pk_ml, pk_x] :
         c.prepared_results<
                 int64_t,
                 int64_t,
                 std::optional<int64_t>,
                 sqlite::blobn<32>,
                 sqlite::blobn<MLKEM768_PUBLICKEYBYTES>,
                 sqlite::blobn<32>>("SELECT created, rotated, seed, pubkey_mlkem768, pubkey_x25519"
                                    " ORDER BY rotated DESC NULLS FIRST, created DESC")) {
        keys.push_back(keys_from_seed<AccountKeys>(seed));
        if (0 != std::memcmp(keys.back().mlkem768_pub.data(), pk_ml.data(), pk_ml.size()) ||
            0 != std::memcmp(keys.back().x25519_pub.data(), pk_x.data(), pk_x.size())) {
            log::warning(
                    cat,
                    "device_group_keys row with id={} ignored: row contains invalid precomputed "
                    "pubkeys",
                    id);
            keys.pop_back();
        }
    }

    return keys;
}

device::map Devices::devices(
        bool include_registered, bool include_pending, bool include_unregistered) {

    std::string where_clause;
    if (include_registered && include_pending && include_unregistered)
        ;  // leave empty to select all
    else {
        std::vector<int> where_states;
        if (include_registered)
            where_states.push_back(static_cast<int>(device::State::Registered));
        if (include_pending)
            where_states.push_back(static_cast<int>(device::State::Pending));
        if (include_unregistered)
            where_states.push_back(static_cast<int>(device::State::Unregistered));
        if (where_states.empty())
            return {};
        where_clause = "WHERE state IN ({})"_format(fmt::join(where_states, ","));
    }

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    device::map devs;

    for (auto [id, devid, state, changes, seqno, timestamp, type, desc, ver, pk_ml, pk_x] :
         c.prepared_results<
                 int64_t,
                 sqlite::blob_guts<std::array<std::byte, 32>>,
                 int,
                 int,
                 int,
                 int64_t,
                 std::string,
                 std::string,
                 int64_t,
                 sqlite::blobn<MLKEM768_PUBLICKEYBYTES>,
                 sqlite::blobn<32>>(R"(
SELECT id, unique_id, state, changes, seqno, timestamp, device_type, description, version,
        pubkey_mlkem768, pubkey_x25519
FROM devices
{}
ORDER BY unique_id
)"_format(where_clause))) {
        auto& info = devs[devid];

        info.id = devid;
        info.seqno = seqno;
        info.timestamp = std::chrono::sys_seconds{std::chrono::seconds{timestamp}};
        info.type = device::Type::Unknown;
        if (type.size() == 1)
            switch (type[0]) {
                case 'a': info.type = device::Type::Session_Android; break;
                case 'd': info.type = device::Type::Session_Desktop; break;
                case 'i': info.type = device::Type::Session_iOS; break;
            }
        if (info.type == device::Type::Unknown)
            info.other_device = std::move(type);
        info.description = std::move(desc);
        info.state = static_cast<device::State>(state);
        info.version[2] = ver % 1000;
        info.version[1] = ver / 1000 % 1000;
        info.version[0] = ver / 1000000;
        std::memcpy(info.pk_x25519.data(), pk_x.data(), info.pk_x25519.size());
        std::memcpy(info.pk_mlkem768.data(), pk_ml.data(), info.pk_mlkem768.size());

        for (auto [key, value] : c.prepared_results<std::string, sqlite::blob>(
                     "SELECT key, bt_value FROM device_unknown WHERE device = ? ORDER BY key",
                     id)) {
            try {
                info.extra[key] = oxenc::bt_deserialize<bt_value>(value);
            } catch (const std::exception& e) {
                log::warning(cat, "Failed to deserialize extra device data: {}", e.what());
            }
        }
    }

    return devs;
}

namespace {

    // Called while building a bt dict to pull out any unknown intermediate keys immediately before
    // appending a new one.  E.g. call `write_extra(out, "a", it, end)` to write out any keys from
    // `it` that precede "a".  `it` is mutated, and left at the first value > "a", ready for the
    // next call. The iterator range must be sorted (such as a bt_dict, or a std::map<std::string,
    // T>, but not an unordered_map).
    template <std::forward_iterator It, std::sentinel_for<It> End>
    void write_extras(bt_dict_producer& out, std::string_view until, It& it, End end) {
        for (; it != end; ++it) {
            auto& [k, v] = *it;
            if (auto comp = k <=> until; comp >= 0) {
                if (comp == 0)
                    // We found an exact match, which probably means we upgraded and learned what
                    // the key meant.  We probably shouldn't get here at all, but just in case skip
                    // it so we don't break the bt_dict.
                    ++it;
                return;
            }
            out.append_bt(k, v);
        }
    }

    // Combines a call to write_extras + out.append for appending simple bt dict keys with scalar
    // values.
    template <typename T, std::forward_iterator It, std::sentinel_for<It> End>
    void write_next(
            oxenc::bt_dict_producer& out, std::string_view key, const T& value, It& it, End end) {
        write_extras(out, key, it, end);
        out.append(key, value);
    }

    std::string encode_device_data(const device::map& devices) {
        oxenc::bt_dict_producer out;
        for (const auto& [id, info] : devices) {
            auto devout = out.append_dict(
                    std::string_view{reinterpret_cast<const char*>(id.data()), id.size()});

            auto xit = info.extra.cbegin();
            auto xend = info.extra.cend();
            write_next(devout, "#", info.seqno, xit, xend);
            write_next(devout, "@", info.timestamp.time_since_epoch().count(), xit, xend);
            write_next(devout, "M", info.pk_mlkem768, xit, xend);
            write_next(devout, "X", info.pk_x25519, xit, xend);
            write_next(devout, "d", info.description, xit, xend);
            write_extras(devout, "t", xit, xend);
            if (auto t = info.encoded_type(); !t.empty())
                devout.append("t", t);
            auto ver = info.version[0] * 1000000 + std::clamp(info.version[1], 0, 999) * 1000 +
                       std::clamp(info.version[2], 0, 999);
            write_extras(devout, "v", xit, xend);
            if (ver != 0)
                devout.append("v", ver);

            for (; xit != xend; ++xit)
                out.append_bt(xit->first, xit->second);
        }

        return std::move(out).str();
    }

    // Stores the current btdc key/value in `extra`; the value is consumed (i.e. the consumer
    // advances to the next key).
    void consume_extra(oxenc::bt_dict_consumer& btdc, oxenc::bt_dict& extra) {
        auto& x = extra[std::string{btdc.key()}];
        if (btdc.is_string())
            x = btdc.consume_string();
        else if (btdc.is_unsigned_integer())
            x = btdc.consume_integer<uint64_t>();
        else if (btdc.is_integer())
            x = btdc.consume_integer<int64_t>();
        else if (btdc.is_dict())
            x = btdc.consume_dict();
        else
            x = btdc.consume_list();
    }

    // Consumes and stores any unknown extra fields from `btdc` up to (but not including) `key` into
    // `extras`
    void read_extras(oxenc::bt_dict_consumer& btdc, std::string_view key, oxenc::bt_dict& extra) {
        while (btdc.key() < key)
            consume_extra(btdc, extra);
    }

    void decode_one(device::Info& info, oxenc::bt_dict_consumer dev, device::State state) {
        read_extras(dev, "#", info.extra);
        info.seqno = dev.require<int64_t>("#");

        read_extras(dev, "@", info.extra);
        info.timestamp = std::chrono::sys_seconds{std::chrono::seconds{dev.require<int64_t>("@")}};

        read_extras(dev, "M", info.extra);
        auto M = dev.require_span<std::byte, MLKEM768_PUBLICKEYBYTES>("M");
        std::memcpy(info.pk_mlkem768.data(), M.data(), M.size());

        read_extras(dev, "X", info.extra);
        auto X = dev.require_span<std::byte, 32>("X");
        std::memcpy(info.pk_x25519.data(), X.data(), X.size());

        read_extras(dev, "d", info.extra);
        info.description = dev.maybe<std::string_view>("d").value_or(""sv);

        read_extras(dev, "t", info.extra);
        auto type = dev.require<std::string_view>("t");
        info.other_device.clear();
        if (type == "i")
            info.type = device::Type::Session_iOS;
        else if (type == "a")
            info.type = device::Type::Session_Android;
        else if (type == "d")
            info.type = device::Type::Session_Desktop;
        else {
            info.type = device::Type::Unknown;
            info.other_device = type;
        }

        read_extras(dev, "v", info.extra);
        auto ver = dev.maybe<int64_t>("v").value_or(0);
        info.version[0] = ver / 1000000;
        info.version[1] = ver / 1000 % 1000;
        info.version[2] = ver % 1000;

        while (!dev.is_finished())
            consume_extra(dev, info.extra);
    }

    device::map decode_device_data(std::span<const unsigned char> data, device::State state) {
        device::map devices;

        oxenc::bt_dict_consumer in{data};
        while (!in.is_finished()) {
            auto in_id = in.key();
            // A 32-byte keys are device IDs, but we allow (and ignore) keys with other sizes to
            // allow for future expansion
            if (in_id.size() != 32) {
                log::debug(
                        cat,
                        "Skipping unknown {}-length key: not a 32-byte device id",
                        in_id.size());
                continue;
            }

            if (in.is_integer()) {
                // An integer indicates a "device removed" timestamp, used to distinguish between
                // "device removed" and "I don't know about the device yet".  It gets pruned when
                // updating once it hits a certain age threshold.
                log::debug(cat, "Skipping recently removed device id={}", oxenc::to_hex(in_id));
                continue;
            }

            std::array<std::byte, 32> id;
            std::memcpy(id.data(), in_id.data(), 32);
            auto [it, ins] = devices.try_emplace(id);
            if (!ins)
                throw std::runtime_error{"Invalid encoded device data: duplicate devices ids"};

            decode_one(it->second, in.consume_dict_consumer(), state);
        }

        return devices;
    }

    constexpr auto PERS_DEV_NONCE = "SessionDevDNonce"_b2b_pers;
    constexpr auto PERS_KEY_NONCE = "SessionDevKNonce"_b2b_pers;
    constexpr auto PERS_KEY_KEY = "SessionDevKeyKey"_b2b_pers;
    constexpr auto PERS_KEY_KEY_IND = "SessionDevKeyInd"_b2b_pers;

    constexpr int bt_bytes_encoded(int x) {
        int sz = 1 + x;

        do {
            ++sz;
        } while (x /= 10);

        return sz;
    }

    static_assert(bt_bytes_encoded(0) == 2);      // "0:"
    static_assert(bt_bytes_encoded(9) == 11);     // "9:…"
    static_assert(bt_bytes_encoded(10) == 13);    // "10:…"
    static_assert(bt_bytes_encoded(99) == 102);   // "99:…"
    static_assert(bt_bytes_encoded(100) == 104);  // "100:…"

}  // namespace

std::vector<std::byte> Devices::encrypt_device_data(const device::map& devices) {
    cleared_uc32 a;
    random::fill(a);

    std::array<unsigned char, 32> A;
    crypto_scalarmult_curve25519_base(A.data(), a.data());

    int padded_count = devices.size();
    padded_count = (padded_count + 3) / 4 * 4;

    auto indices = std::views::iota(0, padded_count);

    // We randomize the positions of devices (and padding) in the list of keys, so build a random
    // mapping first so that we place everything directly into its final position through it:
    std::vector<int> pos_map{indices.begin(), indices.end()};
    std::ranges::shuffle(pos_map, csrng);

    // Holds MLKEM ciphertexts:
    std::vector<unsigned char> ciphertext_raw;
    ciphertext_raw.resize(MLKEM768_CIPHERTEXTBYTES * padded_count);
    // Holds per-device-encrypted copies of the base key, each prefixed with a 2-byte key indicator
    // hash:
    std::vector<unsigned char> enc_key_raw;
    enc_key_raw.resize((2 + 32) * padded_count);

    // Accessor for the relevant, position-mapped subspan of ciphertext_raw/enc_key_raw containing
    // the location of index i as a subspan of the raw vector:
    auto ciphertext = indices | std::views::transform([&](int i) {
                          return std::span<unsigned char, MLKEM768_CIPHERTEXTBYTES>{
                                  ciphertext_raw.data() + pos_map[i] * MLKEM768_CIPHERTEXTBYTES,
                                  MLKEM768_CIPHERTEXTBYTES};
                      });

    auto enc_indicator =
            indices | std::views::transform([&](int i) {
                return std::span<unsigned char, 2>{enc_key_raw.data() + pos_map[i] * (2 + 32), 2};
            });

    auto enc_key = indices | std::views::transform([&](int i) {
                       return std::span<unsigned char, 32>{
                               enc_key_raw.data() + pos_map[i] * (2 + 32) + 2, 32};
                   });

    sodium_array<unsigned char> ml_ss_raw{MLKEM768_BYTES * devices.size()};

    // Dynamic ss subspan accessor of ml_ss_raw, but *doesn't* go through the pos_map (unlike the
    // above constructs), and only goes up to the actual number of devices, not the padded number
    // (because this is never transmitted, and so not shuffled or padded).
    auto ml_ss = std::views::iota(size_t{0}, devices.size()) | std::views::transform([&](size_t i) {
                     return std::span<unsigned char, MLKEM768_BYTES>{
                             ml_ss_raw.data() + i * MLKEM768_BYTES, MLKEM768_BYTES};
                 });

    cleared_uc32 rnd;
    int i = -1;
    for (auto& [devid, info] : devices) {
        ++i;
        random::fill(rnd);
        if (0 != sr_mlkem768_enc_derand(
                         ciphertext[i].data(),
                         ml_ss[i].data(),
                         reinterpret_cast<const unsigned char*>(info.pk_mlkem768.data()),
                         rnd.data()))
            throw std::runtime_error{"ML-KEM-768 encapsulation failed!"};
    }
    // Fill padding entries with randomness:
    for (; i < padded_count; i++)
        random::fill(ciphertext[i]);

    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce;
    hash::blake2b_key_pers(nonce, A, PERS_DEV_NONCE, ciphertext_raw);

    cleared_uc32 key_base;
    random::fill(key_base);

    auto plaintext_devices = encode_device_data(devices);
    std::vector<unsigned char> enc_devices;
    enc_devices.resize(plaintext_devices.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    crypto_aead_xchacha20poly1305_ietf_encrypt(
            enc_devices.data(),
            nullptr,
            reinterpret_cast<const unsigned char*>(plaintext_devices.data()),
            plaintext_devices.size(),
            nullptr,
            0,
            nullptr,
            nonce.data(),
            key_base.data());

    cleared_uc32 ki;
    cleared_uc32 aB;
    i = -1;
    for (auto& [devid, info] : devices) {
        ++i;
        auto eind = enc_indicator[i];
        auto ekey = enc_key[i];
        auto ct = ciphertext[i];

        auto B = to_span<unsigned char>(info.pk_x25519);
        if (0 != crypto_scalarmult_curve25519(aB.data(), a.data(), B.data())) {
            // This really shouldn't happen: we shouldn't have accepted an invalid pubkey in the
            // first place.
            log::error(
                    cat,
                    "X25519 scalarmult failed: device '{}' ({}) published an invalid X25519 "
                    "pubkey!",
                    oxenc::to_hex(devid),
                    info.description);
            // Without a proper key, we can't properly encrypt for the device so we'll just have to
            // fill the entry with random and move on.
            random::fill(eind);
            random::fill(ekey);
            continue;
        }

        hash::blake2b_key_pers(nonce, A, PERS_KEY_NONCE, ct, enc_devices);
        hash::blake2b_pers(ki, PERS_KEY_KEY, aB, A, B, ml_ss[i], info.pk_mlkem768);

        static_assert(decltype(ekey)::extent == key_base.size());
        crypto_stream_xchacha20_xor(
                ekey.data(), key_base.data(), key_base.size(), nonce.data(), ki.data());

        // Hash a bunch of stuff together as a checksum to let decryption skip most not-for-me
        // values.
        hash::blake2b_pers(eind, PERS_KEY_KEY_IND, A, B, info.pk_mlkem768, ct, ekey);
    }
    // Fill padding entries with randomness:
    for (; i < padded_count; i++) {
        random::fill(enc_indicator[i]);
        random::fill(enc_key[i]);
    }

    // We're done: now we just need to encode everything together:
    std::vector<std::byte> out;
    out.resize(
            2                                              // Outer "d" ... "e" delimiters
            + 3 + bt_bytes_encoded(A.size())               // "1:A" + "32:...(A eph pk)..."
            + 3 + bt_bytes_encoded(ciphertext_raw.size())  // "1:C" + "NNNN:...(mlkem cts)..."
            + 3 + bt_bytes_encoded(enc_key_raw.size())     // "1:K" + "NNN:...(encrypted keys)..."
            + 3 + bt_bytes_encoded(enc_devices.size())     // "1:d" + "MMMM:...(enc device info)..."
            + 3 + bt_bytes_encoded(64)                     // "1:~" + "64:...(Ed25519 signature)..."
    );

    oxenc::bt_dict_producer o{reinterpret_cast<char*>(out.data()), out.size()};

    o.append("A", A);
    o.append("C", ciphertext_raw);
    o.append("K", enc_key_raw);
    o.append("d", enc_devices);
    o.append_signature(
            "~", [seed = core.globals.account_seed()](std::span<const unsigned char> body) {
                std::array<unsigned char, 64> sig;
                crypto_sign_ed25519_detached(
                        sig.data(),
                        nullptr,
                        body.data(),
                        body.size(),
                        reinterpret_cast<const unsigned char*>(seed.buf.data()));
                return sig;
            });

    assert(o.view().size() == out.size());  // Ensure we calculated exactly the right size above

    return out;
}

void Devices::receive_device_data(std::span<const unsigned char> data) {
    device::map devs;
    try {
        devs = decrypt_device_data(std::as_bytes(data));
    } catch (const device::decryption_failed& e) {
        log::warning(cat, "Ignoring incoming device group message: {}", e.what());
        return;
    }

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    for (const auto& [id, info] : devs) {
        auto ver = info.version[0] * 1000000 + info.version[1] * 1000 + info.version[2];

        // Returns the row id if inserted or updated (i.e. seqno increased), nullopt if the seqno
        // guard prevented an update.
        auto dev_id = c.prepared_maybe_get<int64_t>(
                R"(INSERT INTO devices
                    (unique_id, state, seqno, timestamp, device_type, description, version,
                     pubkey_mlkem768, pubkey_x25519)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(unique_id) DO UPDATE SET
                       state = excluded.state,
                       seqno = excluded.seqno,
                       timestamp = excluded.timestamp,
                       device_type = excluded.device_type,
                       description = excluded.description,
                       version = excluded.version,
                       pubkey_mlkem768 = excluded.pubkey_mlkem768,
                       pubkey_x25519 = excluded.pubkey_x25519
                   WHERE excluded.seqno > seqno
                   RETURNING id)",
                id,
                static_cast<int>(info.state),
                info.seqno,
                info.timestamp.time_since_epoch().count(),
                info.encoded_type(),
                info.description,
                ver,
                info.pk_mlkem768,
                info.pk_x25519);

        if (!dev_id)
            continue;

        c.prepared_exec("DELETE FROM device_unknown WHERE device = ?", *dev_id);
        for (const auto& [key, val] : info.extra) {
            auto encoded = std::visit(
                    [](const auto& v) { return oxenc::bt_serialize(v); }, val);
            c.prepared_exec(
                    "INSERT INTO device_unknown (device, key, bt_value) VALUES (?, ?, ?)",
                    *dev_id,
                    key,
                    to_span<std::byte>(encoded));
        }
    }

    tx.commit();
}

device::map Devices::decrypt_device_data(std::span<const std::byte> enc_data) {

    oxenc::bt_dict_consumer in{enc_data};
    auto A = in.require_span<unsigned char, 32>("A");
    auto ciphertext_raw = in.require_span<unsigned char>("C");
    auto enc_key_raw = in.require_span<unsigned char>("K");
    auto enc_devices = in.require_span<std::byte>("d");

    in.require_signature(
            "~", [this](std::span<const unsigned char> body, std::span<const unsigned char> sig) {
                if (0 != crypto_sign_ed25519_verify_detached(
                                 sig.data(),
                                 body.data(),
                                 body.size(),
                                 core.globals.pubkey_ed25519().data()))
                    throw std::runtime_error{
                            "Invalid encrypted device message: signature verification failed"};
            });

    in.finish();

    if (ciphertext_raw.size() % MLKEM768_CIPHERTEXTBYTES != 0)
        throw std::runtime_error{
                "Invalid encrypted device group data: invalid ciphertext size ({} is not N*{})"_format(
                        ciphertext_raw.size(), MLKEM768_CIPHERTEXTBYTES)};
    const int count = ciphertext_raw.size() / MLKEM768_CIPHERTEXTBYTES;
    if (enc_key_raw.size() % (32 + 2) != 0)
        throw std::runtime_error{
                "Invalid encrypted device group data: invalid encrypted keys size ({} is not N*34)"_format(
                        enc_key_raw.size())};
    if (const int k_count = enc_key_raw.size() / (32 + 2); count != k_count)
        throw std::runtime_error{
                "Invalid encrypted device data: ciphertext ({}) vs enc key ({}) size mismatch"_format(
                        count, k_count)};
    if (enc_devices.size() <= crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::runtime_error{
                "Invalid encrypted device data: encrypted data is too short ({}B)"_format(
                        enc_devices.size())};

    auto indices = std::views::iota(0, count);

    // Accessors for chunk-by-chunk access to the ciphertext_raw/enc_key_raw spans:
    auto ciphertext = indices | std::views::transform([&](int i) {
                          return std::span<const unsigned char, MLKEM768_CIPHERTEXTBYTES>{
                                  ciphertext_raw.data() + i * MLKEM768_CIPHERTEXTBYTES,
                                  MLKEM768_CIPHERTEXTBYTES};
                      });
    auto enc_indicator =
            indices | std::views::transform([&](int i) {
                return std::span<const unsigned char, 2>{enc_key_raw.data() + i * (2 + 32), 2};
            });
    auto enc_key = indices | std::views::transform([&](int i) {
                       return std::span<const unsigned char, 32>{
                               enc_key_raw.data() + i * (2 + 32) + 2, 32};
                   });

    auto active_keys = active_device_keys();

    std::array<unsigned char, 24> devices_nonce;
    hash::blake2b_pers(devices_nonce, PERS_DEV_NONCE, ciphertext_raw);

    cleared_uc32 ml_ss, aB, ki, key_base;

    std::vector<unsigned char> plaintext_devices;
    plaintext_devices.resize(enc_devices.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);

    // Trial decrypt until we find one that works, except that we can skip most of the heavy
    // operations for most keys not intended for us.  Note that we have to attempt each received key
    // by all of our recent device keys because it might be a pre-rotation message encrypted using
    // an older key, so even if we have only 4 incoming values, we might have 20 recent device keys
    // meaning 80 potential decryptions.
    bool found = false;
    for (int i = 0; !found && i < count; i++) {
        auto ct = ciphertext[i];
        auto ekey = enc_key[i];
        auto eind = enc_indicator[i];

        std::array<unsigned char, 24> knonce;
        hash::blake2b_key_pers(knonce, A, PERS_KEY_NONCE, ct, enc_devices);

        for (int active_i = 0; active_i < active_keys.size(); active_i++) {
            const auto& k = active_keys[active_i];
            const auto& B = k.x25519_pub;
            const auto& M = k.mlkem768_pub;

            // First work out the checksum hash; the vast majority of the time this won't match for
            // a key other than our own (only 1/65535 chance of collision), and so we can short
            // circuit and save a bunch of calculations.
            std::array<unsigned char, 2> our_ind;
            hash::blake2b_pers(our_ind, PERS_KEY_KEY_IND, A, B, M, ct, ekey);
            if (!std::ranges::equal(our_ind, eind))
                continue;

            if (0 != crypto_scalarmult_curve25519(aB.data(), k.x25519_sec.data(), A.data())) {
                log::warning(cat, "X25519 multiplication failed; ignoring encrypted entry");
                continue;
            }

            if (0 != sr_mlkem768_dec(ml_ss.data(), ct.data(), k.mlkem768_sec.data())) {
                log::warning(cat, "MLKEM768 decapsulation failed; skipping device entry");
                continue;
            }

            // Now we have various shared secret data: hash it into the k[i] value that should have
            // been used to encrypt the key_base value for us:
            hash::blake2b_pers(ki, PERS_KEY_KEY, aB, A, B, ml_ss, M);

            // and then use it to recover the key_base:
            static_assert(decltype(ekey)::extent == key_base.size());
            crypto_stream_xchacha20_xor(
                    key_base.data(), ekey.data(), ekey.size(), knonce.data(), ki.data());

            // Now we can decrypt the encrypted payload:
            if (0 == crypto_aead_xchacha20poly1305_ietf_decrypt(
                             plaintext_devices.data(),
                             nullptr,
                             nullptr,
                             reinterpret_cast<const unsigned char*>(enc_devices.data()),
                             enc_devices.size(),
                             nullptr,
                             0,
                             devices_nonce.data(),
                             key_base.data())) {
                found = true;
                break;
            }

            log::debug(
                    cat,
                    "Decryption of record {} against recent key {} failed; probably a checksum "
                    "false positive",
                    i,
                    active_i);
        }
    }

    if (!found) {
        // There are a bunch of reasons for this: maybe we aren't in the device group, maybe it was
        // corrupted, or many it is an old message and we don't have the keys for it anymore.
        log::warning(cat, "Failed to decrypt incoming device data");
        throw device::decryption_failed{"Failed to decrypt incoming device data"};
    }

    return decode_device_data(plaintext_devices, device::State::Registered);
}

}  // namespace session::core
