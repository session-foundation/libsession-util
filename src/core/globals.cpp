#include <oxenc/hex.h>
#include <sodium/utils.h>

#include <concepts>
#include <oxen/log.hpp>
#include <session/core/globals.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/format.hpp>
#include <session/random.hpp>
#include <session/sodium_array.hpp>
#include <session/sqlite.hpp>

namespace session::core {

namespace log = oxen::log;
auto cat = log::Cat("core.gbl");

using namespace std::literals;

static const std::string GET_ONE = "SELECT value FROM globals WHERE key = ? AND typeof(value) = ?"s;

std::optional<int64_t> Globals::get_integer(std::string_view key) {
    return conn().prepared_maybe_get<int64_t>(GET_ONE, key, "integer");
}
std::optional<double> Globals::get_real(std::string_view key) {
    return conn().prepared_maybe_get<double>(GET_ONE, key, "real");
}
std::optional<std::string> Globals::get_text(std::string_view key) {
    return conn().prepared_maybe_get<std::string>(GET_ONE, key, "text");
}
std::optional<std::vector<std::byte>> Globals::get_blob(std::string_view key) {
    std::optional<std::vector<std::byte>> result;
    auto c = conn();
    auto st = c.prepared_bind(GET_ONE, key, "blob");
    if (st->executeStep()) {
        auto data = sqlite::get<sqlite::blob>(st);
        result.emplace().reserve(data.size());
        result->assign(data.begin(), data.end());
    }
    return result;
}
std::optional<session::secure_buffer> Globals::get_blob_secure(std::string_view key) {
    std::optional<secure_buffer> result;
    auto c = conn();
    auto st = c.prepared_bind(GET_ONE, key, "blob");
    if (st->executeStep())
        result.emplace(sqlite::get<sqlite::blob>(st));
    return result;
}
bool Globals::get_blob_to(std::string_view key, std::span<std::byte> to) {
    auto c = conn();
    auto st = c.prepared_bind(GET_ONE, key, "blob");
    if (st->executeStep()) {
        if (auto data = sqlite::get<sqlite::blob>(st); data.size() == to.size()) {
            std::memcpy(to.data(), data.data(), to.size());
            return true;
        }
    }
    return false;
}

static const std::string GET_ANY = "SELECT value, typeof(value) FROM globals WHERE key = ?"s;

template <std::invocable<sqlite::blob> BlobLoader>
static auto get_variant_impl(sqlite::Connection&& c, std::string_view key, BlobLoader&& b) {

    using blob_t = decltype(b(std::declval<sqlite::blob>()));

    std::variant<std::monostate, int64_t, double, std::string, blob_t> result;

    auto st = c.prepared_bind(GET_ANY, key);
    if (st->executeStep()) {
        auto val = st->getColumn(0);
        auto type = static_cast<std::string>(st->getColumn(1));
        if (type == "int")
            result.template emplace<int64_t>(std::move(val));
        else if (type == "text")
            result.template emplace<std::string>(std::move(val));
        else if (type == "blob")
            result = b(sqlite::blob{std::move(val)});
        else if (type == "real")
            result.template emplace<double>(std::move(val));
    }

    return result;
}

std::variant<std::monostate, int64_t, double, std::string, std::vector<std::byte>> Globals::get(
        std::string_view key) {
    return get_variant_impl(conn(), key, [](sqlite::blob data) {
        std::vector<std::byte> v;
        v.reserve(data.size());
        v.assign(data.begin(), data.end());
        return v;
    });
}

std::variant<std::monostate, int64_t, double, std::string, session::secure_buffer>
Globals::get_secure(std::string_view key) {
    return get_variant_impl(conn(), key, [](sqlite::blob data) { return secure_buffer{data}; });
}

static const std::string SET_VAL =
        "INSERT INTO globals (key, value) VALUES (?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value"s;

void Globals::set(std::string_view key, int64_t integer) {
    conn().prepared_exec(SET_VAL, key, integer);
}
void Globals::set(std::string_view key, double real) {
    conn().prepared_exec(SET_VAL, key, real);
}
void Globals::set(std::string_view key, std::string_view text) {
    conn().prepared_exec(SET_VAL, key, text);
}
void Globals::set(std::string_view key, std::span<const std::byte> blob) {
    conn().prepared_exec(SET_VAL, key, blob);
}

void Globals::init() {
    auto c = conn();
    SQLite::Transaction tx{c.sql};
    cleared_b32 seed;
    bool have_seed = get_blob_to("_seed", seed);
    const cleared_b32* seed_to_use = &seed;
    if (!have_seed) {
        if (_predefined_seed) {
            // Use the predefined seed directly, avoiding an extra copy+clear.
            seed_to_use = &*_predefined_seed;
        } else {
            // FIXME: we should allow full 32-byte seeds here, but for now this is compatible with
            // the 16-byte/128-bit seed that Session accounts use which is 16 random bytes followed
            // by 16 0s:
            random::fill(std::span{seed}.first<16>());
            std::memset(seed.data() + 16, 0, 16);
        }
    }

    // Layout: [ed25519_sk(64) | x25519_sk(32)] = 96 bytes
    auto rw = _account_seed.resize(96);

    ed25519::seed_keypair(_pubkey_ed25519, rw.buf.first<64>(), *seed_to_use);
    ed25519::sk_to_x25519(rw.buf.last<32>(), *seed_to_use);

    _predefined_seed.reset();  // Clear now that it has been consumed
    ed25519::pk_to_x25519(_pubkey_x25519, _pubkey_ed25519);

    _session_id[0] = std::byte{0x05};
    std::copy(_pubkey_x25519.begin(), _pubkey_x25519.end(), _session_id.data() + 1);
    _session_id_hex = oxenc::to_hex(_session_id);

    if (!have_seed) {
        log::info(cat, "Generated new Session account seed");
        set("_seed", rw.buf.first(32));
    }

    log::info(cat, "Initialized with Session ID: {}", _session_id_hex);
}

mnemonics::secure_mnemonic Globals::seed_mnemonic(const mnemonics::Mnemonics& lang, bool force_24) {
    auto seed = _account_seed.access();
    // _account_seed stores the 96-byte key material; the first 32 bytes are the account seed.
    // A Session account uses 128-bit entropy when the last 16 bytes of that seed are all zero;
    // in that case we encode only the first 16 bytes.
    auto seed32 = seed.buf.first(32);
    bool is_128bit = !force_24 &&
                     sodium_memcmp(seed32.data() + 16, std::array<std::byte, 16>{}.data(), 16) == 0;
    return mnemonics::bytes_to_words(is_128bit ? seed32.first(16) : seed32, lang);
}

mnemonics::secure_mnemonic Globals::seed_mnemonic(std::string_view lang_name, bool force_24) {
    return seed_mnemonic(mnemonics::get_language(lang_name), force_24);
}

}  // namespace session::core
