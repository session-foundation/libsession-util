#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>

#include <concepts>
#include <oxen/log.hpp>
#include <session/core/globals.hpp>
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
    if (!have_seed) {
        // FIXME: we should allow full 32-byte seeds here, but for now this is compatible with the
        // 16-byte/128-bit seed that Session accounts use which is 16 random bytes followed by 16
        // 0s:
        randombytes_buf(seed.data(), 16);
        std::memset(seed.data() + 16, 0, 16);
    }

    auto rw = _account_seed.resize(64);

    crypto_sign_ed25519_seed_keypair(
            _pubkey_ed25519.data(),
            reinterpret_cast<unsigned char*>(rw.buf.data()),
            reinterpret_cast<unsigned char*>(seed.data()));
    _session_id[0] = 0x05;
    if (0 != crypto_sign_ed25519_pk_to_curve25519(_session_id.data() + 1, _pubkey_ed25519.data()))
        // This *should* be impossible when starting from a seed because that would mean the seed
        // generation produced an invalid Ed pubkey!
        log::critical(cat, "Failed to convert seed-extracted Ed25519 pubkey to X25519 session ID!");

    if (!have_seed) {
        log::info(cat, "Generated new Session account seed");
        set("_seed", rw.buf);
    }

    log::info(cat, "Initialized with Session ID: {}", oxenc::to_hex(_session_id));
}

}  // namespace session::core
