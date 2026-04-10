
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <session/multi_encrypt.h>

#include <session/crypto/x25519.hpp>
#include <session/encrypt.hpp>
#include <session/multi_encrypt.hpp>
#include <session/random.hpp>
#include <stdexcept>

#include "session/hash.hpp"
#include "session/util.hpp"

namespace session {

const size_t encrypt_multiple_message_overhead = encryption::XCHACHA20_ABYTES;

namespace detail {

    void encrypt_multi_key(
            std::span<std::byte, 32> key,
            std::span<const std::byte, 32> a,
            std::span<const std::byte, 32> A,
            std::span<const std::byte, 32> B,
            bool encrypting,
            std::string_view domain) {

        auto buf = x25519::scalarmult(a, B);

        // If we're encrypting then a/A == sender, B = recipient
        // If we're decrypting then a/A = recipient, B = sender
        // We always need the same sR || S || R or rS || S || R, so if we're decrypting we need to
        // put B before A in the hash;
        const auto& S = encrypting ? A : B;
        const auto& R = encrypting ? B : A;
        hash::blake2b_key(key, domain, buf, S, R);
    }

    void encrypt_multi_impl(
            std::vector<std::byte>& out,
            std::span<const std::byte> msg,
            std::span<const std::byte, 32> key,
            std::span<const std::byte, 24> nonce) {

        out.resize(msg.size() + encryption::XCHACHA20_ABYTES);
        encryption::xchacha20poly1305_encrypt(out, msg, nonce, key);
    }

    bool decrypt_multi_impl(
            std::vector<std::byte>& out,
            std::span<const std::byte> ciphertext,
            std::span<const std::byte, 32> key,
            std::span<const std::byte, 24> nonce) {

        if (ciphertext.size() < encryption::XCHACHA20_ABYTES)
            return false;

        out.resize(ciphertext.size() - encryption::XCHACHA20_ABYTES);
        return encryption::xchacha20poly1305_decrypt(out, ciphertext, nonce, key);
    }

}  // namespace detail

std::optional<std::vector<std::byte>> decrypt_for_multiple(
        const std::vector<std::span<const std::byte>>& ciphertexts,
        std::span<const std::byte> nonce,
        std::span<const std::byte> privkey,
        std::span<const std::byte> pubkey,
        std::span<const std::byte> sender_pubkey,
        std::string_view domain) {

    auto it = ciphertexts.begin();
    return decrypt_for_multiple(
            [&]() -> std::optional<std::span<const std::byte>> {
                if (it == ciphertexts.end())
                    return std::nullopt;
                return *it++;
            },
            nonce,
            privkey,
            pubkey,
            sender_pubkey,
            domain);
}

std::vector<std::byte> encrypt_for_multiple_simple(
        const std::vector<std::span<const std::byte>>& messages,
        const std::vector<std::span<const std::byte>>& recipients,
        std::span<const std::byte, 32> privkey,
        std::span<const std::byte, 32> pubkey,
        std::string_view domain,
        std::optional<std::span<const std::byte, 24>> nonce,
        int pad) {

    oxenc::bt_dict_producer d;

    std::array<std::byte, 24> random_nonce;
    if (!nonce) {
        random::fill(random_nonce);
        nonce.emplace(random_nonce);
    } else if (nonce->size() != 24) {
        throw std::invalid_argument{"Invalid nonce: nonce must be 24 bytes"};
    }

    d.append("#", *nonce);
    {
        auto enc_list = d.append_list("e");

        int msg_count = 0;
        encrypt_for_multiple(
                messages,
                recipients,
                *nonce,
                privkey,
                pubkey,
                domain,
                [&](std::span<const std::byte> encrypted) {
                    enc_list.append(encrypted);
                    msg_count++;
                });

        if (int pad_size = pad > 1 && !messages.empty() ? messages.front().size() : 0) {
            std::vector<std::byte> junk;
            junk.resize(pad_size);
            for (; msg_count % pad != 0; msg_count++) {
                random::fill(junk);
                enc_list.append(to_string(junk));
            }
        }
    }

    return to_vector(d.span<unsigned char>());
}

std::vector<std::byte> encrypt_for_multiple_simple(
        const std::vector<std::span<const std::byte>>& messages,
        const std::vector<std::span<const std::byte>>& recipients,
        const ed25519::PrivKeySpan& ed25519_secret_key,
        std::string_view domain,
        std::optional<std::span<const std::byte, 24>> nonce,
        int pad) {

    auto [x_privkey, x_pubkey] = ed25519::x25519_keypair(ed25519_secret_key);

    return encrypt_for_multiple_simple(
            messages, recipients, x_privkey, x_pubkey, domain, nonce, pad);
}

std::optional<std::vector<std::byte>> decrypt_for_multiple_simple(
        std::span<const std::byte> encoded,
        std::span<const std::byte, 32> privkey,
        std::span<const std::byte, 32> pubkey,
        std::span<const std::byte, 32> sender_pubkey,
        std::string_view domain) {
    try {
        oxenc::bt_dict_consumer d{encoded};
        auto nonce = d.require<std::span<const std::byte>>("#");
        if (nonce.size() != 24)
            return std::nullopt;
        auto enc_list = d.require<oxenc::bt_list_consumer>("e");

        return decrypt_for_multiple(
                [&]() -> std::optional<std::span<const std::byte>> {
                    if (enc_list.is_finished())
                        return std::nullopt;
                    return enc_list.consume<std::span<const std::byte>>();
                },
                nonce,
                privkey,
                pubkey,
                sender_pubkey,
                domain);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<std::byte>> decrypt_for_multiple_simple(
        std::span<const std::byte> encoded,
        const ed25519::PrivKeySpan& ed25519_secret_key,
        std::span<const std::byte, 32> sender_pubkey,
        std::string_view domain) {

    auto [x_privkey, x_pubkey] = ed25519::x25519_keypair(ed25519_secret_key);

    return decrypt_for_multiple_simple(encoded, x_privkey, x_pubkey, sender_pubkey, domain);
}

std::optional<std::vector<std::byte>> decrypt_for_multiple_simple_ed25519(
        std::span<const std::byte> encoded,
        const ed25519::PrivKeySpan& ed25519_secret_key,
        std::span<const std::byte, 32> sender_ed25519_pubkey,
        std::string_view domain) {

    auto sender_pub = ed25519::pk_to_x25519(sender_ed25519_pubkey);

    return decrypt_for_multiple_simple(encoded, ed25519_secret_key, sender_pub, domain);
}

}  // namespace session

using namespace session;

static unsigned char* to_c_buffer(std::span<const std::byte> x, size_t* out_len) {
    auto* ret = static_cast<unsigned char*>(malloc(x.size()));
    *out_len = x.size();
    std::memcpy(ret, x.data(), x.size());
    return ret;
}

LIBSESSION_C_API unsigned char* session_encrypt_for_multiple_simple(
        size_t* out_len,
        const unsigned char* const* messages,
        const size_t* message_lengths,
        size_t n_messages,
        const unsigned char* const* recipients,
        size_t n_recipients,
        const unsigned char* x25519_privkey,
        const unsigned char* x25519_pubkey,
        const char* domain,
        const unsigned char* nonce,
        int pad) {

    std::vector<std::span<const std::byte>> msgs, recips;
    msgs.reserve(n_messages);
    recips.reserve(n_recipients);
    for (size_t i = 0; i < n_messages; i++)
        msgs.emplace_back(to_byte_span(messages[i], message_lengths[i]));
    for (size_t i = 0; i < n_recipients; i++)
        recips.emplace_back(to_byte_span<32>(recipients[i]));
    std::optional<std::span<const std::byte, 24>> maybe_nonce;
    if (nonce)
        maybe_nonce.emplace(to_byte_span<24>(nonce));

    try {
        auto encoded = session::encrypt_for_multiple_simple(
                msgs,
                recips,
                to_byte_span<32>(x25519_privkey),
                to_byte_span<32>(x25519_pubkey),
                domain,
                std::move(maybe_nonce),
                pad);
        return to_c_buffer(encoded, out_len);
    } catch (...) {
        return nullptr;
    }
}

LIBSESSION_C_API unsigned char* session_encrypt_for_multiple_simple_ed25519(
        size_t* out_len,
        const unsigned char* const* messages,
        const size_t* message_lengths,
        size_t n_messages,
        const unsigned char* const* recipients,
        size_t n_recipients,
        const unsigned char* ed25519_secret_key,
        const char* domain,
        const unsigned char* nonce,
        int pad) {

    try {
        auto [priv, pub] = session::ed25519::x25519_keypair(to_byte_span<64>(ed25519_secret_key));
        return session_encrypt_for_multiple_simple(
                out_len,
                messages,
                message_lengths,
                n_messages,
                recipients,
                n_recipients,
                to_unsigned(priv.data()),
                to_unsigned(pub.data()),
                domain,
                nonce,
                pad);
    } catch (...) {
        return nullptr;
    }
}

LIBSESSION_C_API unsigned char* session_decrypt_for_multiple_simple(
        size_t* out_len,
        const unsigned char* encoded,
        size_t encoded_len,
        const unsigned char* x25519_privkey,
        const unsigned char* x25519_pubkey,
        const unsigned char* sender_x25519_pubkey,
        const char* domain) {

    try {
        if (auto decrypted = session::decrypt_for_multiple_simple(
                    to_byte_span(encoded, encoded_len),
                    to_byte_span<32>(x25519_privkey),
                    to_byte_span<32>(x25519_pubkey),
                    to_byte_span<32>(sender_x25519_pubkey),
                    domain)) {
            return to_c_buffer(*decrypted, out_len);
        }
    } catch (...) {
    }

    return nullptr;
}

LIBSESSION_C_API unsigned char* session_decrypt_for_multiple_simple_ed25519_from_x25519(
        size_t* out_len,
        const unsigned char* encoded,
        size_t encoded_len,
        const unsigned char* ed25519_secret,
        const unsigned char* sender_x25519_pubkey,
        const char* domain) {

    try {
        if (auto decrypted = session::decrypt_for_multiple_simple(
                    to_byte_span(encoded, encoded_len),
                    to_byte_span<64>(ed25519_secret),
                    to_byte_span<32>(sender_x25519_pubkey),
                    domain)) {
            return to_c_buffer(*decrypted, out_len);
        }
    } catch (...) {
    }

    return nullptr;
}

LIBSESSION_C_API unsigned char* session_decrypt_for_multiple_simple_ed25519(
        size_t* out_len,
        const unsigned char* encoded,
        size_t encoded_len,
        const unsigned char* ed25519_secret,
        const unsigned char* sender_ed25519_pubkey,
        const char* domain) {

    try {
        if (auto decrypted = session::decrypt_for_multiple_simple_ed25519(
                    to_byte_span(encoded, encoded_len),
                    to_byte_span<64>(ed25519_secret),
                    to_byte_span<32>(sender_ed25519_pubkey),
                    domain)) {
            return to_c_buffer(*decrypted, out_len);
        }
    } catch (...) {
    }

    return nullptr;
}
