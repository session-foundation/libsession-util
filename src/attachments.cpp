#include <sodium/crypto_core_hchacha20.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include <cstring>
#include <fstream>
#include <functional>
#include <oxen/log/format.hpp>
#include <session/attachments.hpp>
#include <session/util.hpp>
#include <stdexcept>
#include <type_traits>

namespace session::attachment {

using namespace oxen::log::literals;

static_assert(ENCRYPT_HEADER == crypto_secretstream_xchacha20poly1305_HEADERBYTES);
static_assert(ENCRYPT_CHUNK_OVERHEAD == crypto_secretstream_xchacha20poly1305_ABYTES);
static_assert(ENCRYPT_KEY_SIZE == crypto_secretstream_xchacha20poly1305_KEYBYTES);

size_t encrypted_padding(size_t data_size) {
    constexpr size_t prefix_size = 1 + ENCRYPT_HEADER;
    constexpr size_t min_padding = 1;

    // the number of mac+tag values embedded every 32kiB in the data stream:
    const size_t stream_chunks = (data_size + ENCRYPT_CHUNK_SIZE - 1) / ENCRYPT_CHUNK_SIZE;

    const size_t enc_size =
            data_size + prefix_size + min_padding + stream_chunks * ENCRYPT_CHUNK_OVERHEAD;

    const size_t pad_factor = std::bit_floor(std::max<size_t>(enc_size, 131072)) >> 5;

    // Round up to next multiple of pad_factor:
    const size_t padded_size = (enc_size + pad_factor - 1) / pad_factor * pad_factor;

    size_t padding = padded_size - enc_size + min_padding;

    // For every complete ENCRYPT_CHUNK_SIZE padding that we add we implicitly also add a stream
    // tag, and so we want to subtract one tag per (ENCRYPT_CHUNK_SIZE+ENCRYPT_CHUNK_OVERHEAD) bytes
    // of padding to compensate (so that the added tag gets counted as an implicit part of the
    // padding):
    size_t implicit_padding = 0;
    if (padding >= ENCRYPTED_CHUNK_TOTAL)
        implicit_padding = (padding / ENCRYPTED_CHUNK_TOTAL) * ENCRYPT_CHUNK_OVERHEAD;

    // After accounting for the full stream + tag blocks above, we might still have enough to spill
    // over the stream into the next chunk, and so if that is going to happen, we want to count the
    // implied additional tag as part of the padding as well.

    // This is how much padding we can add without spilling over into a new stream chunk:
    const size_t free_padding = stream_chunks * ENCRYPT_CHUNK_SIZE - data_size;

    if (padding % ENCRYPTED_CHUNK_TOTAL > free_padding)
        implicit_padding += ENCRYPT_CHUNK_OVERHEAD;

    padding -= implicit_padding;

    return padding;
}

// We have to roll our own custom version of crypto_secretstream_xchacha20poly1305_init_push here
// because libsodium offers no way to provide the randomness it uses (it hard codes a call to
// randombytes_buf), and so this repeats its internal implementation but using our hashed data for
// the randomness.
static crypto_secretstream_xchacha20poly1305_state
secretstream_xchacha20poly1305_init_push_with_nonce(
        std::span<unsigned char, ENCRYPT_HEADER> header,
        std::span<const unsigned char, ENCRYPT_KEY_SIZE> key,
        std::span<const unsigned char, ENCRYPT_HEADER> nonce) {

    crypto_secretstream_xchacha20poly1305_state st;

    std::memcpy(header.data(), nonce.data(), ENCRYPT_HEADER);
    crypto_core_hchacha20(
            st.k, header.data(), reinterpret_cast<const unsigned char*>(key.data()), nullptr);
    static_assert(sizeof(st) == 52);
    std::memset(st.nonce, 0, 4 /*crypto_secretstream_xchacha20poly1305_COUNTERBYTES*/);
    st.nonce[0] = 1;
    std::memcpy(
            st.nonce + 4 /*crypto_secretstream_xchacha20poly1305_COUNTERBYTES*/,
            header.data() + crypto_core_hchacha20_INPUTBYTES,
            8 /*crypto_secretstream_xchacha20poly1305_INONCEBYTES*/);
    std::memset(st._pad, 0, sizeof(st._pad));

    return st;
}

std::pair<std::vector<std::byte>, std::array<std::byte, ENCRYPT_KEY_SIZE>> encrypt(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        bool allow_large) {

    if (seed.size() < 32)
        throw std::invalid_argument{"attachment::encrypt requires a 32-byte uploader seed"};

    if (data.size() > ENCRYPT_MAX_SIZE && !allow_large)
        throw std::invalid_argument{"data to encrypt is too large"};

    std::pair<std::vector<std::byte>, std::array<std::byte, ENCRYPT_KEY_SIZE>> result;
    auto& [out, key] = result;

    std::span<const unsigned char> udata{
            reinterpret_cast<const unsigned char*>(data.data()), data.size()};

    std::array<unsigned char, ENCRYPT_HEADER + ENCRYPT_KEY_SIZE> nonce_key;

    crypto_generichash_blake2b_state b_st;
    const auto domain_byte = static_cast<uint8_t>(domain);
    crypto_generichash_blake2b_init(&b_st, &domain_byte, 1, nonce_key.size());
    crypto_generichash_blake2b_update(
            &b_st, reinterpret_cast<const unsigned char*>(seed.data()), 32);
    crypto_generichash_blake2b_update(&b_st, udata.data(), udata.size());
    crypto_generichash_blake2b_final(&b_st, nonce_key.data(), nonce_key.size());
    std::memcpy(key.data(), nonce_key.data() + ENCRYPT_HEADER, ENCRYPT_KEY_SIZE);

    size_t padding = encrypted_padding(data.size());
    assert(padding >= 1);

    size_t padded_size = data.size() + padding;
    size_t tags_size =
            (padded_size + ENCRYPT_CHUNK_SIZE - 1) / ENCRYPT_CHUNK_SIZE * ENCRYPT_CHUNK_OVERHEAD;

    out.resize(1 + ENCRYPT_HEADER + data.size() + padding + tags_size);
    out[0] = std::byte{'S'};

    std::span<unsigned char> uout{reinterpret_cast<unsigned char*>(out.data()), out.size()};

    std::span<unsigned char, ENCRYPT_HEADER> header{uout.data() + 1, ENCRYPT_HEADER};

    auto st = secretstream_xchacha20poly1305_init_push_with_nonce(
            header, as_span(std::span{key}), std::span{nonce_key}.first<ENCRYPT_HEADER>());

    auto* outpos = uout.data() + 1 + ENCRYPT_HEADER;
    auto* const outend = uout.data() + uout.size();
    auto* inpos = udata.data();
    auto* const inend = inpos + udata.size();

    // Now we build a buffer containing padding, plus whatever initial actual data goes on the end
    // of the last chunk of padding:
    {
        std::vector<unsigned char> buf;
        buf.reserve(std::min(ENCRYPT_CHUNK_SIZE, padded_size));
        for (size_t padding_remaining = padding; padding_remaining;) {
            if (padding_remaining > ENCRYPT_CHUNK_SIZE) {
                // Full chunk of 0x00 padding (with more padding in the next chunk)
                buf.resize(ENCRYPT_CHUNK_SIZE);
                padding_remaining -= ENCRYPT_CHUNK_SIZE;
            } else {
                buf.resize(padding_remaining - 1);  // 0x00 padding
                buf.push_back(0x01);                // padding terminator
                if (size_t first_data =
                            std::min(ENCRYPT_CHUNK_SIZE - padding_remaining, udata.size())) {
                    buf.insert(buf.end(), inpos, inpos + first_data);
                    inpos += first_data;
                }
                padding_remaining = 0;
            }

            assert(outpos + buf.size() + crypto_secretstream_xchacha20poly1305_ABYTES <= outend);

            unsigned char tag = inpos < inend ? 0 : crypto_secretstream_xchacha20poly1305_TAG_FINAL;

            unsigned long long out_len;
            crypto_secretstream_xchacha20poly1305_push(
                    &st, outpos, &out_len, buf.data(), buf.size(), nullptr, 0, tag);
            assert(out_len == buf.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
            outpos += out_len;
        }
    }

    // Now we're through the initial padding (and probably some initial data): now all we need to do
    // is push the rest of the data
    while (inpos < inend) {
        auto* chunk_start = inpos;
        inpos = std::min(chunk_start + ENCRYPT_CHUNK_SIZE, inend);
        assert(outpos + (inpos - chunk_start) + crypto_secretstream_xchacha20poly1305_ABYTES <=
               outend);

        unsigned char tag = inpos < inend ? 0 : crypto_secretstream_xchacha20poly1305_TAG_FINAL;

        unsigned long long out_len;
        crypto_secretstream_xchacha20poly1305_push(
                &st, outpos, &out_len, chunk_start, inpos - chunk_start, nullptr, 0, tag);
        assert(out_len == inpos - chunk_start + crypto_secretstream_xchacha20poly1305_ABYTES);
        outpos += out_len;
    }

    return result;
}

std::vector<std::byte> decrypt(
        std::span<const std::byte> encrypted, std::span<const std::byte, ENCRYPT_KEY_SIZE> key) {

    if (encrypted.size() <= 1 + ENCRYPT_HEADER + ENCRYPT_CHUNK_OVERHEAD)
        throw std::runtime_error{"Attachment decryption failed: encrypted data too short"};

    if (encrypted.front() != std::byte{'S'})
        throw std::runtime_error{
                "Attachment decryption failed: unknown encryption type 0x{:02x}; expected 0x53 (S)"_format(
                        +static_cast<unsigned char>(encrypted.front()))};

    std::span<const unsigned char> uenc{
            reinterpret_cast<const unsigned char*>(encrypted.data()), encrypted.size()};

    auto header = uenc.subspan<1, ENCRYPT_HEADER>();

    crypto_secretstream_xchacha20poly1305_state st;
    crypto_secretstream_xchacha20poly1305_init_pull(
            &st, uenc.data() + 1, reinterpret_cast<const unsigned char*>(key.data()));

    auto* inpos = uenc.data() + 1 + ENCRYPT_HEADER;
    auto* const inend = uenc.data() + uenc.size();

    std::vector<std::byte> decrypted;
    bool done = false;

    // Discard any leading padding chunks (of which there is *always* at least 1 because we always
    // have at least one byte of padding, even for an empty file).  The last such chunk will
    // typically have the beginning of the actual data.  Once we figure out how much padding there
    // is we can calculate the remaining data and reserve the output buffer.
    {
        std::vector<std::byte> padbuf;
        padbuf.reserve(std::min(inend - inpos - ENCRYPT_CHUNK_OVERHEAD, ENCRYPT_CHUNK_SIZE));
        do {
            if (inpos + ENCRYPT_CHUNK_OVERHEAD >= inend)
                throw std::runtime_error{
                        "Attachment decryption failed: data ended in the middle of padding"};

            size_t chunk_size =
                    std::min(inend - inpos - ENCRYPT_CHUNK_OVERHEAD, ENCRYPT_CHUNK_SIZE);
            padbuf.resize(chunk_size);

            unsigned char tag;
            if (crypto_secretstream_xchacha20poly1305_pull(
                        &st,
                        reinterpret_cast<unsigned char*>(padbuf.data()),
                        nullptr,
                        &tag,
                        inpos,
                        chunk_size + ENCRYPT_CHUNK_OVERHEAD,
                        nullptr,
                        0) != 0)
                throw std::runtime_error{
                        "Attachment decryption failed: invalid key or corrupted data"};

            inpos += chunk_size + ENCRYPT_CHUNK_OVERHEAD;

            auto padend = std::find_if_not(padbuf.begin(), padbuf.end(), [](const std::byte c) {
                return c == std::byte{0x00};
            });
            if (padend != padbuf.end()) {
                if (*padend != std::byte{0x01})
                    throw std::runtime_error{"Attachment decryption failed: invalid padding"};
                ++padend;

                std::span<const std::byte> init_data{padend, padbuf.end()};
                // We've identified the start of the data: assuming it is valid, the remaining of
                // the encrypted data consists of N chunks of
                // (ENCRYPT_CHUNK_SIZE+ENCRYPT_CHUNK_OVERHEAD) full data chunks plus one final
                // (chunk+ENCRYPT_CHUNK_OVERHEAD).
                size_t final_size = init_data.size() + (inend - inpos) -
                                    (inend - inpos + ENCRYPTED_CHUNK_TOTAL - 1) /
                                            ENCRYPTED_CHUNK_TOTAL * ENCRYPT_CHUNK_OVERHEAD;
                decrypted.reserve(final_size);
                decrypted.insert(decrypted.end(), padend, padbuf.end());

                if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
                    if (inpos != inend)
                        throw std::runtime_error{
                                "Attachment decryption failed: FINAL tag before end of the "
                                "encrypted data"};
                    done = true;
                } else if (
                        inpos == inend && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
                    throw std::runtime_error{
                            "Attachment decryption failed: end of data without FINAL tag"};
                }

                break;
            }
        } while (true);
    }

    while (!done) {
        if (inpos + ENCRYPT_CHUNK_OVERHEAD >= inend)
            throw std::runtime_error{
                    "Attachment decryption failed: data ended before end of stream"};

        size_t chunk_size = std::min(inend - inpos - ENCRYPT_CHUNK_OVERHEAD, ENCRYPT_CHUNK_SIZE);
        assert(decrypted.capacity() >= decrypted.size() + chunk_size);
        decrypted.resize(decrypted.size() + chunk_size);
        auto* out =
                reinterpret_cast<unsigned char*>(decrypted.data() + decrypted.size() - chunk_size);

        unsigned char tag;
        if (crypto_secretstream_xchacha20poly1305_pull(
                    &st,
                    out,
                    nullptr,
                    &tag,
                    inpos,
                    chunk_size + ENCRYPT_CHUNK_OVERHEAD,
                    nullptr,
                    0) != 0)
            throw std::runtime_error{"Attachment decryption failed: invalid key or corrupted data"};

        inpos += chunk_size + ENCRYPT_CHUNK_OVERHEAD;

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            if (inpos != inend)
                throw std::runtime_error{
                        "Attachment decryption failed: FINAL tag before end of the "
                        "encrypted data"};
            done = true;
        } else if (inpos == inend && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            throw std::runtime_error{"Attachment decryption failed: end of data without FINAL tag"};
        }
    }

    return decrypted;
}

Decryptor::Decryptor(
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key_,
        std::function<void(std::span<const std::byte> decrypted)> output_) :
        output{std::move(output_)} {

    std::memcpy(key.data(), key_.data(), key.size());

    static_assert(
            sizeof(crypto_secretstream_xchacha20poly1305_state) == sizeof(Decryptor::st_data));
    static_assert(alignof(crypto_secretstream_xchacha20poly1305_state) == 1);
    static_assert(std::is_trivially_copyable_v<crypto_secretstream_xchacha20poly1305_state>);
}

static crypto_secretstream_xchacha20poly1305_state* st(unsigned char* st_data) {
    return reinterpret_cast<crypto_secretstream_xchacha20poly1305_state*>(st_data);
}
void Decryptor::process_header(std::span<const std::byte, 1 + ENCRYPT_HEADER> hdr) {
    assert(!header);

    if (hdr[0] != std::byte{'S'}) {
        failed = true;
        return;
    }

    crypto_secretstream_xchacha20poly1305_init_pull(
            st(st_data),
            reinterpret_cast<const unsigned char*>(hdr.data() + 1),
            reinterpret_cast<const unsigned char*>(key.data()));
    header = true;
}

void Decryptor::process_chunk(std::span<const std::byte> chunk, bool is_final) {
    if (hit_final) {
        failed = true;
        return;
    }
    assert(is_final || chunk.size() == ENCRYPTED_CHUNK_TOTAL);
    assert(chunk.size() <= ENCRYPTED_CHUNK_TOTAL);
    if (chunk.size() < ENCRYPT_CHUNK_OVERHEAD) {
        failed = true;
        return;
    }

    unsigned char tag;
    std::array<std::byte, ENCRYPT_CHUNK_SIZE> outa;
    std::span out{outa.data(), chunk.size() - ENCRYPT_CHUNK_OVERHEAD};
    if (crypto_secretstream_xchacha20poly1305_pull(
                st(st_data),
                reinterpret_cast<unsigned char*>(out.data()),
                nullptr,
                &tag,
                reinterpret_cast<const unsigned char*>(chunk.data()),
                chunk.size(),
                nullptr,
                0) != 0) {
        failed = true;
        return;
    }

    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        hit_final = true;

    if (!depadded) {
        auto padend = std::find_if_not(
                out.begin(), out.end(), [](const std::byte c) { return c == std::byte{0x00}; });
        if (padend != out.end()) {
            if (*padend != std::byte{0x01}) {
                failed = true;
                return;
            }
            depadded = true;
            if (++padend != out.end())
                output(std::span<const std::byte>{padend, out.end()});
        }
        return;
    }

    output(out);
}

bool Decryptor::update(std::span<const std::byte> enc_data) {
    if (failed)
        return false;
    if (finished)
        throw std::logic_error{"cannot call update after finalize()"};

    if (!buf.empty()) {
        auto buf_steal = [this, &enc_data](size_t target_buf_size) {
            assert(buf.size() < target_buf_size);
            size_t steal = std::min(target_buf_size - buf.size(), enc_data.size());
            buf.insert(buf.end(), enc_data.begin(), enc_data.begin() + steal);
            enc_data = enc_data.subspan(steal);
            assert(buf.size() <= target_buf_size);
            return buf.size() == target_buf_size;
        };

        if (!header) {
            if (!buf_steal(1 + ENCRYPT_HEADER))
                return true;
            process_header(std::span{buf}.first<1 + ENCRYPT_HEADER>());
        } else {
            if (!buf_steal(ENCRYPTED_CHUNK_TOTAL))
                return true;
            process_chunk(std::span{buf}.first<ENCRYPTED_CHUNK_TOTAL>());
        }
        buf.clear();
        if (failed)
            return false;
    }

    if (!header) {
        if (enc_data.size() >= 1 + ENCRYPT_HEADER) {
            process_header(enc_data.first<1 + ENCRYPT_HEADER>());
            if (failed)
                return false;
            enc_data = enc_data.subspan(1 + ENCRYPT_HEADER);
        } else {
            buf.assign(enc_data.begin(), enc_data.end());
            return true;
        }
    }

    while (enc_data.size() >= ENCRYPTED_CHUNK_TOTAL) {
        process_chunk(enc_data.first<ENCRYPTED_CHUNK_TOTAL>());
        if (failed)
            return false;
        enc_data = enc_data.subspan(ENCRYPTED_CHUNK_TOTAL);
    }

    if (!enc_data.empty())
        buf.assign(enc_data.begin(), enc_data.end());

    return true;
}

bool Decryptor::finalize() {
    if (failed)
        return false;

    if (!buf.empty()) {
        process_chunk(buf, true);
        buf.clear();
    }

    if (failed)
        return false;

    if (!hit_final) {
        failed = true;
        return false;
    }

    return true;
}

void decrypt(
        std::span<const std::byte> encrypted,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        const std::filesystem::path& filename) {

    try {
        std::ofstream out;
        out.exceptions(std::ios::failbit | std::ios::badbit);
        out.open(filename, std::ios::binary | std::ios::out | std::ios::trunc);
        Decryptor d{key, [&out](std::span<const std::byte> data) {
                        out.write(reinterpret_cast<const char*>(data.data()), data.size());
                    }};

        d.update(encrypted);
        d.finalize();
    } catch (const std::exception& e) {
        std::error_code ec;
        std::filesystem::remove(filename, ec);
        throw;
    }
}

}  // namespace session::attachment
