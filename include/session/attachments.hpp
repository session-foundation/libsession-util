#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <vector>

#include "session/sodium_array.hpp"

namespace session::attachment {

/// Attachment domain separators, used to differentiate the key/nonce generated for an attachment
/// used for a different purpose.
enum class Domain : uint8_t {
    /// Domain for a generic attachment, i.e. a file sent from one user to another:
    ATTACHMENT = 0x00,
    /// Domain for profile pics:
    PROFILE_PIC = 0x01,
};

// Size of initial encryption header (== crypto_secretstream_xchacha20poly1305_HEADERBYTES)
constexpr size_t ENCRYPT_HEADER = 24;
// Size of chunks that we encrypt at a time:
constexpr size_t ENCRYPT_CHUNK_SIZE = 32'768;
// The overhead of the mac+tag added to each chunk (== crypto_secretstream_xchacha20poly1305_ABYTES)
constexpr size_t ENCRYPT_CHUNK_OVERHEAD = 17;

constexpr size_t ENCRYPTED_CHUNK_TOTAL = ENCRYPT_CHUNK_SIZE + ENCRYPT_CHUNK_OVERHEAD;

// Random encryption key size: (== crypto_secretstream_xchacha20poly1305_KEYBYTES)
constexpr size_t ENCRYPT_KEY_SIZE = 32;

// The maximum file size that may be encrypted (unless passing the `allow_large` flag).  This is the
// maximum size (with a small allowance for padding and request overhead) that can be sent or
// retrieved via oxen-storage-server onion requests, and its padded size is the maximum attachment
// size allowed by the storage server.  (Technically this value was chosen as it is the largest
// unencrypted data size that has the same padded+encrypted size as a 10'000'000B file).
constexpr size_t ENCRYPT_MAX_SIZE =
        10218286;  // == 10223616 after stream mac+tag and (1-byte) padding

// Returns the amount of padding to add to an attachment to obfuscate the true size, given
// crypto_secretstream encryption with a 32kiB chunk size.  We determine the padded size as follows,
// given an input size N:
//
// - compute the total raw size M as N plus:
// - 1 for the 'S' prefix (outside the encryption)
// - 17 byte encryption overhead (crypto_secretstream_xchacha20poly1305_ABYTES = poly1305 MAC +
//   1-byte tag) for every 32kiB (or piece thereof)
// - 1 byte for the minimum padding size
//
// We then take keep the most-significant bit of M (i.e. reduce to the largest power of 2 <= M),
// right-shift this by 5, and that round up to the next multiple of that padding factor.
//
// For example, for an input of 1MB (N=100000), we have an unpadded total size of 1000000+1+31*17 =
// 1000528 (i.e. accounting for the 'S' identifier, and the 31 mac+tag values).  We then obtain the
// highest power of two <= this (524288 = 2^19), right-shift by 5 to get 16384 (2^14), and then
// round up the total size to the next multiple of that: 1015808.  Thus we require an additional
// 15280 padding bytes, and so in total we get:
//
//   1 -- the leading (unencrypted) S
// + 15279 × 0x00 -- leading padding bytes
// + 1 × 0x01 -- final padding byte
// + 1000000 -- encrypted file stream data (ignoring embedded mac+tags)
// + 31 × 17 -- embedded mac+tags after every 32kiB of file stream data
// = 1015808 final output.
//
// (Note that we always including at least one padding byte, and there are some complications in the
// calculation as padding values get large enough to start inducing additional mac+tags; see the
// implementation for details).
size_t encrypted_padding(size_t data_size);

/// API: crypto/attachment::encrypt
///
/// Encrypt an attachment for storage on the file server and distribution to other users using
/// deterministic encryption where we use a cryptographically secure hash of the sending user's
/// private key and file content to generate the encryption key/nonce pair.  The main advantage of
/// this is deduplication: the same attachment uploaded by the same user will result in the same
/// encrypted content, thus allowing deduplication of identical uploads on the file server.  This is
/// particularly important for profile pictures, which are frequently re-uploaded to keep the
/// attachment alive.
///
/// We currently always encrypt in chunks of (max) 32kiB via libsodium's crypto_secretstream API,
/// and prefix the encrypted data with a 0x53 ('S') to indicate this.  Any other value of the first
/// byte is reserved for possible alternative future encryption mechanisms.
///
/// We prepend padding of at least 1 byte before the actual data, by prepending (PADDING-1) 0x00
/// bytes followed by a single 0x01 byte to the actual data stream; this data is discard when
/// decrypting.
///
/// Inputs:
/// - `seed` -- the 32-byte seed of the sender; it is recommended that this be the 32-byte Session
///   seed so that the same Session ID always uses the same base seed, but any 32-byte value can be
///   passed (i.e. it is not strictly required that it be a Session seed).  Only the first 32 bytes
///   of longer values will be used (and thus passing the 64-byte seed+pubkey libsodium full secret
///   is equivalent to passing just the seed).
///
/// - `data` -- the buffer of data to encrypt.
///
/// - `domain` -- domain separator; uploads of funamentally different types should use a different
///   value, so that an identical upload used for different purposes will have unrelated key/nonce
///   values.
///
/// - `allow_large` -- defaults to false; if true, this function will accept an input larger value
///   than MAX_REGULAR_SIZE.  This option should only be passed when compatibility with onion
///   requests is not needed.
///
/// Outputs:
/// - Pair of values: the padded+encrypted data, and the decryption key (32 bytes), both in raw
/// bytes.
///
/// Throws std::invalid_argument if `seed` is shorter than 32 bytes, or if data is larger than
/// MAX_REGULAR_SIZE (unless `allow_large` is true).
///
std::pair<std::vector<std::byte>, std::array<std::byte, ENCRYPT_KEY_SIZE>> encrypt(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        bool allow_large = false);

/// API: crypto/attachment::decrypt
///
/// Decrypts an attachment allegedly produced by attachment::encrypt to a single in-memory buffer.
///
/// Inputs:
/// - `data` -- in-memory buffer of data to decrypt.
/// - `key` -- the 32-byte decryption key
///
/// Outputs:
/// - std::vector<std::byte> of decrypted, de-padded data.
///
/// Throws std::runtime_error if decryption fails.
std::vector<std::byte> decrypt(
        std::span<const std::byte> encrypted, std::span<const std::byte, ENCRYPT_KEY_SIZE> key);

/// API: crypto/attachment::Decryptor
///
/// Object-based interfaced to streaming decryption.  The basic usage is to construct the object
/// with an output callback, then repeatedly feed it any amount of additional data via `update()`
/// until all data has been provided.  Calls to `update()` will invoke the output callback as soon
/// as enough data has been provided to advance to the next stream chunk(s), and so one call to
/// update() could result in any number of calls to output(), including 0.  Once all data has been
/// provided, `finalize()` is called to signal the end of the input data.
///
/// If a problem with the data is found, the `update()` or `finalize()` call will returns false
/// indicating that the decryption failed, and any partially decrypted output data provided to the
/// output callback should be discarded or deleted.  Further calls to `update()` or `finalize()`
/// after such a failure will simply return false without processing any additional data.
///
/// This class is not recommended if the intention is to build an in-memory buffer from existing
/// in-memory data: `decrypt()` will be more memory efficient in that case.
class Decryptor {
    std::function<void(std::span<const std::byte> decrypted)> output;
    std::vector<std::byte> buf;
    bool header = false;
    bool depadded = false;
    bool failed = false;
    bool finished = false;
    bool hit_final = false;
    cleared_uc32 key;
    unsigned char st_data[52];  // crypto_secretstream_xchacha20poly1305_state data

    void process_header(std::span<const std::byte, 1 + ENCRYPT_HEADER> chunk);
    void process_chunk(std::span<const std::byte> chunk, bool is_final = false);

  public:
    /// Constructs a decryptor.  The given output will be called as soon as enough data has been
    /// accumulated to validate additional decrypted data.
    Decryptor(
            std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
            std::function<void(std::span<const std::byte> decrypted)> output);

    /// Provides more data to the decryptor.  If the additional data completes an input data chunk
    /// then output will be called with the partially decrypted data.  Returns true if the data was
    /// accepted, false if data stream decryption failed (either because of the new data, or some
    /// previous failure).
    ///
    /// Throws std::logic_error if called after a successful finalize().
    bool update(std::span<const std::byte> enc_data);

    /// Called to signal the end of the encrypted data stream.  If all data was processed
    /// successfully and the stream ended properly, this returns true; returns false if the stream
    /// data did not indicate finality (or if a previous update returned failure).
    ///
    /// Throws std::logic_error if called after a successful finalize().
    bool finalize();
};

/// API: crypto/attachment::decrypt
///
/// Decrypts an attachment allegedly produced by attachment::encrypt to an output file.  Overwrites
/// the file if it already exists.
///
/// Inputs:
/// - `data` -- in-memory buffer of data to decrypt.
/// - `key` -- the 32-byte decryption key.
/// - `filename` -- where to write the output file.
///
/// Outputs: None.
///
/// Throws std::runtime_error if decryption fails or if writing to the file fails.  Upon exception a
/// partially written file will be deleted.
void decrypt(
        std::span<const std::byte> encrypted,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        const std::filesystem::path& filename);

}  // namespace session::attachment
