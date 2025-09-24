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
constexpr size_t MAX_REGULAR_SIZE =
        10218286;  // == 10223616 after stream mac+tag and (1-byte) padding

// Returns the amount of padding to add to an attachment to obfuscate the true size, given
// crypto_secretstream encryption with a 32kiB chunk size.  We determine the padded size as
// follows, given an input size N:
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
// (Note that we always including at least one padding byte, and there are some complications in
// the calculation as padding values get large enough to start inducing additional mac+tags; see
// the implementation for details).
size_t encrypted_padding(size_t data_size);

/// API: crypto/attachment::encrypted_size
///
/// Returns the exact final encrypted (including any overhead and padding) of an input of
/// `plaintext_size`.
size_t encrypted_size(size_t plaintext_size);

/// API: crypto/attachment::decrypted_max_size
///
/// Returns the maximum possible decrypted size of encrypted data of length `encrypted_size`.  The
/// actual size can be (and usually is) less than this depending on how much padding is in the data.
/// Returns std::nullopt if the input is too small to be a valid encrypted attachment.
std::optional<size_t> decrypted_max_size(size_t encrypted_size);

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

/// API: crypto/attachment::encrypt
///
/// Similar to the above `encrypt` except that instead of allocating and returning a vector it
/// writes the encrypted result directly into a given output span.  The output span *must* be
/// exactly `encrypted_size()` bytes long (but this is checked via assertion in debug builds).
///
/// Inputs:
/// - `seed` -- as above
/// - `data` -- as above
/// - `domain` -- as above
/// - `out` -- writeable span into which the encrypted data will be written.  This span must be
///   exactly `encrypted_size(data.size())` bytes long.
/// - `allow_large` -- as above.
///
/// Outputs:
/// - 32 byte decryption key
///
/// Throws std::invalid_argument if `seed` is shorter than 32 bytes, or if data is larger than
/// MAX_REGULAR_SIZE (unless `allow_large` is true).
std::array<std::byte, ENCRYPT_KEY_SIZE> encrypt(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        std::span<std::byte> out,
        bool allow_large = false);

/// API: crypto/attachment::encrypt
///
/// Encrypts the contents of a file on disk into a buffer.  This requires reading the file twice
/// (once in order to generate the deterministic encryption key and nonce, and then a second time
/// for the actual encryption), but does not require holding the file contents in memory.
///
/// Inputs:
/// - `seed`, `domain`, `allow_large` -- see above.
/// - `file` -- path to the file to encrypt.
///
/// Outputs:
/// - Pair of values: the padded+encrypted data, and the decryption key (32 bytes), both in raw
/// bytes.
///
/// Throws std::invalid_argument if `seed` is shorter than 32 bytes, or if the file is larger than
/// MAX_REGULAR_SIZE.
std::pair<std::vector<std::byte>, std::array<std::byte, ENCRYPT_KEY_SIZE>> encrypt(
        std::span<const std::byte> seed,
        const std::filesystem::path& file,
        Domain domain,
        bool allow_large = false);

/// API: crypto/attachment::encrypt
///
/// Encrypts the contents of a file on disk into a buffer.  This method is a more general version of
/// the above that allows allocation of the encrypted buffer via a callback once the size is
/// determined from the file.
///
/// Inputs:
/// - `seed`, `domain`, `allow_large` -- see above.
/// - `file` -- path to the file to encrypt.
/// - `make_buffer` -- callback that is invoked with the exact required encrypted size for the file
///   that must return a byte span of that exact file where the encrypted data will be written.
///
/// Outputs:
/// - The 32-byte decryption key, in raw bytes.
///
/// Throws std::invalid_argument if `seed` is shorter than 32 bytes, or if the file is larger than
/// MAX_REGULAR_SIZE.
/// Throws std::runtime_error if the file size changes between first and second passes.
std::array<std::byte, ENCRYPT_KEY_SIZE> encrypt(
        std::span<const std::byte> seed,
        const std::filesystem::path& file,
        Domain domain,
        std::function<std::span<std::byte>(size_t enc_size)> make_buffer,
        bool allow_large = false);

/// API: crypto/attachment::encrypt
///
/// Encrypts the contents of a plaintext buffer, writing the encrypted data to a file.  The file
/// will be overwritten.
///
/// Inputs:
/// - `seed`, `domain`, `allow_large` -- see above.
/// - `data` -- the buffer of data to encrypt.
/// - `file` -- path to the file to write to.
///
/// Outputs:
/// - The 32-byte decryption key, in raw bytes.
///
/// Throws std::invalid_argument if `seed` is shorter than 32 bytes, or if data is larger than
/// MAX_REGULAR_SIZE (unless `allow_large` is given).  Throws on I/O error.  If decryption fails
/// then any partially written output file will be removed.
std::array<std::byte, ENCRYPT_KEY_SIZE> encrypt(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        const std::filesystem::path& file,
        bool allow_large = false);

/// API: crypto/attachment::decrypt
///
/// Decrypts an attachment allegedly produced by attachment::encrypt to an in-memory byte vector.
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

/// API: crypto/attachment::decrypt
///
/// Decrypts an attachment allegedly produced by attachment::encrypt to a single in-memory,
/// caller-provided buffer.  This version writes into a given output span rather than allocating a
/// new vector.
///
/// Inputs:
/// - `data` -- in-memory buffer of data to decrypt.
/// - `key` -- the 32-byte decryption key
/// - `out` -- writeable output span in which the decrypted value should be written.  The given span
///   must be at least `decrypted_max_size(data.size())` bytes large.
///
/// Outputs:
/// - size_t -- the actual decrypted data size written into `out` which could be (and often is, due
///   to padding) less than `out.size()`.
///
/// Throws std::runtime_error if decryption fails.
size_t decrypt(
        std::span<const std::byte> encrypted,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        std::span<std::byte> out);

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

/// API: crypto/attachment::decrypt
///
/// Decrypts an encrypted attachment stored in an input file into a byte vector.
///
/// Inputs:
/// - `filename` -- path to encrypted file.
/// - `key` -- the 32-byte decryption key.
///
/// Outputs:
/// - vector of decrypted content.
///
/// Throws std::runtime_error if decryption fails; can throw I/O exceptions if reading the file
/// fails.
std::vector<std::byte> decrypt(
        const std::filesystem::path& encrypted_file,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key);

/// API: crypto/attachment::decrypt
///
/// Decrypts an encrypted attachment stored in an input file into a provided memory buffer.
///
/// Inputs:
/// - `filename` -- path to encrypted file.
/// - `key` -- the 32-byte decryption key.
/// - `make_buffer` -- callback that is invoked to allocate the buffer into which the content should
///   be written.  This is passed the required buffer size.  Note that this buffer may not be
///   completely filled: the return value of `decrypt()` indicates the actual amount of the buffer
///   that was written.
///
/// Outputs:
/// - size_t the actual decrypted size.  Can be less than the value passed to `decrypted.size()`
///   because of padding.
///
/// Throws std::runtime_error if decryption fails; can throw I/O exceptions if reading the file
/// fails.
size_t decrypt(
        const std::filesystem::path& encrypted_file,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        std::function<std::span<std::byte>(size_t dec_size)> make_buffer);

/// API: crypto/attachment::decrypt
///
/// Decrypts an attachment allegedly produced by attachment::encrypt stored in a file to another
/// output file.  Overwrites the destination file if it already exists.
///
/// Unlike the various decrypt functions above, this version does not need to hold more than a few
/// kB of the input/output file in memory at a time, regardless of the size of the input or output
/// files.
///
/// Inputs:
/// - `file_in` -- filename containing the data to decrypt.
/// - `key` -- the 32-byte decryption key.
/// - `file_out` -- where to write the output file.
///
/// Outputs: None.
///
/// Throws std::runtime_error if decryption fails or if writing to the file fails.  Upon exception a
/// partially written file will be deleted.
void decrypt(
        const std::filesystem::path& file_in,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        const std::filesystem::path& file_out);

}  // namespace session::attachment
