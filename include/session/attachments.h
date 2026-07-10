#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "export.h"

typedef enum ATTACHMENT_DOMAIN {
    ATTACHMENT_DOMAIN_ATTACHMENT = 0x00,
    ATTACHMENT_DOMAIN_PROFILE_PIC = 0x01,
} ATTACHMENT_DOMAIN;

// The size of the encryption key, which is always 32 bytes.
extern const size_t ATTACHMENT_ENCRYPT_KEY_SIZE;

// The maximum allowed size of an regular attachment that might be sent or retrieved via onion
// requests.  Larger attachments are permitted, but will be too large (after padding+encryption) for
// transmission via onion requests.
extern const size_t ATTACHMENT_MAX_REGULAR_SIZE;  // 10218286 input == 10223616 encrypted

/// API: crypto/session_attachment_encrypted_size
///
/// Returns the exact encrypted+padded output size of an input of `plaintext_size` bytes.  This is
/// the size of buffer that must be preallocated for the session_attachment_encrypt functions.
LIBSESSION_EXPORT size_t session_attachment_encrypted_size(size_t plaintext_size);

/// API: crypto/session_attachment_decrypted_max_size
///
/// Returns the maximum possible size of the plaintext data given encrypted data of the given size.
/// The actual decrypted size can be smaller, depending on the amount of padding in the encrypted
/// attachment.  Returns `(size_t)-1` if the given encrypted size is too small to be a valid
/// encrypted attachment.
LIBSESSION_EXPORT size_t session_attachment_decrypted_max_size(size_t encrypted_size);

/// API: crypto/session_attachment_encrypt
///
/// Encrypt an attachment for storage on the file server into a preallocated buffer.
///
/// Inputs:
/// - `seed` -- the 32-byte unique sender data; typically simply the sender's Ed25519 seed.
/// - `data` -- pointer to the buffer of data to encrypt
/// - `datalen` -- length of the data to encrypt
/// - `domain` -- domain separator; should be an ATTACHMENT_DOMAIN value.
/// - `key_out` -- Pointer to an existing 32-byte buffer where the 32-byte binary decryption key
///   will be written.
/// - `out` -- Pointer to an output buffer, which must be able to contain exactly
///   `session_attachment_encrypted_size(datalen)` encrypted output bytes.
/// - `error` -- if non-NULL and encryption fails then a reason for the error is written here; must
///   be a buffer of at least 256 bytes (or NULL).
///
/// This method always passes `allow_large` to the underlying C++ implementation; the caller should
/// ensure that the input is less than `ATTACHMENT_MAX_REGULAR_SIZE` bytes before calling this (if
/// compatibility with onion requests is needed).
///
/// Outputs:
/// - returns the number of encrypted data bytes written to `out` on success, 0 if encryption fails
///   (in which case `error` will be written with the error reason, if non-NULL).
LIBSESSION_EXPORT bool session_attachment_encrypt(
        const unsigned char* seed,
        const unsigned char* data,
        size_t datalen,
        ATTACHMENT_DOMAIN domain,
        unsigned char* key_out,
        unsigned char* out,
        char* error);

/// API: crypto/session_attachment_encrypt_file
///
/// Encrypt an attachment for storage on the file server from a plaintext file on disk into a
/// preallocated buffer.
///
/// Note that this implementation needs to read the file *twice*: a first pass to obtain the
/// file-dependent encryption and nonce; and then a second pass to perform the actual encryption,
/// but unlike first reading into a memory buffer, does not have to store the file contents in
/// memory.
///
/// Inputs:
/// - `seed` -- the 32-byte unique sender data; typically simply the sender's Ed25519 seed.
/// - `filename` -- the filename to read (null-terminated C string).
/// - `domain` -- domain separator; should be an ATTACHMENT_DOMAIN value.
/// - `key_out` -- Pointer to an existing 32-byte buffer where the 32-byte binary decryption key
///   will be written.
/// - `make_buffer` -- callback to invoke to allocate a buffer of the required size into which to
///   write the encrypted data.  It is passed two arguments: the required output buffer size, and
///   `ctx`, and must return a pointer to the beginning of a buffer of the requested size in which
///   to write the encrypted data.  Can return NULL to abort encryption (e.g. if the size is too
///   large).
/// - `ctx` - arbitrary pointer (which can be null) to pass to make_buffer to pass user-defined
///   context into the callback.  This encrypt function does not otherwise touch the pointer.
/// - `error` -- if non-NULL and encryption fails then a reason for the error is written here; must
///   be a buffer of at least 256 bytes (or NULL).
///
/// This method always passes `allow_large` to the underlying C++ implementation; the caller should
/// ensure that the input is less than `ATTACHMENT_MAX_REGULAR_SIZE` bytes before calling this (if
/// compatibility with onion requests is needed).
///
/// Outputs:
/// - returns the number of encrypted data bytes written (which will always equal the value passed
///   into `make_buffer`) on success; 0 if encryption fails (in which case `error` will be written
///   with the error reason, if non-NULL).
LIBSESSION_EXPORT size_t session_attachment_encrypt_file(
        const unsigned char* seed,
        const char* filename,
        ATTACHMENT_DOMAIN domain,
        unsigned char* key_out,
        unsigned char* (*make_buffer)(size_t, void* ctx),
        void* ctx,
        char* error);

/// API: crypto/session_attachment_decrypt
///
/// Decrypts an attachment allegedly produced by session_attachment_encrypt into a provided
/// in-memory buffer.
///
/// Inputs:
/// - `data` -- pointer to the buffer of data to decrypt
/// - `datalen` -- length of the `data`
/// - `key` -- pointer to the 32-byte binary decryption key
/// - `out` -- output buffer pointer; this buffer must be able to accept the entire decrypted file,
///   which can be anything up to `session_attachment_decrypted_max_size(datalen)` bytes.  Note that
///   this buffer may be partially overwritten even if the function returns false (for cases when
///   the decryption error happens later in the encrypted stream).
/// - `outlen` -- pointer in which to store the final decrypted data size written to `out`, which is
///   often shorter than `session_attachment_decrypted_max_size(datalen)` (because of removed
///   padding).   Not touched if the function returns false.
/// - `error` -- if non-NULL and decryption fails then a reason for the error is written here; must
///   be a buffer of at least 256 bytes (or NULL).
///
/// Outputs:
/// - returns true if decryption succeeds: the `*outlen` bytes decrypted value will be written
///   starting at `out`.  Returns false decryption fails (in which case `error` will be written with
///   the error reason, if provided).
LIBSESSION_EXPORT bool session_attachment_decrypt(
        const unsigned char* data,
        size_t datalen,
        const unsigned char* key,
        unsigned char* out,
        size_t* outlen,
        char* error);

/// API: crypto/session_attachment_decrypt
///
/// Decrypts an attachment allegedly produced by session_attachment_encrypt into a single in-memory
/// allocated buffer.
///
/// Inputs:
/// - `data` -- pointer to the buffer of data to decrypt
/// - `datalen` -- length of the `data`
/// - `key` -- pointer to the 32-byte binary decryption key
/// - `out` -- Pointer-pointer to an output buffer; a new buffer is allocated, the decrypted
///   attachment written to it, and then the pointer to that buffer is stored here.  This buffer
///   must be `free()`d by the caller when done with it *unless* the function returns false, in
///   which case the buffer pointer will not be set.
/// - `outlen` -- pointer in which to store final decrypted data size.  Not touched if the function
///   returns false.
/// - `error` -- if non-NULL and decryption fails then a reason for the error is written here; must
///   be a buffer of at least 256 bytes (or NULL).
///
/// Outputs:
/// - returns true if decryption succeeds and `out` was set to the decrypted data; false if
///   decryption fails (in which case `error` will be written with the error reason, if provided).
LIBSESSION_EXPORT bool session_attachment_decrypt_alloc(
        const unsigned char* data,
        size_t datalen,
        const unsigned char* key,
        unsigned char** out,
        size_t* outlen,
        char* error);

/// API: crypto/session_attachment_decrypt_file
///
/// Decrypts an attachment from a file on disk and loads the decrypted content into an in-memory
/// buffer.
///
/// Inputs:
/// - `file_in` -- C string of input filename
/// - `datalen` -- length of the `data`
/// - `key` -- pointer to the 32-byte binary decryption key
/// - `make_buffer` -- callback to invoke to allocate a buffer of the required size into which to
///   write the decrypted data.  It is passed two arguments: the required output buffer size, and
///   `ctx`, and must return a pointer to the beginning of a buffer of the requested size in which
///   to write the encrypted data.  Can return NULL to abort encryption (e.g. if the size is too
///   large).  Note that some of the buffer may not end up being used, due to padding: the return
///   value of `session_attachment_decrypt_file` indicates the actual amount of decrypted data
///   written to the buffer.
/// - `ctx` - arbitrary pointer (which can be null) to pass to make_buffer to pass user-defined
///   context into the callback.  This encrypt function does not otherwise touch the pointer.
/// - `error` -- if non-NULL and decryption fails then a reason for the error is written here; must
///   be a buffer of at least 256 bytes (or NULL).
///
/// Outputs:
/// - returns the amount of decrypted data written to the buffer, (which can be 0, for an empty
///   encrypted file!).  If decryption fails this will be set to `(size_t)-1` to indicate the
///   failure, and `error` will be written with the error reason, if provided.
///
LIBSESSION_EXPORT size_t session_attachment_decrypt_file(
        const char* file_in,
        const unsigned char* key,
        unsigned char* (*make_buffer)(size_t, void* ctx),
        void* ctx,
        char* error);

/// API: crypto/session_attachment_decrypt_to_file
///
/// Decrypts an attachment from a in-memory buffer writing the decrypted data to a file on disk.
///
/// Inputs:
/// - `data` -- pointer to the buffer of data to decrypt
/// - `datalen` -- length of the `data`
/// - `key` -- pointer to the 32-byte binary decryption key
/// - `filename` -- C string of output filename to write the decrypted data to.  The file will be
///   overwritten if it exists.  If a failure occurs during decryption the file will be removed.
/// - `error` -- if non-NULL and decryption fails then a reason for the error is written here; must
///   be a buffer of at least 256 bytes (or NULL).
///
/// Outputs:
/// - returns true if decryption succeeds; false if decryption fails (in which case `error` will be
///   written with the error reason, if provided).
///
LIBSESSION_EXPORT bool session_attachment_decrypt_to_file(
        const unsigned char* data,
        size_t datalen,
        const unsigned char* key,
        const char* filename,
        char* error);

/// API: crypto/session_attachment_decrypt_file_to_file
///
/// Decrypts an attachment from an encrypted file on disk to another path on disk.
///
/// - `file_in` -- C string input filename containing encrypted data.
/// - `key` -- pointer to the 32-byte binary decryption key
/// - `file_out` -- C string of output filename to write the decrypted data to.  The file will be
///   overwritten if it exists.  If a failure occurs during decryption the file will be removed.
/// - `error` -- if non-NULL and decryption fails then a reason for the error is written here; must
///   be a buffer of at least 256 bytes (or NULL).
///
/// Outputs:
/// - returns true if decryption succeeds; false if decryption fails (in which case `error` will be
///   written with the error reason, if provided).
LIBSESSION_EXPORT bool session_attachment_decrypt_file_to_file(
        const char* file_in, const unsigned char* key, const char* file_out, char* error);

#ifdef __cplusplus
}
#endif
