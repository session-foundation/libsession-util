-- message_attachments was built for outgoing files only, where a local path is always known
-- because it is what we read from.  An attachment we *receive* has no local file: it is a url and
-- a key, and where a user later saves it to is the application's business, not ours.
--
-- The two directions want the same set of columns, so they share the table rather than getting one
-- each; `messages.outgoing` says which reading applies.  What each direction knows is the opposite
-- end of the same transfer:
--
--   outgoing -- `path` is the file to upload; `url IS NULL` means not uploaded yet
--   incoming -- `url` is where the file is, and is required; `path` is always NULL
--
-- so `path` becomes nullable, and stays what it always was: the source of an upload, kept only
-- because a send interrupted before its uploads finished has to re-read those files to resume.
--
-- SQLite cannot drop a NOT NULL, so this is a table rebuild rather than an ALTER.  Safe inside the
-- migration's transaction despite foreign keys being on: this is the child of messages, nothing
-- references it, and every row copied across was already valid.

CREATE TABLE message_attachments_new (
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,

    -- Position within the message's attachment list, which is the order they appear in the
    -- protobuf and how a progress report names one of them.
    idx INTEGER NOT NULL,

    -- The local file: for an outgoing attachment the one we uploaded, which may since have been
    -- moved or deleted (only fatal if this row still needs uploading); for an incoming one where
    -- we saved the download, NULL until it is asked for.
    path TEXT,

    -- Descriptive fields, carried straight through the protobuf pointer in both directions.
    -- content_type is what a recipient displays by; the rest are optional and simply omitted when
    -- null.  On an incoming attachment these are the sender's claims and nothing more.
    content_type TEXT,
    filename TEXT,
    caption TEXT,
    flags INTEGER NOT NULL DEFAULT 0,
    width INTEGER,
    height INTEGER,

    -- Where the file is on the file server, the key it is encrypted with, and its encrypted size.
    -- Set together when an upload succeeds, or read together out of an arriving pointer.
    url TEXT,
    key BLOB,
    size INTEGER,

    -- Legacy attachments authenticate with a separate SHA-256 digest over the ciphertext, and
    -- carry a 64-byte `key` (AES key then HMAC key) rather than the 32-byte stream key.  Null for
    -- anything encrypted with the stream scheme, which authenticates each chunk as it goes.
    digest BLOB,

    PRIMARY KEY (message, idx)
) STRICT;

INSERT INTO message_attachments_new
    (message, idx, path, content_type, filename, caption, flags, width, height, url, key, size)
SELECT message, idx, path, content_type, filename, caption, flags, width, height, url, key, size
FROM message_attachments;

DROP TABLE message_attachments;

ALTER TABLE message_attachments_new RENAME TO message_attachments;
