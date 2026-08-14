-- Files attached to an outgoing message, held only while the message is getting sent.
--
-- Sending a message with attachments is two stages: each file is encrypted and uploaded, and only
-- then can the message be built, since it has to name where those files ended up.  A failure
-- between the two leaves a message that cannot be finished from the message alone -- what it needs
-- is the local files and whatever their uploads already achieved, neither of which the protobuf
-- carries.  Retrying without that would mean re-uploading files that already arrived.
--
-- There is no state column: `url IS NULL` *is* "not uploaded yet".  Retrying is then "upload every
-- row for this message that has no url, then build the message and send it", which cannot disagree
-- with itself the way a separate state could, and is safe to run twice.
--
-- The local `path` outlives the upload deliberately.  It is what makes an attachment we sent
-- displayable without fetching our own upload back, and it is the only record of it: what persists
-- of a sent attachment otherwise is the pointer inside message_raw_content.
CREATE TABLE message_attachments (
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,

    -- Position within the message's attachment list, which is the order they appear in the
    -- protobuf and how a progress report names one of them.
    idx INTEGER NOT NULL,

    -- The local file.  May since have been moved or deleted, which is only fatal if this row still
    -- needs uploading.
    path TEXT NOT NULL,

    -- Descriptive fields, carried through to the protobuf pointer as-is.  content_type is what a
    -- recipient displays by; the rest are optional and simply omitted when null.
    content_type TEXT,
    filename TEXT,
    caption TEXT,
    flags INTEGER NOT NULL DEFAULT 0,
    width INTEGER,
    height INTEGER,

    -- Set together, once the upload succeeds: where the file landed, the key it was encrypted
    -- with, and its encrypted size.
    url TEXT,
    key BLOB,
    size INTEGER,

    PRIMARY KEY (message, idx)
) STRICT;
