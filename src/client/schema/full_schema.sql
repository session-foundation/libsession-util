-- The Client schema with every migration in this directory applied.  A database with none of
-- them applied is built from this in one step; the migrations are then recorded without being
-- run.  Keep this in step with the migrations: test_client.cpp compares the two.

-- Every account we have seen, whether or not it is a contact: a message sender needs a row, so
-- this is "accounts we know of", with contact-ness being state on the row rather than the reason
-- the row exists.
--
-- display_name is currently only what we have observed from the LokiProfile on incoming messages.
-- Once Core carries the Contacts config, that config is reconciled *into* this table rather than
-- replacing it: the config is the synced representation, this is the queryable one, and it also
-- holds local-only fields the config knows nothing about.
--
-- Approval state arrives with it -- whether we have accepted messages from this account and whether
-- they have accepted ours -- and belongs here rather than on conversations, because it is a
-- property of the account.  It is what separates a conversation from a message request.
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    session_id BLOB NOT NULL UNIQUE,    -- 33 bytes, 0x05-prefixed
    display_name TEXT                   -- NULL when no name is known; never an empty string
) STRICT;

CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    group_id BLOB NOT NULL UNIQUE       -- 33 bytes, 0x03-prefixed
) STRICT;

CREATE TABLE communities (
    id INTEGER PRIMARY KEY,
    base_url TEXT NOT NULL,             -- lowercased, no trailing slash
    room TEXT NOT NULL,                 -- lowercased
    UNIQUE (base_url, room)
) STRICT;

CREATE TABLE conversations (
    id INTEGER PRIMARY KEY,
    -- What the conversation is with.  Exactly one of these is set, and which one it is *is* the
    -- conversation's kind -- there is no separate type column that could disagree with it.  Each
    -- is UNIQUE so a given peer, group or room has at most one conversation; SQLite treats NULLs
    -- as distinct, so the unused columns do not collide across rows.
    -- ("closed_group" rather than "group" because the latter is a SQL keyword.)
    dm INTEGER UNIQUE REFERENCES accounts(id),
    closed_group INTEGER UNIQUE REFERENCES groups(id),
    community INTEGER UNIQUE REFERENCES communities(id),
    created INTEGER NOT NULL,           -- ms since epoch
    last_activity INTEGER NOT NULL,     -- ms since epoch; conversation list ordering
    -- Read watermark: incoming messages with a strictly greater timestamp are unread.  A
    -- timestamp rather than a per-message flag because that is what ConvoInfoVolatile syncs, so
    -- adopting it here costs nothing later.
    last_read INTEGER NOT NULL DEFAULT 0,
    -- Cached rather than counted per query: a conversation list is redrawn far more often than its
    -- messages change.  `count` is maintained by the triggers below; `unread_count` is maintained
    -- by the application, for the reason given there.
    count INTEGER NOT NULL DEFAULT 0,
    unread_count INTEGER NOT NULL DEFAULT 0,
    -- Pinning, mirroring the value the Contacts and UserGroups configs sync: 0 is unpinned, a
    -- positive value is pinned with higher values sorting first, and a negative value is hidden.
    -- Kept numerically identical to the config so that reconciling one into the other is a copy
    -- rather than a translation.
    priority INTEGER NOT NULL DEFAULT 0,
    CHECK ((dm IS NOT NULL) + (closed_group IS NOT NULL) + (community IS NOT NULL) = 1)
) STRICT;

CREATE INDEX conversations_order ON conversations(priority DESC, last_activity DESC);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    conversation INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    -- The sender's Content.msgId: 8 random bytes separating this message from another they sent in
    -- the same millisecond.  Every copy of a message carries the same value -- it is set before the
    -- copy for the recipient and the copy for our own swarm diverge -- which is what makes it the
    -- one identifier both parties agree on.
    --
    -- Only ever meaningful together with `timestamp`; it is far too small to identify a message on
    -- its own.  See the field's comment in SessionProtos.proto.
    --
    -- NULL for a message whose sender predates the field, which cannot then be told apart from
    -- another they sent in the same millisecond.
    --
    -- An opaque 64-bit pattern rather than a number: SQLite integers are signed, so a value above
    -- INT64_MAX is stored negative.  Compared for equality and nothing else.
    msgid INTEGER,
    -- Swarm-assigned hash; NULL for an outgoing message not yet stored on the swarm.  SQLite
    -- treats NULLs as distinct in a unique index, so those never collide with each other.
    swarm_hash TEXT UNIQUE,
    sender INTEGER NOT NULL REFERENCES accounts(id),
    outgoing INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,         -- ms since epoch; the Content sigTimestamp
    body TEXT NOT NULL,
    -- Delivery state of the copy sent to the recipient's swarm, for outgoing messages only:
    --   0 = queued locally, not yet dispatched
    --   1 = handed to the swarm, awaiting confirmation
    --   2 = accepted by a swarm node
    --   3 = terminal failure
    --   4 = in flight when the process exited, so the outcome is unknown
    --
    -- ...and the same for the copy deposited in our own swarm, which is how our other devices see
    -- an outgoing message.  The two are independent sends, retried separately, so a message can
    -- have reached its recipient while still owing our other devices a copy.
    --
    -- NULL in either means there is no such send: both are NULL on an incoming message, and
    -- sync_send_state is NULL for a note to self, where the recipient's swarm is our own and a
    -- second store would be the same store twice.
    send_state INTEGER,
    sync_send_state INTEGER
) STRICT;

-- Delivery is at-least-once, so a redelivered message must not duplicate.  This also catches what
-- the swarm hash cannot: our own message arriving back from our swarm, which carries the same msgid
-- as the copy we sent.  Both columns are needed -- see the protobuf comment for why msgid is not an
-- identifier on its own.
CREATE UNIQUE INDEX messages_msgid ON messages(conversation, timestamp, msgid);

CREATE INDEX messages_history ON messages(conversation, timestamp DESC, id DESC);
CREATE INDEX messages_unread ON messages(conversation, timestamp) WHERE outgoing = 0;

-- Quotes and reactions from clients that set no msgId address their target by author and timestamp
-- alone.  Needed for as long as such clients exist.
CREATE INDEX messages_wire_key ON messages(conversation, sender, timestamp);

-- `count` is a structural fact about the messages table, so triggers can own it outright: there is
-- no judgement involved in how many rows a conversation has.
--
-- `unread_count` deliberately is *not* maintained here.  What counts as unread is policy, not
-- structure -- mutes, message requests, tombstones, a message arriving with a timestamp older than
-- the read watermark -- and that policy will grow.  Encoding it in triggers would scatter it
-- across SQL that is awkward to test and invisible from the code that decides it, so the
-- application maintains unread_count wherever it changes what has been read.
CREATE TRIGGER messages_insert AFTER INSERT ON messages
BEGIN
    UPDATE conversations SET count = count + 1 WHERE id = NEW.conversation;
END;

CREATE TRIGGER messages_delete AFTER DELETE ON messages
BEGIN
    UPDATE conversations SET count = count - 1 WHERE id = OLD.conversation;
END;

CREATE TRIGGER messages_move AFTER UPDATE OF conversation ON messages
WHEN OLD.conversation != NEW.conversation
BEGIN
    UPDATE conversations SET count = count - 1 WHERE id = OLD.conversation;
    UPDATE conversations SET count = count + 1 WHERE id = NEW.conversation;
END;

-- The full decrypted Content protobuf, kept out of the messages table so that the history scan --
-- the hot query -- does not drag it through overflow pages.  Retained so fields this schema does
-- not yet model (attachments, quotes, reactions) can be recovered without re-fetching the swarm.
CREATE TABLE message_raw_content (
    message INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    content BLOB NOT NULL
) STRICT;

-- Files attached to a message, in either direction.
--
-- The two directions are the same set of columns and differ only in which end is known first, so
-- they share the table; `messages.outgoing` says which reading applies.  `path` is the local copy
-- and `url` the remote one, and exactly one of them exists from the start:
--
--   outgoing -- `path` is the file we uploaded, and is required; `url IS NULL` means not uploaded
--   incoming -- `url` is where the file is, and is required; `path IS NULL` means not saved
--
-- Sending with attachments is two stages: each file is encrypted and uploaded, and only then can
-- the message be built, since it has to name where those files ended up.  A failure between the two
-- leaves a message that cannot be finished from the message alone -- what it needs is the local
-- files and whatever their uploads already achieved, neither of which the protobuf carries.
-- Retrying without that would mean re-uploading files that already arrived.
--
-- There is no state column: for an outgoing attachment `url IS NULL` *is* "not uploaded yet".
-- Retrying is then "upload every row for this message that has no url, then build the message and
-- send it", which cannot disagree with itself the way a separate state could, and is safe to run
-- twice.
--
-- An outgoing row's `path` outlives the upload deliberately.  It is what makes an attachment we
-- sent displayable without fetching our own upload back, and it is the only record of it: what
-- persists of a sent attachment otherwise is the pointer inside message_raw_content.
CREATE TABLE message_attachments (
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
