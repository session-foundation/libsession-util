
CREATE TABLE conversations (
    id TEXT PRIMARY KEY NOT NULL,       -- ConversationId::to_string()
    type INTEGER NOT NULL,              -- ConversationId::Type
    display_name TEXT NOT NULL DEFAULT '',
    created INTEGER NOT NULL,           -- ms since epoch
    last_activity INTEGER NOT NULL,     -- ms since epoch; conversation list ordering
    -- Read watermark: incoming messages with a strictly greater timestamp are unread.  A
    -- timestamp rather than a per-message flag because that is what ConvoInfoVolatile syncs, so
    -- adopting it here costs nothing later.
    last_read INTEGER NOT NULL DEFAULT 0,
    draft TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX conversations_activity ON conversations(last_activity DESC);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY,             -- rowid; Client's stable message id
    conversation TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    -- Swarm-assigned hash.  NULL for an outgoing message not yet stored on the swarm; SQLite
    -- treats NULLs as distinct in a unique index, so those never collide with each other while
    -- the index still enforces at-most-once storage of a received hash.
    hash TEXT UNIQUE,
    sender BLOB NOT NULL,               -- 33-byte 0x05-prefixed session ID
    outgoing INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,         -- ms since epoch; the Content sigTimestamp
    body TEXT NOT NULL DEFAULT '',
    send_state INTEGER,                 -- client::SendState; NULL for incoming
    -- The full decrypted Content protobuf, retained so that fields this schema does not yet model
    -- (attachments, quotes, reactions) can be recovered without re-fetching from the swarm.
    content BLOB
) STRICT;

CREATE INDEX messages_history ON messages(conversation, timestamp DESC, id DESC);
CREATE INDEX messages_unread ON messages(conversation, timestamp) WHERE outgoing = 0;
