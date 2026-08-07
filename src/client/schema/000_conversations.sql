
-- Every account we have seen, whether or not it is a contact: a message sender needs a row, so
-- this is "accounts we know of", with contact-ness being state on the row rather than the reason
-- the row exists.
--
-- display_name is currently only what we have observed from the LokiProfile on incoming messages.
-- Once Core carries the Contacts config, that config is reconciled *into* this table rather than
-- replacing it: the config is the synced representation, this is the queryable one, and it also
-- holds local-only fields the config knows nothing about.
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    session_id BLOB NOT NULL UNIQUE,    -- 33 bytes, 0x05-prefixed
    display_name TEXT                   -- NULL when no name is known; never an empty string
) STRICT;

CREATE TABLE conversations (
    id INTEGER PRIMARY KEY,
    -- The conversation's identity in a single uniform form, whatever its kind:
    --   DM         66 hex characters -- the 0x05-prefixed 33-byte session ID
    --   group      66 hex characters -- the 0x03-prefixed 33-byte group ID
    --   community  "community:", then the server URL (lowercased, no trailing slash), "/", then
    --              the room token (lowercased)
    -- This is also the form a user pastes or bookmarks, so it must stay stable.
    key TEXT NOT NULL UNIQUE,
    type INTEGER NOT NULL,              -- 0 = DM, 1 = group, 2 = community
    -- The remote account, for DMs; NULL for groups and communities, which are keyed on something
    -- other than an account.
    peer INTEGER REFERENCES accounts(id),
    created INTEGER NOT NULL,           -- ms since epoch
    last_activity INTEGER NOT NULL,     -- ms since epoch; conversation list ordering
    -- Read watermark: incoming messages with a strictly greater timestamp are unread.  A
    -- timestamp rather than a per-message flag because that is what ConvoInfoVolatile syncs, so
    -- adopting it here costs nothing later.
    last_read INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX conversations_activity ON conversations(last_activity DESC);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    conversation INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    -- BLAKE2b over the sender and the unpadded serialised Content protobuf.  This is identical for
    -- every copy of a message because it is computed above the encryption layer: re-encrypting the
    -- same content for another recipient, or for our own other devices, changes the ciphertext and
    -- therefore the swarm hash, but not this.  It is also computable for existing rows, since the
    -- raw content is retained.
    content_hash BLOB NOT NULL,
    -- Swarm-assigned hash; NULL for an outgoing message not yet stored on the swarm.  SQLite
    -- treats NULLs as distinct in a unique index, so those never collide with each other.
    swarm_hash TEXT UNIQUE,
    sender INTEGER NOT NULL REFERENCES accounts(id),
    outgoing INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,         -- ms since epoch; the Content sigTimestamp
    body TEXT NOT NULL,
    -- Delivery state, for outgoing messages only; NULL for incoming.
    --   0 = queued locally, not yet dispatched
    --   1 = handed to the swarm, awaiting confirmation
    --   2 = accepted by a swarm node
    --   3 = terminal failure
    --   4 = in flight when the process exited, so the outcome is unknown
    send_state INTEGER
) STRICT;

-- Delivery is at-least-once, so a redelivered message must not duplicate.  Deduping on the content
-- hash rather than only the swarm hash also catches the case the swarm hash cannot: our own
-- message arriving back from our swarm, which the outgoing row was stored without a hash for.
CREATE UNIQUE INDEX messages_content ON messages(conversation, content_hash);

CREATE INDEX messages_history ON messages(conversation, timestamp DESC, id DESC);
CREATE INDEX messages_unread ON messages(conversation, timestamp) WHERE outgoing = 0;

-- Quotes and reactions arriving from other clients address their target by author and timestamp;
-- there is no message id on the wire.  Needed until a real identifier ships.
CREATE INDEX messages_wire_key ON messages(conversation, sender, timestamp);

-- The full decrypted Content protobuf, kept out of the messages table so that the history scan --
-- the hot query -- does not drag it through overflow pages.  Retained so fields this schema does
-- not yet model (attachments, quotes, reactions) can be recovered without re-fetching the swarm.
CREATE TABLE message_content (
    message INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    content BLOB NOT NULL
) STRICT;
