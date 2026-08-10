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
