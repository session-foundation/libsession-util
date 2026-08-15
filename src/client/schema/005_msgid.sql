-- Messages gain an identifier, and lose the content hash that was standing in for one.
--
-- The hash could never have been that identifier.  A one-to-one message is stored on both
-- participants' swarms, and the two copies do not have the same bytes: the one we keep for our own
-- devices carries `syncTarget`, naming who the message was for, and that field is inside the
-- Content protobuf, which is what the hash was taken over.  So the sender and the recipient know
-- the same message by different hashes, and neither can derive the other's -- protobuf has no
-- canonical serialisation, so "parse it, drop the field, serialise it again" is not guaranteed to
-- reproduce another implementation's bytes.  The column's own comment claimed the opposite, that
-- the hash was "identical for every copy of a message"; that is true of encryption and false of
-- syncTarget.
--
-- The wire now carries `Content.msgId`: 8 random bytes set before the copies diverge, so every copy
-- of a message has the same one.  A message is identified by (conversation, timestamp, msgId) --
-- always both, never msgId alone, which is sized only to separate messages within one
-- sender-millisecond.  See the field's comment in SessionProtos.proto.
--
-- That also replaces what the hash was doing here, which was dedupe, and does it better: it is the
-- same on both copies, so our own message returning from our swarm is recognised directly rather
-- than by the two copies happening to hash alike -- which, per the above, they did not.
--
-- What is lost in the meantime: a message from a client that sets no msgId has NULL here, and
-- SQLite treats NULLs as distinct in a unique index, so two such messages never dedupe against each
-- other.  Plain redelivery is still caught by the unique swarm hash; what is not is a sender who
-- retried a store that had actually succeeded, which will show twice.  Keeping the content hash
-- purely for that was judged not worth a column: it is a visible duplicate rather than a lost
-- message, it only affects clients that have not adopted msgId, and those clients drop
-- same-millisecond messages themselves -- so a workaround here buys correctness their own other
-- devices and other recipients will not share.
--
-- messages is rebuilt rather than altered because content_hash is NOT NULL and SQLite cannot drop
-- that.  Safe inside the migration's transaction with foreign keys on: nothing references messages
-- except message_raw_content and message_attachments, whose rows are preserved by keeping the same
-- ids.

CREATE TABLE messages_new (
    id INTEGER PRIMARY KEY,
    conversation INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    -- The sender's Content.msgId.  NULL for a message whose sender did not set one.  Only ever
    -- meaningful alongside `timestamp`; see SessionProtos.proto.
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
    send_state INTEGER,
    sync_send_state INTEGER
) STRICT;

INSERT INTO messages_new
    (id, conversation, swarm_hash, sender, outgoing, timestamp, body, send_state, sync_send_state)
SELECT id, conversation, swarm_hash, sender, outgoing, timestamp, body, send_state, sync_send_state
FROM messages;

DROP TABLE messages;

ALTER TABLE messages_new RENAME TO messages;

-- Delivery is at-least-once, so a redelivered message must not duplicate.  Both columns are needed:
-- see the protobuf comment for why msgid is not an identifier on its own.
CREATE UNIQUE INDEX messages_msgid ON messages(conversation, timestamp, msgid);

CREATE INDEX messages_history ON messages(conversation, timestamp DESC, id DESC);
CREATE INDEX messages_unread ON messages(conversation, timestamp) WHERE outgoing = 0;

-- Quotes and reactions from clients that set no msgId address their target by author and timestamp
-- alone.  Needed for as long as such clients exist.
CREATE INDEX messages_wire_key ON messages(conversation, sender, timestamp);

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
