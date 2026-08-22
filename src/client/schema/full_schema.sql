-- The Client schema with every migration in this directory applied.  A database with none of
-- them applied is built from this in one step; the migrations are then recorded without being
-- run.  Keep this in step with the migrations: test_client.cpp compares the two.

-- Every account we have seen, whether or not it is a contact: a message sender needs a row, so
-- this is "accounts we know of".  Being a contact is a row in `contacts`, not a property here.
--
-- The profile fields are what an account says about itself, learned either from the LokiProfile on
-- an incoming message or from the Contacts config.  `profile_updated` decides between them: it is
-- the account's *own* stamp of when it last changed its profile, not ours of when we saw it, so a
-- message arriving out of order cannot replace a newer profile with an older one.  Out of order is
-- the normal case rather than the exception, since a profile is observed from group messages as
-- readily as from a DM.  A message carrying no stamp counts as 0, so it applies only when we have
-- never had one.
--
-- The same stamp is what keeps this from churning: every message from someone repeats the value
-- they last set, so the common case compares equal, changes nothing, and dirties no config.
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    -- 33 bytes.  The prefix says which kind of identity it is: 0x05 for an account, 0x15 or 0x25
    -- for a community-blinded one, which carries a profile of its own and so gets its own row.
    session_id BLOB NOT NULL UNIQUE,
    name TEXT,                          -- NULL when no name is known; never an empty string
    -- Set together, or both NULL: a URL without its key cannot be decrypted, so either one missing
    -- is no picture at all.
    profile_pic_url TEXT,
    profile_pic_key BLOB,               -- 32 bytes
    profile_updated INTEGER NOT NULL DEFAULT 0,  -- unix seconds
    -- Session Pro.  `pro_flags` is what the profile claims -- a badge, an animated avatar -- and
    -- the proof is what lets the claim be checked.  A NULL tag means we have never seen a proof,
    -- which is not the same as holding one that has expired.
    pro_flags INTEGER NOT NULL DEFAULT 0,
    -- Set together or both NULL, like the picture above: an expiry with no tag beside it cannot be
    -- checked against the revocation list, so neither half says anything on its own.
    pro_revocation_tag BLOB,            -- 32 bytes
    pro_expiry INTEGER                  -- unix seconds
) STRICT;

-- One row per entry in the Contacts config.  Existence here *is* being a contact, so there is no
-- flag that could disagree with itself, and a contact removed on another device becomes a row that
-- goes away -- while the `accounts` row stays, because we have still seen that person.
--
-- Only what needs a relationship to mean anything lives here.  A name and a picture belong to the
-- account, since we learn those for people who are not contacts at all.
CREATE TABLE contacts (
    account INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    nickname TEXT,                      -- our own name for them, synced to our other devices
    -- Approval in each direction: whether we have accepted messages from this account, and whether
    -- it has accepted ours.  This is what separates a conversation from a message request.
    approved INTEGER NOT NULL DEFAULT 0,
    approved_me INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0
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
    -- Time units differ by column here, deliberately and in step with what the configs carry: a
    -- value that gets compared against a message timestamp is in milliseconds, and everything else
    -- is unix seconds.  Nobody needs the sub-second moment a conversation was created.
    created INTEGER NOT NULL,           -- unix seconds
    last_activity INTEGER NOT NULL,     -- ms since epoch; conversation list ordering
    -- Read watermark: incoming messages with a strictly greater timestamp are unread.  A timestamp
    -- rather than a per-message flag because that is what ConvoInfoVolatile syncs.
    --
    -- Milliseconds, for the reason above: the other side of the comparison is `messages.timestamp`.
    -- At second resolution, reading a message stamped mid-second would force a choice between
    -- leaving that message unread and marking everything else in the same second read.
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
    -- The settings below are carried per-kind by the configs -- `contact_info` for a DM,
    -- `base_group_info` for a group or community -- but they mean the same thing in each, so they
    -- are one set of columns here rather than three.
    --
    -- Set by the user to make a conversation unread again after reading it.  Independent of
    -- unread_count, which counts messages: this survives having read all of them.
    marked_unread INTEGER NOT NULL DEFAULT 0,
    -- 0 default, 1 all, 2 disabled, 3 mentions only.  Mentions-only is a group notion; a DM
    -- carrying it reads as `all`.
    notifications INTEGER NOT NULL DEFAULT 0,
    mute_until INTEGER NOT NULL DEFAULT 0,  -- unix seconds; 0 is not muted
    -- Disappearing messages: 0 none, 1 after send, 2 after read.  The timer is meaningless when the
    -- mode is none, and is a duration rather than a moment, so seconds either way.
    exp_mode INTEGER NOT NULL DEFAULT 0,
    exp_timer INTEGER NOT NULL DEFAULT 0,   -- seconds
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
    sync_send_state INTEGER,
    -- Set once the message's content has been removed but the row has to stay:
    --   1 = deleted here only
    --   2 = deleted everywhere, either because we asked for that or because the sender did
    --
    -- A row rather than a DELETE because `swarm_hash` is what a redelivery dedupes against, and a
    -- message deleted only here is still on the swarm to be delivered again.  Removing the row
    -- would let it come back looking new -- which is not hypothetical: a storage server stops
    -- honouring a `last_hash` once it has expired, and the poll that follows returns the whole
    -- retention window.
    --
    -- Which of the two it is has to survive, not just that it happened: deleting for everyone is
    -- still offerable on a message already deleted here, and the two are different things to draw.
    -- The direction that completes the picture is `outgoing`, so there is no column for it.
    deleted INTEGER
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

    -- Where the file is, or came from: for an outgoing attachment the one we uploaded, for an
    -- incoming one where the user asked us to save the download (NULL until they do).
    --
    -- Informational rather than owning -- closer to a symlink than a handle.  The file at the far
    -- end belongs to the user in both directions: they chose it to attach, or they chose where to
    -- put it.  So it may be moved or deleted behind our back (only fatal while this row still needs
    -- uploading), and nothing here ever unlinks it.
    --
    -- A cache of our own -- attachments kept encrypted so they outlive the file server -- would be a
    -- third thing, at a path we picked, and wants its own column: that is what a
    -- delete-attachments-before instruction is entitled to remove, and sharing this column would
    -- leave it unable to tell our copy from the user's.
    --
    -- Such a cache cannot be freed by deleting files alongside the rows that name them, because the
    -- rows go by cascade when a conversation is deleted and no code of ours runs.  It wants the same
    -- treatment as everything else here: compare and converge.  List the cached paths still
    -- referenced, list the cache directory, unlink the difference.  That survives a cascade, and
    -- also collects what a crash mid-download left behind -- which collecting paths before a delete
    -- never would.  It needs a directory we own outright, since "anything not in the list" is only
    -- safe there, and it must not eat a download in flight: either the row exists before the
    -- transfer starts, or the sweep skips the in-progress suffix.
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

    -- ms since epoch: when the *recipient* of this message last saved this attachment.  On an
    -- incoming attachment that is us, writing it to disk; on an outgoing one it is the other party,
    -- telling us they saved it.  One meaning in both directions -- "the recipient saved this, then".
    --
    -- Not a path: where a file went is the application's business, and one recorded here would be
    -- wrong as soon as it moved the file.  This answers the question an application actually has,
    -- which is whether offering "save" again is pointless.
    --
    -- NULL means "not known to have been saved", never "not saved": the outgoing case depends on
    -- the other end volunteering a DataExtractionNotification, which many clients do not.
    saved_at INTEGER,

    PRIMARY KEY (message, idx)
) STRICT;
