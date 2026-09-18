-- Everything the attachment-availability work needs of the schema, as one step.
--
-- It arrived over several commits and each carried its own migration while the branch was being
-- built; they are collapsed here because a migration is a permanent, numbered, ordered artifact and
-- the intermediate states never shipped.  The commits themselves still show the steps.

-- The cache is rebuilt rather than altered, for two reasons that arrived together.
--
-- Its filenames are keyed now (see `cache::name_for`), so every name derived under the old unkeyed
-- scheme names a file nothing will ever look for again: a lookup computes the new name, misses, and
-- downloads afresh, while the row goes on counting towards the cache limit and evicting live
-- entries to make room for a file that can no longer be found.
--
-- And `name` stops being the key.  An attachment now references its cached copy (see `cached`
-- below), and what it stores should be an integer rather than a second copy of the name -- which
-- also leaves the name free to change shape again later without the references to it meaning
-- anything different.  A surrogate cannot be added to an existing table without rebuilding it
-- anyway.
--
-- Dropping the rows leaves their files on disk referenced by nothing, which is precisely what the
-- reconcile sweep collects, so the next one unlinks them without being told to.  A cache is the one
-- thing that costs nothing to lose: everything in it can be fetched again.
--
-- Display pictures need no equivalent.  They have no rows, and the sweep already keeps only what
-- some `accounts.profile_pic_url` still hashes to -- which, under the new key, is none of the old
-- ones.
DROP TABLE attachment_cache;

CREATE TABLE attachment_cache (
    id INTEGER PRIMARY KEY,
    -- The file on disk: a keyed hash of the url, deliberately not the url itself, so that someone
    -- reading the cache directory cannot tell which files this account has fetched.
    --
    -- Nothing reads this to *find* an entry -- that is what the reference from message_attachments
    -- is for -- so the hash is only ever applied to a file being written, and changing it costs
    -- nothing already downloaded.
    name TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    last_used INTEGER NOT NULL      -- ms since epoch
) STRICT;

CREATE INDEX attachment_cache_lru ON attachment_cache(last_used);

-- What the last attempt to fetch this file found, when what it found was that it could not be
-- fetched: the file server answered that it does not hold it -- which is also how an expired upload
-- answers -- or the bytes arrived and failed to authenticate.
--
-- A cached answer rather than a fact about the url, which is the distinction that decides its
-- lifetime.  An attachment url is a hash of the encrypted body, and the encryption is
-- deterministic, so the same file sent again by the same account lands at the *same* url.  That is
-- the repair path: the recipient is told the file could not be fetched, asks for it again, and the
-- sender's re-upload puts those bytes back where they were.  A flag that never cleared would block
-- exactly the action that fixes the problem.
--
-- So it is set across every row naming a url when a fetch of it fails, and cleared across every row
-- naming that url when a new attachment row quoting it arrives -- a resend being the only evidence
-- available that the server holds it again.  Cleared for the old rows too, not just the new one: it
-- is the same file, and a transcript showing one message's copy as broken and another's as fine
-- would be showing the same bytes two ways.
--
-- The value is *why*, not merely that: the file server's status for a server answer -- 404 for an
-- upload it does not hold, expired or otherwise -- and `ATTACHMENT_UNREADABLE` for bytes that
-- arrived and could not be turned back into the file they claimed to be.  A display says different
-- things to the user about those, and "ask them to send it again" is only right for the first.
--
-- NULL means only that nothing has proved otherwise: an attachment nobody has tried to fetch is
-- indistinguishable from one that will succeed.
ALTER TABLE message_attachments ADD COLUMN unavailable INTEGER;

-- The local copy of this file, or NULL for no local copy -- which is also what eviction leaves
-- behind: ON DELETE SET NULL clears this as the cache row goes.  That is what makes "this row says
-- cached" and "that file has an entry" impossible to disagree in the direction that matters, since
-- the only way to be marked is to reference a living row.
--
-- Stored rather than derived from `url`, which is the whole point of the rebuild above: the cached
-- file is *named* by a keyed hash of the url, so deriving it would make that hash load-bearing for
-- everything already downloaded rather than only for what is being written.
--
-- The other direction of disagreement -- a row naming a file something outside us deleted -- is
-- still possible, and is what the reconcile sweep is for.
ALTER TABLE message_attachments
    ADD COLUMN cached INTEGER REFERENCES attachment_cache(id) ON DELETE SET NULL;

-- Which messages show a given file.  Every question the attachment cache asks of this table is
-- that one -- marking a file unfetchable, clearing it again on a resend, reporting a transfer
-- starting, finishing or being evicted -- and more than one message routinely quotes the same file,
-- because an attachment url is a hash of the encrypted body: the same file sent twice by the same
-- account lands at the same url.  Without this, each of those answers scans the whole table to
-- touch a handful of rows.
--
-- Partial because a row with no url has nothing to fetch and is never the subject of any of them:
-- an outgoing attachment before its upload finishes, which on a sending-heavy account is a large
-- share of the table.
CREATE INDEX message_attachments_url ON message_attachments(url) WHERE url IS NOT NULL;

-- Which messages show a file that is being evicted, which is the question a keyed hash cannot
-- answer: it does not run backwards, so without this the only route from a cached file to the
-- messages drawing it is to hash every url in the table.
--
-- Partial for the same reason as above: most rows are not cached at any given moment, and those are
-- never the subject of this question.
CREATE INDEX message_attachments_cached ON message_attachments(cached) WHERE cached IS NOT NULL;
