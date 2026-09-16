-- The serialised state of each config object, so a config survives a restart without being rebuilt
-- from its swarm.  A dump holds the merged config together with the bookkeeping a merge needs --
-- which message hashes currently represent it, and which ones it obsoletes -- so restoring one is
-- what lets this device rejoin an ongoing exchange with its other devices rather than starting from
-- whatever the swarm happens to still hold.
--
-- Keyed by the config's encryption domain rather than its storage namespace.  The two coincide for
-- most configs but answer different questions: the domain says *which config this is*, while the
-- namespace says *where it is pushed*, which the Local config has no answer for -- it is never
-- pushed anywhere, and reports UserProfile's namespace as a stand-in.  The domain is also already
-- required to be unique per config type, and can never be changed, since changing it would break
-- decryption of everything previously written under it.
--
-- pubkey is whose config it is: this account's, or a particular group's.  Configs for different
-- pubkeys are stored, pushed and fetched separately even when their swarms coincide.
CREATE TABLE config_dumps (
    pubkey BLOB NOT NULL CHECK(length(pubkey) = 33),
    type TEXT NOT NULL,     -- ConfigBase::encryption_domain(): "UserProfile", "Contacts", ...
    data BLOB NOT NULL,
    PRIMARY KEY (pubkey, type)
) STRICT;
