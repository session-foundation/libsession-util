
-- Table storing all the device group info
CREATE TABLE devices (
    id INTEGER PRIMARY KEY NOT NULL,
    unique_id device_id BLOB UNIQUE NOT NULL CHECK(length(id) == 32),

    state INTEGER NOT NULL CHECK(state == 0 OR state == 1 OR state == 2), -- registered, pending, unregistered
    changes INTEGER NOT NULL DEFAULT 0, -- 1 means there are unpushed local device info changes
    seqno INTEGER NOT NULL DEFAULT 1,
    timestamp INTEGER NOT NULL,
    device_type TEXT NOT NULL, -- typically a/i/d (Android/iOS/Desktop), but can be anything
    description TEXT NOT NULL, -- freeform device description
    version INTEGER NOT NULL, -- = 1000000*V + 1000*v + p for version "V.v.p"
    pubkey_mlkem768 BLOB NOT NULL CHECK(length(pubkey_mlkem768) == 1184),
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) == 32)
) STRICT;

-- This table holds any extra info not captured by the above.  The data is stored as key/value pairs
-- where the value is the bt-encoded data received in the last device info message.  The purpose of
-- this is so that future versions that add new fields can have those unknown fields propagated by
-- older clients that do not yet understand them without the older clients silently dropping unknown
-- fields.
CREATE TABLE device_unknown (
    device INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    bt_value BLOB NOT NULL,
    PRIMARY KEY(device, key)
) STRICT;

-- This table holds current and recent device private keys for *this* device, including the
-- timestamp then the device keypairs were created, and when they were rotated away from.
CREATE TABLE device_privkeys (
    id INTEGER PRIMARY KEY NOT NULL,
    created INTEGER NOT NULL, -- unix timestamp
    rotated INTEGER, -- timestamp when a newer key was added, superceding this key
    pushed INTEGER, -- timestamp when this key was verified as pushed to the device group
    seed BLOB NOT NULL CHECK(length(seed) == 32),
) STRICT;

-- This trigger handles key rotation: whenever we insert a new key, any existing keys are
-- automatically rotated with the `creation` timestamp of the new row as the rotation timestamp.
CREATE TRIGGER device_privkey_rotation AFTER INSERT ON device_privkeys
FOR EACH ROW WHEN NEW.rotated IS NULL
BEGIN
    UPDATE device_privkeys SET rotated = NEW.created WHERE rotated IS NULL;
END;

-- This table holds current and recent *account* keys, which are shared within the device
-- group and have their public keys published for remote users to use to encrypt messages.
-- Unlike device_privkeys, these keys are shared among all devices in the device group.
CREATE TABLE device_group_keys (
    id INTEGER PRIMARY KEY NOT NULL,
    created INTEGER NOT NULL,
    rotated INTEGER, -- timestamp when a new key superceded this key
    seed BLOB NOT NULL CHECK(length(seed) == 32),
    pubkey_mlkem768 BLOB NOT NULL CHECK(length(pubkey_mlkem768) == 1184),
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) == 32),
    -- Virtual column containing the first two mlkem pubkey values to assist with lookups based on
    -- incoming message key indicator:
    key_indicator BLOB GENERATED ALWAYS AS (substr(pubkey_mlkem768, 1, 2)) VIRTUAL
) STRICT;
CREATE INDEX device_group_keys_ki_index ON device_group_keys(key_indicator);
