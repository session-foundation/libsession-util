# Session message format v1

Session currently uses an overcomplicated Protobuf message encoding; since PFS+PQ encryption
requires a backwards-incompatible message encryption change already, this is the right time to also
moderately clean up that message format.

The new message format is described in ./protocol-v2.md, in the section "One-to-one Message
Encryption".

The existing format is as follows, from outermost (fully encoded and encrypted) to innermost (fully
decoded):

- Protobuf `WebSocketMessage` - this is a pointless wrapper.  It is always constructed with
  type=Type::REQUEST, and `request` set to a WebSocketRequestMessage.

- Protobuf `WebSocketRequestMessage` - this is another pointless wrapper.  It is always constructed
  with everything empty except `body`, and body contains a *serialized* Envelope.

- The bytes then decode to a protobuf `Envelope` value; this contains:
    - type=Type::SESSION_MESSAGE (also pointless: CLOSED_GROUP_MESSAGE is no longer used).
    - timestamp=...(value is sometimes used with v1 message, but will not be used in v2 messages)...
    - content=encrypted body (bytes)
    - proSig = 64-bytes

`proSig` here is a signature over the encrypted body, but cannot yet be verified until later in
message handling (once the pubkey is known, which is inside the decrypted plaintext payload), and so
is simply retained for later use.  This *may* be an actual valid Pro signature, or may be a dummy
value included to obscure whether the message actually includes a valid Pro signature or not.

The encrypted body is a libsodium "sealed box", which encrypts the value:

    plaintext = Msg || Padding || SenderEd || Sig

where Padding consists of an initial 0x80 byte followed by any number of 0x00 bytes (to obfuscate
message size from someone who observes the encrypted content; this is typically selected to make the
combined Msg || Padding value a multiple of 160 bytes).  SenderEd is the 32-byte Ed25519 (not
X25519) pubkey of the sender, which can be converted to X25519 to obtain the session_id (without the
leading 0x05 prefix byte).

Sig here is an Ed25519 signature of the value:

    Msg || Padding || SenderEd[32B] || RecipientX[32B]

where RecipientX is the target recipient X25519 pubkey (that is: 33-byte raw session ID, with the
leading 0x05 byte stripped off).  Note that RecipientX is implied and not actually included in the
message.

The Sig value is checked against the implied message, and if this signature failed, the message is
discarded as invalid.

If accepted, the Msg value (i.e. with padding removed) is then parsed as a protobuf Content.

Further details of message handling is not dealt with here.
