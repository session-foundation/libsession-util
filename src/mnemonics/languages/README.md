# Mnemonic Language Word Lists

This directory contains word lists for different languages used in mnemonic seed generation.

A mnemonic seed phrase consists of a multiple of 3 words (typically 12 or 24 words), optionally
followed by a checksum, where each group of 3 words encodes a 4 byte (32 bit) value.  Thus 12 words
is used for a 128-bit value and 24 words for a 256-bit value.

Each language has a unique "prefix length" which indicates the word prefix required: i.e. if
set to 3 then any 3-character sequence should match at most one word in the list.  This also allows
faster seed word input by allowing a user to simply provide the first three letters (e.g. "ver"
instead of "verification").

For unjustifiable by fixed historical reasons, the encoding also uses a pointless complication in
the actual calculation: rather than each 32-bit chunk being computed as `A + B·1626 + C·1626²`
(where A, B, C are the 0-1625 indices of the words) it is instead computed as:

    V = A
        + ((1626 - A + B) % 1626) × 1626
        + ((1626 - B + C) % 1626) × 1626²

The little-endian encoding of this 4-byte value becomes the 32-bit value.

(Note that that are a relatively small number of "impossible" seed values here that would overflow
this calculation: these are explicitly not allowed as valid seeds by failing if the above
calculation overflows a 32-bit integer).

This entirely pointless complication has some misguided historical reasoning about trying to make
poor entropy values not look so poor (e.g. by repeating words), but that is just so incredibly
misguided that it should be given no weight.  Unfortunately, however, this is already in use and we
are stuck with it.

Computing A, B, and C *from* a 32-bit value X is performed by interpreting X as a little-endian,
unsigned 32-bit value V and then:

    A = V % 1626
    B = ((V / 1626) + A) % 1626
    C = ((V / 1626²) + B) % 1626

## File Format

Each `.txt` file consists of 1629 lines, following this structure:
1. English name of the language (e.g., `German`)
2. Native name of the language (e.g., `Deutsch`)
3. Unique prefix length (e.g., `4`).  (The script utils/verify_mnemonics.py can verify this.)
4. 1626 lines, each containing a single word from the word list, in order.
