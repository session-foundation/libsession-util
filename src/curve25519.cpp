#include "session/crypto/ed25519.hpp"
#include "session/crypto/x25519.hpp"

#include <cstring>

#include "session/export.h"
#include "session/util.hpp"

// This file provides the C API wrappers for curve25519/x25519 operations.  The C++ functions
// these previously wrapped (session::curve25519::*) have been replaced by session::x25519::* and
// session::ed25519::*.

using namespace session;

LIBSESSION_C_API bool session_curve25519_key_pair(
        unsigned char* curve25519_pk_out, unsigned char* curve25519_sk_out) {
    try {
        auto [pk, sk] = x25519::keypair();
        std::memcpy(curve25519_pk_out, pk.data(), pk.size());
        std::memcpy(curve25519_sk_out, sk.data(), sk.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_to_curve25519_pubkey(
        const unsigned char* ed25519_pubkey, unsigned char* curve25519_pk_out) {
    try {
        auto xpk = ed25519::pk_to_x25519(to_byte_span<32>(ed25519_pubkey));
        std::memcpy(curve25519_pk_out, xpk.data(), xpk.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_to_curve25519_seckey(
        const unsigned char* ed25519_seckey, unsigned char* curve25519_sk_out) {
    try {
        auto xsk = ed25519::sk_to_x25519(to_byte_span<64>(ed25519_seckey));
        std::memcpy(curve25519_sk_out, xsk.data(), xsk.size());
        return true;
    } catch (...) {
        return false;
    }
}
