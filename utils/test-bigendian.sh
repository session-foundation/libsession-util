#!/usr/bin/env bash
#
# Occasional big-endian sanity audit for libsession-util. NOT wired into CI — run it by hand now and
# then (especially after touching hashing or any wire/config serialization).
#
# Most of libsession runs only on little-endian hosts, so endian-sensitive byte serialization — the
# Pro signed-digest encoding (hash::detail::make_hashable's byte-swap branch), config data, protobuf
# packing — normally never exercises its big-endian path. This script builds and runs the test suite
# inside an emulated big-endian target (s390x) so those paths run for real. In particular it exercises
# the [endian] known-answer test (hash::blake2b_pers integer args must be little-endian) on an actual
# big-endian machine, where make_hashable takes its otherwise-never-compiled swap branch.
#
# Cost: everything runs under qemu-user emulation, so the build is slow (tens of minutes) — the
# submodule-built networking stack (oxen-libquic / session-router) is the bulk of it. That's fine for
# an occasional manual audit; it is deliberately not in CI.
#
# Requires: Docker able to run foreign-arch images via qemu-user/binfmt. Run from the repo root with
# submodules checked out.
set -euo pipefail

# Register qemu-user binfmt handlers for s390x (idempotent; needs --privileged once per boot).
docker run --privileged --rm tonistiigi/binfmt --install s390x

# Build + test inside an emulated s390x Debian. BUILD_STATIC_DEPS=OFF pulls the heavy deps
# (libsodium, protobuf, curl, sqlite, zstd) as prebuilt s390x apt packages rather than compiling them
# from source under emulation.
docker run --platform=linux/s390x --rm -v "$PWD:/src" -w /src s390x/debian:bookworm bash -euxc '
    apt-get update
    apt-get install -y --no-install-recommends \
        g++ cmake ninja-build pkg-config git ca-certificates \
        libsodium-dev libprotobuf-dev protobuf-compiler libcurl4-openssl-dev \
        libsqlite3-dev libzstd-dev
    cmake -B build-bigendian -G Ninja -DBUILD_STATIC_DEPS=OFF -DCMAKE_BUILD_TYPE=Release
    cmake --build build-bigendian --target testAll
    # [endian] is the make_hashable little-endian known-answer test; the Pro / protocol / config tags
    # also exercise serialization on this big-endian host. Drop the filter for a full run.
    ./build-bigendian/tests/testAll "[endian],[hash],[pro_backend],[session_protocol],[config]"
'
echo "big-endian audit passed"
