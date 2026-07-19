#!/usr/bin/env bash
#
# Occasional big-endian sanity audit for libsession-util. NOT wired into CI — run it by hand now and
# then (especially after touching hashing or any wire/config serialization).
#
# Most of libsession runs only on little-endian hosts, so endian-sensitive byte serialization — the
# Pro signed-digest encoding, config data, protobuf packing — normally never exercises its big-endian
# path. This script builds and runs the test suite inside an emulated big-endian target (s390x) so
# those paths run for real.
#
# Cost: everything runs under qemu-user emulation, so the build is slow (tens of minutes) — the
# submodule-built networking stack (oxen-libquic / session-router) is the bulk of it. That's fine for
# an occasional manual audit; it is deliberately not in CI.
#
# Requires: Docker, plus a one-time host install of qemu-user-static + binfmt-support (see below).
# Run from the repo root with submodules checked out.
set -euo pipefail

# One-time host prerequisite (Debian/Ubuntu):
#     sudo apt install qemu-user-static binfmt-support
# That registers the binfmt_misc handlers with the "F" (fix-binary) flag, which is what lets Docker
# transparently run foreign-arch images under emulation from inside a container — no privileged helper
# container needed.
if [ ! -e /proc/sys/fs/binfmt_misc/qemu-s390x ]; then
    echo "s390x binfmt handler not registered; run: sudo apt install qemu-user-static binfmt-support" >&2
    exit 1
fi

# Build + test inside an emulated s390x Debian. BUILD_STATIC_DEPS=OFF pulls the heavy deps
# (libsodium, protobuf, curl, sqlite, zstd) as prebuilt s390x apt packages rather than compiling them
# from source under emulation.
docker run --platform=linux/s390x --rm -v "$PWD:/src" -w /src debian:sid bash -euxc '
    apt-get update
    apt-get install -y --no-install-recommends \
        g++ cmake ninja-build pkg-config git ca-certificates \
        libsodium-dev libprotobuf-dev protobuf-compiler libcurl4-openssl-dev \
        libsqlite3-dev libzstd-dev
    cmake -B build-bigendian -G Ninja -DBUILD_STATIC_DEPS=OFF -DCMAKE_BUILD_TYPE=Release
    cmake --build build-bigendian --target testAll
    # These tags exercise byte serialization on this big-endian host. Drop the filter for a full run.
    ./build-bigendian/tests/testAll "[endian],[hash],[pro_backend],[session_protocol],[config]"
'
echo "big-endian audit passed"
