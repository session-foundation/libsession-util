#!/bin/bash

set -e

if ! [ -f LICENSE ] || ! [ -d include/session ]; then
    echo "You need to run this as ./utils/macos.sh from the top-level libsession-util project directory"
    exit 1
fi

if ! command -v xcodebuild; then
    echo "xcodebuild not found; are you on macOS with Xcode and Xcode command-line tools installed?" >&2
    exit 1
fi

archive="${1:-libsession-util-macos-TAG.tar.xz}"

if [[ "$archive" =~ TAG ]]; then
    if [ -n "$DRONE_TAG" ]; then
        tag="$DRONE_TAG"
    elif [ -n "$DRONE_COMMIT" ]; then
        tag="$(date --date=@$DRONE_BUILD_CREATED +%Y%m%dT%H%M%SZ)-${DRONE_COMMIT:0:9}"
    else
        tag="$(date +%Y%m%dT%H%M%SZ)-$(git rev-parse --short=9 HEAD)"
    fi

    archive="${archive/TAG/$tag}"
fi


set -x

for i in arm64 x86_64; do
    build="build-macos/$i"

    if [ "$(uname -m)" == "$i" ]; then
        echo "Building for macos ($i) in $build"
        ./utils/static-bundle.sh "$build" ""
    else
        echo "Cross-compiling for macos ($i) in $build"
        # The args here are a bit weird:
        # - CMAKE_SYSTEM_NAME is needed for make cmake realize it is cross-compiling (even though
        #   it's setting it to the default value).  See cmake issue #21885.
        # - CMAKE_OSX_ARCHITECTURES tells cmake what to build for but it doesn't set the above
        #   because, well, yeah it does.  See CMake issue #21885 again.
        # - The "16" in ARCH_TRIPLET (which we need to cross-compile static deps) corresponds to
        #   macOS 10.12, but of course Apple doesn't publish that anywhere because you should be
        #   using swift and the app store.
        ./utils/static-bundle.sh "$build" "" \
            -DCMAKE_SYSTEM_NAME=Darwin \
            -DARCH_TRIPLET="$i-apple-darwin16" \
            -DCMAKE_OSX_ARCHITECTURES=$i \
            -DLOCAL_MIRROR=https://oxen.rocks/deps
    fi
done

pkg="${archive%%.tar.xz}"
pkg_dir="build-macos/$pkg"

mkdir -p "$pkg_dir"/{lib,include}

# Combine arch builds a multi-arch lib
lipo -create build-macos/{arm64,x86_64}/libsession-util.a -output "$pkg_dir"/lib/libsession-util.a

# Copy the headers over
cp -rv include/session "$pkg_dir/include"

(cd build-macos && tar cvJf "$archive" "$pkg")

echo "Packaged everything up at build-macos/$archive"
