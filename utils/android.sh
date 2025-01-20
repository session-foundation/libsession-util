#!/bin/bash

set -e

if ! [ -f LICENSE ] || ! [ -d include/session ]; then
    echo "You need to run this as ./utils/android.sh from the top-level libsession-util project directory"
    exit 1
fi

if [ -z "$NDK" ]; then
    echo "NDK environment variable needs to be set to the Android NDK path" >&2
    exit 1
fi

archive="${1:-libsession-util-android-TAG.tar.xz}"

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

abis=(armeabi-v7a arm64-v8a x86_64 x86)
for abi in "${abis[@]}"; do
    build="build-android/$abi"
    echo "Building android $abi in $build"

    ./utils/static-bundle.sh "$build" "" \
        -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI=$abi \
        -DANDROID_ARM_MODE=arm \
        -DANDROID_PLATFORM=android-23 \
        -DANDROID_STL=c++_static
done

cd build-android

pkg="${archive%%.tar.xz}"

mkdir -p "$pkg"/include
cp -rv ../include/session "$pkg"/include/

for abi in "${abis[@]}"; do
    mkdir -p "$pkg"/lib/$abi
    cp -v $abi/libsession-util.a "$pkg"/lib/$abi
done

tar cvJf "$archive" "$pkg"

echo "Packaged everything up at build-android/$archive"
