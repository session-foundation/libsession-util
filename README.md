# Session utility library

## Build

```
# Pre-requisites
apt install cmake build-essential git libssl-dev m4 pkg-config ninja-build

# Configure the build
#
# Options
#   - Enable APIs for creating onion-requests with (default: ON)
#
#     -D ENABLE_ONIONREQ=ON
#
#   - Enable SQLCipher database support (default: ON)
#
#     -D ENABLE_DATABASE=ON
#
#   - Enable testing of a Session Pro Backend by defining on the configure line (default: OFF)
#
#     -D TEST_PRO_BACKEND_WITH_DEV_SERVER=ON
#
#     These tests require the Session Pro Backend running in development mode
#     (SESH_PRO_BACKEND_DEV=1) to be running and tests the request and response flow of registering,
#     updating and revoking Session Pro from the development backend. You must also have a libcurl
#     available such that `find_package(CURL)` succeeds (e.g. a system installed libcurl) for this
#     to compile successfully.
#
#     These tests do not run by default, they can be invoked by passing the dev server URL in the
#     CLI arg --pro-backend-dev-server-url="<url>" when invoking the test suite.
#
cmake -G Ninja -S . -B Build

# Build
cmake --build Build --parallel --verbose

# Regenerate protobuf files
cmake --build Build --target regen-protobuf --parallel --verbose
```

## Docs

C Library: https://api.oxen.io/libsession-util-c/#/

C++ Library: https://api.oxen.io/libsession-util-cpp/#/
