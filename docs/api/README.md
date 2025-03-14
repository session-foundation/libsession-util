# Libsession Utils Documentation Websites

# Getting Started

## Install dependencies

```sh
pip install -r requirements.txt
```

## Building

Building happens in the `dist` directory.

```sh
# Build libsession-util C API functions
make build-h

# Build libsession-util C++  API functions
make build-cpp

# Build both C and C++ API functions
make build-all
```

## Hosting

```sh
# Serve libsession-util C API functions on localhost:8000
make serve-c

# Serve libsession-util C++ API functions on localhost:8001
make serve-cpp
```

## Developing

> [!WARNING]
>  Any changes to `dist` directory will be hot-reloaded but are not tracked by git.

```sh
# Serve libsession-util C API functions on localhost:8000
make dev-c

# Serve libsession-util C++ API functions on localhost:8000
make dev-cpp
```

# Resources

- [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)
- [MkDocs](https://www.mkdocs.org/)
