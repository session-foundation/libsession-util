#!/bin/bash

set -e

if [ "$(basename $(pwd))" != "api" ]; then
    echo "Error: you must run this from the docs/api directory" >&2
    exit 1
fi

destdir="$1"
shift

if [ -d "$destdir" ]; then
    rm -rf "$destdir"
fi


./api-to-markdown.py --out="$destdir" "$@"
cd $destdir && mkdocs build && cd -
