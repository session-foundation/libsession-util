#!/usr/bin/env bash
test "x$IGNORE" != "x" && exit 0
repo=$(readlink -e $(dirname $0)/../../)
clang-format-17 -i $(find $repo/src $repo/include $repo/tests | grep -E '\.[hc](pp)?$')
jsonnetfmt -i $repo/.drone.jsonnet
git --no-pager diff --exit-code --color || (echo -ne '\n\n\e[31;1mLint check failed; please run ./utils/format.sh\e[0m\n\n' ; exit 1)
