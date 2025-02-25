#!/bin/bash

# The following npm packages must be installed 
# docsify-cli docsify-themeable docsify-katex@1.4.4 katex marked@4

# To customise the theme see:
# https://jhildenbiddle.github.io/docsify-themeable/#/customization

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

npx docsify init --local "$destdir"

rm -Rf "$destdir"/vendor/themes
rm -f "$destdir"/README.md

if [ -n "$NPM_PACKAGES" ]; then
    npm_dir="$NPM_PACKAGES/lib/node_modules"
elif [ -n "$NODE_PATH" ]; then
    npm_dir="$NODE_PATH"
elif [ -d "$HOME/node_modules" ]; then
    npm_dir="$HOME/node_modules"
elif [ -d "/usr/local/lib/node_modules" ]; then
    npm_dir="/usr/local/lib/node_modules"
else
    echo "Can't determine your node_modules path; set NPM_PACKAGES or NODE_PATH appropriately" >&2
    exit 1
fi

cp $npm_dir/docsify/lib/plugins/search.min.js "$destdir"/vendor
cp $npm_dir/prismjs/components/prism-{json,python,http}.min.js "$destdir"/vendor
cp $npm_dir/docsify-themeable/dist/css/theme-simple.css "$destdir"/vendor
cp $npm_dir/docsify-themeable/dist/css/theme-simple-dark.css "$destdir"/vendor
cp $npm_dir/docsify-themeable/dist/js/docsify-themeable.min.js "$destdir"/vendor
cp $npm_dir/marked/marked.min.js "$destdir"/vendor
cp $npm_dir/katex/dist/katex.min.js "$destdir"/vendor
cp $npm_dir/katex/dist/katex.min.css "$destdir"/vendor
cp -R $npm_dir/katex/dist/fonts "$destdir"/vendor
cp $npm_dir/docsify-katex/dist/docsify-katex.js "$destdir"/vendor

./api-to-markdown.py --out="$destdir" "$@"

perl -ni -e '
BEGIN { $first = 0; }
if (m{^\s*<script>\s*$} .. m{^\s*</script>\s*$}) {
    if (not $first) {
        $first = false;
        print qq{
  <script>
    window.\$docsify = {
      name: "Libsession Utils API",
      repo: "https://github.com/session-foundation/libsession-util",
      loadSidebar: "sidebar.md",
      subMaxLevel: 2,
      homepage: "index.md",
      themeable: {
        readyTransition : true, // default
        responsiveTables: true  // default
      }
    }
  </script>\n};
    }
} else {
    s{<title>.*</title>}{<title>Libsession Utils API</title>};
    s{(name="description" content=)"[^"]*"}{$1"libsession-util function documentation"};
    s{^\s*<link rel="stylesheet" href="vendor/themes/vue.css">\s*$}{};
    if (m{^\s*</body>}) {
        print qq{
  <link rel="stylesheet" href="vendor/katex.min.css" />
  <link rel="stylesheet" media="(prefers-color-scheme: light)" href="vendor/theme-simple.css">
  <link rel="stylesheet" media="(prefers-color-scheme: dark)" href="vendor/theme-simple-dark.css">
  <style>
    :root {
      --content-max-width : 1100px;
    }
  </style>
  <script src="vendor/search.min.js"></script>
  <script src="vendor/prism-json.min.js"></script>
  <script src="vendor/prism-python.min.js"></script>
  <script src="vendor/prism-http.min.js"></script>
  <script src="vendor/marked.min.js"></script>
  <script src="vendor/katex.min.js"></script>
  <script src="vendor/docsify-katex.js"></script>
  <script src="vendor/docsify-themeable.min.js"></script>\n};
    }
    print;
}' "$destdir"/index.html
