#!/usr/bin/env python3

import sys
import os
import shutil
import re
import fileinput
from enum import Enum, auto
import json
import argparse
import requests

parser = argparse.ArgumentParser()
parser.add_argument(
    "-L",
    "--markdown-level",
    type=int,
    choices=[1, 2, 3, 4],
    default=2,
    help="Specify a heading level for the top-level endpoints; the default is 2, which means "
    "endpoints start in a `## name` section. For example, 3 would start endpoints with `### name` "
    "instead.",
)
parser.add_argument("--out", "-o", metavar='DIR', default="api", help="Output directory for generated endpoints")
parser.add_argument("--disable-no-args", action='store_true', help="disable NO_ARGS enforcement of `Inputs: none`")
parser.add_argument("--no-sort", "-S", action='store_true', help="disable sorting endpoints by name (use file order)")
parser.add_argument("--no-group", "-G", action='store_true', help="disable grouping endpoints by category")
parser.add_argument("--no-emdash", "-M", action='store_true', help="disable converting ' -- ' to ' — ' (em-dashes)")
parser.add_argument("filename", nargs="+")
args = parser.parse_args()

for f in args.filename:
    if not os.path.exists(f):
        parser.error(f"{f} does not exist!")


# We parse the file looking for `///` comment blocks beginning with "API: <cat>/<name>".
#
# <name> is the API endpoint name to use in the documentation (alternative names can be specified
# using "Old names:"; see below).
#
# <cat> is the category for grouping endpoints together.
#
# Following comment lines are then a Markdown long description, until we find one or more of:
#
# "Inputs: none."
# "Outputs: none."
# "Member variable."
# "Constant." (auto-detected for simple const/constexpr values).
# "Inputs:" followed by markdown (typically an unordered list) until the next match from this list.
# "Outputs:" followed by markdown
# "Old names: a, b, c"
#
# subject to the following rules:
# - each section must have exactly one Input; if the type inherits NO_ARGS then it *must* be an
#   "Inputs: none".
# - each section must have exactly one Output
# - Old names is permitted only once, if it occurs at all; the given names will be indicated as
#   deprecated, old names for the endpoint.
#
# Immediately following the command we expect to find a not-only-comment line (e.g. `struct
# <whatever>`) and apply some checks to this:
# - if the line contains the word `NO_ARGS` then we double-check that "Inputs: none" was also given
#   and error if a more complex Inputs: section was written.


hdr = '#' * args.markdown_level
MD_INPUT_HEADER = f"{hdr}# Parameters"
MD_OUTPUT_HEADER = f"{hdr}# Returns"

MD_DECL_HEADER = f"{hdr}# Declaration"

MD_NO_INPUT = "This endpoint takes no inputs."

API_COMMENT = re.compile(r"^\s*/// ?")
API_START = re.compile(r"^API:\s*(\w+)/(\w+.*?)\s*$")
IN_NONE = re.compile(r"^Inputs?: *[nN]one\.?$")
IN_SOME = re.compile(r"^Inputs?:\s*$")
MEMBER_VAR = re.compile(r"^Member +[vV]ar(?:iable)?\.?$")
CONSTANT = re.compile(r"^Constant\.?$")
DECL_SOME = re.compile(r"^Declaration?:\s*$")
OUT_SOME = re.compile(r"^Outputs?:\s*$")
OLD_NAMES = re.compile(r"[Oo]ld [nN]ames?:")
PLAIN_NAME = re.compile(r"\w+")
NO_ARGS = re.compile(r"\bNO_ARGS\b")

CONSTANT_DECLARATION = re.compile(r"^\s*(?:static )?const(?:expr)? (?:\w+(::\w+)* )+= ")

input = fileinput.input(args.filename)
api_name = None


def error(msg):
    print(
        f"\x1b[31;1mERROR\x1b[0m[{input.filename()}:{input.filelineno()}] "
        f"while parsing endpoint {api_name}:",
        file=sys.stderr,
    )
    if msg and isinstance(msg, list):
        for m in msg:
            print(f"    - {m}", file=sys.stderr)
    else:
        print(f"    {msg}", file=sys.stderr)
    sys.exit(1)


class Parsing(Enum):
    DESC = auto()
    INPUTS = auto()
    DECL = auto()
    OUTPUTS = auto()
    NONE = auto()


cur_file = None

endpoints = {}

while True:
    line = input.readline()
    if not line:
        break

    cur_file = input.filename()

    line, removed_comment = re.subn(API_COMMENT, "", line, count=1)
    if not removed_comment:
        continue

    m = re.search(API_START, line)
    if not m:
        continue

    cat, api_name = m[1], m[2]
    if args.no_group:
        cat = ''
    description, decl, inputs, outputs = "", "", "", ""
    done_desc = False
    no_inputs = False
    member_var = False
    constant = False
    old_names = []

    mode = Parsing.DESC

    while True:
        line = input.readline()
        line, removed_comment = re.subn(API_COMMENT, "", line, count=1)
        if not removed_comment:
            if not decl:
                decl_lines = []
                decl_prefix = 1000
                while line and line.lstrip(' ')[0:2] not in ('//', '/*'):
                    decl_lines.append(line.rstrip())
                    indent = len(line) - len(line.lstrip(' '))
                    if indent < decl_prefix:
                        decl_prefix = indent
                    if ';' in line or '{' in line:
                        break

                    line = input.readline()

                if decl_lines:
                    if re.search(CONSTANT_DECLARATION, decl_lines[0]):
                        constant = True

                    if decl_prefix > 0:
                        decl_lines = [x[decl_prefix:] for x in decl_lines]
                    decl = '```cpp\n' + '\n'.join(decl_lines) + '\n```'

            break

        if re.search(IN_NONE, line):
            if inputs:
                error("found multiple Inputs:")
            inputs, no_inputs, mode = MD_NO_INPUT, True, Parsing.NONE

        elif re.search(MEMBER_VAR, line):
            member_var, no_inputs, mode = True, True, Parsing.DESC

        elif re.search(CONSTANT, line):
            constant, in_inputs, mode = True, True, Parsing.DESC

        elif re.search(DECL_SOME, line):
            if inputs:
                error("found multiple Syntax:")
            mode = Parsing.DECL

        elif re.search(IN_SOME, line):
            if inputs:
                error("found multiple Inputs:")
            mode = Parsing.INPUTS

        elif re.search(OUT_SOME, line):
            if outputs:
                error("found multiple Outputs:")
            mode = Parsing.OUTPUTS

        elif re.search(OLD_NAMES, line):
            old_names = [x.strip() for x in line.split(':', 1)[1].split(',')]
            if not old_names or not all(re.fullmatch(PLAIN_NAME, n) for n in old_names):
                error(f"found unparseable old names line: {line}")

        elif mode == Parsing.NONE:
            if line and not line.isspace():
                error(f"Found unexpected content while looking for a tag: '{line}'")

        elif mode == Parsing.DESC:
            description += line

        elif mode == Parsing.DECL:
            decl += line

        elif mode == Parsing.INPUTS:
            inputs += line

        elif mode == Parsing.OUTPUTS:
            outputs += line

    problems = []
    # We hit the end of the commented section
    if not description or inputs.isspace():
        problems.append("endpoint has no description")
    if (not inputs or inputs.isspace()) and not member_var and not constant:
        problems.append(
                "endpoint has no inputs description; perhaps you need to add "
                "'Inputs: none.', 'Member variable.', or 'Constant.'?"
        )

    if old_names:
        s = 's' if len(old_names) > 1 else ''
        description += f"\n\n> _For backwards compatibility this endpoint is also accessible via the following deprecated endpoint name{s}:_"
        for n in old_names:
            description += f"\n> - _`{n}`_"

    if not args.disable_no_args:
        if re.search(NO_ARGS, line) and not no_inputs:
            problems.append("found NO_ARGS, but 'Inputs: none' was specified in description")

    if problems:
        error(problems)

    md = f"""
{hdr} `{api_name}`

{description}

{MD_DECL_HEADER}

{decl}
"""
    if not member_var and not constant:
        md = md + f"""
{MD_INPUT_HEADER}

{inputs}

{MD_OUTPUT_HEADER}

{outputs}
"""

    if not args.no_emdash:
        md = md.replace(" -- ", " — ")

    if cat in endpoints:
        endpoints[cat].append((api_name, md))
    else:
        endpoints[cat] = [(api_name, md)]

if not endpoints:
    error(f"Found no parseable endpoint descriptions in {cur_file}")

if not args.no_sort:
    for v in endpoints.values():
        v.sort(key=lambda x: x[0])

output_path = os.path.dirname(os.path.realpath(__file__)) +  f'/{args.out}'
os.makedirs(output_path, exist_ok=True)

# copy the mkdocs.yml file to the root of the output directory
shutil.copyfile('mkdocs.yml', f"{output_path}/mkdocs.yml")
print(f"Copied mkdocs.yml => {output_path}/mkdocs.yml")

STATIC_FOLDER = 'docs'
static_path = os.path.dirname(os.path.realpath(__file__)) + f'/{STATIC_FOLDER}'

# copy the static folder over to the output directory
shutil.copytree(static_path, f"{output_path}/{STATIC_FOLDER}")

preamble_prefix = static_path + '/preamble-'

for cat, eps in endpoints.items():
    out = f"{output_path}/{STATIC_FOLDER}/{cat}.md"
    with open(out, "w") as f:
        preamble = f"{preamble_prefix}{cat}.md"
        if os.path.isfile(preamble):
            with open(preamble, "r") as fp:
                for line in fp:
                    f.write(line)
            f.write("\n\n")
        else:
            print(f"Warning: {preamble} doesn't exist, writing generic preamble for {cat}", file=sys.stderr)
            f.write(f"# {cat.replace('_', ' ').title()}\n\n")

        for _, md in eps:
            f.write(md)
    print(f"Wrote {out}")
