#!/usr/bin/env python3

# MIT License
#
# Copyright (C) 2025 Brad House
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice (including the next
# paragraph) shall be included in all copies or substantial portions of the
# Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

import string
import sys
import urllib.request

def is_hex(s: str) -> bool:
    return all(c in string.hexdigits for c in s)

if len(sys.argv) != 6:
    print(f"Usage: {sys.argv[0]} url headers datatype varname casefold.c")
    print(f"Example: {sys.argv[0]} https://www.unicode.org/Public/17.0.0/ucd/CaseFolding.txt ares_casefold.h ares_casefold_data_t ares_casefold_data ares_casefold.c")
    sys.exit(1)

url = sys.argv[1]
headers = sys.argv[2].split(",")
datatype = sys.argv[3]
varname = sys.argv[4]
outfile = sys.argv[5]

try:
    with urllib.request.urlopen(url) as response:
        data = response.read()
        casefold = data.decode('utf-8')
except Exception as e:
    print(f"An unexpected error occurred: {e}")
    sys.exit(1)

codepoints = []

# Lines look like this:
#  0041; C; 0061; # LATIN CAPITAL LETTER A
lines = casefold.splitlines()
for line in lines:
    if line.startswith('#') or len(line) == 0:
        continue

    sects = line.split(";")
    if len(sects) != 4:
        print(f"Expected 4 sections delimited by ';' on line: {line}")
        sys.exit(1)

    # Usage:
    #  A. To do a simple case folding, use the mappings with status C + S.
    #  B. To do a full case folding, use the mappings with status C + F.
    type = sects[1].strip()
    if type not in [ "C", "S" ]:
        continue

    # Don't use strip() as there may be spaces inside as delimiters.
    code = sects[0].replace(" ", "")
    mapping = sects[2].replace(" ", "")
    if not is_hex(code) or not is_hex(mapping):
        print(f"code or mapping not hex formatted: {line}")
        sys.exit(1)

    codepoints.append((int(code, 16), int(mapping, 16)))

if len(codepoints) == 0:
    print(f"Invalid file format, no codepoints parsed")
    sys.exit(1)

# Make sure codepoints are sorted since we want this to be binary searchable
codepoints.sort()

try:
    with open(outfile, 'w') as file:
        file.write(f"/* Generated via {sys.argv[0]} {url} {','.join(headers)} {datatype} {varname} {outfile} */\n")
        for header in headers:
            file.write(f'#include "{header}"\n')
        file.write("\n")
        file.write(f"size_t {varname}_len = {len(codepoints)};\n")
        file.write(f"{datatype} {varname}[] = {{\n")
        for entry in codepoints:
            file.write(f"  {{ {hex(entry[0])}, {hex(entry[1])} }},\n")
        file.write(f"}};\n")

except Exception as e:
    print(f"An unexpected error occurred: {e}")
    sys.exit(1)

print(f"wrote {outfile}")
sys.exit(0)
