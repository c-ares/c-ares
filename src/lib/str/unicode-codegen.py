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
    print(f"Example: {sys.argv[0]} https://www.unicode.org/Public/17.0.0/idna/IdnaMappingTable.txt ares_idnamap.h ares_idnamap_data_t ares_idnamap_data ares_idnamap.c")
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
# FA6E..FA6F    ; disallowed                 # NA   <reserved-FA6E>..<reserved-FA6F>
# FD40..FD4F    ; valid      ;      ; NV8    # 14.0 ARABIC LIGATURE RAHIMAHU ALLAAH..ARABIC LIGATURE RAHIMAHUM ALLAAH
# FD92          ; mapped     ; 0645 062C 062E #1.1  ARABIC LIGATURE MEEM WITH JEEM WITH KHAH INITIAL FORM

lines = casefold.splitlines()
for line in lines:
    if line.startswith('#') or len(line) == 0:
        continue

    # Strip off any comments
    line = line.split("#")[0];

    sects = line.split(";")
    if len(sects) < 2 or len(sects) > 4:
        print(f"Expected 2 - 4 sections delimited by ';' on line: {line}")
        sys.exit(1)

    # Map. For each code point in the domain_name string, look up the Status
    #      value in Section 5, IDNA Mapping Table, and take the following
    #      actions:
    #    * disallowed: Leave the code point unchanged in the string. Note: The
    #      Convert/Validate step below checks for disallowed characters, after
    #      mapping and normalization.
    #    * ignored: Remove the code point from the string. This is equivalent to
    #      mapping the code point to an empty string.
    #    * mapped: If Transitional_Processing (deprecated) and the code point is
    #      U+1E9E capital sharp s (ẞ), then replace the code point in the string
    #      by “ss”. Otherwise: Replace the code point in the string by the value
    #      for the mapping in Section 5, IDNA Mapping Table.
    #    * deviation: If Transitional_Processing (deprecated), replace the code
    #      point in the string by the value for the mapping in Section 5, IDNA
    #      Mapping Table. Otherwise, leave the code point unchanged in the
    #      string.
    #    * valid: Leave the code point unchanged in the string.
    status = sects[1].strip()
    if status not in [ "disallowed", "ignored", "mapped", "deviation", "valid" ]:
        print(f"unrecognized status {status} in line: {line}")
        sys.exit(1)

    code = sects[0].strip().replace("..","-").split("-")

    if len(sects) >= 3 and len(sects[2].strip()) > 0:
        mapping = sects[2].strip().split(" ")
    else:
        mapping = []

    if len(code) > 2:
        print(f"Too many codes: {line}")
        sys.exit(1)

    # Code can be a range of codes
    int_code = []
    for entry in code:
        if not is_hex(entry):
            print(f"code {entry} not hex formatted: {line}")
            sys.exit(1)
        int_code.append(int(entry, 16))

    # A single code may map to multiple codepoints in its final representation
    int_mapping = []
    for entry in mapping:
        if not is_hex(entry):
            print(f"mapping {entry} not hex formatted: {line}")
            sys.exit(1)
        int_mapping.append(int(entry, 16))

    # IDNA2008 Status There are two values: NV8 and XV8. NV8 is only present if
    # the Status is valid but the character is excluded by IDNA2008 from all
    # domain names for all versions of Unicode. XV8 is present when the
    # character is excluded by IDNA2008 for the current version of Unicode.
    # These are not normative values.

    idna2008_status=""
    if status == "valid" and len(sects) == 4:
        idna2008_status = sects[3]

    if status == "valid" and idna2008_status in [ "NV8", "XV8" ]:
        status = "disallowed"

    # We are not supporting transitional processing.
    if status == "deviation":
        status = "valid"

    # Lets assume if its not in the output table its valid.
    if status == "valid":
        continue

    # Map status to a numeric value
    if status == "disallowed":
        status = 1
    elif status == "ignored":
        status = 2
    elif status == "mapped":
        status = 3

    codepoints.append(
        {
            "code_min": int_code[0],
            "code_max": int_code[1] if len(code) > 1 else int_code[0],
            "status": status,
            "mapping":  int_mapping,
        }
    )

if len(codepoints) == 0:
    print(f"Invalid file format, no codepoints parsed")
    sys.exit(1)

# Make sure codepoints are sorted since we want this to be binary searchable
codepoints = sorted(codepoints, key=lambda d: d['code_min'])

# Merge contiguous ranges that are the same
i = 1
while i < len(codepoints):
    if (codepoints[i]["code_min"] == codepoints[i-1]["code_max"]+1 and
        codepoints[i]["status"] == codepoints[i-1]["status"] and
        codepoints[i]["mapping"] == codepoints[i-1]["mapping"]):
        codepoints[i-1]["code_max"] = codepoints[i]["code_max"]
        del codepoints[i]
    else:
        i+=1

with open(outfile, 'w') as file:
    file.write(f"/* Generated via {sys.argv[0]} {url} {','.join(headers)} {datatype} {varname} {outfile} */\n")
    for header in headers:
        file.write(f'#include "{header}"\n')
    file.write("\n")
    file.write(f"size_t {varname}_len = {len(codepoints)};\n")
    file.write(f"{datatype} {varname}[] = {{\n")
    for entry in codepoints:
        file.write("  { %10s, %10s, %d, { %10s, %10s, %10s } },\n" % (
                hex(entry["code_min"]),
                hex(entry["code_max"]),
                entry["status"],
                hex(0 if len(entry["mapping"]) < 1 else entry["mapping"][0]),
                hex(0 if len(entry["mapping"]) < 2 else entry["mapping"][1]),
                hex(0 if len(entry["mapping"]) < 3 else entry["mapping"][2])
            )
        )

    file.write(f"}};\n")



print(f"wrote {outfile}")
sys.exit(0)
