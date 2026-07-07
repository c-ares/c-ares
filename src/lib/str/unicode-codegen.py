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

# Generates the UTS #46 IDNA mapping table (ares_idnamap.c) from the Unicode
# Character Database's IdnaMappingTable.txt.
#
# Requires the Unicode 15.1 or later format of the data file (earlier versions
# contain disallowed_STD3_* statuses which this parser intentionally rejects).
#
# Mappings are variable length (up to 18 codepoints in Unicode 17), so the
# mapped UTF-8 sequences are emitted into a shared byte pool referenced by
# offset/length from each table entry.  Duplicate mapping sequences share pool
# data.  Generation hard-errors if a mapping cannot be represented rather than
# silently truncating.
#
# The emitted table is wrapped in clang-format off/on markers so the repository
# clang-format CI treats the generated formatting as authoritative.

import string
import sys
import urllib.request

def is_hex(s: str) -> bool:
    return all(c in string.hexdigits for c in s)

if len(sys.argv) != 6:
    print(f"Usage: {sys.argv[0]} url_or_file headers datatype varname out.c")
    print(f"Example: {sys.argv[0]} https://www.unicode.org/Public/17.0.0/idna/IdnaMappingTable.txt ares_private.h,ares_idnamap.h ares_idnamap_data_t ares_idnamap_data ares_idnamap.c")
    sys.exit(1)

url = sys.argv[1]
headers = sys.argv[2].split(",")
datatype = sys.argv[3]
varname = sys.argv[4]
outfile = sys.argv[5]

try:
    if url.startswith("http://") or url.startswith("https://"):
        with urllib.request.urlopen(url) as response:
            data = response.read()
            casefold = data.decode('utf-8')
    else:
        with open(url, encoding='utf-8') as f:
            casefold = f.read()
except Exception as e:
    print(f"An unexpected error occurred: {e}")
    sys.exit(1)

codepoints = []

# Lines look like this:
# FA6E..FA6F    ; disallowed                 # NA   <reserved-FA6E>..<reserved-FA6F>
# FD40..FD4F    ; valid      ;      ; NV8    # 14.0 ARABIC LIGATURE RAHIMAHU ALLAAH..ARABIC LIGATURE RAHIMAHUM ALLAAH
# FD92          ; mapped     ; 0645 062C 062E #1.1  ARABIC LIGATURE MEEM WITH JEEM WITH KHAH INITIAL FORM
for line in casefold.splitlines():
    # Strip comments
    line = line.split("#")[0].strip()
    if len(line) == 0:
        continue

    sects = [ s.strip() for s in line.split(";") ]
    if len(sects) < 2:
        print(f"invalid line format: {line}")
        sys.exit(1)

    code = sects[0].split("..")

    # Status handling, from UTS #46:
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

    mapping = []

    if len(sects) >= 3 and len(sects[2].strip()) > 0:
        mapping = sects[2].strip().split(" ")

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

    if status == 3 and len(int_mapping) == 0:
        print(f"mapped status without mapping data: {line}")
        sys.exit(1)

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

# UTS #46 performs validation AFTER mapping, so a codepoint whose mapping
# target is itself disallowed (possible here because we reinterpret the
# non-normative NV8/XV8 IDNA2008 exclusions as disallowed, e.g. U+2152 VULGAR
# FRACTION ONE TENTH maps to '1/10' using U+2044 FRACTION SLASH which is NV8)
# must be rejected.  Resolve that at generation time by flipping such entries
# to disallowed so the runtime mapper never needs a second validation pass.
# ASCII targets are exempt: the runtime passes ASCII through without
# consulting the table and hostname validity is enforced at query-write time.
def find_status(cp):
    for entry in codepoints:
        if entry["code_min"] <= cp <= entry["code_max"]:
            return entry["status"]
    return 0  # valid

for entry in codepoints:
    if entry["status"] != 3:
        continue
    for cp in entry["mapping"]:
        if cp >= 0x80 and find_status(cp) == 1:
            entry["status"] = 1
            entry["mapping"] = []
            break

# Re-merge ranges that have become identical after the disallowed flip
i = 1
while i < len(codepoints):
    if (codepoints[i]["code_min"] == codepoints[i-1]["code_max"]+1 and
        codepoints[i]["status"] == codepoints[i-1]["status"] and
        codepoints[i]["mapping"] == codepoints[i-1]["mapping"]):
        codepoints[i-1]["code_max"] = codepoints[i]["code_max"]
        del codepoints[i]
    else:
        i+=1

# Build the UTF-8 mapping pool.  Each mapped entry stores an offset/length
# into this shared pool.  Identical mapping sequences share pool bytes.
pool = bytearray()
pool_index = {}
for entry in codepoints:
    utf8 = "".join(chr(cp) for cp in entry["mapping"]).encode("utf-8")
    if len(utf8) == 0:
        entry["map_offset"] = 0
        entry["map_len"] = 0
        continue
    if len(utf8) > 255:
        print(f"mapping exceeds 255 UTF-8 bytes, format cannot represent it: {entry}")
        sys.exit(1)
    if utf8 in pool_index:
        offset = pool_index[utf8]
    else:
        offset = len(pool)
        pool_index[utf8] = offset
        pool.extend(utf8)
    entry["map_offset"] = offset
    entry["map_len"] = len(utf8)

if len(pool) > 0xFFFFFFFF:
    print(f"pool exceeds unsigned int range")
    sys.exit(1)

with open(outfile, 'w') as file:
    file.write("/* clang-format off */\n")
    # The tag strings are split so the REUSE scanner sees only the emitted
    # file's tags, not phantom (and malformed) ones in this script's source.
    file.write("/* SPDX-FileCopyright" "Text: (C) The c-ares project and its contributors\n")
    file.write(" * SPDX-License" "-Identifier: MIT\n")
    file.write(" *\n")
    file.write(" * Table data derived from the Unicode(R) Character Database,\n")
    file.write(" * (C) Unicode, Inc., licensed under the UNICODE LICENSE V3\n")
    file.write(" * (https://www.unicode.org/license.txt).\n")
    file.write(" *\n")
    file.write(f" * Generated via {sys.argv[0]} with:\n")
    file.write(f" *   url:      {url}\n")
    file.write(f" *   headers:  {','.join(headers)}\n")
    file.write(f" *   datatype: {datatype}\n")
    file.write(f" *   varname:  {varname}\n")
    file.write(f" *   outfile:  {outfile}\n")
    file.write(" * DO NOT EDIT MANUALLY.\n")
    file.write(" */\n")
    for header in headers:
        file.write(f'#include "{header}"\n')
    file.write("\n")

    file.write(f"const unsigned char {varname}_pool[] = {{\n")
    for i in range(0, len(pool), 12):
        chunk = ", ".join("0x%02x" % b for b in pool[i:i+12])
        file.write(f"  {chunk},\n")
    file.write("};\n\n")

    file.write(f"const {datatype} {varname}[] = {{\n")
    for entry in codepoints:
        file.write("  { %10s, %10s, %d, %3d, %5d },\n" % (
                hex(entry["code_min"]),
                hex(entry["code_max"]),
                entry["status"],
                entry["map_len"],
                entry["map_offset"]
            )
        )
    file.write("};\n\n")

    file.write(f"const size_t {varname}_len =\n")
    file.write(f"  sizeof({varname}) / sizeof(*{varname});\n")
    file.write("/* clang-format on */\n")

print(f"wrote {outfile}: {len(codepoints)} entries, {len(pool)} pool bytes")
sys.exit(0)
