#!/bin/sh

# Copyright (c) The c-ares project and its contributors
# SPDX-License-Identifier: MIT

set -e

for x in `find . -name "ax_*.m4"` ; do
  ax_name=`basename $x`
  echo "Fetching latest ${ax_name}"
  curl -s -o "${ax_name}" "https://raw.githubusercontent.com/autoconf-archive/autoconf-archive/refs/heads/master/m4/${ax_name}"
done
