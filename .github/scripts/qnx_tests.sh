#!/bin/sh
# Copyright (C) The c-ares project and its contributors
# SPDX-License-Identifier: MIT
set -e

echo " * Extracting tests..."
tar -C /system/lib/ -xvf gtest.tar
tar -xvf cares-bin.tar
tar -xvf cares-lib.tar

echo " * Running Tests"

echo "   * adig test"
./adig www.google.com

echo ""
echo "   * ahost test"
./ahost www.google.com

echo ""
echo "   * arestest suite"
./arestest www.google.com --gtest_filter="-*LiveSearchTXT*:*LiveSearchANY*:*ServiceName*"
echo ""

nsip=`grep ^nameserver /etc/resolv.conf | head -n 1 | cut -d ' ' -f 2`
echo " * Changing DNS Configuration to use confstr(resolve, ${nsip}) and rerunning adig and ahost"
setconf resolve nameserver_${nsip}
rm -f /etc/resolv.conf

echo ""
echo "   * adig test"
./adig www.google.com

echo "   * ahost test"
./ahost www.google.com
