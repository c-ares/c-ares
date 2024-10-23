#!/bin/sh
# Copyright (C) The c-ares project and its contributors
# SPDX-License-Identifier: MIT
set -e -x

OS=`uname -s || true`

if [ "$OS" = "Linux" ]; then
    # Make distribution tarball
    autoreconf -fi
    ./configure
    make dist VERSION=99.98.97
    # Extract distribution tarball for building
    tar xvf c-ares-99.98.97.tar.gz
    cd c-ares-99.98.97
    # Build autotools
    mkdir build-autotools
    cd build-autotools
    ../configure --disable-symbol-hiding --enable-expose-statics --enable-maintainer-mode --enable-debug
    make
    cd test
    $TEST_WRAP ./arestest -4 -v $TEST_FILTER
    cd ../..
    # Build CMake
    mkdir build-cmake
    cd build-cmake
    cmake -DCMAKE_BUILD_TYPE=DEBUG -DCARES_STATIC=ON -DCARES_STATIC_PIC=ON -DCARES_BUILD_TESTS=ON ..
    make
    cd bin
    $TEST_WRAP ./arestest -4 -v $TEST_FILTER
    cd ../..
fi
