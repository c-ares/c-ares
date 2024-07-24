#!/bin/sh
# Copyright (C) The c-ares project and its contributors
# SPDX-License-Identifier: MIT
set -e -x

OS=""
if [ "$TRAVIS_OS_NAME" != "" ]; then
    OS="$TRAVIS_OS_NAME"
elif [ "$CIRRUS_OS" != "" ]; then
    OS="$CIRRUS_OS"
fi

if [ "$DIST" = "iOS" ] ; then
   XCODE_PATH=`xcode-select -print-path`
   SYSROOT="${XCODE_PATH}/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/"
fi

if [ "$BUILD_TYPE" = "autotools" -o "$BUILD_TYPE" = "coverage" ]; then
    autoreconf -fi
    rm -rf atoolsbld
    mkdir atoolsbld
    cd atoolsbld
    if [ "$DIST" = "iOS" ] ; then
        export CFLAGS="${CFLAGS} -isysroot ${SYSROOT}"
        export CXXFLAGS="${CXXFLAGS} -isysroot ${SYSROOT}"
        export LDFLAGS="${LDFLAGS} -isysroot ${SYSROOT}"
    fi
    export CFLAGS="${CFLAGS} -O0 -g"
    export CXXFLAGS="${CXXFLAGS} -O0 -g"
    if [ "$DIST" != "Windows" ] ; then
        CONFIG_OPTS="${CONFIG_OPTS} --disable-symbol-hiding"
    fi
    $SCAN_WRAP ../configure --enable-maintainer-mode $CONFIG_OPTS
    $SCAN_WRAP make
    cd ..
else
    # Use cmake for everything else
    rm -rf cmakebld
    mkdir cmakebld
    cd cmakebld
    if [ "$DIST" = "iOS" ] ; then
        CMAKE_FLAGS="${CMAKE_FLAGS} -DCMAKE_OSX_SYSROOT=${SYSROOT}"
    fi
    $SCAN_WRAP cmake ${CMAKE_FLAGS} ${CMAKE_TEST_FLAGS} ..
    $SCAN_WRAP cmake --build .
    cd ..
fi
