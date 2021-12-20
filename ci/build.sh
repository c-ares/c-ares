#!/bin/sh
set -e

OS=""
if [ "$TRAVIS_OS_NAME" != "" ]; then
    OS="$TRAVIS_OS_NAME"
elif [ "$CIRRUS_OS" != "" ]; then
    OS="$CIRRUS_OS"
fi

if [ "$BUILD_TYPE" != "cmake" -a "$BUILD_TYPE" != "valgrind" ]; then
    autoreconf -fi
    mkdir atoolsbld
    cd atoolsbld
    $SCAN_WRAP ../configure --disable-symbol-hiding --enable-expose-statics --enable-maintainer-mode --enable-debug $CONFIG_OPTS
    $SCAN_WRAP make
else
    # Use cmake for valgrind to prevent libtool script wrapping of tests that interfere with valgrind
    mkdir cmakebld
    cd cmakebld
    cmake ${CMAKE_FLAGS} ..
    make
fi
