#!/bin/sh
set -e
if [ "$BUILD_TYPE" != "ios" -a "$BUILD_TYPE" != "analyse" -a "$BUILD_TYPE" != "cmake" ]; then
    $TEST_WRAP ./examples/adig www.google.com
    $TEST_WRAP ./examples/acountry www.google.com
    $TEST_WRAP ./examples/ahost www.google.com
    cd test
    make
    $TEST_WRAP ./arestest -v $TEST_FILTER
    ./fuzzcheck.sh
    cd ..
fi
