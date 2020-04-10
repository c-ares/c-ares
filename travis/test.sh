#!/bin/sh
set -e
if [ "$BUILD_TYPE" != "ios" -a "$BUILD_TYPE" != "analyse" -a "$BUILD_TYPE" != "cmake" -a "$BUILD_TYPE" != "valgrind" ]; then
    $TEST_WRAP ./adig www.google.com
    $TEST_WRAP ./acountry www.google.com
    $TEST_WRAP ./ahost www.google.com
    cd test
    make
    $TEST_WRAP ./arestest -4 -v $TEST_FILTER
    ./fuzzcheck.sh
    ./dnsdump  fuzzinput/answer_a fuzzinput/answer_aaaa
    cd ..
elif [ "$BUILD_TYPE" = "cmake" -o "$BUILD_TYPE" = "valgrind" ] ; then
    # We need to use cmake for valgrind because otehrwise the executables are bash
    # scripts created by libtool.
    TESTDIR=../../test/
    cd cmakebld/bin
    $TEST_WRAP ./adig www.google.com
    $TEST_WRAP ./acountry www.google.com
    $TEST_WRAP ./ahost www.google.com
    $TEST_WRAP ./arestest -4 -v $TEST_FILTER
    ./aresfuzz $TESTDIR/fuzzinput/*
    ./aresfuzzname $TESTDIR/fuzznames/*
    ./dnsdump $TESTDIR/fuzzinput/answer_a $TESTDIR/fuzzinput/answer_aaaa
    cd ../..
fi
