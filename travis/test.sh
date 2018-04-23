#!/bin/sh
set -e
if [ "$BUILD_TYPE" != "ios" -a "$BUILD_TYPE" != "analyse" -a "$BUILD_TYPE" != "cmake" ]; then
    $TEST_WRAP ./adig www.google.com
    $TEST_WRAP ./acountry www.google.com
    $TEST_WRAP ./ahost www.google.com
    cd test
    make
    $TEST_WRAP ./arestest -4 -v $TEST_FILTER
    ./fuzzcheck.sh
    ./dnsdump  fuzzinput/answer_a fuzzinput/answer_aaaa
    cd ..
elif [ "$BUILD_TYPE" = "cmake" ] ; then
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
