#!/bin/bash
# Copyright (C) The c-ares project and its contributors
# SPDX-License-Identifier: MIT
set -e -x -o pipefail

# Travis on MacOS uses CloudFlare's DNS (1.1.1.1/1.0.0.1) which rejects ANY requests.
# Also, LiveSearchTXT is known to fail on Cirrus-CI on some MacOS hosts, we don't get
# a truncated UDP response so we never follow up with TCP.
# Note res_ninit() and /etc/resolv.conf actually have different configs, bad Travis
[ -z "$TEST_FILTER" ] && export TEST_FILTER="-4 --gtest_filter=-*LiveSearchTXT*:*LiveSearchANY*"

# No tests for ios as it is a cross-compile
if [ "$BUILD_TYPE" = "ios" -o "$BUILD_TYPE" = "ios-cmake" -o "$DIST" = "iOS" ] ; then
    exit 0
fi

# Analyze tests don't need runtime, its static analysis
if [ "$BUILD_TYPE" = "analyze" ] ; then
    exit 0
fi

PWD=`pwd`
TESTDIR="${PWD}/test"

if [ "$BUILD_TYPE" = "autotools" -o "$BUILD_TYPE" = "coverage" ]; then
    if [ -f "${PWD}/atoolsbld/src/tools/.libs/adig" ] ; then
        TOOLSBIN="${PWD}/atoolsbld/src/tools/.libs/"
    else
        TOOLSBIN="${PWD}/atoolsbld/src/tools/"
    fi
    if [ -f "${PWD}/atoolsbld/test/.libs/arestest" ] ; then
        TESTSBIN="${PWD}/atoolsbld/test/.libs/"
    else
        TESTSBIN="${PWD}/atoolsbld/test/"
    fi
    export LD_LIBRARY_PATH=${PWD}/atoolsbld/src/lib/.libs:$LD_LIBRARY_PATH
    export DYLD_LIBRARY_PATH=${PWD}/atoolsbld/src/lib/.libs:$DYLD_LIBRARY_PATH
else
    TOOLSBIN="${PWD}/cmakebld/bin"
    TESTSBIN="${PWD}/cmakebld/bin"
fi

$TEST_WRAP "${TOOLSBIN}/adig" www.google.com
$TEST_WRAP "${TOOLSBIN}/ahost" www.google.com
cd "${TESTSBIN}"

if [ "$TEST_WRAP" != "" ] ; then
  $TEST_WRAP ./arestest $TEST_FILTER
elif [ "$TEST_DEBUGGER" = "gdb" ] ; then
  gdb --batch --batch-silent --return-child-result -ex "handle SIGPIPE nostop noprint pass" -ex "run" -ex "thread apply all bt" -ex "quit" --args ./arestest $TEST_FILTER
elif [ "$TEST_DEBUGGER" = "lldb" ] ; then
  # LLDB won't return the exit code of the child process, so we need to extract it from the test output and verify it.
  lldb --batch -o "settings set target.process.extra-startup-command 'process handle SIGPIPE -n true -p true -s false'" -o "process launch --shell-expand-args 0" -k "thread backtrace all" -k "quit 1" -- ./arestest $TEST_FILTER 2>&1 | tee test_output.txt
  exit_code=`grep "Process [0-9]* exited with status = [0-9]* (.*)" test_output.txt | sed 's/.* = \([0-9]*\).*/\1/'`
  echo "Test Exit Code: ${exit_code}"
  if [ "${exit_code}" != "0" ] ; then
    exit 1
  fi
else
  ./arestest $TEST_FILTER
fi

./aresfuzz ${TESTDIR}/fuzzinput/*
./aresfuzzname ${TESTDIR}/fuzznames/*
./dnsdump "${TESTDIR}/fuzzinput/answer_a" "${TESTDIR}/fuzzinput/answer_aaaa"
cd "${PWD}"
