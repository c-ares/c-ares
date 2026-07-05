c-ares Unit Test Suite
======================

This directory holds the c-ares test suite (C++14, GoogleTest).

Building and running
--------------------

```sh
cmake -DCMAKE_BUILD_TYPE=DEBUG -DCARES_BUILD_TESTS=ON -G Ninja -B build
ninja -C build
./build/bin/arestest -4 --gtest_filter='<Pattern>'
```

Autotools works too: `./configure --enable-tests && make`.

 - Always filter; the full suite is slow and includes live-network
   tests.  Skip those with `--gtest_filter=-*Live*`.
 - `arestest` flags: `-v` verbose, `-4`/`-6` address family,
   `-p <port>` mock server port; all other args pass through to
   GoogleTest.
 - Container tests (resolv.conf/hosts scenarios via `CONTAINED_TEST_F`)
   are Linux-only: `-DCARES_BUILD_CONTAINER_TESTS=ON`.
 - Tests of internal (non-`CARES_EXTERN`) functions are excluded when
   the library is built with symbol hiding; they are wrapped in
   `#ifndef CARES_SYMBOL_HIDING`.

Test types
----------

 - `ares-test-internal.cc` — unit tests of internal helpers (buffers,
   strings, data structures, DNS record internals).
 - `ares-test-mock.cc`, `ares-test-mock-et.cc` (event thread),
   `ares-test-mock-ai.cc` (getaddrinfo) — integration tests against a
   mock DNS server with crafted responses; `dns-proto.h` provides C++
   packet-builder helpers.
 - `ares-test-init.cc` — configuration/init, including the container
   tests.
 - `ares-test-parse-*.cc` — legacy `ares_parse_*_reply` API tests.
 - `ares-test-live.cc` — real DNS queries; requires connectivity.
 - Fixtures live in `ares-test.h`; `LibraryTest::SetAllocFail` injects
   allocation failures for OOM-path testing.

Fuzzing
-------

`aresfuzz` drives `ares_dns_parse` and round-trips through
`ares_dns_write`; `aresfuzzname` fuzzes name parsing.  The corpora in
`fuzzinput/` and `fuzznames/` are executed on every CI run — add
corpus entries when introducing new record types or wire-format
handling.  See `../FUZZING.md` for libFuzzer/AFL instructions.

Code coverage
-------------

```sh
cmake -DCMAKE_BUILD_TYPE=DEBUG -DCARES_BUILD_TESTS=ON -DCARES_COVERAGE=ON -G Ninja -B build
ninja -C build && ./build/bin/arestest && ninja -C build coverage
```

Requires `gcov`/`lcov`.  Coverage policy (>90%, exclusion annotation
tags) is documented in `../CONTRIBUTING.md`.
