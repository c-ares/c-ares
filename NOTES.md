# Google Patch Rewards — c-ares local draft notes

**Date:** 2026-09-11 (America/Chicago)  
**Do not claim yet:** need upstream merge + ≥30 days, then https://bughunters.google.com/report/patch_rewards

## Chosen target + why

- **Project:** c-ares (Tier-1 **Other essential libraries** / DNS resolver used by curl, Node.js, gRPC, etc. — 2× memory-safety multiplier through end-2026)
- **Upstream:** https://github.com/c-ares/c-ares (prefer `main`)
- **Local clone:** `/workspace/google-patch-c-ares`
- **Branch:** `local/ares-buf-fbounds-safety` (from `main`)
- **Why this target:**
  1. Critical DNS infrastructure; AGENTS.md calls out that all parsing/serialization goes through `ares_buf_*()` on untrusted wire/config bytes.
  2. Clear, mergeable first-CL scope: **one** opaque buffer struct — `struct ares_buf` — with existing `alloc_buf`/`alloc_buf_len` and `data`/`data_len` pairs — not a whole-library sweep.
  3. Same pattern as libpng / libwebp / giflib / lz4 / zstd: **inert macros** when the flag is off; experimental Clang `-fbounds-safety` only when explicitly enabled.
  4. Struct is **opaque** (defined only in `ares_buf.c`); field order preserved (pointer before size); no public ABI change.
  5. Not already done upstream (no `__sized_by` / `-fbounds-safety` / `ptrcheck.h` in tree; no overlapping annotation PRs).
  6. AI gate clear: `AGENTS.md` **welcomes** coding agents with hard rules; CONTRIBUTING / README / SECURITY / `.github` have **no AI / LLM ban**.

**Why `alloc_buf`/`alloc_buf_len` (+ `data`/`data_len`) over public API params:** The opaque `ares_buf` is the library’s canonical safe buffer for DNS wire parse/build. Annotating the owned allocation (`alloc_buf`) and the logical view (`data`) systematizes the capacity relationships every consumer already maintains.

## Security benefit

`ares_buf` holds bytes from untrusted DNS responses, hosts files, and config. The library already tracks capacities in `alloc_buf_len` / `data_len`, but the compiler cannot see that `alloc_buf` / `data` are bounded by those fields.

This draft:

1. Introduces `src/lib/include/ares_bounds_safety.h` with `ARES_SIZED_BY` / `ARES_SIZED_BY_OR_NULL` / `ARES_COUNTED_BY*` (empty by default).
2. Annotates **only** the opaque `struct ares_buf` fields:
   - `alloc_buf` → `ARES_SIZED_BY_OR_NULL(alloc_buf_len)` (nullable on const buffers)
   - `data` → `ARES_SIZED_BY_OR_NULL(data_len)` (nullable after create / before first append)
3. Keeps existing field order. Documents capacity-then-pointer at bind sites (`ares_buf_create_const`, `ares_buf_reclaim`, `ares_buf_ensure_space` realloc).
4. Wires optional `CARES_ENABLE_FBOUNDS_SAFETY` (CMake, default **OFF**) → `-DCARES_SUPPORT_FBOUNDS_SAFETY` + `-fbounds-safety` (Clang only). Autotools: pass the same via `CFLAGS`/`CPPFLAGS` (macros remain inert unless defined).

**Default builds are unchanged:** macros expand to nothing; no new runtime checks without the experimental flag.

## Files changed

| File | Change |
|------|--------|
| `src/lib/include/ares_bounds_safety.h` | **New** — inert / Clang bounds macros (MIT) |
| `src/lib/str/ares_buf.c` | Include header; annotate `data` / `alloc_buf`; capacity-first assigns |
| `src/lib/Makefile.inc` | List new header in `HHEADERS` |
| `CMakeLists.txt` | `CARES_ENABLE_FBOUNDS_SAFETY` option OFF |
| `src/lib/CMakeLists.txt` | Apply `-fbounds-safety` when option ON (shared + static) |
| `NOTES.md` | This file |

## Verified locally 2026-09-11

| Check | Result |
|-------|--------|
| Default `CARES_ENABLE_FBOUNDS_SAFETY=OFF` CMake build (library, gcc 14.2, Ninja) | **PASS** (`libcares.so` linked; `ares_buf.c` compiled) |
| `CARES_ENABLE_FBOUNDS_SAFETY=ON` | **Not feasible on this box** — needs Clang with `-fbounds-safety` / `ptrcheck.h` |

## How to build / test

Default (macros inert — must stay green):

```sh
cmake -DCMAKE_BUILD_TYPE=DEBUG -DCARES_BUILD_TESTS=ON -G Ninja -B build
ninja -C build
./build/bin/arestest -4 --gtest_filter='*Buf*'
# or skip live network:
./build/bin/arestest -4 --gtest_filter='-*Live*'
```

With experimental bounds-safety toolchain (maintainers / CI; **not** available on this box — no Clang/`ptrcheck.h`):

```sh
cmake -DCMAKE_BUILD_TYPE=DEBUG -DCARES_ENABLE_FBOUNDS_SAFETY=ON \
  -DCMAKE_C_COMPILER=<clang-with-fbounds-safety> -G Ninja -B build-fbs
ninja -C build-fbs
```

Autotools equivalent (macros still inert unless `-DCARES_SUPPORT_FBOUNDS_SAFETY` is passed):

```sh
autoreconf -fi && ./configure && make -j
# experimental:
./configure CFLAGS='-DCARES_SUPPORT_FBOUNDS_SAFETY -fbounds-safety' CC=<clang-with-fbounds-safety>
```

## Upstream submit plan

1. Open a focused GitHub PR against `c-ares/c-ares` branch **`main`**.
2. Proposed title: `ares_buf: add optional -fbounds-safety annotations for alloc_buf/data`
3. Frame as secure-by-design / Safe Buffers-style systematization of existing buffer + capacity pairs; cite libwebp/libpng/lz4/zstd prior art and Google Patch Rewards Tier-1 goals.
4. Emphasize: default build behavior unchanged; flag OFF; no PoC / no CVE claim; opaque struct field order unchanged; C89-safe empty macros; `Signed-off-by` present.
5. Comply with `AGENTS.md` / `CONTRIBUTING.md` (C89, coverage, clang-format on changed lines).
6. Do **not** claim on https://bughunters.google.com/report/patch_rewards until **merge + ≥30 days**.

## Follow-ups (separate CLs)

- Parameter annotations on `ares_buf_append` / `ares_buf_create_const` / fetch helpers (`data`/`data_len` args)
- `ares_array` / other DSA buffer+size pairs
- Whole-TU `__ptrcheck_abi_assume_unsafe_indexable()` baseline so `CARES_ENABLE_FBOUNDS_SAFETY=ON` compiles under experimental Clang

## AI gate

- **AGENTS.md** present — explicitly rules for coding agents (welcome, not a ban).
- Searched CONTRIBUTING.md, README.md, SECURITY.md, `.github/` — **no AI-tool ban**.
- **AI gate: CLEAR** (no ban found).

## Status

**LOCAL DRAFT ONLY** — commit on `local/ares-buf-fbounds-safety`. Do **not** push/PR from this agent run. Still **no claim** until merge + ≥30 days unreverted.
