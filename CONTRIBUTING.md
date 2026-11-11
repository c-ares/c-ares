Contributing to c-ares
======================

Submit patches as GitHub pull requests.  Requirements:

 - CI must be green ("All Checks") with no new warnings on any platform.
 - Add tests for any new functionality or behavior change; prefer tests
   that fail without your change.
 - **Coverage must stay above 90%** (lcov/Coveralls).  New reachable
   logic needs tests.
 - Allocation failures must return an error (`ARES_ENOMEM`), never
   crash.  Those paths are untestable, so annotate them:
   `/* LCOV_EXCL_LINE: OutOfMemory */`.  Other allowed tags:
   `DefensiveCoding` (can't-happen guards), `UntestablePath`
   (OS-dependent), `FallbackCode` (platform fallbacks; use
   `LCOV_EXCL_START`/`STOP` for blocks).  Never use annotations to skip
   testing reachable logic.
 - **No API or ABI breaks.**  `include/ares*.h` is additive-only;
   deprecate with `CARES_DEPRECATED_FOR()`, never remove.  New members
   may be appended to `struct ares_options` (with an `ARES_OPT_*` bit)
   only if they need no allocation/deallocation —
   `ares_destroy_options()` cannot free them.  Anything else gets
   `ares_set_*()`/`ares_get_*()` functions.  Update `ares_dup()` either
   way.
 - Public API changes update the man pages in `docs/` in the same PR.
   Do not edit `RELEASE-NOTES.md` (written at release time).
 - Commit subject `subsystem: summary` (e.g. `ares_dns_parse: ...`,
   `test: ...`), explanatory body, ending with
   `Signed-off-by: Your Name <email>`.  PRs are squash-merged.

Coding conventions: see `AGENTS.md` (applies to humans too) and
`DEVELOPER-NOTES.md` (build systems, C89 requirement).
