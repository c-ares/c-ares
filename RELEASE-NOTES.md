## c-ares version 1.25.0 - Jan 3 2024

This is a maintenance release.

Changes:

* AutoTools: rewrite build system to be lighter weight and fix issues in some semi-modern systems. It is likely this has broken building on some less common and legacy OSs, please report issues. [PR #674](https://github.com/c-ares/c-ares/pull/674)
* Rewrite ares\_strsplit() as a wrapper for ares\_\_buf\_split() for memory safety reasons. [88c444d](https://github.com/c-ares/c-ares/commit/88c444d)
* The ahost utility now uses ares\_getaddrinfo() and returns both IPv4 and IPv6 addresses by default. [PR #669](https://github.com/c-ares/c-ares/pull/669)
* OpenBSD: Add SOCK\_DNS flag when creating socket. [PR #659](https://github.com/c-ares/c-ares/pull/659)

Bugfixes:

* Tests: Live reverse lookups for Google's public DNS servers no longer return results, replace with CloudFlare pubic DNS servers. [1231aa7](https://github.com/c-ares/c-ares/commit/1231aa7)
* MacOS legacy SDKs require sys/socket.h before net/if.h [PR #673](https://github.com/c-ares/c-ares/pull/673)
* Connection failures should increment the server failure count first or a retry might be enqueued to the same server. [05181a6](https://github.com/c-ares/c-ares/commit/05181a6)
* On systems that don't implement the ability to enumerate network interfaces the stubs used the wrong prototype. [eebfe0c](https://github.com/c-ares/c-ares/commit/eebfe0c)
* Fix minor warnings and documentation typos. [PR #666](https://github.com/c-ares/c-ares/pull/666)
* Fix support for older GoogleTest versions. [d186f11](https://github.com/c-ares/c-ares/commit/d186f11)
* getrandom() may require sys/random.h on some systems. [Issue #665](https://github.com/c-ares/c-ares/issues/665)
* Fix building tests with symbol hiding enabled. [Issue #664](https://github.com/c-ares/c-ares/issues/664)

Thanks go to these friendly people for their efforts and contributions:

* Brad House (@bradh352)
* Daniel Stenberg (@bagder)
* Gregor Jasny (@gjasny)
* Martin Chang (@marty1885)
(4 contributors)
