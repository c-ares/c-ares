// This file includes tests that attempt to do real lookups
// of DNS names using the local machine's live infrastructure.
// As a result, we don't check the results very closely, to allow
// for varying local configurations.

#include "ares-test.h"
#include "ares-test-ai.h"

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

namespace ares {
namespace test {

MATCHER_P(IncludesAtLeastNumAddresses, n, "") {
  int cnt = 0;
  for (const ares_addrinfo* ai = arg.get(); ai != NULL; ai = ai->ai_next)
    cnt++;
  return cnt >= n;
}

MATCHER_P(OnlyIncludesAddrType, addrtype, "") {
  for (const ares_addrinfo* ai = arg.get(); ai != NULL; ai = ai->ai_next)
    if (ai->ai_family != addrtype)
      return false;
  return true;
}

MATCHER_P(IncludesAddrType, addrtype, "") {
  for (const ares_addrinfo* ai = arg.get(); ai != NULL; ai = ai->ai_next)
    if (ai->ai_family == addrtype)
      return true;
  return false;
}

void DefaultChannelTestAI::Process() {
  ProcessWork(channel_, NoExtraFDs, nullptr);
}

// Use the address of Google's public DNS servers as example addresses that are
// likely to be accessible everywhere/everywhen.

VIRT_NONVIRT_TEST_F(DefaultChannelTestAI, LiveGetHostByNameV4) {
  struct ares_addrinfo hints = {};
  hints.ai_family = AF_INET;
  AddrInfoResult result;
  ares_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_THAT(result.ai_, IncludesAtLeastNumAddresses(1));
  EXPECT_THAT(result.ai_, OnlyIncludesAddrType(AF_INET));
}

VIRT_NONVIRT_TEST_F(DefaultChannelTestAI, LiveGetHostByNameV6) {
  struct ares_addrinfo hints = {};
  hints.ai_family = AF_INET6;
  AddrInfoResult result;
  ares_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_THAT(result.ai_, IncludesAtLeastNumAddresses(1));
  EXPECT_THAT(result.ai_, OnlyIncludesAddrType(AF_INET6));
}

VIRT_NONVIRT_TEST_F(DefaultChannelTestAI, LiveGetHostByNameV4AndV6) {
  struct ares_addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  AddrInfoResult result;
  ares_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_THAT(result.ai_, IncludesAtLeastNumAddresses(2));
  EXPECT_THAT(result.ai_, IncludesAddrType(AF_INET6));
  EXPECT_THAT(result.ai_, IncludesAddrType(AF_INET));
}

}  // namespace test
}  // namespace ares
