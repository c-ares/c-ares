#include "ares-test-ai.h"
#include "dns-proto.h"

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <arpa/inet.h>
#include <sstream>
#include <vector>

using testing::InvokeWithoutArgs;
using testing::DoAll;

namespace ares {
namespace test {

MATCHER_P(IncludesNumAddresses, n, "") {
  int cnt = 0;
  for (const ares_addrinfo* ai = arg; ai != NULL; ai = ai->ai_next)
    cnt++;
  return n == cnt;
}

MATCHER_P(IncludesV4Address, address, "") {
  in_addr addressnum = {};
  if (!inet_pton(AF_INET, address, &addressnum))
    return false; // wrong number format?
  for (const ares_addrinfo* ai = arg; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family != AF_INET)
      continue;
    if (reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr.s_addr ==
        addressnum.s_addr)
      return true; // found
  }
  return false;
}

MATCHER_P(IncludesV6Address, address, "") {
  in6_addr addressnum = {};
  if (!inet_pton(AF_INET6, address, &addressnum)) {
    return false; // wrong number format?
  }
  for (const ares_addrinfo* ai = arg; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family != AF_INET6)
      continue;
    if (!memcmp(
        reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr.s6_addr,
        addressnum.s6_addr, sizeof(addressnum.s6_addr)))
      return true; // found
  }
  return false;
}

TEST_P(MockChannelTestAI, FamilyV6) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x21, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03}));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp6));
  AIResult result;
  struct ares_addrinfo hints = {};
  hints.ai_family = AF_INET6;
  ares_getaddrinfo(channel_, "example.com.", NULL, &hints,
                   AICallback, &result);
  Process();
  EXPECT_TRUE(result.done);
  EXPECT_EQ(result.status, ARES_SUCCESS);
  EXPECT_THAT(result.airesult, IncludesNumAddresses(1));
  EXPECT_THAT(result.airesult, IncludesV6Address("2121:0000:0000:0000:0000:0000:0000:0303"));
  ares_freeaddrinfo(result.airesult);
}


TEST_P(MockChannelTestAI, FamilyV4) {
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp4));
  AIResult result = {};
  struct ares_addrinfo hints = {};
  hints.ai_family = AF_INET;
  ares_getaddrinfo(channel_, "example.com.", NULL, &hints,
                   AICallback, &result);
  Process();
  EXPECT_TRUE(result.done);
  EXPECT_EQ(result.status, ARES_SUCCESS);
  EXPECT_THAT(result.airesult, IncludesNumAddresses(1));
  EXPECT_THAT(result.airesult, IncludesV4Address("2.3.4.5"));
  ares_freeaddrinfo(result.airesult);
}

TEST_P(MockChannelTestAI, FamilyV4_MultipleAddresses) {
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 100, {2, 3, 4, 5}))
    .add_answer(new DNSARR("example.com", 100, {7, 8, 9, 0}));
  ON_CALL(server_, OnRequest("example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp4));
  AIResult result = {};
  struct ares_addrinfo hints = {};
  hints.ai_family = AF_INET;
  ares_getaddrinfo(channel_, "example.com.", NULL, &hints,
                   AICallback, &result);
  Process();
  EXPECT_TRUE(result.done);
  EXPECT_EQ(result.status, ARES_SUCCESS);
  EXPECT_THAT(result.airesult, IncludesNumAddresses(2));
  EXPECT_THAT(result.airesult, IncludesV4Address("2.3.4.5"));
  EXPECT_THAT(result.airesult, IncludesV4Address("7.8.9.0"));
  ares_freeaddrinfo(result.airesult);
}

TEST_P(MockChannelTestAI, FamilyUnspecified) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x21, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03}));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp6));
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp4));
  AIResult result;
  struct ares_addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  ares_getaddrinfo(channel_, "example.com.", NULL, &hints,
                   AICallback, &result);
  Process();
  EXPECT_TRUE(result.done);
  EXPECT_EQ(result.status, ARES_SUCCESS);
  EXPECT_THAT(result.airesult, IncludesNumAddresses(2));
  EXPECT_THAT(result.airesult, IncludesV4Address("2.3.4.5"));
  EXPECT_THAT(result.airesult, IncludesV6Address("2121:0000:0000:0000:0000:0000:0000:0303"));
  ares_freeaddrinfo(result.airesult);
}

INSTANTIATE_TEST_CASE_P(AddressFamilies, MockChannelTestAI,
                        ::testing::Values(std::make_pair<int, bool>(AF_INET, false)));


}  // namespace test
}  // namespace ares
