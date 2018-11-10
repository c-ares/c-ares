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

// UDP only so mock server doesn't get confused by concatenated requests
TEST_P(MockUDPChannelTestAI, ParallelLookups) {
  DNSPacket rsp1;
  rsp1.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp1));
  DNSPacket rsp2;
  rsp2.set_response().set_aa()
    .add_question(new DNSQuestion("www.example.com", ns_t_a))
    .add_answer(new DNSARR("www.example.com", 100, {1, 2, 3, 4}));
  ON_CALL(server_, OnRequest("www.example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp2));

  struct ares_addrinfo hints = {};
  hints.ai_family = AF_INET;
  AIResult result1;
  ares_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AICallback, &result1);
  AIResult result2;
  ares_getaddrinfo(channel_, "www.example.com.", NULL, &hints, AICallback, &result2);
  AIResult result3;
  ares_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AICallback, &result3);
  Process();

  EXPECT_TRUE(result1.done);
  EXPECT_EQ(result1.status, ARES_SUCCESS);
  EXPECT_THAT(result1.airesult, IncludesNumAddresses(1));
  EXPECT_THAT(result1.airesult, IncludesV4Address("2.3.4.5"));
  ares_freeaddrinfo(result1.airesult);

  EXPECT_TRUE(result2.done);
  EXPECT_EQ(result2.status, ARES_SUCCESS);
  EXPECT_THAT(result2.airesult, IncludesNumAddresses(1));
  EXPECT_THAT(result2.airesult, IncludesV4Address("1.2.3.4"));
  ares_freeaddrinfo(result2.airesult);

  EXPECT_TRUE(result3.done);
  EXPECT_EQ(result3.status, ARES_SUCCESS);
  EXPECT_THAT(result3.airesult, IncludesNumAddresses(1));
  EXPECT_THAT(result3.airesult, IncludesV4Address("2.3.4.5"));
  ares_freeaddrinfo(result3.airesult);
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

TEST_P(MockChannelTestAI, SearchDomains) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  ON_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", ns_t_a))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillByDefault(SetReply(&server_, &yesthird));

  AIResult result;
  struct ares_addrinfo hints = {};
  hints.ai_family = AF_INET;
  ares_getaddrinfo(channel_, "www", NULL, &hints, AICallback, &result);
  Process();
  EXPECT_TRUE(result.done);
  EXPECT_EQ(result.status, ARES_SUCCESS);
  EXPECT_THAT(result.airesult, IncludesNumAddresses(1));
  EXPECT_THAT(result.airesult, IncludesV4Address("2.3.4.5"));
  ares_freeaddrinfo(result.airesult);
}

TEST_P(MockChannelTestAI, SearchDomainsServFailOnAAAA) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.first.com", ns_t_aaaa));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nofirst4;
  nofirst4.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &nofirst4));
  
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.second.org", ns_t_aaaa));
  ON_CALL(server_, OnRequest("www.second.org", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket yessecond4;
  yessecond4.set_response().set_aa()
    .add_question(new DNSQuestion("www.second.org", ns_t_a))
    .add_answer(new DNSARR("www.second.org", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillByDefault(SetReply(&server_, &yessecond4));
  
  DNSPacket failthird;
  failthird.set_response().set_aa().set_rcode(ns_r_servfail)
    .add_question(new DNSQuestion("www.third.gov", ns_t_aaaa));
  ON_CALL(server_, OnRequest("www.third.gov", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &failthird));
  DNSPacket failthird4;
  failthird4.set_response().set_aa().set_rcode(ns_r_servfail)
    .add_question(new DNSQuestion("www.third.gov", ns_t_a));
  ON_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillByDefault(SetReply(&server_, &failthird4));
  
  AIResult result;
  struct ares_addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  ares_getaddrinfo(channel_, "www", NULL, &hints, AICallback, &result);
  Process();
  EXPECT_TRUE(result.done);
  EXPECT_EQ(result.status, ARES_SUCCESS);
  EXPECT_THAT(result.airesult, IncludesNumAddresses(1));
  EXPECT_THAT(result.airesult, IncludesV4Address("2.3.4.5"));
  ares_freeaddrinfo(result.airesult);
}

INSTANTIATE_TEST_CASE_P(AddressFamiliesAI, MockChannelTestAI,
                        ::testing::Values(std::make_pair<int, bool>(AF_INET, false)));

INSTANTIATE_TEST_CASE_P(AddressFamiliesAI, MockUDPChannelTestAI,
                        ::testing::ValuesIn(ares::test::families));

}  // namespace test
}  // namespace ares
