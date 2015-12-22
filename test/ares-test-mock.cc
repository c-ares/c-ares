#include "ares-test.h"
#include "dns-proto.h"

#include <sys/socket.h>

#include <sstream>
#include <vector>

using testing::InvokeWithoutArgs;

namespace ares {
namespace test {

TEST_P(MockChannelTest, Basic) {
  std::vector<byte> reply = {
    0x00, 0x00,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // 1 question
    0x00, 0x01,  // 1 answer RRs
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs
    // Question
    0x03, 'w', 'w', 'w',
    0x06, 'g', 'o', 'o', 'g', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer
    0x03, 'w', 'w', 'w',
    0x06, 'g', 'o', 'o', 'g', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    0x00, 0x00, 0x01, 0x00,  // TTL
    0x00, 0x04,  // rdata length
    0x01, 0x02, 0x03, 0x04
  };

  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReplyData(&server_, reply));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, SearchDomains) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillOnce(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillOnce(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", ns_t_a))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillOnce(SetReply(&server_, &yesthird));

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SearchDomainsBare) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillOnce(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillOnce(SetReply(&server_, &nosecond));
  DNSPacket nothird;
  nothird.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.third.gov", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillOnce(SetReply(&server_, &nothird));
  DNSPacket yesbare;
  yesbare.set_response().set_aa()
    .add_question(new DNSQuestion("www", ns_t_a))
    .add_answer(new DNSARR("www", 0x0200, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www", ns_t_a))
    .WillOnce(SetReply(&server_, &yesbare));

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SearchNoDataThenSuccess) {
  // First two search domains recognize the name but have no A records.
  DNSPacket nofirst;
  nofirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillOnce(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa()
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillOnce(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", ns_t_a))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillOnce(SetReply(&server_, &yesthird));

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SearchNoDataThenFail) {
  // First two search domains recognize the name but have no A records.
  DNSPacket nofirst;
  nofirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillOnce(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa()
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillOnce(SetReply(&server_, &nosecond));
  DNSPacket nothird;
  nothird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillOnce(SetReply(&server_, &nothird));
  DNSPacket nobare;
  nobare.set_response().set_aa()
    .add_question(new DNSQuestion("www", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www", ns_t_a))
    .WillOnce(SetReply(&server_, &nobare));

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENODATA, result.status_);
}

TEST_P(MockChannelTest, SearchAllocFailure) {
  SearchResult result;
  SetAllocFail(1);
  ares_search(channel_, "fully.qualified.", ns_c_in, ns_t_a, SearchCallback, &result);
  /* Already done */
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOMEM, result.status_);
}

TEST_P(MockChannelTest, SearchHighNdots) {
  DNSPacket nobare;
  nobare.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("a.b.c.w.w.w", ns_t_a));
  EXPECT_CALL(server_, OnRequest("a.b.c.w.w.w", ns_t_a))
    .WillOnce(SetReply(&server_, &nobare));
  DNSPacket yesfirst;
  yesfirst.set_response().set_aa()
    .add_question(new DNSQuestion("a.b.c.w.w.w.first.com", ns_t_a))
    .add_answer(new DNSARR("a.b.c.w.w.w.first.com", 0x0200, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("a.b.c.w.w.w.first.com", ns_t_a))
    .WillOnce(SetReply(&server_, &yesfirst));

  SearchResult result;
  ares_search(channel_, "a.b.c.w.w.w", ns_c_in, ns_t_a, SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  std::stringstream ss;
  ss << PacketToString(result.data_);
  EXPECT_EQ("RSP QRY AA NOERROR Q:{'a.b.c.w.w.w.first.com' IN A} "
            "A:{'a.b.c.w.w.w.first.com' IN A TTL=512 2.3.4.5}",
            ss.str());
}

TEST_P(MockChannelTest, UnspecifiedFamilyV6) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x21, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03}));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp6));

  HostResult result;
  ares_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  // Default to IPv6 when both are available.
  EXPECT_EQ("{'example.com' aliases=[] addrs=[2121:0000:0000:0000:0000:0000:0000:0303]}", ss.str());
}

TEST_P(MockChannelTest, UnspecifiedFamilyV4) {
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp4));
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp6));

  HostResult result;
  ares_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, UnspecifiedFamilyNoData) {
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a));
  ON_CALL(server_, OnRequest("example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp4));
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa))
    .add_answer(new DNSCnameRR("example.com", 100, "elsewhere.com"));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp6));

  HostResult result;
  ares_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'' aliases=[] addrs=[]}", ss.str());
}

TEST_P(MockChannelTest, ExplicitIP) {
  HostResult result;
  ares_gethostbyname(channel_, "1.2.3.4", AF_INET, HostCallback, &result);
  EXPECT_TRUE(result.done_);  // Immediate return
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'1.2.3.4' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, ExplicitIPAllocFail) {
  HostResult result;
  SetAllocSizeFail(strlen("1.2.3.4") + 1);
  ares_gethostbyname(channel_, "1.2.3.4", AF_INET, HostCallback, &result);
  EXPECT_TRUE(result.done_);  // Immediate return
  EXPECT_EQ(ARES_ENOMEM, result.status_);
}

TEST_P(MockChannelTest, SortListV4) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 100, {22, 23, 24, 25}))
    .add_answer(new DNSARR("example.com", 100, {12, 13, 14, 15}))
    .add_answer(new DNSARR("example.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp));

  {
    ares_set_sortlist(channel_, "12.13.0.0/255.255.0.0 1234::5678");
    HostResult result;
    ares_gethostbyname(channel_, "example.com.", AF_INET, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[12.13.14.15, 22.23.24.25, 2.3.4.5]}", ss.str());
  }
  {
    ares_set_sortlist(channel_, "2.3.0.0/16 130.140.150.160/26");
    HostResult result;
    ares_gethostbyname(channel_, "example.com.", AF_INET, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[2.3.4.5, 22.23.24.25, 12.13.14.15]}", ss.str());
  }
  struct ares_options options;
  memset(&options, 0, sizeof(options));
  int optmask = 0;
  EXPECT_EQ(ARES_SUCCESS, ares_save_options(channel_, &options, &optmask));
  EXPECT_TRUE(optmask & ARES_OPT_SORTLIST);
  ares_destroy_options(&options);
}

TEST_P(MockChannelTest, SortListV6) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02}))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x21, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03}));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp));

  {
    ares_set_sortlist(channel_, "1111::/16 2.3.0.0/255.255.0.0");
    HostResult result;
    ares_gethostbyname(channel_, "example.com.", AF_INET6, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[1111:0000:0000:0000:0000:0000:0000:0202, "
              "2121:0000:0000:0000:0000:0000:0000:0303]}", ss.str());
  }
  {
    ares_set_sortlist(channel_, "2121::/8");
    HostResult result;
    ares_gethostbyname(channel_, "example.com.", AF_INET6, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[2121:0000:0000:0000:0000:0000:0000:0303, "
              "1111:0000:0000:0000:0000:0000:0000:0202]}", ss.str());
  }
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, SearchDomainsAllocFail) {
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

  // Fail a variety of different memory allocations, and confirm
  // that the operation either fails with ENOMEM or succeeds
  // with the expected result.
  const int kCount = 34;
  HostResult results[kCount];
  for (int ii = 1; ii <= kCount; ii++) {
    HostResult* result = &(results[ii - 1]);
    ClearFails();
    SetAllocFail(ii);
    ares_gethostbyname(channel_, "www", AF_INET, HostCallback, result);
    Process();
    EXPECT_TRUE(result->done_);
    if (result->status_ != ARES_ENOMEM) {
      std::stringstream ss;
      ss << result->host_;
      EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str()) << " failed alloc #" << ii;
      if (verbose) std::cerr << "Succeeded despite failure of alloc #" << ii << std::endl;
    }
  }

  // Explicitly destroy the channel now, so that the HostResult objects
  // are still valid (in case any pending work refers to them).
  ares_destroy(channel_);
  channel_ = nullptr;
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, Resend) {
  std::vector<byte> nothing;
  DNSPacket reply;
  reply.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 0x0100, {0x01, 0x02, 0x03, 0x04}));

  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReplyData(&server_, nothing))
    .WillOnce(SetReplyData(&server_, nothing))
    .WillOnce(SetReply(&server_, &reply));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(2, result.timeouts_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, CancelImmediate) {
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  ares_cancel(channel_);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ECANCELLED, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, CancelLater) {
  std::vector<byte> nothing;

  // On second request, cancel the channel.
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReplyData(&server_, nothing))
    .WillOnce(CancelChannel(&server_, channel_));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ECANCELLED, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, GetHostByNameDestroyAbsolute) {
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);

  ares_destroy(channel_);
  channel_ = nullptr;

  EXPECT_TRUE(result.done_);  // Synchronous
  EXPECT_EQ(ARES_EDESTRUCTION, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, GetHostByNameDestroyRelative) {
  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);

  ares_destroy(channel_);
  channel_ = nullptr;

  EXPECT_TRUE(result.done_);  // Synchronous
  EXPECT_EQ(ARES_EDESTRUCTION, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, GetHostByAddrDestroy) {
  unsigned char gdns_addr4[4] = {0x08, 0x08, 0x08, 0x08};
  HostResult result;
  ares_gethostbyaddr(channel_, gdns_addr4, sizeof(gdns_addr4), AF_INET, HostCallback, &result);

  ares_destroy(channel_);
  channel_ = nullptr;

  EXPECT_TRUE(result.done_);  // Synchronous
  EXPECT_EQ(ARES_EDESTRUCTION, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, HostAlias) {
  DNSPacket reply;
  reply.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 0x0100, {0x01, 0x02, 0x03, 0x04}));
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReply(&server_, &reply));

  TempFile aliases("\n\n# www commentedout\nwww www.google.com\n");
  EnvValue with_env("HOSTALIASES", aliases.filename());

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, HostAliasMissing) {
  DNSPacket yesfirst;
  yesfirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", ns_t_a))
    .add_answer(new DNSARR("www.first.com", 0x0200, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillOnce(SetReply(&server_, &yesfirst));

  TempFile aliases("\n\n# www commentedout\nww www.google.com\n");
  EnvValue with_env("HOSTALIASES", aliases.filename());
  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.first.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, HostAliasMissingFile) {
  DNSPacket yesfirst;
  yesfirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", ns_t_a))
    .add_answer(new DNSARR("www.first.com", 0x0200, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillOnce(SetReply(&server_, &yesfirst));

  EnvValue with_env("HOSTALIASES", "bogus.mcfile");
  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.first.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, HostAliasUnreadable) {
  TempFile aliases("www www.google.com\n");
  chmod(aliases.filename(), 0);
  EnvValue with_env("HOSTALIASES", aliases.filename());

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_EFILE, result.status_);
  chmod(aliases.filename(), 0777);
}

INSTANTIATE_TEST_CASE_P(AddressFamilies, MockChannelTest,
                        ::testing::Values(std::make_pair<int, bool>(AF_INET, false),
                                          std::make_pair<int, bool>(AF_INET, true),
                                          std::make_pair<int, bool>(AF_INET6, false),
                                          std::make_pair<int, bool>(AF_INET6, true)));

INSTANTIATE_TEST_CASE_P(AddressFamilies, MockUDPChannelTest,
                        ::testing::Values(AF_INET, AF_INET6));

}  // namespace test
}  // namespace ares
