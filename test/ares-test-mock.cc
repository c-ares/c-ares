#include "ares-test.h"
#include "dns-proto.h"

#include <sys/socket.h>

#include <sstream>
#include <vector>

using testing::InvokeWithoutArgs;

namespace ares {
namespace test {

TEST_F(MockChannelTest, Basic) {
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

TEST_F(MockChannelTest, SearchDomains) {
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

TEST_F(MockChannelTest, Resend) {
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

TEST_F(MockChannelTest, CancelImmediate) {
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  ares_cancel(channel_);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ECANCELLED, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_F(MockChannelTest, CancelLater) {
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

TEST_F(MockChannelTest, Destroy) {
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  ares_destroy(channel_);
  channel_ = nullptr;
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_EDESTRUCTION, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

}  // namespace test
}  // namespace ares
