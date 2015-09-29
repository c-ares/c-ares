#include "ares-test.h"
#include "dns-proto.h"

#include <sstream>
#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, ParseAReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 0x01020304, {0x02, 0x03, 0x04, 0x05}));
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };
  EXPECT_EQ(data, pkt.data());
  struct hostent *host = nullptr;
  struct ares_addrttl info[5];
  int count = 5;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), data.size(),
                                             &host, info, &count));
  EXPECT_EQ(1, count);
  EXPECT_EQ(0x01020304, info[0].ttl);
  unsigned long expected_addr = htonl(0x02030405);
  EXPECT_EQ(expected_addr, info[0].ipaddr.s_addr);
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseAReplyErrors) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_answer(new DNSARR("example.com", 0x01020304, {0x02, 0x03, 0x04, 0x05}));
  std::vector<byte> data = pkt.data();

  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  // No question
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply(data.data(), data.size(),
                                              &host, info, &count));
  EXPECT_EQ(nullptr, host);

  // Question != answer
  pkt.add_question(new DNSQuestion("Axample.com", ns_t_a));
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_a_reply(data.data(), data.size(),
                                              &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", ns_t_a));

#ifdef DISABLED
  // Not a response.
  pkt.set_response(false);
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply(data.data(), data.size(),
                                              &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.set_response(true);

  // Bad return code.
  pkt.set_rcode(ns_r_formerr);
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_a_reply(data.data(), data.size(),
                                              &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.set_rcode(ns_r_noerror);
#endif

  // 2 questions
  pkt.add_question(new DNSQuestion("example.com", ns_t_a));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply(data.data(), data.size(),
                                              &host, info, &count));
  EXPECT_EQ(nullptr, host);

  // Wrong sort of answer.
  pkt.answers_.clear();
  pkt.add_answer(new DNSMxRR("example.com", 0x01020304, 100, "mx1.example.com"));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply(data.data(), data.size(),
                                              &host, info, &count));
  EXPECT_EQ(nullptr, host);

  // No answer
  pkt.answers_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply(data.data(), data.size(),
                                              &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.add_answer(new DNSARR("example.com", 0x01020304, {0x02, 0x03, 0x04, 0x05}));

  // Truncated packets.
  data = pkt.data();
  for (size_t len = 1; len < data.size(); len++) {
    EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply(data.data(), len,
                                                &host, info, &count));
    EXPECT_EQ(nullptr, host);
  }
}

TEST_F(LibraryTest, ParseAReplyAllocFail) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("Axample.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 0x01020304, {0x02, 0x03, 0x04, 0x05}));
  std::vector<byte> data = pkt.data();

  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  SetAllocSizeFail(1 * sizeof(struct in_addr));
  EXPECT_EQ(ARES_ENOMEM, ares_parse_a_reply(data.data(), data.size(),
                                            &host, info, &count));
  EXPECT_EQ(nullptr, host);

  SetAllocSizeFail(2 * sizeof(char *));
  EXPECT_EQ(ARES_ENOMEM, ares_parse_a_reply(data.data(), data.size(),
                                            &host, info, &count));
  EXPECT_EQ(nullptr, host);

}

TEST_F(LibraryTest, ParseAaaaReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa))
    .add_answer(new DNSAaaaRR("example.com", 0x01020304,
                              {0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                               0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04}));
  std::vector<byte> data = pkt.data();
  struct hostent *host = nullptr;
  struct ares_addr6ttl info[5];
  int count = 5;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_aaaa_reply(data.data(), data.size(),
                                                &host, info, &count));
  EXPECT_EQ(1, count);
  EXPECT_EQ(0x01020304, info[0].ttl);
  EXPECT_EQ(0x01, info[0].ip6addr._S6_un._S6_u8[0]);
  EXPECT_EQ(0x02, info[0].ip6addr._S6_un._S6_u8[4]);
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'example.com' aliases=[] addrs=[0101:0101:0202:0202:0303:0303:0404:0404]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseAaaaReplyErrors) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_answer(new DNSAaaaRR("example.com", 0x01020304,
                              {0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                               0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04}));
  std::vector<byte> data = pkt.data();

  struct hostent *host = nullptr;
  struct ares_addr6ttl info[2];
  int count = 2;
  // No question
  EXPECT_EQ(ARES_EBADRESP, ares_parse_aaaa_reply(data.data(), data.size(),
                                                 &host, info, &count));
  EXPECT_EQ(nullptr, host);

  // Question != answer
  pkt.add_question(new DNSQuestion("Axample.com", ns_t_aaaa));
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_aaaa_reply(data.data(), data.size(),
                                                &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", ns_t_aaaa));

  // 2 questions
  pkt.add_question(new DNSQuestion("example.com", ns_t_aaaa));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_aaaa_reply(data.data(), data.size(),
                                                 &host, info, &count));
  EXPECT_EQ(nullptr, host);

  // Wrong sort of answer.
  pkt.answers_.clear();
  pkt.add_answer(new DNSMxRR("example.com", 0x01020304, 100, "mx1.example.com"));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_aaaa_reply(data.data(), data.size(),
                                                  &host, info, &count));
  EXPECT_EQ(nullptr, host);

  // No answer
  pkt.answers_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_aaaa_reply(data.data(), data.size(),
                                                 &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.add_answer(new DNSAaaaRR("example.com", 0x01020304,
                              {0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                               0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04}));

  // Truncated packets.
  data = pkt.data();
  for (size_t len = 1; len < data.size(); len++) {
    EXPECT_EQ(ARES_EBADRESP, ares_parse_aaaa_reply(data.data(), len,
                                                   &host, info, &count));
    EXPECT_EQ(nullptr, host);
  }
}

TEST_F(LibraryTest, ParsePtrReplyOK) {
  byte addrv4[4] = {0x10, 0x20, 0x30, 0x40};
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("64.48.32.16.in-addr.arpa", ns_t_ptr))
    .add_answer(new DNSPtrRR("64.48.32.16.in-addr.arpa", 0x01020304, "other.com"));
  std::vector<byte> data = pkt.data();

  struct hostent *host = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_ptr_reply(data.data(), data.size(),
                                               addrv4, sizeof(addrv4), AF_INET, &host));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'other.com' aliases=[other.com] addrs=[16.32.48.64]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseNsReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_ns))
    .add_answer(new DNSNsRR("example.com", 0x01020304, "ns.example.com"));
  std::vector<byte> data = pkt.data();

  struct hostent *host = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_ns_reply(data.data(), data.size(), &host));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'example.com' aliases=[ns.example.com] addrs=[]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseSrvReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_srv))
    .add_answer(new DNSSrvRR("example.com", 0x01020304, 10, 20, 30, "srv.example.com"))
    .add_answer(new DNSSrvRR("example.com", 0x01020304, 11, 21, 31, "srv2.example.com"));
  std::vector<byte> data = pkt.data();

  struct ares_srv_reply* srv = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_srv_reply(data.data(), data.size(), &srv));
  ASSERT_NE(nullptr, srv);

  EXPECT_EQ("srv.example.com", std::string(srv->host));
  EXPECT_EQ(10, srv->priority);
  EXPECT_EQ(20, srv->weight);
  EXPECT_EQ(30, srv->port);

  struct ares_srv_reply* srv2 = srv->next;
  ASSERT_NE(nullptr, srv2);
  EXPECT_EQ("srv2.example.com", std::string(srv2->host));
  EXPECT_EQ(11, srv2->priority);
  EXPECT_EQ(21, srv2->weight);
  EXPECT_EQ(31, srv2->port);
  EXPECT_EQ(nullptr, srv2->next);

  ares_free_data(srv);
}

TEST_F(LibraryTest, ParseMxReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_mx))
    .add_answer(new DNSMxRR("example.com", 0x01020304, 100, "mx1.example.com"))
    .add_answer(new DNSMxRR("example.com", 0x01020304, 200, "mx2.example.com"));
  std::vector<byte> data = pkt.data();

  struct ares_mx_reply* mx = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_mx_reply(data.data(), data.size(), &mx));
  ASSERT_NE(nullptr, mx);
  EXPECT_EQ("mx1.example.com", std::string(mx->host));
  EXPECT_EQ(100, mx->priority);

  struct ares_mx_reply* mx2 = mx->next;
  ASSERT_NE(nullptr, mx2);
  EXPECT_EQ("mx2.example.com", std::string(mx2->host));
  EXPECT_EQ(200, mx2->priority);
  EXPECT_EQ(nullptr, mx2->next);

  ares_free_data(mx);
}

TEST_F(LibraryTest, ParseTxtReplyOK) {
  DNSPacket pkt;
  std::string expected1 = "txt1.example.com";
  std::string expected2a = "txt2a";
  std::string expected2b("ABC\0ABC", 7);
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_mx))
    .add_answer(new DNSTxtRR("example.com", 0x01020304, {expected1}))
    .add_answer(new DNSTxtRR("example.com", 0x01020304, {expected2a, expected2b}));
  std::vector<byte> data = pkt.data();

  struct ares_txt_reply* txt = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_txt_reply(data.data(), data.size(), &txt));
  ASSERT_NE(nullptr, txt);
  EXPECT_EQ(std::vector<byte>(expected1.data(), expected1.data() + expected1.size()),
            std::vector<byte>(txt->txt, txt->txt + txt->length));

  struct ares_txt_reply* txt2 = txt->next;
  ASSERT_NE(nullptr, txt2);
  EXPECT_EQ(std::vector<byte>(expected2a.data(), expected2a.data() + expected2a.size()),
            std::vector<byte>(txt2->txt, txt2->txt + txt2->length));

  struct ares_txt_reply* txt3 = txt2->next;
  ASSERT_NE(nullptr, txt3);
  EXPECT_EQ(std::vector<byte>(expected2b.data(), expected2b.data() + expected2b.size()),
            std::vector<byte>(txt3->txt, txt3->txt + txt3->length));
  EXPECT_EQ(nullptr, txt3->next);

  ares_free_data(txt);
}

TEST_F(LibraryTest, ParseTxtReplyErrors) {
  DNSPacket pkt;
  std::string expected1 = "txt1.example.com";
  std::string expected2a = "txt2a";
  std::string expected2b = "txt2b";
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_mx))
    .add_answer(new DNSTxtRR("example.com", 0x01020304, {expected1}))
    .add_answer(new DNSTxtRR("example.com", 0x01020304, {expected1}))
    .add_answer(new DNSTxtRR("example.com", 0x01020304, {expected2a, expected2b}));
  std::vector<byte> data = pkt.data();
  struct ares_txt_reply* txt = nullptr;

  // Truncated packets.
  for (size_t len = 1; len < data.size(); len++) {
    txt = nullptr;
    EXPECT_NE(ARES_SUCCESS, ares_parse_txt_reply(data.data(), len, &txt));
    EXPECT_EQ(nullptr, txt);
  }

  // No question
  pkt.questions_.clear();
  data = pkt.data();
  txt = nullptr;
  EXPECT_EQ(ARES_EBADRESP, ares_parse_txt_reply(data.data(), data.size(), &txt));
  EXPECT_EQ(nullptr, txt);
  pkt.add_question(new DNSQuestion("example.com", ns_t_mx));

  // No answer
  pkt.answers_.clear();
  data = pkt.data();
  txt = nullptr;
  EXPECT_EQ(ARES_ENODATA, ares_parse_txt_reply(data.data(), data.size(), &txt));
  EXPECT_EQ(nullptr, txt);
  pkt.add_answer(new DNSTxtRR("example.com", 0x01020304, {expected1}));
}

TEST_F(LibraryTest, ParseSoaReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_soa))
    .add_answer(new DNSSoaRR("example.com", 0x01020304,
                             "soa1.example.com", "fred.example.com",
                             1, 2, 3, 4, 5));
  std::vector<byte> data = pkt.data();

  struct ares_soa_reply* soa = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_soa_reply(data.data(), data.size(), &soa));
  ASSERT_NE(nullptr, soa);
  EXPECT_EQ("soa1.example.com", std::string(soa->nsname));
  EXPECT_EQ("fred.example.com", std::string(soa->hostmaster));
  EXPECT_EQ(1, soa->serial);
  EXPECT_EQ(2, soa->refresh);
  EXPECT_EQ(3, soa->retry);
  EXPECT_EQ(4, soa->expire);
  EXPECT_EQ(5, soa->minttl);
  ares_free_data(soa);
}

TEST_F(LibraryTest, ParseNaptrReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_soa))
    .add_answer(new DNSNaptrRR("example.com", 0x01020304,
                               10, 20, "SP", "service", "regexp", "replace"));
  std::vector<byte> data = pkt.data();

  struct ares_naptr_reply* naptr = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_naptr_reply(data.data(), data.size(), &naptr));
  ASSERT_NE(nullptr, naptr);
  EXPECT_EQ("SP", std::string((char*)naptr->flags));
  EXPECT_EQ("service", std::string((char*)naptr->service));
  EXPECT_EQ("regexp", std::string((char*)naptr->regexp));
  EXPECT_EQ("replace", std::string((char*)naptr->replacement));
  EXPECT_EQ(10, naptr->order);
  EXPECT_EQ(20, naptr->preference);
  EXPECT_EQ(nullptr, naptr->next);

  ares_free_data(naptr);
}

TEST_F(LibraryTest, ParseRootName) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion(".", ns_t_a))
    .add_answer(new DNSARR(".", 0x01020304, {0x02, 0x03, 0x04, 0x05}));
  std::vector<byte> data = pkt.data();

  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), data.size(),
                                             &host, info, &count));
  EXPECT_EQ(1, count);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseIndirectRootName) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0xC0, 0x04,  // weird: pointer to a random zero earlier in the message
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0xC0, 0x04,
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };

  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), data.size(),
                                             &host, info, &count));
  EXPECT_EQ(1, count);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseEscapedName) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x05, 'a', '\\', 'b', '.', 'c',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0x05, 'a', '\\', 'b', '.', 'c',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), data.size(),
                                             &host, info, &count));
  EXPECT_EQ(1, count);
  HostEnt hent(host);
  std::stringstream ss;
  ss << hent;
  // The printable name is expanded with escapes.
  EXPECT_EQ(11, hent.name_.size());
  EXPECT_EQ('a', hent.name_[0]);
  EXPECT_EQ('\\', hent.name_[1]);
  EXPECT_EQ('\\', hent.name_[2]);
  EXPECT_EQ('b', hent.name_[3]);
  EXPECT_EQ('\\', hent.name_[4]);
  EXPECT_EQ('.', hent.name_[5]);
  EXPECT_EQ('c', hent.name_[6]);
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParsePartialCompressedName) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0x03, 'w', 'w', 'w',
    0xc0, 0x10,  // offset 16
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), data.size(),
                                             &host, info, &count));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseFullyCompressedName) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0xc0, 0x0c,  // offset 12
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), data.size(),
                                             &host, info, &count));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseFullyCompressedName2) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0xC0, 0x12,  // pointer to later in message
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), data.size(),
                                             &host, info, &count));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}

}  // namespace test
}  // namespace ares
