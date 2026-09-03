/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ares-test.h"
#include "dns-proto.h"

#include <sstream>
#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, ParseSrvReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_SRV))
    .add_answer(new DNSSrvRR("example.com", 100, 10, 20, 30, "srv.example.com"))
    .add_answer(new DNSSrvRR("example.com", 100, 11, 21, 31, "srv2.example.com"));
  std::vector<byte> data = pkt.data();

  struct ares_srv_reply* srv = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
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

// Real-world servers (Samba's AD DC internal DNS in particular) still send
// SRV replies with the TARGET name compressed via a pointer, even though
// RFC2782 tells senders not to do that. RFC3597 section 4 tells receivers to
// decompress it anyway, so this needs to keep parsing rather than bailing out
// with a bad-name error, or SRV-based service discovery against those servers
// breaks (this is what SSSD hit against Samba AD).
TEST_F(LibraryTest, ParseSrvReplyCompressedTarget) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x81, 0x80,  // response + AA
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question: example.com SRV IN
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x21,  // type SRV
    0x00, 0x01,  // class IN
    // Answer: name is a pointer back to the question name at offset 12
    0xc0, 0x0c,
    0x00, 0x21,  // type SRV
    0x00, 0x01,  // class IN
    0x00, 0x00, 0x00, 0x64,  // TTL
    0x00, 0x08,  // rdlength
    0x00, 0x0a,  // priority
    0x00, 0x14,  // weight
    0x00, 0x1e,  // port
    0xc0, 0x0c,  // target: also a pointer back to offset 12, i.e. "example.com"
  };
  struct ares_srv_reply* srv = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
  ASSERT_NE(nullptr, srv);
  EXPECT_EQ("example.com", std::string(srv->host));
  EXPECT_EQ(10, srv->priority);
  EXPECT_EQ(20, srv->weight);
  EXPECT_EQ(30, srv->port);
  ares_free_data(srv);
}

TEST_F(LibraryTest, ParseSrvReplySingle) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.abc.def.com", T_SRV))
    .add_answer(new DNSSrvRR("example.abc.def.com", 180, 0, 10, 8160, "example.abc.def.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else1.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else2.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else3.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else4.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else5.where.com"))
    .add_additional(new DNSARR("else2.where.com", 42, {172,19,0,1}))
    .add_additional(new DNSARR("else5.where.com", 42, {172,19,0,2}));
  std::vector<byte> data = pkt.data();

  struct ares_srv_reply* srv = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
  ASSERT_NE(nullptr, srv);

  EXPECT_EQ("example.abc.def.com", std::string(srv->host));
  EXPECT_EQ(0, srv->priority);
  EXPECT_EQ(10, srv->weight);
  EXPECT_EQ(8160, srv->port);
  EXPECT_EQ(nullptr, srv->next);

  ares_free_data(srv);
}

TEST_F(LibraryTest, ParseSrvReplyMalformed) {
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
    0x00, 0x21,  // type SRV
    0x00, 0x01,  // class IN
    // Answer 1
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x21,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length -- too short
    0x02, 0x03, 0x04, 0x05,
  };

  struct ares_srv_reply* srv = nullptr;
  EXPECT_EQ(ARES_EBADRESP, ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
  ASSERT_EQ(nullptr, srv);
}

TEST_F(LibraryTest, ParseSrvReplyMultiple) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_ra().set_rd()
    .add_question(new DNSQuestion("srv.example.com", T_SRV))
    .add_answer(new DNSSrvRR("srv.example.com", 300, 0, 5, 6789, "a1.srv.example.com"))
    .add_answer(new DNSSrvRR("srv.example.com", 300, 0, 5, 4567, "a2.srv.example.com"))
    .add_answer(new DNSSrvRR("srv.example.com", 300, 0, 5, 5678, "a3.srv.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns1.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns2.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns3.example.com"))
    .add_additional(new DNSARR("a1.srv.example.com", 300, {172,19,1,1}))
    .add_additional(new DNSARR("a2.srv.example.com", 300, {172,19,1,2}))
    .add_additional(new DNSARR("a3.srv.example.com", 300, {172,19,1,3}))
    .add_additional(new DNSARR("n1.example.com", 300, {172,19,0,1}))
    .add_additional(new DNSARR("n2.example.com", 300, {172,19,0,2}))
    .add_additional(new DNSARR("n3.example.com", 300, {172,19,0,3}));
  std::vector<byte> data = pkt.data();

  struct ares_srv_reply* srv0 = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_srv_reply(data.data(), (int)data.size(), &srv0));
  ASSERT_NE(nullptr, srv0);
  struct ares_srv_reply* srv = srv0;

  EXPECT_EQ("a1.srv.example.com", std::string(srv->host));
  EXPECT_EQ(0, srv->priority);
  EXPECT_EQ(5, srv->weight);
  EXPECT_EQ(6789, srv->port);
  EXPECT_NE(nullptr, srv->next);
  srv = srv->next;

  EXPECT_EQ("a2.srv.example.com", std::string(srv->host));
  EXPECT_EQ(0, srv->priority);
  EXPECT_EQ(5, srv->weight);
  EXPECT_EQ(4567, srv->port);
  EXPECT_NE(nullptr, srv->next);
  srv = srv->next;

  EXPECT_EQ("a3.srv.example.com", std::string(srv->host));
  EXPECT_EQ(0, srv->priority);
  EXPECT_EQ(5, srv->weight);
  EXPECT_EQ(5678, srv->port);
  EXPECT_EQ(nullptr, srv->next);

  ares_free_data(srv0);
}

TEST_F(LibraryTest, ParseSrvReplyCname) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.abc.def.com", T_SRV))
    .add_answer(new DNSCnameRR("example.abc.def.com", 300, "cname.abc.def.com"))
    .add_answer(new DNSSrvRR("cname.abc.def.com", 300, 0, 10, 1234, "srv.abc.def.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else1.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else2.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else3.where.com"))
    .add_additional(new DNSARR("example.abc.def.com", 300, {172,19,0,1}))
    .add_additional(new DNSARR("else1.where.com", 42, {172,19,0,1}))
    .add_additional(new DNSARR("else2.where.com", 42, {172,19,0,2}))
    .add_additional(new DNSARR("else3.where.com", 42, {172,19,0,3}));
  std::vector<byte> data = pkt.data();

  struct ares_srv_reply* srv = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
  ASSERT_NE(nullptr, srv);

  EXPECT_EQ("srv.abc.def.com", std::string(srv->host));
  EXPECT_EQ(0, srv->priority);
  EXPECT_EQ(10, srv->weight);
  EXPECT_EQ(1234, srv->port);
  EXPECT_EQ(nullptr, srv->next);

  ares_free_data(srv);
}

TEST_F(LibraryTest, ParseSrvReplyCnameMultiple) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_ra().set_rd()
    .add_question(new DNSQuestion("query.example.com", T_SRV))
    .add_answer(new DNSCnameRR("query.example.com", 300, "srv.example.com"))
    .add_answer(new DNSSrvRR("srv.example.com", 300, 0, 5, 6789, "a1.srv.example.com"))
    .add_answer(new DNSSrvRR("srv.example.com", 300, 0, 5, 4567, "a2.srv.example.com"))
    .add_answer(new DNSSrvRR("srv.example.com", 300, 0, 5, 5678, "a3.srv.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns1.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns2.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns3.example.com"))
    .add_additional(new DNSARR("a1.srv.example.com", 300, {172,19,1,1}))
    .add_additional(new DNSARR("a2.srv.example.com", 300, {172,19,1,2}))
    .add_additional(new DNSARR("a3.srv.example.com", 300, {172,19,1,3}))
    .add_additional(new DNSARR("n1.example.com", 300, {172,19,0,1}))
    .add_additional(new DNSARR("n2.example.com", 300, {172,19,0,2}))
    .add_additional(new DNSARR("n3.example.com", 300, {172,19,0,3}));
  std::vector<byte> data = pkt.data();

  struct ares_srv_reply* srv0 = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_srv_reply(data.data(), (int)data.size(), &srv0));
  ASSERT_NE(nullptr, srv0);
  struct ares_srv_reply* srv = srv0;

  EXPECT_EQ("a1.srv.example.com", std::string(srv->host));
  EXPECT_EQ(0, srv->priority);
  EXPECT_EQ(5, srv->weight);
  EXPECT_EQ(6789, srv->port);
  EXPECT_NE(nullptr, srv->next);
  srv = srv->next;

  EXPECT_EQ("a2.srv.example.com", std::string(srv->host));
  EXPECT_EQ(0, srv->priority);
  EXPECT_EQ(5, srv->weight);
  EXPECT_EQ(4567, srv->port);
  EXPECT_NE(nullptr, srv->next);
  srv = srv->next;

  EXPECT_EQ("a3.srv.example.com", std::string(srv->host));
  EXPECT_EQ(0, srv->priority);
  EXPECT_EQ(5, srv->weight);
  EXPECT_EQ(5678, srv->port);
  EXPECT_EQ(nullptr, srv->next);

  ares_free_data(srv0);
}

TEST_F(LibraryTest, ParseSrvReplyErrors) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.abc.def.com", T_SRV))
    .add_answer(new DNSSrvRR("example.abc.def.com", 180, 0, 10, 8160, "example.abc.def.com"));
  std::vector<byte> data;
  struct ares_srv_reply* srv = nullptr;

  // No question.
  pkt.questions_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
  pkt.add_question(new DNSQuestion("example.abc.def.com", T_SRV));

#ifdef DISABLED
  // Question != answer
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("Axample.com", T_SRV));
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", T_SRV));
#endif

  // Two questions.
  pkt.add_question(new DNSQuestion("example.abc.def.com", T_SRV));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("64.48.32.16.in-addr.arpa", T_PTR));

  // Wrong sort of answer.
  pkt.answers_.clear();
  pkt.add_answer(new DNSMxRR("example.com", 100, 100, "mx1.example.com"));
  data = pkt.data();
  EXPECT_EQ(ARES_SUCCESS, ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
  EXPECT_EQ(nullptr, srv);
  pkt.answers_.clear();
  pkt.add_answer(new DNSSrvRR("example.abc.def.com", 180, 0, 10, 8160, "example.abc.def.com"));

  // No answer.
  pkt.answers_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
  pkt.add_answer(new DNSSrvRR("example.abc.def.com", 180, 0, 10, 8160, "example.abc.def.com"));

  // Truncated packets.
  data = pkt.data();
  for (size_t len = 1; len < data.size(); len++) {
    int rc = ares_parse_srv_reply(data.data(), (int)len, &srv);
    EXPECT_TRUE(rc == ARES_EBADRESP || rc == ARES_EBADNAME);
  }

  // Negative Length
  EXPECT_EQ(ARES_EBADRESP, ares_parse_srv_reply(data.data(), -1, &srv));
}

TEST_F(LibraryTest, ParseSrvReplyAllocFail) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.abc.def.com", T_SRV))
    .add_answer(new DNSCnameRR("example.com", 300, "c.example.com"))
    .add_answer(new DNSSrvRR("example.abc.def.com", 180, 0, 10, 8160, "example.abc.def.com"));
  std::vector<byte> data = pkt.data();
  struct ares_srv_reply* srv = nullptr;

  for (int ii = 1; ii <= 5; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(ARES_ENOMEM, ares_parse_srv_reply(data.data(), (int)data.size(), &srv)) << ii;
  }
}

// RFC 2782: the SRV TARGET must not use name compression.  A response whose
// SRV target is a compression pointer must be rejected rather than followed.
// This used to be ParseSrvRejectsCompressedTarget, added alongside the
// original write-side "don't allow compression in RFC1035-unlisted RR types"
// change. Rejecting a compressed SRV TARGET on read matches what RFC2782
// asks senders not to do, but it isn't what RFC3597 section 4 asks receivers
// to do, and real DNS servers (Samba's AD DC among them) still send it
// compressed regardless. Once #1287 made that an interop-breaking regression
// for anyone resolving SRV records against those servers, this test's
// expectation flipped along with the fix: parsing a compressed SRV TARGET is
// expected to succeed and decompress correctly now, same as any other name.
TEST_F(LibraryTest, ParseSrvAcceptsCompressedTarget) {
  const unsigned char data[] = {
    0x12, 0x34,              // qid
    0x84, 0x00,              // response + AA, rcode NOERROR
    0x00, 0x01,              // qdcount
    0x00, 0x01,              // ancount
    0x00, 0x00,              // nscount
    0x00, 0x00,              // arcount
    // Question (name starts at offset 0x0c)
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x21,              // type SRV (33)
    0x00, 0x01,              // class IN
    // Answer
    0xc0, 0x0c,              // name -> pointer to example.com
    0x00, 0x21,              // type SRV
    0x00, 0x01,              // class IN
    0x00, 0x00, 0x00, 0x3c,  // TTL
    0x00, 0x08,              // rdlength
    0x00, 0x0a,              // priority
    0x00, 0x14,              // weight
    0x00, 0x1e,              // port
    0xc0, 0x0c,              // TARGET -> compression pointer, decompresses to example.com
  };

  ares_dns_record_t *dnsrec = NULL;
  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(data, sizeof(data), 0, &dnsrec));
  ASSERT_NE(nullptr, dnsrec);

  const ares_dns_rr_t *rr = ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, 0);
  ASSERT_NE(nullptr, rr);
  EXPECT_EQ(std::string("example.com"),
            std::string(ares_dns_rr_get_str(rr, ARES_RR_SRV_TARGET)));

  ares_dns_record_destroy(dnsrec);
}

}  // namespace test
}  // namespace ares
