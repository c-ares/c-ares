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

#include <cstring>
#include <sstream>
#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, ParseNameExactly255WireOctets) {
  std::vector<byte> data;
  ares_dns_record_t *dnsrec = nullptr;
  const char        *qname  = nullptr;

  PushInt16(&data, 0x1234);
  PushInt16(&data, 0x8400);
  PushInt16(&data, 1);
  PushInt16(&data, 0);
  PushInt16(&data, 0);
  PushInt16(&data, 0);

  /* QNAME: 63+63+63+61 labels => 255 octets on wire including root */
  data.push_back(63);
  data.insert(data.end(), 63, 'a');
  data.push_back(63);
  data.insert(data.end(), 63, 'b');
  data.push_back(63);
  data.insert(data.end(), 63, 'c');
  data.push_back(61);
  data.insert(data.end(), 61, 'd');
  data.push_back(0);

  PushInt16(&data, T_A);
  PushInt16(&data, C_IN);

  EXPECT_EQ(ARES_SUCCESS,
            ares_dns_parse(data.data(), data.size(), 0, &dnsrec));

  ASSERT_NE(nullptr, dnsrec);
  EXPECT_EQ(ARES_SUCCESS,
            ares_dns_record_query_get(dnsrec, 0, &qname, nullptr, nullptr));
  ASSERT_NE(nullptr, qname);
  EXPECT_EQ(253U, std::strlen(qname));

  if (dnsrec != nullptr) {
    ares_dns_record_destroy(dnsrec);
  }
}

TEST_F(LibraryTest, ParseNameOver255WireOctetsViaCompression) {
  std::vector<byte> data;
  ares_dns_record_t *dnsrec = nullptr;
  const byte         qname_offset = 0x0C;

  PushInt16(&data, 0x1234);
  PushInt16(&data, 0x8400);
  PushInt16(&data, 1);
  PushInt16(&data, 1);
  PushInt16(&data, 0);
  PushInt16(&data, 0);

  /* Question name that is exactly 255 octets on wire */
  data.push_back(63);
  data.insert(data.end(), 63, 'a');
  data.push_back(63);
  data.insert(data.end(), 63, 'b');
  data.push_back(63);
  data.insert(data.end(), 63, 'c');
  data.push_back(61);
  data.insert(data.end(), 61, 'd');
  data.push_back(0);

  PushInt16(&data, T_A);
  PushInt16(&data, C_IN);

  // Answer name: label 'x' + pointer to original question name
  // Compression pointer points to offset 12 (start of QNAME)
  data.push_back(0x01);
  data.push_back('x');
  data.push_back(0xC0);
  data.push_back(qname_offset);

  // RR TYPE, CLASS, TTL, RDLENGTH, RDATA
  PushInt16(&data, T_A);
  PushInt16(&data, C_IN);
  PushInt32(&data, 60);
  PushInt16(&data, 4);
  data.push_back(1);
  data.push_back(2);
  data.push_back(3);
  data.push_back(4);

  // Valid DNS packet; failure must be due to expanded name >255
  EXPECT_EQ(ARES_EBADNAME,
            ares_dns_parse(data.data(), data.size(), 0, &dnsrec));

  if (dnsrec != nullptr) {
    ares_dns_record_destroy(dnsrec);
  }
}

TEST_F(LibraryTest, ParseRootName) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion(".", T_A))
    .add_answer(new DNSARR(".", 100, {0x02, 0x03, 0x04, 0x05}));
  std::vector<byte> data = pkt.data();

  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
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
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  EXPECT_EQ(1, count);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}


#if 0 /* We are validating hostnames now, its not clear how this would ever be valid */
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
#endif

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
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
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
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, DNSParseNormalCompressedName) {
  std::vector<byte> data;
  ares_dns_record_t *dnsrec = nullptr;

  PushInt16(&data, 0x1234);
  PushInt16(&data, 0x8400);
  PushInt16(&data, 1);
  PushInt16(&data, 1);
  PushInt16(&data, 0);
  PushInt16(&data, 0);

  data.push_back(0x03);
  data.push_back('w');
  data.push_back('w');
  data.push_back('w');
  data.push_back(0x07);
  data.push_back('e');
  data.push_back('x');
  data.push_back('a');
  data.push_back('m');
  data.push_back('p');
  data.push_back('l');
  data.push_back('e');
  data.push_back(0x03);
  data.push_back('c');
  data.push_back('o');
  data.push_back('m');
  data.push_back(0x00);

  PushInt16(&data, T_A);
  PushInt16(&data, C_IN);

  // Answer NAME via backward compression pointer to QNAME at offset 12
  data.push_back(0xC0);
  data.push_back(0x0C);
  PushInt16(&data, T_A);
  PushInt16(&data, C_IN);
  PushInt32(&data, 0x01020304);
  PushInt16(&data, 4);
  data.push_back(0x02);
  data.push_back(0x03);
  data.push_back(0x04);
  data.push_back(0x05);

  EXPECT_EQ(ARES_SUCCESS,
            ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  ASSERT_NE(nullptr, dnsrec);
  EXPECT_EQ(1U, ares_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(1U, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER));

  if (dnsrec != nullptr) {
    ares_dns_record_destroy(dnsrec);
  }
}


}  // namespace test
}  // namespace ares
