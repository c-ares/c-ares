#include "ares-test.h"
#include "dns-proto.h"

#include <sstream>
#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, ParseTxtReplyOK) {
  DNSPacket pkt;
  std::string expected1 = "txt1.example.com";
  std::string expected2a = "txt2a";
  std::string expected2b("ABC\0ABC", 7);
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_mx))
    .add_answer(new DNSTxtRR("example.com", 100, {expected1}))
    .add_answer(new DNSTxtRR("example.com", 100, {expected2a, expected2b}));
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
    .add_answer(new DNSTxtRR("example.com", 100, {expected1}))
    .add_answer(new DNSTxtRR("example.com", 100, {expected1}))
    .add_answer(new DNSTxtRR("example.com", 100, {expected2a, expected2b}));
  std::vector<byte> data = pkt.data();
  struct ares_txt_reply* txt = nullptr;

  // No question.
  pkt.questions_.clear();
  data = pkt.data();
  txt = nullptr;
  EXPECT_EQ(ARES_EBADRESP, ares_parse_txt_reply(data.data(), data.size(), &txt));
  EXPECT_EQ(nullptr, txt);
  pkt.add_question(new DNSQuestion("example.com", ns_t_mx));

#ifdef DISABLED
  // Question != answer
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("Axample.com", ns_t_txt));
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_txt_reply(data.data(), data.size(), &txt));
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", ns_t_txt));
#endif

  // Two questions.
  pkt.add_question(new DNSQuestion("example.com", ns_t_mx));
  data = pkt.data();
  txt = nullptr;
  EXPECT_EQ(ARES_EBADRESP, ares_parse_txt_reply(data.data(), data.size(), &txt));
  EXPECT_EQ(nullptr, txt);
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", ns_t_mx));

  // No answer.
  pkt.answers_.clear();
  data = pkt.data();
  txt = nullptr;
  EXPECT_EQ(ARES_ENODATA, ares_parse_txt_reply(data.data(), data.size(), &txt));
  EXPECT_EQ(nullptr, txt);
  pkt.add_answer(new DNSTxtRR("example.com", 100, {expected1}));

  // Truncated packets.
  for (size_t len = 1; len < data.size(); len++) {
    txt = nullptr;
    EXPECT_NE(ARES_SUCCESS, ares_parse_txt_reply(data.data(), len, &txt));
    EXPECT_EQ(nullptr, txt);
  }
}

TEST_F(LibraryTest, ParseTxtReplyAllocFail) {
  DNSPacket pkt;
  std::string expected1 = "txt1.example.com";
  std::string expected2a = "txt2a";
  std::string expected2b = "txt2b";
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_mx))
    .add_answer(new DNSCnameRR("example.com", 300, "c.example.com"))
    .add_answer(new DNSTxtRR("c.example.com", 100, {expected1}))
    .add_answer(new DNSTxtRR("c.example.com", 100, {expected1}))
    .add_answer(new DNSTxtRR("c.example.com", 100, {expected2a, expected2b}));
  std::vector<byte> data = pkt.data();
  struct ares_txt_reply* txt = nullptr;

  for (int ii = 1; ii <= 13; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(ARES_ENOMEM, ares_parse_txt_reply(data.data(), data.size(), &txt)) << ii;
  }
}


}  // namespace test
}  // namespace ares
