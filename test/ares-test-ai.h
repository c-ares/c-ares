/*
 * Copyright (C) The c-ares project
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef ARES_TEST_AI_H
#define ARES_TEST_AI_H

#include <utility>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "ares-test.h"

namespace ares {
namespace test {

class MockChannelTestAI
  : public MockChannelOptsTest,
    public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  MockChannelTestAI()
    : MockChannelOptsTest(1, GetParam().first, GetParam().second, nullptr, 0)
  {
  }
};

class MockUDPChannelTestAI : public MockChannelOptsTest,
                             public ::testing::WithParamInterface<int> {
public:
  MockUDPChannelTestAI() : MockChannelOptsTest(1, GetParam(), false, nullptr, 0)
  {
  }
};

class MockUDPChannelSingleRetryServerTestAI : public MockChannelOptsTest,
                             public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  MockUDPChannelSingleRetryServerTestAI() : MockChannelOptsTest(3, GetParam().first, GetParam().second, FillOptions(),
        ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS |
        ARES_OPT_TRIES | ARES_OPT_DOMAINS |
        ARES_OPT_LOOKUPS | ARES_OPT_SOCK_STATE_CB) {
    okrsp.set_response().set_aa()
        .add_question(new DNSQuestion("example.com", T_A))
        .add_answer(new DNSARR("example.com", 100, {2,3,4,5}));

    okrspv6.set_response().set_aa()
      .add_question(new DNSQuestion("example.com", T_AAAA))
      .add_answer(new DNSAaaaRR("example.com", 100,
                                {0x21, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03}));
  }

  static struct ares_options* FillOptions() {
    static struct ares_options opts;
    memset(&opts, 0, sizeof(struct ares_options));
    opts.tries = 1;
    opts.flags = ARES_FLAG_STAYOPEN |  // do not close idle sockets
                 ARES_FLAG_NOALIASES;  // ignore HOSTALIASES from env
    opts.lookups = const_cast<char*>("b");  // network lookups only
    return &opts;
  }

  void PutServerDown(int index) {
    std::vector<byte> nothing;
    ON_CALL(*servers_[index], OnRequest("example.com", T_A))
      .WillByDefault(SetReplyData(servers_[index].get(), nothing));
    ON_CALL(*servers_[index], OnRequest("example.com", T_AAAA))
      .WillByDefault(SetReplyData(servers_[index].get(), nothing));
  }

  void PutServerUp(int index) {
    ON_CALL(*servers_[index], OnRequest("example.com", T_A))
      .WillByDefault(SetReply(servers_[index].get(), &okrsp));
    ON_CALL(*servers_[index], OnRequest("example.com", T_AAAA))
      .WillByDefault(SetReply(servers_[index].get(), &okrspv6));
  }

  const char* TwoAddrsString() {
    return "{addr=[2.3.4.5], addr=[[2121:0000:0000:0000:0000:0000:0000:0303]]}";
  }
private:
  DNSPacket okrsp;
  DNSPacket okrspv6;
};

class MockTCPChannelTestAI : public MockChannelOptsTest,
                             public ::testing::WithParamInterface<int> {
public:
  MockTCPChannelTestAI() : MockChannelOptsTest(1, GetParam(), true, nullptr, 0)
  {
  }
};

// Test fixture that uses a default channel.
class DefaultChannelTestAI : public LibraryTest {
public:
  DefaultChannelTestAI() : channel_(nullptr)
  {
    EXPECT_EQ(ARES_SUCCESS, ares_init(&channel_));
    EXPECT_NE(nullptr, channel_);
  }

  ~DefaultChannelTestAI()
  {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  // Process all pending work on ares-owned file descriptors.
  void Process();

protected:
  ares_channel_t *channel_;
};

}  // namespace test
}  // namespace ares

#endif
