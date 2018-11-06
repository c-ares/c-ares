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
      public ::testing::WithParamInterface< std::pair<int, bool> > {
 public:
  MockChannelTestAI() : MockChannelOptsTest(1, GetParam().first, GetParam().second, nullptr, 0) {}
};

// Structure that describes the result of an ares_addr_callback invocation.
struct AIResult {
  // Whether the callback has been invoked.
  bool done;
  // Explicitly provided result information.
  int status;
  // Contents of the ares_addrinfo structure, if provided.
  struct ares_addrinfo* airesult;
};

}
}

#endif
