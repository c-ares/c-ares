#include "ares-test.h"

extern "C" int ares_test_wake_pipe(int);

namespace ares {
namespace test {

TEST(WakePipeTest, SuccessPreservesFlags)
{
  int result = ares_test_wake_pipe(-1);
  if (result == -2) {
    GTEST_SKIP();
  }
  EXPECT_EQ(0, result);
}

TEST(WakePipeTest, FcntlFailures)
{
  for (int i = 0; i <= 5; i++) {
    SCOPED_TRACE(i);
    int result = ares_test_wake_pipe(i);
    if (result == -2) {
      GTEST_SKIP();
    }
    EXPECT_EQ(0, result);
  }
}

}  // namespace test
}  // namespace ares
