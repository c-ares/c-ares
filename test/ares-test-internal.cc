#include "ares-test.h"
#include "dns-proto.h"

extern "C" {
#include "ares_nowarn.h"
#include "ares_inet_net_pton.h"
#include "bitncmp.h"
}

#include <string>
#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, InetPtoN) {
  struct in_addr a4;
  struct in6_addr a6;
#ifdef DISABLED
  EXPECT_EQ(1, ares_inet_net_pton(AF_INET, "1.2.3.4", &a4, sizeof(a4)));
  EXPECT_EQ(1, ares_inet_net_pton(AF_INET6, "12:34::ff", &a6, sizeof(a6)));
  EXPECT_EQ(1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(0, ares_inet_net_pton(AF_INET, "xyzzy", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET+AF_INET6, "1.2.3.4", &a4, sizeof(a4)));
#endif
  EXPECT_EQ(1, ares_inet_pton(AF_INET, "1.2.3.4", &a4));
  EXPECT_EQ(1, ares_inet_pton(AF_INET6, "12:34::ff", &a6));
  EXPECT_EQ(1, ares_inet_pton(AF_INET6, "12:34::ffff:1.2.3.4", &a6));
  EXPECT_EQ(0, ares_inet_pton(AF_INET, "xyzzy", &a4));
  EXPECT_EQ(-1, ares_inet_pton(AF_INET+AF_INET6, "1.2.3.4", &a4));
}

#ifdef DISABLED
TEST(Misc, Bitncmp) {
  byte a[4] = {0x80, 0x01, 0x02, 0x03};
  byte b[4] = {0x80, 0x01, 0x02, 0x04};
  EXPECT_EQ(-1, ares__bitncmp(a, b, sizeof(a)*8));
  EXPECT_EQ(1, ares__bitncmp(b, a, sizeof(a)*8));
  EXPECT_EQ(0, ares__bitncmp(a, a, sizeof(a)*8));
}

TEST_F(LibraryTest, Casts) {
  ssize_t ssz = 100;
  unsigned int u = 100;
  int i = 100;

  unsigned int ru = aresx_sztoui(ssz);
  EXPECT_EQ(u, ru);
  int ri = aresx_sztosi(ssz);
  EXPECT_EQ(i, ri);
}
#endif


}  // namespace test
}  // namespace ares
