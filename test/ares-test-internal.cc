#include "ares-test.h"
#include "dns-proto.h"

extern "C" {
// Remove command-line defines of package variables for the test project...
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
// ... so we can include the library's config without symbol redefinitions.
#include "ares_config.h"
#include "ares_nowarn.h"
#include "ares_inet_net_pton.h"
#include "ares_data.h"
#include "bitncmp.h"
char *ares_strdup(const char*);

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
}

#include <string>
#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, InetPtoN) {
  struct in_addr a4;
  struct in6_addr a6;

#ifndef CARES_SYMBOL_HIDING
  EXPECT_EQ(4 * 8, ares_inet_net_pton(AF_INET, "1.2.3.4", &a4, sizeof(a4)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "12:34::ff", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "xyzzy", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET+AF_INET6, "1.2.3.4", &a4, sizeof(a4)));
#endif

  EXPECT_EQ(1, ares_inet_pton(AF_INET, "1.2.3.4", &a4));
  EXPECT_EQ(1, ares_inet_pton(AF_INET6, "12:34::ff", &a6));
  EXPECT_EQ(1, ares_inet_pton(AF_INET6, "12:34::ffff:1.2.3.4", &a6));
  EXPECT_EQ(0, ares_inet_pton(AF_INET, "xyzzy", &a4));
  EXPECT_EQ(-1, ares_inet_pton(AF_INET+AF_INET6, "1.2.3.4", &a4));
}

TEST_F(LibraryTest, FreeCorruptData) {
  // ares_free_data(p) expects that there is a type field and a marker
  // field in the memory before p.  Feed it incorrect versions of each.
  struct ares_data *data = (struct ares_data *)malloc(sizeof(struct ares_data));
  void* p = &(data->data);

  // Invalid type
  data->type = (ares_datatype)99;
  data->mark = ARES_DATATYPE_MARK;
  ares_free_data(p);

  // Invalid marker
  data->type = (ares_datatype)ARES_DATATYPE_MX_REPLY;
  data->mark = ARES_DATATYPE_MARK + 1;
  ares_free_data(p);

  // Null pointer
  ares_free_data(nullptr);

  free(data);
}

#ifndef CARES_SYMBOL_HIDING
TEST(LibraryInit, StrdupFailures) {
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  char* copy = ares_strdup("string");
  EXPECT_NE(nullptr, copy);
  free(copy);
  ares_library_cleanup();
}

TEST_F(LibraryTest, StrdupFailures) {
  SetAllocFail(1);
  char* copy = ares_strdup("string");
  EXPECT_EQ(nullptr, copy);
}

TEST_F(LibraryTest, MallocDataFail) {
  EXPECT_EQ(nullptr, ares_malloc_data((ares_datatype)99));
  SetAllocSizeFail(sizeof(struct ares_data));
  EXPECT_EQ(nullptr, ares_malloc_data(ARES_DATATYPE_MX_REPLY));
}

TEST(Misc, Bitncmp) {
  byte a[4] = {0x80, 0x01, 0x02, 0x03};
  byte b[4] = {0x80, 0x01, 0x02, 0x04};
  byte c[4] = {0x01, 0xFF, 0x80, 0x02};
  EXPECT_GT(0, ares__bitncmp(a, b, sizeof(a)*8));
  EXPECT_LT(0, ares__bitncmp(b, a, sizeof(a)*8));
  EXPECT_EQ(0, ares__bitncmp(a, a, sizeof(a)*8));

  for (int ii = 1; ii < (3*8+5); ii++) {
    EXPECT_EQ(0, ares__bitncmp(a, b, ii));
    EXPECT_EQ(0, ares__bitncmp(b, a, ii));
    EXPECT_LT(0, ares__bitncmp(a, c, ii));
    EXPECT_GT(0, ares__bitncmp(c, a, ii));
  }

  // Last byte differs at 5th bit
  EXPECT_EQ(0, ares__bitncmp(a, b, 3*8 + 3));
  EXPECT_EQ(0, ares__bitncmp(a, b, 3*8 + 4));
  EXPECT_EQ(0, ares__bitncmp(a, b, 3*8 + 5));
  EXPECT_GT(0, ares__bitncmp(a, b, 3*8 + 6));
  EXPECT_GT(0, ares__bitncmp(a, b, 3*8 + 7));
}

TEST_F(LibraryTest, Casts) {
  ssize_t ssz = 100;
  unsigned int u = 100;
  int i = 100;
  long l = 100;

  unsigned int ru = aresx_sztoui(ssz);
  EXPECT_EQ(u, ru);
  int ri = aresx_sztosi(ssz);
  EXPECT_EQ(i, ri);

  ri = aresx_sltosi(l);
  EXPECT_EQ(l, (long)ri);
}
#endif

}  // namespace test
}  // namespace ares
