// This file includes tests that attempt to do real lookups
// of DNS names using the local machine's live infrastructure.

#include "ares-test.h"

#include <netdb.h>

namespace ares {
namespace test {

TEST_F(DefaultChannelTest, LiveGetHostByNameV4) {
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET, result.host_.addrtype_);
}

TEST_F(DefaultChannelTest, LiveGetHostByNameV6) {
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET6, result.host_.addrtype_);
}

TEST_F(DefaultChannelTest, LiveGetHostByAddrV4) {
  HostResult result;
  unsigned char addr[4] = {8, 8, 8, 8};
  ares_gethostbyaddr(channel_, addr, sizeof(addr), AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET, result.host_.addrtype_);
}

TEST_F(DefaultChannelTest, LiveGetHostByAddrV6) {
  HostResult result;
  unsigned char addr[16] = {0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88};
  ares_gethostbyaddr(channel_, addr, sizeof(addr), AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET6, result.host_.addrtype_);
}

TEST_F(DefaultChannelTest, LiveGetHostByAddrFailFamily) {
  HostResult result;
  unsigned char addr[4] = {8, 8, 8, 8};
  ares_gethostbyaddr(channel_, addr, sizeof(addr), AF_INET6+AF_INET,
                     HostCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOTIMP, result.status_);
}

TEST_F(DefaultChannelTest, LiveGetHostByAddrFailAddrSize) {
  HostResult result;
  unsigned char addr[4] = {8, 8, 8, 8};
  ares_gethostbyaddr(channel_, addr, sizeof(addr) - 1, AF_INET,
                     HostCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOTIMP, result.status_);
}

TEST_F(DefaultChannelTest, LiveGetHostByAddrFailAlloc) {
  HostResult result;
  unsigned char addr[4] = {8, 8, 8, 8};
  SetAllocFail(1);
  ares_gethostbyaddr(channel_, addr, sizeof(addr), AF_INET,
                     HostCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOMEM, result.status_);
}

TEST_F(DefaultChannelTest, LiveSearchA) {
  SearchResult result;
  ares_search(channel_, "www.facebook.com.", ns_c_in, ns_t_a,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

TEST_F(DefaultChannelTest, LiveSearchNS) {
  SearchResult result;
  ares_search(channel_, "google.com.", ns_c_in, ns_t_ns,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

TEST_F(DefaultChannelTest, LiveSearchMX) {
  SearchResult result;
  ares_search(channel_, "google.com.", ns_c_in, ns_t_mx,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

TEST_F(DefaultChannelTest, LiveSearchTXT) {
  SearchResult result;
  ares_search(channel_, "google.com.", ns_c_in, ns_t_txt,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

TEST_F(DefaultChannelTest, LiveSearchSOA) {
  SearchResult result;
  ares_search(channel_, "google.com.", ns_c_in, ns_t_soa,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

TEST_F(DefaultChannelTest, LiveSearchANY) {
  SearchResult result;
  ares_search(channel_, "facebook.com.", ns_c_in, ns_t_any,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

TEST_F(DefaultChannelTest, LiveGetNameInfo) {
  NameInfoResult result;
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(53);
  sockaddr.sin_addr.s_addr = htonl(0x08080808);
  ares_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   ARES_NI_LOOKUPHOST|ARES_NI_LOOKUPSERVICE|ARES_NI_UDP,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

}  // namespace test
}  // namespace ares
