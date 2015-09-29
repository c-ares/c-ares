#include "ares-test.h"
#include "dns-proto.h"

#include <string>
#include <vector>

namespace ares {
namespace test {

std::vector<std::string> GetNameServers(ares_channel channel) {
  struct ares_addr_node* servers = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_get_servers(channel, &servers));
  struct ares_addr_node* server = servers;
  std::vector<std::string> results;
  while (server) {
    switch (server->family) {
    case AF_INET:
      results.push_back(AddressToString((char*)&server->addr.addr4, 4));
      break;
    case AF_INET6:
      results.push_back(AddressToString((char*)&server->addr.addr6, 16));
      break;
    default:
      results.push_back("<unknown family>");
      break;
    }
    server = server->next;
  }
  ares_free_data(servers);
  return results;
}

TEST_F(DefaultChannelTest, GetServers) {
  std::vector<std::string> servers = GetNameServers(channel_);
  if (verbose) {
    for (const std::string& server : servers) {
      std::cerr << "Nameserver: " << server << std::endl;
    }
  }
}

TEST_F(DefaultChannelTest, SetServers) {
  EXPECT_EQ(ARES_SUCCESS, ares_set_servers(channel_, nullptr));
  std::vector<std::string> empty;
  EXPECT_EQ(empty, GetNameServers(channel_));

  struct ares_addr_node server1;
  struct ares_addr_node server2;
  server1.next = &server2;
  server1.family = AF_INET;
  server1.addr.addr4.s_addr = htonl(0x01020304);
  server2.next = nullptr;
  server2.family = AF_INET;
  server2.addr.addr4.s_addr = htonl(0x02030405);
  EXPECT_EQ(ARES_ENODATA, ares_set_servers(nullptr, &server1));

  EXPECT_EQ(ARES_SUCCESS, ares_set_servers(channel_, &server1));
  std::vector<std::string> expected = {"1.2.3.4", "2.3.4.5"};
  EXPECT_EQ(expected, GetNameServers(channel_));
}

TEST_F(DefaultChannelTest, SetServersCSV) {
  EXPECT_EQ(ARES_ENODATA, ares_set_servers_csv(nullptr, "1.2.3.4"));
  EXPECT_EQ(ARES_ENODATA, ares_set_servers_csv(nullptr, "xyzzy,plugh"));
  EXPECT_EQ(ARES_ENODATA, ares_set_servers_csv(nullptr, "256.1.2.3"));
  EXPECT_EQ(ARES_ENODATA, ares_set_servers_csv(nullptr, "1.2.3.4.5"));
  EXPECT_EQ(ARES_ENODATA, ares_set_servers_csv(nullptr, "1:2:3:4:5"));

  EXPECT_EQ(ARES_SUCCESS,
            ares_set_servers_csv(channel_, "1.2.3.4,0102:0304:0506:0708:0910:1112:1314:1516,2.3.4.5"));
  std::vector<std::string> expected = {"1.2.3.4", "0102:0304:0506:0708:0910:1112:1314:1516", "2.3.4.5"};
  EXPECT_EQ(expected, GetNameServers(channel_));

  // Same, with spaces
  EXPECT_EQ(ARES_EBADSTR,
            ares_set_servers_csv(channel_, "1.2.3.4 , 0102:0304:0506:0708:0910:1112:1314:1516, 2.3.4.5"));

  // Same, with ports -- currently ignored
  EXPECT_EQ(ARES_SUCCESS,
            ares_set_servers_csv(channel_, "1.2.3.4:54,[0102:0304:0506:0708:0910:1112:1314:1516]:80,2.3.4.5:55"));
  EXPECT_EQ(expected, GetNameServers(channel_));
}

TEST_F(DefaultChannelTest, TimeoutValue) {
  struct timeval tinfo;
  tinfo.tv_sec = 0;
  tinfo.tv_usec = 0;
  struct timeval tmax;
  tmax.tv_sec = 0;
  tmax.tv_usec = 10;
  struct timeval* pt;

  // No timers => get max back.
  pt = ares_timeout(channel_, &tmax, &tinfo);
  EXPECT_EQ(&tmax, pt);
  EXPECT_EQ(0, pt->tv_sec);
  EXPECT_EQ(10, pt->tv_usec);

  pt = ares_timeout(channel_, nullptr, &tinfo);
  EXPECT_EQ(nullptr, pt);

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);

  // Now there's a timer running.
  pt = ares_timeout(channel_, &tmax, &tinfo);
  EXPECT_EQ(&tmax, pt);
  EXPECT_EQ(0, pt->tv_sec);
  EXPECT_EQ(10, pt->tv_usec);

  tmax.tv_sec = 100;
  pt = ares_timeout(channel_, &tmax, &tinfo);
  EXPECT_EQ(&tinfo, pt);

  pt = ares_timeout(channel_, nullptr, &tinfo);
  EXPECT_EQ(&tinfo, pt);

  Process();
}

TEST_F(LibraryTest, InetNtoP) {
  struct in_addr addr;
  addr.s_addr = htonl(0x01020304);
  char buffer[256];
  EXPECT_EQ(buffer, ares_inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)));
  EXPECT_EQ("1.2.3.4", std::string(buffer));
}

TEST_F(LibraryTest, Mkquery) {
  byte* p;
  int len;
  ares_mkquery("example.com", ns_c_in, ns_t_a, 0x1234, 0, &p, &len);
  std::vector<byte> data(p, p + len);
  ares_free_string(p);

  std::string actual = PacketToString(data);
  DNSPacket pkt;
  pkt.set_qid(0x1234).add_question(new DNSQuestion("example.com", ns_t_a));
  std::string expected = PacketToString(pkt.data());
  EXPECT_EQ(expected, actual);
}

TEST_F(LibraryTest, CreateQuery) {
  byte* p;
  int len;
  ares_create_query("exam\\@le.com", ns_c_in, ns_t_a, 0x1234, 0, &p, &len, 0);
  std::vector<byte> data(p, p + len);
  ares_free_string(p);

  std::string actual = PacketToString(data);
  DNSPacket pkt;
  pkt.set_qid(0x1234).add_question(new DNSQuestion("exam@le.com", ns_t_a));
  std::string expected = PacketToString(pkt.data());
  EXPECT_EQ(expected, actual);
}

TEST_F(LibraryTest, CreateEDNSQuery) {
  byte* p;
  int len;
  ares_create_query("example.com", ns_c_in, ns_t_a, 0x1234, 0, &p, &len, 1280);
  std::vector<byte> data(p, p + len);
  ares_free_string(p);

  std::string actual = PacketToString(data);
  DNSPacket pkt;
  pkt.set_qid(0x1234).add_question(new DNSQuestion("example.com", ns_t_a))
    .add_additional(new DNSOptRR(0, 1280));
  std::string expected = PacketToString(pkt.data());
  EXPECT_EQ(expected, actual);
}

TEST_F(LibraryTest, CreateRootQuery) {
  byte* p;
  int len;
  ares_create_query(".", ns_c_in, ns_t_a, 0x1234, 0, &p, &len, 0);
  std::vector<byte> data(p, p + len);
  ares_free_string(p);

  std::string actual = PacketToString(data);
  DNSPacket pkt;
  pkt.set_qid(0x1234).add_question(new DNSQuestion("", ns_t_a));
  std::string expected = PacketToString(pkt.data());
  EXPECT_EQ(expected, actual);
}

TEST_F(LibraryTest, Version) {
  // Assume linked to same version
  EXPECT_EQ(std::string(ARES_VERSION_STR),
            std::string(ares_version(nullptr)));
  int version;
  ares_version(&version);
  EXPECT_EQ(ARES_VERSION, version);
}

TEST_F(LibraryTest, Strerror) {
  EXPECT_EQ("Successful completion",
            std::string(ares_strerror(ARES_SUCCESS)));
  EXPECT_EQ("DNS query cancelled",
            std::string(ares_strerror(ARES_ECANCELLED)));
  EXPECT_EQ("unknown",
            std::string(ares_strerror(99)));
}

TEST_F(LibraryTest, ExpandString) {
  std::vector<byte> s1 = { 3, 'a', 'b', 'c'};
  char* result;
  long len;
  EXPECT_EQ(ARES_SUCCESS,
            ares_expand_string(s1.data(), s1.data(), s1.size(),
                               (unsigned char**)&result, &len));
  EXPECT_EQ("abc", std::string(result));
  EXPECT_EQ(1 + 3, len);  // amount of data consumed includes 1 byte len
  EXPECT_EQ(ARES_EBADSTR,
            ares_expand_string(s1.data() + 1, s1.data(), s1.size(),
                               (unsigned char**)&result, &len));
  EXPECT_EQ(ARES_EBADSTR,
            ares_expand_string(s1.data() + 4, s1.data(), s1.size(),
                               (unsigned char**)&result, &len));
}

}  // namespace test
}  // namespace ares
