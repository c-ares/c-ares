
#include "ares-test.h"

// library initialization is only needed for windows builds
#ifdef USE_WINSOCK
#define EXPECTED_NONINIT ARES_ENOTINITIALIZED
#else
#define EXPECTED_NONINIT ARES_SUCCESS
#endif

namespace ares {
namespace test {

TEST(LibraryInit, Basic) {
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
}

TEST(LibraryInit, UnexpectedCleanup) {
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
}

TEST(LibraryInit, DISABLED_InvalidParam) {
  // TODO: police flags argument to ares_library_init()
  EXPECT_EQ(ARES_EBADQUERY, ares_library_init(ARES_LIB_INIT_ALL << 2));
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  ares_library_cleanup();
}

TEST(LibraryInit, Nested) {
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
}

TEST_F(LibraryTest, BasicChannelInit) {
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  ares_channel channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  EXPECT_NE(nullptr, channel);
  ares_destroy(channel);
  ares_library_cleanup();
}

TEST_F(LibraryTest, OptionsChannelInit) {
  struct ares_options opts = {0};
  int optmask = 0;
  opts.flags = ARES_FLAG_USEVC;
  optmask |= ARES_OPT_FLAGS;
  opts.timeout = 2000;
  optmask |= ARES_OPT_TIMEOUTMS;
  opts.tries = 2;
  optmask |= ARES_OPT_TRIES;
  opts.ndots = 4;
  optmask |= ARES_OPT_NDOTS;
  opts.udp_port = 54;
  optmask |= ARES_OPT_UDP_PORT;
  opts.tcp_port = 54;
  optmask |= ARES_OPT_TCP_PORT;
  opts.socket_send_buffer_size = 514;
  optmask |= ARES_OPT_SOCK_SNDBUF;
  opts.socket_receive_buffer_size = 514;
  optmask |= ARES_OPT_SOCK_RCVBUF;
  opts.ednspsz = 1280;
  optmask |= ARES_OPT_EDNSPSZ;
  opts.nservers = 2;
  opts.servers = (struct in_addr *)malloc(opts.nservers * sizeof(struct in_addr));
  opts.servers[0].s_addr = htonl(0x01020304);
  opts.servers[1].s_addr = htonl(0x02030405);
  optmask |= ARES_OPT_SERVERS;
  opts.ndomains = 2;
  opts.domains = (char **)malloc(opts.ndomains * sizeof(char *));
  opts.domains[0] = strdup("example.com");
  opts.domains[1] = strdup("example2.com");
  optmask |= ARES_OPT_DOMAINS;
  opts.lookups = strdup("b");
  optmask |= ARES_OPT_LOOKUPS;
  optmask |= ARES_OPT_ROTATE;

  ares_channel channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &opts, optmask));
  EXPECT_NE(nullptr, channel);

  ares_channel channel2 = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_dup(&channel2, channel));

  struct ares_options opts2 = {0};
  int optmask2 = 0;
  ares_save_options(channel2, &opts2, &optmask2);

  // Note that not all opts-settable fields are saved (e.g.
  // ednspsz, socket_{send,receive}_buffer_size).
  EXPECT_EQ(opts.flags, opts2.flags);
  EXPECT_EQ(opts.timeout, opts2.timeout);
  EXPECT_EQ(opts.tries, opts2.tries);
  EXPECT_EQ(opts.ndots, opts2.ndots);
  EXPECT_EQ(opts.udp_port, opts2.udp_port);
  EXPECT_EQ(opts.tcp_port, opts2.tcp_port);
  EXPECT_EQ(opts.nservers, opts2.nservers);
  EXPECT_EQ(opts.servers[0].s_addr, opts2.servers[0].s_addr);
  EXPECT_EQ(opts.servers[1].s_addr, opts2.servers[1].s_addr);
  EXPECT_EQ(opts.ndomains, opts2.ndomains);
  EXPECT_EQ(std::string(opts.domains[0]), std::string(opts2.domains[0]));
  EXPECT_EQ(std::string(opts.domains[1]), std::string(opts2.domains[1]));
  EXPECT_EQ(std::string(opts.lookups), std::string(opts2.lookups));

  ares_destroy_options(&opts);
  ares_destroy_options(&opts2);
  ares_destroy(channel);
  ares_destroy(channel2);
}

TEST_F(LibraryTest, FailChannelInit) {
  EXPECT_EQ(ARES_SUCCESS,
            ares_library_init_mem(ARES_LIB_INIT_ALL,
                                  &LibraryTest::amalloc,
                                  &LibraryTest::afree,
                                  &LibraryTest::arealloc));
  SetAllocFail(1);
  ares_channel channel = nullptr;
  EXPECT_EQ(ARES_ENOMEM, ares_init(&channel));
  EXPECT_EQ(nullptr, channel);
  ares_library_cleanup();
}

#ifdef USE_WINSOCK
TEST(Init, NoLibraryInit) {
  ares_channel channel = nullptr;
  EXPECT_EQ(ARES_ENOTINITIALIZED, ares_init(&channel));
}
#endif

}  // namespace test
}  // namespace ares
