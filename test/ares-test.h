// -*- mode: c++ -*-
#ifndef ARES_TEST_H
#define ARES_TEST_H

#include "ares.h"

#include "dns-proto.h"

// Include ares internal file for DNS protocol constants
#include "nameser.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <functional>
#include <map>

namespace ares {

typedef unsigned char byte;

namespace test {

extern bool verbose;
extern int mock_port;

// Process all pending work on ares-owned file descriptors, plus
// optionally the given FD + work function.
void ProcessWork(ares_channel channel,
                 int extrafd, std::function<void(int)> process_extra);

// Test fixture that ensures library initialization, and allows
// memory allocations to be failed.
class LibraryTest : public ::testing::Test {
 public:
  LibraryTest() {
    EXPECT_EQ(ARES_SUCCESS,
              ares_library_init_mem(ARES_LIB_INIT_ALL,
                                    &LibraryTest::amalloc,
                                    &LibraryTest::afree,
                                    &LibraryTest::arealloc));
  }
  ~LibraryTest() {
    ares_library_cleanup();
    ClearFails();
  }
  // Set the n-th malloc call (of any size) from the library to fail.
  // (nth == 1 means the next call)
  static void SetAllocFail(int nth);
  // Set the next malloc call for the given size to fail.
  static void SetAllocSizeFail(size_t size);
  // Remove any pending alloc failures.
  static void ClearFails();

  static void *amalloc(size_t size);
  static void* arealloc(void *ptr, size_t size);
  static void afree(void *ptr);
 private:
  static bool ShouldAllocFail(size_t size);
  static unsigned long fails_;
  static std::map<size_t, int> size_fails_;
};

// Test fixture that uses a default channel.
class DefaultChannelTest : public LibraryTest {
 public:
  DefaultChannelTest() : channel_(nullptr) {
    EXPECT_EQ(ARES_SUCCESS, ares_init(&channel_));
    EXPECT_NE(nullptr, channel_);
  }

  ~DefaultChannelTest() {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  // Process all pending work on ares-owned file descriptors.
  void Process();

 protected:
  ares_channel channel_;
};

// Test fixture that uses a default channel with the specified lookup mode.
class DefaultChannelModeTest
    : public LibraryTest,
      public ::testing::WithParamInterface<std::string> {
 public:
  DefaultChannelModeTest() : channel_(nullptr) {
    struct ares_options opts = {0};
    opts.lookups = strdup(GetParam().c_str());
    int optmask = ARES_OPT_LOOKUPS;
    EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
    EXPECT_NE(nullptr, channel_);
    free(opts.lookups);
  }

  ~DefaultChannelModeTest() {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  // Process all pending work on ares-owned file descriptors.
  void Process();

 protected:
  ares_channel channel_;
};

// Mock DNS server to allow responses to be scripted by tests.
class MockServer {
 public:
  MockServer(int family, int port);
  ~MockServer();

  // Mock method indicating the processing of a particular <name, RRtype>
  // request.
  MOCK_METHOD2(OnRequest, void(const std::string& name, int rrtype));

  // Set the reply to be sent next; the query ID field will be overwritten
  // with the value from the request.
  void SetReplyData(const std::vector<byte>& reply) { reply_ = reply; }
  void SetReply(const DNSPacket* reply) { SetReplyData(reply->data()); }

  // Process activity on the mock server's socket FD.
  void Process(int fd);

  int port() const { return port_; }
  int sockfd() const { return sockfd_; }

 private:
  void ProcessRequest(struct sockaddr_storage* addr, int addrlen,
                      int qid, const std::string& name, int rrtype);

  int port_;
  int sockfd_;
  std::vector<byte> reply_;
};

// Test fixture that uses a mock DNS server.
class MockChannelOptsTest : public LibraryTest {
 public:
  MockChannelOptsTest(int family, struct ares_options* givenopts, int optmask);
  ~MockChannelOptsTest();

  // Process all pending work on ares-owned and mock-server-owned file descriptors.
  void Process();

 protected:
  testing::NiceMock<MockServer> server_;
  ares_channel channel_;
};

class MockChannelTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface<int> {
 public:
  MockChannelTest() : MockChannelOptsTest(GetParam(), nullptr, 0) {}
};

// gMock action to set the reply for a mock server.
ACTION_P2(SetReplyData, mockserver, data) {
  mockserver->SetReplyData(data);
}
ACTION_P2(SetReply, mockserver, reply) {
  mockserver->SetReply(reply);
}
// gMock action to cancel a channel.
ACTION_P2(CancelChannel, mockserver, channel) {
  ares_cancel(channel);
}

// C++ wrapper for struct hostent.
struct HostEnt {
  HostEnt() : addrtype_(-1) {}
  HostEnt(const struct hostent* hostent);
  std::string name_;
  std::vector<std::string> aliases_;
  int addrtype_;  // AF_INET or AF_INET6
  std::vector<std::string> addrs_;
};
std::ostream& operator<<(std::ostream& os, const HostEnt& result);

// Structure that describes the result of an ares_host_callback invocation.
struct HostResult {
  // Whether the callback has been invoked.
  bool done_;
  // Explicitly provided result information.
  int status_;
  int timeouts_;
  // Contents of the hostent structure, if provided.
  HostEnt host_;
};
std::ostream& operator<<(std::ostream& os, const HostResult& result);

// Structure that describes the result of an ares_callback invocation.
struct SearchResult {
  // Whether the callback has been invoked.
  bool done_;
  // Explicitly provided result information.
  int status_;
  int timeouts_;
  std::vector<byte> data_;
};
std::ostream& operator<<(std::ostream& os, const SearchResult& result);

// Structure that describes the result of an ares_nameinfo_callback invocation.
struct NameInfoResult {
  // Whether the callback has been invoked.
  bool done_;
  // Explicitly provided result information.
  int status_;
  int timeouts_;
  std::string node_;
  std::string service_;
};
std::ostream& operator<<(std::ostream& os, const NameInfoResult& result);

// Standard implementation of ares callbacks that fill out the corresponding
// structures.
void HostCallback(void *data, int status, int timeouts,
                  struct hostent *hostent);
void SearchCallback(void *data, int status, int timeouts,
                    unsigned char *abuf, int alen);
void NameInfoCallback(void *data, int status, int timeouts,
                      char *node, char *service);

// RAII class for a temporary file with the given contents.
class TempFile {
 public:
  TempFile(const std::string& contents);
  ~TempFile();
  const char *filename() const {
    return filename_;
  }
 private:
  char *filename_;
};

// RAII class for a temporary environment variable value.
class EnvValue {
 public:
  EnvValue(const char *name, const char *value) : name_(name), restore_(false) {
    char *original = getenv(name);
    if (original) {
      restore_ = true;
      original_ = original;
    }
    setenv(name_.c_str(), value, 1);
  }
  ~EnvValue() {
    if (restore_) {
      setenv(name_.c_str(), original_.c_str(), 1);
    } else {
      unsetenv(name_.c_str());
    }
  }
 private:
  std::string name_;
  bool restore_;
  std::string original_;
};

}  // namespace test
}  // namespace ares

#endif
