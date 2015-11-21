#include "ares-test.h"
#include "dns-proto.h"

// Include ares internal files for DNS protocol details
#include "nameser.h"
#include "ares_dns.h"

#include <netdb.h>

#include <functional>
#include <sstream>

namespace ares {
namespace test {

void ProcessWork(ares_channel channel,
                 int extrafd, std::function<void(int)> process_extra) {
  int nfds, count;
  fd_set readers, writers;
  struct timeval tv;
  struct timeval* tvp;
  while (true) {
    // Retrieve the set of file descriptors that the library wants us to monitor.
    FD_ZERO(&readers);
    FD_ZERO(&writers);
    nfds = ares_fds(channel, &readers, &writers);

    // Add in the extra FD if present
    if (extrafd >= 0)
      FD_SET(extrafd, &readers);

    if (nfds == 0)  // no work left to do
      return;

    // Also retrieve the timeout value that the library wants us to use.
    tvp = ares_timeout(channel, nullptr, &tv);
    EXPECT_EQ(tvp, &tv);

    // Wait for activity or timeout.
    count = select(nfds, &readers, &writers, nullptr, tvp);
    if (count < 0) {
      fprintf(stderr, "select() failed, errno %d\n", errno);
      return;
    }

    // Let the library process any activity.
    ares_process(channel, &readers, &writers);
    // Let the provided callback process any activity on the extra FD.
    if (extrafd > 0 && FD_ISSET(extrafd, &readers))
      process_extra(extrafd);
  }
}

bool verbose = false;
int mock_port = 5300;

unsigned long LibraryTest::fails_ = 0;
std::map<size_t, int> LibraryTest::size_fails_;

// static
void LibraryTest::SetAllocFail(int nth) {
  assert(nth > 0);
  fails_ |= (1 << (nth - 1));
}

// static
void LibraryTest::SetAllocSizeFail(size_t size) {
  size_fails_[size]++;
}

// static
void LibraryTest::ClearFails() {
  fails_ = 0;
  size_fails_.clear();
}


// static
bool LibraryTest::ShouldAllocFail(size_t size) {
  bool fail = (fails_ & 0x01);
  fails_ >>= 1;
  if (size_fails_[size] > 0) {
    size_fails_[size]--;
    fail = true;
  }
  return fail;
}

// static
void* LibraryTest::amalloc(size_t size) {
  if (ShouldAllocFail(size)) {
    if (verbose) std::cerr << "Failing malloc(" << size << ") request" << std::endl;
    return nullptr;
  } else {
    return malloc(size);
  }
}

// static
void* LibraryTest::arealloc(void *ptr, size_t size) {
  if (ShouldAllocFail(size)) {
    if (verbose) std::cerr << "Failing realloc(" << ptr << ", " << size << ") request" << std::endl;
    return nullptr;
  } else {
    return realloc(ptr, size);
  }
}

// static
void LibraryTest::afree(void *ptr) {
  free(ptr);
}

void DefaultChannelTest::Process() {
  ProcessWork(channel_, -1, nullptr);
}

void DefaultChannelModeTest::Process() {
  ProcessWork(channel_, -1, nullptr);
}

MockServer::MockServer(int port) : port_(port) {
  // Create a UDP socket to receive data on.
  sockfd_ = socket(AF_INET, SOCK_DGRAM, 0);
  EXPECT_NE(-1, sockfd_);

  // Bind it to the given port.
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port_);
  int rc = bind(sockfd_, (struct sockaddr*)&addr, sizeof(addr));
  EXPECT_EQ(0, rc) << "Failed to bind to port " << port_;
}

MockServer::~MockServer() {
  close(sockfd_);
  sockfd_ = -1;
}

void MockServer::Process(int fd) {
  if (fd != sockfd_) return;
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  byte buffer[2048];
  int len = recvfrom(fd, buffer, sizeof(buffer), 0,
                     (struct sockaddr *)&addr, &addrlen);

  // Assume the packet is a well-formed DNS request and extract the request
  // details.
  if (len < NS_HFIXEDSZ) {
    std::cerr << "Packet too short (" << len << ")" << std::endl;
    return;
  }
  int qid = DNS_HEADER_QID(buffer);
  if (DNS_HEADER_QR(buffer) != 0) {
    std::cerr << "Not a request" << std::endl;
    return;
  }
  if (DNS_HEADER_OPCODE(buffer) != ns_o_query) {
    std::cerr << "Not a query (opcode " << DNS_HEADER_OPCODE(buffer)
              << ")" << std::endl;
    return;
  }
  if (DNS_HEADER_QDCOUNT(buffer) != 1) {
    std::cerr << "Unexpected question count (" << DNS_HEADER_QDCOUNT(buffer)
              << ")" << std::endl;
    return;
  }
  byte* question = buffer + 12;
  int qlen = len - 12;

  char *name = nullptr;
  long enclen;
  ares_expand_name(question, buffer, len, &name, &enclen);
  qlen -= enclen;
  question += enclen;
  std::string namestr(name);
  free(name);

  if (qlen < 4) {
    std::cerr << "Unexpected question size (" << qlen
              << " bytes after name)" << std::endl;
    return;
  }
  if (DNS_QUESTION_CLASS(question) != ns_c_in) {
    std::cerr << "Unexpected question class (" << DNS_QUESTION_CLASS(question)
              << ")" << std::endl;
    return;
  }
  int rrtype = DNS_QUESTION_TYPE(question);

  if (verbose) std::cerr << "ProcessRequest(" << qid << ", '" << namestr
                         << "', " << RRTypeToString(rrtype) << ")" << std::endl;
  ProcessRequest(&addr, addrlen, qid, namestr, rrtype);
}

void MockServer::ProcessRequest(struct sockaddr_storage* addr, int addrlen,
                                int qid, const std::string& name, int rrtype) {
  // Before processing, let gMock know the request is happening.
  OnRequest(name, rrtype);

  // Send the current pending reply.  First overwrite the qid with the value
  // from the argument.
  if (reply_.size() <  2) {
    if (verbose) std::cerr << "Skipping reply as not-present/too-short" << std::endl;
    return;
  }
  reply_[0] = (byte)((qid >> 8) & 0xff);
  reply_[1] = (byte)(qid & 0xff);
  if (verbose) std::cerr << "sending reply " << PacketToString(reply_) << std::endl;
  int rc = sendto(sockfd_, reply_.data(), reply_.size(), 0,
                  (struct sockaddr *)addr, addrlen);
  if (rc < static_cast<int>(reply_.size())) {
    std::cerr << "Failed to send full reply, rc=" << rc << std::endl;
  }
}

MockChannelOptsTest::MockChannelOptsTest(struct ares_options* givenopts,
                                         int optmask)
  : server_(mock_port), channel_(nullptr) {
  // Set up channel options.
  struct ares_options opts;
  if (givenopts) {
    memcpy(&opts, givenopts, sizeof(opts));
  } else {
    EXPECT_EQ(0, optmask);
    memset(&opts, 0, sizeof(opts));
  }

  // Force communication with the mock server.
  opts.udp_port = server_.port();
  optmask |= ARES_OPT_UDP_PORT;
  opts.tcp_port = server_.port();
  optmask |= ARES_OPT_TCP_PORT;
  opts.nservers = 1;
  struct in_addr server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.s_addr = htonl(0x7F000001);
  opts.servers = &server_addr;
  optmask |= ARES_OPT_SERVERS;

  // If not already overridden, set short timeouts.
  if (!(optmask & (ARES_OPT_TIMEOUTMS|ARES_OPT_TIMEOUT))) {
    opts.timeout = 100;
    optmask |= ARES_OPT_TIMEOUTMS;
  }
  // If not already overridden, set 3 retries.
  if (!(optmask & ARES_OPT_TRIES)) {
    opts.tries = 3;
    optmask |= ARES_OPT_TRIES;
  }
  // If not already overridden, set search domains.
  const char *domains[3] = {"first.com", "second.org", "third.gov"};
  if (!(optmask & ARES_OPT_DOMAINS)) {
    opts.ndomains = 3;
    opts.domains = (char**)domains;
    optmask |= ARES_OPT_DOMAINS;
  }

  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
  EXPECT_NE(nullptr, channel_);
}

MockChannelOptsTest::~MockChannelOptsTest() {
  if (channel_) {
    ares_destroy(channel_);
  }
  channel_ = nullptr;
}

void MockChannelOptsTest::Process() {
  using namespace std::placeholders;
  ProcessWork(channel_, server_.sockfd(),
              std::bind(&MockServer::Process, &server_, _1));
}

std::ostream& operator<<(std::ostream& os, const HostResult& result) {
  os << '{';
  if (result.done_) {
    os << StatusToString(result.status_) << " " << result.host_;
  } else {
    os << "(incomplete)";
  }
  os << '}';
  return os;
}

HostEnt::HostEnt(const struct hostent *hostent) {
  if (!hostent) return;
  if (hostent->h_name) name_ = hostent->h_name;
  if (hostent->h_aliases) {
    char** palias = hostent->h_aliases;
    while (*palias != nullptr) {
      aliases_.push_back(*palias);
      palias++;
    }
  }
  addrtype_ = hostent->h_addrtype;
  if (hostent->h_addr_list) {
    char** paddr = hostent->h_addr_list;
    while (*paddr != nullptr) {
      std::string addr = AddressToString(*paddr, hostent->h_length);
      addrs_.push_back(addr);
      paddr++;
    }
  }
}

std::ostream& operator<<(std::ostream& os, const HostEnt& host) {
  os << '{';
  os << "'" << host.name_ << "' "
     << "aliases=[";
  for (size_t ii = 0; ii < host.aliases_.size(); ii++) {
    if (ii > 0) os << ", ";
    os << host.aliases_[ii];
  }
  os << "] ";
  os << "addrs=[";
  for (size_t ii = 0; ii < host.addrs_.size(); ii++) {
    if (ii > 0) os << ", ";
    os << host.addrs_[ii];
  }
  os << "]";
  os << '}';
  return os;
}
void HostCallback(void *data, int status, int timeouts,
                  struct hostent *hostent) {
  EXPECT_NE(nullptr, data);
  HostResult* result = reinterpret_cast<HostResult*>(data);
  result->done_ = true;
  result->status_ = status;
  result->timeouts_ = timeouts;
  result->host_ = HostEnt(hostent);
  if (verbose) std::cerr << "HostCallback(" << *result << ")" << std::endl;
}

std::ostream& operator<<(std::ostream& os, const SearchResult& result) {
  os << '{';
  if (result.done_) {
    os << StatusToString(result.status_) << " " << PacketToString(result.data_);
  } else {
    os << "(incomplete)";
  }
  os << '}';
  return os;
}

void SearchCallback(void *data, int status, int timeouts,
                    unsigned char *abuf, int alen) {
  EXPECT_NE(nullptr, data);
  SearchResult* result = reinterpret_cast<SearchResult*>(data);
  result->done_ = true;
  result->status_ = status;
  result->timeouts_ = timeouts;
  result->data_.assign(abuf, abuf + alen);
  if (verbose) std::cerr << "SearchCallback(" << *result << ")" << std::endl;
}

std::ostream& operator<<(std::ostream& os, const NameInfoResult& result) {
  os << '{';
  if (result.done_) {
    os << StatusToString(result.status_) << " " << result.node_ << " " << result.service_;
  } else {
    os << "(incomplete)";
  }
  os << '}';
  return os;
}

void NameInfoCallback(void *data, int status, int timeouts,
                      char *node, char *service) {
  EXPECT_NE(nullptr, data);
  NameInfoResult* result = reinterpret_cast<NameInfoResult*>(data);
  result->done_ = true;
  result->status_ = status;
  result->timeouts_ = timeouts;
  result->node_ = std::string(node ? node : "");
  result->service_ = std::string(service ? service : "");
  if (verbose) std::cerr << "NameInfoCallback(" << *result << ")" << std::endl;
}

}  // namespace test
}  // namespace ares
