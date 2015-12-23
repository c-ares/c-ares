#include "ares-test.h"
#include "dns-proto.h"

// Include ares internal files for DNS protocol details
#include "nameser.h"
#include "ares_dns.h"

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

#include <functional>
#include <sstream>

namespace ares {
namespace test {

bool verbose = false;
int mock_port = 5300;

unsigned long LibraryTest::fails_ = 0;
std::map<size_t, int> LibraryTest::size_fails_;

void ProcessWork(ares_channel channel,
                 std::function<std::set<int>()> get_extrafds,
                 std::function<void(int)> process_extra) {
  int nfds, count;
  fd_set readers, writers;
  struct timeval tv;
  while (true) {
    // Retrieve the set of file descriptors that the library wants us to monitor.
    FD_ZERO(&readers);
    FD_ZERO(&writers);
    nfds = ares_fds(channel, &readers, &writers);
    if (nfds == 0)  // no work left to do in the library
      return;

    // Add in the extra FDs if present.
    std::set<int> extrafds = get_extrafds();
    for (int extrafd : extrafds) {
      FD_SET(extrafd, &readers);
      if (extrafd >= nfds) {
        nfds = extrafd + 1;
      }
    }

    // Wait for activity or timeout.
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  // 100ms
    count = select(nfds, &readers, &writers, nullptr, &tv);
    if (count < 0) {
      fprintf(stderr, "select() failed, errno %d\n", errno);
      return;
    }

    // Let the library process any activity.
    ares_process(channel, &readers, &writers);

    // Let the provided callback process any activity on the extra FD.
    for (int extrafd : extrafds) {
      if (FD_ISSET(extrafd, &readers)) {
        process_extra(extrafd);
      }
    }
  }
}

// static
void LibraryTest::SetAllocFail(int nth) {
  assert(nth > 0);
  assert(nth <= (int)(8 * sizeof(fails_)));
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

std::set<int> NoExtraFDs() {
  return std::set<int>();
}

void DefaultChannelTest::Process() {
  ProcessWork(channel_, NoExtraFDs, nullptr);
}

void DefaultChannelModeTest::Process() {
  ProcessWork(channel_, NoExtraFDs, nullptr);
}

MockServer::MockServer(int family, int port) : port_(port), qid_(-1) {
  // Create a TCP socket to receive data on.
  tcpfd_ = socket(family, SOCK_STREAM, 0);
  EXPECT_NE(-1, tcpfd_);
  int optval = 1;
  setsockopt(tcpfd_, SOL_SOCKET, SO_REUSEADDR,
             (const void *)&optval , sizeof(int));

  // Create a UDP socket to receive data on.
  udpfd_ = socket(family, SOCK_DGRAM, 0);
  EXPECT_NE(-1, udpfd_);

  // Bind the sockets to the given port.
  if (family == AF_INET) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port_);
    int tcprc = bind(tcpfd_, (struct sockaddr*)&addr, sizeof(addr));
    EXPECT_EQ(0, tcprc) << "Failed to bind AF_INET to TCP port " << port_;
    int udprc = bind(udpfd_, (struct sockaddr*)&addr, sizeof(addr));
    EXPECT_EQ(0, udprc) << "Failed to bind AF_INET to UDP port " << port_;
  } else {
    EXPECT_EQ(AF_INET6, family);
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port_);
    int tcprc = bind(tcpfd_, (struct sockaddr*)&addr, sizeof(addr));
    EXPECT_EQ(0, tcprc) << "Failed to bind AF_INET6 to UDP port " << port_;
    int udprc = bind(udpfd_, (struct sockaddr*)&addr, sizeof(addr));
    EXPECT_EQ(0, udprc) << "Failed to bind AF_INET6 to UDP port " << port_;
  }

  // For TCP, also need to listen for connections.
  EXPECT_EQ(0, listen(tcpfd_, 5)) << "Failed to listen for TCP connections";
}

MockServer::~MockServer() {
  for (int fd : connfds_) {
    close(fd);
  }
  close(tcpfd_);
  close(udpfd_);
}

void MockServer::Process(int fd) {
  if (fd != tcpfd_ && fd != udpfd_ && connfds_.find(fd) == connfds_.end()) {
    std::cerr << "Asked to process unknown fd " << fd << std::endl;
    return;
  }
  if (fd == tcpfd_) {
    int connfd = accept(tcpfd_, NULL, NULL);
    if (connfd < 0) {
      std::cerr << "Error accepting connection on fd " << fd << std::endl;
    } else {
      connfds_.insert(connfd);
    }
    return;
  }

  // Activity on a data-bearing file descriptor.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  byte buffer[2048];
  int len = recvfrom(fd, buffer, sizeof(buffer), 0,
                     (struct sockaddr *)&addr, &addrlen);
  byte* data = buffer;
  if (fd != udpfd_) {
    if (len == 0) {
      connfds_.erase(std::find(connfds_.begin(), connfds_.end(), fd));
      close(fd);
      return;
    }
    if (len < 2) {
      std::cerr << "Packet too short (" << len << ")" << std::endl;
      return;
    }
    int tcplen = (data[0] << 8) + data[1];
    data += 2;
    len -= 2;
    if (tcplen != len) {
      std::cerr << "Warning: TCP length " << tcplen
                << " doesn't match remaining data length " << len << std::endl;
    }
  }

  // Assume the packet is a well-formed DNS request and extract the request
  // details.
  if (len < NS_HFIXEDSZ) {
    std::cerr << "Packet too short (" << len << ")" << std::endl;
    return;
  }
  int qid = DNS_HEADER_QID(data);
  if (DNS_HEADER_QR(data) != 0) {
    std::cerr << "Not a request" << std::endl;
    return;
  }
  if (DNS_HEADER_OPCODE(data) != ns_o_query) {
    std::cerr << "Not a query (opcode " << DNS_HEADER_OPCODE(data)
              << ")" << std::endl;
    return;
  }
  if (DNS_HEADER_QDCOUNT(data) != 1) {
    std::cerr << "Unexpected question count (" << DNS_HEADER_QDCOUNT(data)
              << ")" << std::endl;
    return;
  }
  byte* question = data + 12;
  int qlen = len - 12;

  char *name = nullptr;
  long enclen;
  ares_expand_name(question, data, len, &name, &enclen);
  if (!name) {
    std::cerr << "Failed to retrieve name" << std::endl;
    return;
  }
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

  if (verbose) {
    std::vector<byte> req(data, data + len);
    std::cerr << "received " << (fd == udpfd_ ? "UDP" : "TCP") << " request " << PacketToString(req) << std::endl;
    std::cerr << "ProcessRequest(" << qid << ", '" << namestr
              << "', " << RRTypeToString(rrtype) << ")" << std::endl;
  }
  ProcessRequest(fd, &addr, addrlen, qid, namestr, rrtype);
}

std::set<int> MockServer::fds() const {
  std::set<int> result = connfds_;
  result.insert(tcpfd_);
  result.insert(udpfd_);
  return result;
}

void MockServer::ProcessRequest(int fd, struct sockaddr_storage* addr, int addrlen,
                                int qid, const std::string& name, int rrtype) {
  // Before processing, let gMock know the request is happening.
  OnRequest(name, rrtype);

  if (reply_.size() == 0) {
    return;
  }

  // Make a local copy of the current pending reply.
  std::vector<byte> reply = reply_;

  if (qid_ >= 0) {
    // Use the explicitly specified query ID.
    qid = qid_;
  }
  if (reply.size() >=  2) {
    // Overwrite the query ID if space to do so.
    reply[0] = (byte)((qid >> 8) & 0xff);
    reply[1] = (byte)(qid & 0xff);
  }
  if (verbose) std::cerr << "sending reply " << PacketToString(reply) << std::endl;

  // Prefix with 2-byte length if TCP.
  if (fd != udpfd_) {
    int len = reply.size();
    std::vector<byte> vlen = {(byte)((len & 0xFF00) >> 8), (byte)(len & 0xFF)};
    reply.insert(reply.begin(), vlen.begin(), vlen.end());
    // Also, don't bother with the destination address.
    addr = nullptr;
    addrlen = 0;
  }

  int rc = sendto(fd, reply.data(), reply.size(), 0,
                  (struct sockaddr *)addr, addrlen);
  if (rc < static_cast<int>(reply.size())) {
    std::cerr << "Failed to send full reply, rc=" << rc << std::endl;
  }
}

MockChannelOptsTest::MockChannelOptsTest(int family,
                                         bool force_tcp,
                                         struct ares_options* givenopts,
                                         int optmask)
  : server_(family, mock_port), channel_(nullptr) {
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
  if (family == AF_INET) {
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.s_addr = htonl(0x7F000001);
    opts.servers = &server_addr;
    optmask |= ARES_OPT_SERVERS;
  }

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
  if (force_tcp) {
    opts.flags |= ARES_FLAG_USEVC;
    optmask |= ARES_OPT_FLAGS;
  }

  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
  EXPECT_NE(nullptr, channel_);

  // For IPv6 servers, have to set up after construction.
  if (family == AF_INET6) {
    struct ares_addr_node addr;
    memset(&addr, 0, sizeof(addr));
    addr.family = AF_INET6;
    addr.addr.addr6._S6_un._S6_u8[15] = 1;
    EXPECT_EQ(ARES_SUCCESS, ares_set_servers(channel_, &addr));
  }
}

MockChannelOptsTest::~MockChannelOptsTest() {
  if (channel_) {
    ares_destroy(channel_);
  }
  channel_ = nullptr;
}

void MockChannelOptsTest::Process() {
  using namespace std::placeholders;
  ProcessWork(channel_,
              std::bind(&MockServer::fds, &server_),
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

HostEnt::HostEnt(const struct hostent *hostent) : addrtype_(-1) {
  if (!hostent)
    return;
  if (hostent->h_name)
    name_ = hostent->h_name;
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

TempFile::TempFile(const std::string& contents)
  : filename_(tempnam(nullptr, "ares")) {
  if (!filename_) {
    std::cerr << "Error: failed to generate temporary filename" << std::endl;
    return;
  }
  FILE *f = fopen(filename_, "w");
  if (!f) {
    std::cerr << "Error: failed to create temporary file " << filename_ << std::endl;
    return;
  }
  int rc = fwrite(contents.data(), 1, contents.size(), f);
  if (rc < (int)contents.size()) {
    std::cerr << "Error: failed to store data in temporary file " << filename_ << std::endl;
  }
  fclose(f);
}

TempFile::~TempFile() {
  if (filename_) {
    unlink(filename_);
    free(filename_);
  }
}

}  // namespace test
}  // namespace ares
