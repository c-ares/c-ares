/* MIT License
 *
 * Copyright (c) 2026 Brad House
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

/* Focused DNS-over-TLS edge-case tests driven through the gmock mock server.
 *
 * Unlike the socketpair backend harness (ares-test-tls.cc), these run a real
 * ares_gethostbyname() through the full process loop against a MockServer that
 * terminates TLS with whichever crypto backend c-ares was built against.  That
 * means the same tests exercise the OpenSSL and Schannel client backends
 * without either needing the other's library.  We only sanity check the
 * edge cases specific to TLS, not the whole query suite. */

#include "ares-test.h"

extern "C" {
// Remove command-line defines of package variables for the test project...
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
// ... so we can include the library's config without symbol redefinitions.
#include "ares_private.h"
}

/* Needs the crypto subsystem and symbol visibility into the library
 * (ares_tls_set_cadata / channel->crypto_ctx).  Backend-agnostic and not
 * POSIX-only: runs anywhere the mock server's TLS termination is available. */
#if defined(CARES_USE_CRYPTO) && !defined(CARES_SYMBOL_HIDING)

#  include <sstream>

namespace ares {
namespace test {

class MockDoTServerTest : public LibraryTest {
public:
  MockDoTServerTest()
  {
    tls_ctx_ = TlsServerCtx::Create();
    if (tls_ctx_ == nullptr) {
      return;
    }
    server_.reset(new testing::NiceMock<MockServer>(AF_INET, mock_port));
    server_->SetTLSCtx(tls_ctx_);
  }

  ~MockDoTServerTest()
  {
    if (channel_ != nullptr) {
      ares_destroy(channel_);
    }
  }

  bool HasBackend() const
  {
    return tls_ctx_ != nullptr;
  }

  /* Build a channel pointed at the mock DoT server.  trust=true injects the
   * server's CA into the client trust store; verify selects the URI
   * verification mode; hostname (optional) sets SNI / the session-cache key. */
  bool BuildChannel(bool trust, const char *verify,
                    const char *hostname = nullptr)
  {
    struct ares_options opts;
    int                 optmask = 0;
    char                csv[192];

    memset(&opts, 0, sizeof(opts));
    /* Deterministic: no search domains, short timeout, no query cache */
    opts.ndomains        = 0;
    optmask             |= ARES_OPT_DOMAINS;
    opts.timeout         = 1000;
    optmask             |= ARES_OPT_TIMEOUTMS;
    opts.tries           = 2;
    optmask             |= ARES_OPT_TRIES;
    opts.qcache_max_ttl  = 0;
    optmask             |= ARES_OPT_QUERY_CACHE;

    if (ares_init_options(&channel_, &opts, optmask) != ARES_SUCCESS) {
      return false;
    }

    if (trust) {
      std::string ca = tls_ctx_->CaPEM();
      if (ares_tls_set_cadata(channel_->crypto_ctx,
                              (const unsigned char *)ca.data(),
                              ca.size()) != ARES_SUCCESS) {
        return false;
      }
    }

    if (hostname != nullptr) {
      snprintf(csv, sizeof(csv), "dns+tls://127.0.0.1:%u?hostname=%s&verify=%s",
               (unsigned int)server_->tcpport(), hostname, verify);
    } else {
      snprintf(csv, sizeof(csv), "dns+tls://127.0.0.1:%u?verify=%s",
               (unsigned int)server_->tcpport(), verify);
    }
    return ares_set_servers_csv(channel_, csv) == ARES_SUCCESS;
  }

  void Process(unsigned int cancel_ms = 0)
  {
    using namespace std::placeholders;
    ProcessWork(channel_, std::bind(&MockServer::fds, server_.get()),
                std::bind(&MockServer::ProcessFD, server_.get(), _1),
                cancel_ms);
  }

protected:
  std::shared_ptr<TlsServerCtx>                  tls_ctx_;
  std::unique_ptr<testing::NiceMock<MockServer>> server_;
  ares_channel_t                                *channel_ = nullptr;
};

/* Handshake + framed query/response over the encrypted channel. */
TEST_F(MockDoTServerTest, Query)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "strict", kMockDoTHostname));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'dot.example.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

/* Strict verification against an untrusted server cert must fail the query,
 * not fall back to plaintext or hang. */
TEST_F(MockDoTServerTest, VerifyFailStrict)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(false, "strict", kMockDoTHostname));

  /* The query must never reach the server: verification fails during the
   * handshake, before any application data is transmitted. */
  EXPECT_CALL(*server_, OnRequest("dot.example.com", T_A)).Times(0);

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_NE(ARES_SUCCESS, result.status_);
}

/* Strict verification with a name that does NOT match the certificate's SAN
 * must fail, even though the cert chains to a trusted CA. */
TEST_F(MockDoTServerTest, StrictNameMismatch)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "strict", "wrong.example.com"));

  /* As above, a name mismatch must abort before the query is transmitted. */
  EXPECT_CALL(*server_, OnRequest("dot.example.com", T_A)).Times(0);

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_NE(ARES_SUCCESS, result.status_);
}

/* verify=default with an authentication name resolves to strict, so a
 * matching name succeeds and a mismatched one fails (enforcement == strict). */
TEST_F(MockDoTServerTest, DefaultWithNameMatches)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "default", kMockDoTHostname));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

TEST_F(MockDoTServerTest, DefaultWithNameMismatch)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "default", "wrong.example.com"));

  /* verify=default + hostname resolves to strict, so a name mismatch must abort
   * before the query is transmitted (mirrors StrictNameMismatch). */
  EXPECT_CALL(*server_, OnRequest("dot.example.com", T_A)).Times(0);

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_NE(ARES_SUCCESS, result.status_);
}

/* Strict verification with no authentication name must be rejected at config
 * time (fail-closed), not silently degraded to chain-only. */
TEST_F(MockDoTServerTest, StrictRequiresHostname)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  EXPECT_FALSE(BuildChannel(true, "strict"));
}

/* An IP literal is not a usable TLS authentication name: RFC 6066 forbids an
 * IP-literal SNI, and the reference identity matches only dNSName SANs (never
 * iPAddress), so a numeric hostname= is rejected at config time rather than
 * deferred to a guaranteed handshake failure. */
TEST_F(MockDoTServerTest, IPLiteralHostnameRejected)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  EXPECT_FALSE(BuildChannel(true, "strict", "1.1.1.1"));
}

/* Opportunistic mode encrypts without verifying, so an untrusted cert still
 * yields a successful query. */
TEST_F(MockDoTServerTest, Opportunistic)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(false, "opportunistic"));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 5, 6, 7, 8 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

/* verify=default with no hostname resolves to opportunistic (RFC 8310), so an
 * untrusted cert still yields a successful query.  Exercises the DEFAULT ->
 * opportunistic arm of the effective-verify folding, which the other default
 * tests (which all supply a hostname, hitting DEFAULT -> strict) never reach.
 */
TEST_F(MockDoTServerTest, DefaultNoHostnameOpportunistic)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(false, "default"));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 9, 10, 11, 12 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

/* Server closes the connection after replying; a subsequent query must open a
 * fresh connection, re-handshake and still succeed. */
TEST_F(MockDoTServerTest, ServerCloseThenReconnect)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "strict", kMockDoTHostname));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  server_->DisconnectAfterReply();
  HostResult r1;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback, &r1);
  Process();
  EXPECT_TRUE(r1.done_);
  EXPECT_EQ(ARES_SUCCESS, r1.status_);

  HostResult r2;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback, &r2);
  Process();
  EXPECT_TRUE(r2.done_);
  EXPECT_EQ(ARES_SUCCESS, r2.status_);
}

/* The first query establishes and caches a TLS session; after that connection
 * closes, a second query opens a fresh connection that must resume the cached
 * session rather than perform another full handshake. */
TEST_F(MockDoTServerTest, SessionResumption)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  /* Strict verification with the matching hostname (the cert's SAN) so this
   * also covers session resumption under full certificate verification. */
  ASSERT_TRUE(BuildChannel(true, "strict", kMockDoTHostname));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  /* First query: full handshake, then close so the next query must reconnect */
  server_->DisconnectAfterReply();
  HostResult r1;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback, &r1);
  Process();
  ASSERT_TRUE(r1.done_);
  ASSERT_EQ(ARES_SUCCESS, r1.status_);
  EXPECT_EQ(1, server_->TLSFullHandshakes());
  EXPECT_EQ(0, server_->TLSResumedHandshakes());

  /* Second query on a fresh connection must resume the cached session */
  HostResult r2;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback, &r2);
  Process();
  ASSERT_TRUE(r2.done_);
  ASSERT_EQ(ARES_SUCCESS, r2.status_);
  EXPECT_EQ(1, server_->TLSResumedHandshakes())
    << "second connection did not resume the TLS session";
  EXPECT_EQ(1, server_->TLSFullHandshakes());
}

/* Two queries issued together share a single TLS connection: exactly one
 * handshake, no resumption.  This also exercises the coalesced/pipelined
 * read path (two responses over one connection). */
TEST_F(MockDoTServerTest, ConnectionReuse)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "strict", kMockDoTHostname));

  DNSPacket rsp1;
  rsp1.set_response()
    .set_aa()
    .add_question(new DNSQuestion("a.example.com", T_A))
    .add_answer(new DNSARR("a.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("a.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp1));
  DNSPacket rsp2;
  rsp2.set_response()
    .set_aa()
    .add_question(new DNSQuestion("b.example.com", T_A))
    .add_answer(new DNSARR("b.example.com", 100, { 5, 6, 7, 8 }));
  ON_CALL(*server_, OnRequest("b.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp2));

  /* Both queries in flight before processing, so they share one connection */
  HostResult r1;
  HostResult r2;
  ares_gethostbyname(channel_, "a.example.com", AF_INET, HostCallback, &r1);
  ares_gethostbyname(channel_, "b.example.com", AF_INET, HostCallback, &r2);
  Process();
  EXPECT_TRUE(r1.done_);
  EXPECT_EQ(ARES_SUCCESS, r1.status_);
  EXPECT_TRUE(r2.done_);
  EXPECT_EQ(ARES_SUCCESS, r2.status_);
  EXPECT_EQ(1, server_->TLSFullHandshakes());
  EXPECT_EQ(0, server_->TLSResumedHandshakes());
}

/* A tampered application-data record must fail the query cleanly (a security
 * / connection error), not hang waiting on an event that never fires nor be
 * misclassified as a retriable transport error. */
TEST_F(MockDoTServerTest, TamperedRecord)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "strict", kMockDoTHostname));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));
  server_->SetTLSCorruptAppData();

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  auto start = std::chrono::steady_clock::now();
  Process();
  auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - start)
                      .count();
  EXPECT_TRUE(result.done_);
  EXPECT_NE(ARES_SUCCESS, result.status_);
  /* The handshake itself completes; the tampered record fails afterward.  At
   * least one full handshake proves the failure is at the application-data
   * layer (exercising the decrypt-failure classification), not a handshake
   * failure.  How many times it then retries is backend-specific -- OpenSSL
   * tears the connection down and reconnects, Schannel fails terminally -- so
   * assert only that the handshake was reached, not an exact count. */
  EXPECT_GE(server_->TLSFullHandshakes(), 1);
  /* Prove it failed *promptly* rather than degrading to a hang until the query
   * timed out: a silent mishandling of the decrypt failure as WOULDBLOCK would
   * stall for at least one full timeout period (opts.timeout == 1000ms).  On
   * localhost the classify-and-fail path is tens of ms even with a retry, so a
   * bound below a single timeout period cleanly distinguishes the two. */
  EXPECT_LT(elapsed_ms, 900);
}

/* Server drops the connection mid-handshake: the query must fail cleanly,
 * not hang or fall back to plaintext. */
TEST_F(MockDoTServerTest, MidHandshakeClose)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "strict", kMockDoTHostname));
  server_->SetTLSHandshakeMode(MockServer::kTlsHsCloseDuringHandshake);

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_NE(ARES_SUCCESS, result.status_);
}

/* Server accepts but never responds to the ClientHello: the handshake must
 * time out and the query fail. */
TEST_F(MockDoTServerTest, HandshakeStallTimeout)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "strict", kMockDoTHostname));
  server_->SetTLSHandshakeMode(MockServer::kTlsHsStall);

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_NE(ARES_SUCCESS, result.status_);
}

/* Regression test for the handshake busy-spin (and its counterpart, the
 * post-handshake query flush).
 *
 * A DoT query is queued behind the TLS handshake and can't drain until the
 * handshake completes.  The connection must therefore not stay armed for the
 * write event while the handshake is blocked on a *readable* socket -- doing
 * so pins a level-triggered event loop at 100% CPU on the persistently
 * writable fd.  This drives the loop manually against a stalled server and
 * proves the connection settles onto read-only interest (select() blocks to
 * its timeout instead of returning writable every iteration).
 *
 * It then releases the stall so the handshake completes on a read event with
 * the write event unarmed -- the exact path where the read side must re-flush
 * the queued query, or it would strand and time out. */
TEST_F(MockDoTServerTest, HandshakeNoBusySpin)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "strict", kMockDoTHostname));
  server_->SetTLSHandshakeMode(MockServer::kTlsHsStall);

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);

  /* Pump while the server stalls the handshake.  With the busy-spin the
   * connection stays armed for write on a persistently-writable socket, so
   * select() returns immediately every iteration and never idles.  With the
   * fix the handshake blocks on read, so once the ClientHello is sent (and the
   * TFO connect-notification write consumed) select() blocks to its timeout. */
  bool saw_idle = false;
  for (int iter = 0; iter < 200 && !saw_idle; iter++) {
    fd_set                  readers;
    fd_set                  writers;
    int                     nfds = 0;
    struct timeval          tv;
    std::set<ares_socket_t> sfds = server_->fds();

    FD_ZERO(&readers);
    FD_ZERO(&writers);
    nfds = ares_fds(channel_, &readers, &writers);
    for (ares_socket_t f : sfds) {
      FD_SET(f, &readers);
      if ((int)f + 1 > nfds) {
        nfds = (int)f + 1;
      }
    }

    tv.tv_sec  = 0;
    tv.tv_usec = 20 * 1000;
    if (select(nfds, &readers, &writers, nullptr, &tv) == 0) {
      /* Nothing ready within the timeout: the client is blocked on read, not
       * spinning on a writable socket.  Only accept this once the ClientHello
       * has reached the server, so a pre-connect lull can't masquerade as the
       * settled state. */
      if (server_->PendingTLSHandshakes() > 0) {
        saw_idle = true;
      }
      continue;
    }
    ares_process(channel_, &readers, &writers);
    for (ares_socket_t f : sfds) {
      if (FD_ISSET(f, &readers)) {
        server_->ProcessFD(f);
      }
    }
  }
  EXPECT_TRUE(saw_idle) << "DoT handshake busy-spun on a writable socket "
                           "instead of blocking on read";

  /* Directly confirm the wait-set: read armed, write not armed. */
  {
    ares_socket_t socks[ARES_GETSOCK_MAXNUM];
    int           bits     = ares_getsock(channel_, socks, ARES_GETSOCK_MAXNUM);
    bool          any      = false;
    bool          readable = false;
    bool          writable = false;
    for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
      if (ARES_GETSOCK_READABLE(bits, i)) {
        readable = true;
        any      = true;
      }
      if (ARES_GETSOCK_WRITABLE(bits, i)) {
        writable = true;
        any      = true;
      }
    }
    EXPECT_TRUE(any);
    EXPECT_TRUE(readable);
    EXPECT_FALSE(writable);
  }

  /* Release the stall: the server emits its flight from the ClientHello it
   * already buffered.  The client completes the handshake on a read event with
   * the write event unarmed, so the queued query only goes out if the read
   * path re-flushes it. */
  server_->SetTLSHandshakeMode(MockServer::kTlsHsNormal);
  server_->ResumeStalledHandshakes();
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

namespace {
const char *DoTEvsysName(ares_evsys_t evsys)
{
  switch (evsys) {
    case ARES_EVSYS_WIN32:
      return "WIN32";
    case ARES_EVSYS_EPOLL:
      return "EPOLL";
    case ARES_EVSYS_KQUEUE:
      return "KQUEUE";
    case ARES_EVSYS_POLL:
      return "POLL";
    case ARES_EVSYS_SELECT:
      return "SELECT";
    default:
      return "DEFAULT";
  }
}

std::string DoTPrintEvsysFamily(
  const testing::TestParamInfo<std::tuple<ares_evsys_t, int>> &info)
{
  std::string name  = DoTEvsysName(std::get<0>(info.param));
  name             += "_";
  name             += af_tostr(std::get<1>(info.param));
  return name;
}
}  // namespace

/* Run a DoT query under c-ares's own event thread, parametrized over every
 * event backend the platform supports (epoll / kqueue / poll / select / IOCP).
 * The want-flag remapping the TLS layer performs is exactly the kind of thing
 * that behaves differently per backend, so this is the DoT-specific sweep. */
class MockDoTEventThreadTest
  : public LibraryTest,
    public ::testing::WithParamInterface<std::tuple<ares_evsys_t, int>> {
public:
  MockDoTEventThreadTest()
  {
    tls_ctx_ = TlsServerCtx::Create();
    if (tls_ctx_ == nullptr) {
      return;
    }
    server_.reset(
      new testing::NiceMock<MockServer>(std::get<1>(GetParam()), mock_port));
    server_->SetTLSCtx(tls_ctx_);
  }

  ~MockDoTEventThreadTest()
  {
    if (channel_ != nullptr) {
      ares_destroy(channel_);
    }
  }

  bool HasBackend() const
  {
    return tls_ctx_ != nullptr;
  }

  bool BuildChannel()
  {
    struct ares_options opts;
    int                 optmask = 0;
    char                csv[160];
    int                 family = std::get<1>(GetParam());
    const char         *ip     = (family == AF_INET) ? "127.0.0.1" : "[::1]";

    memset(&opts, 0, sizeof(opts));
    opts.evsys           = std::get<0>(GetParam());
    optmask             |= ARES_OPT_EVENT_THREAD;
    opts.ndomains        = 0;
    optmask             |= ARES_OPT_DOMAINS;
    opts.timeout         = 1000;
    optmask             |= ARES_OPT_TIMEOUTMS;
    opts.tries           = 2;
    optmask             |= ARES_OPT_TRIES;
    opts.qcache_max_ttl  = 0;
    optmask             |= ARES_OPT_QUERY_CACHE;

    if (ares_init_options(&channel_, &opts, optmask) != ARES_SUCCESS) {
      return false;
    }

    {
      std::string ca = tls_ctx_->CaPEM();
      if (ares_tls_set_cadata(channel_->crypto_ctx,
                              (const unsigned char *)ca.data(),
                              ca.size()) != ARES_SUCCESS) {
        return false;
      }
    }

    snprintf(csv, sizeof(csv), "dns+tls://%s:%u?hostname=%s&verify=strict", ip,
             (unsigned int)server_->tcpport(), kMockDoTHostname);
    return ares_set_servers_csv(channel_, csv) == ARES_SUCCESS;
  }

  /* c-ares drives the client via its own event thread; we only pump the mock
   * server's sockets (mirrors MockEventThreadOptsTest::Process). */
  void Process()
  {
    while (ares_queue_active_queries(channel_)) {
      std::set<ares_socket_t> fds = server_->fds();
      fd_set                  readers;
      int                     nfds = 0;
      struct timeval          tv;

      FD_ZERO(&readers);
      for (ares_socket_t fd : fds) {
        FD_SET(fd, &readers);
        if (fd >= (ares_socket_t)nfds) {
          nfds = (int)fd + 1;
        }
      }
      tv.tv_sec  = 0;
      tv.tv_usec = 20000;
      if (select(nfds, &readers, nullptr, nullptr, &tv) < 0) {
        return;
      }
      for (ares_socket_t fd : fds) {
        if (FD_ISSET(fd, &readers)) {
          server_->ProcessFD(fd);
        }
      }
    }
  }

protected:
  std::shared_ptr<TlsServerCtx>                  tls_ctx_;
  std::unique_ptr<testing::NiceMock<MockServer>> server_;
  ares_channel_t                                *channel_ = nullptr;
};

TEST_P(MockDoTEventThreadTest, Query)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel());

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

INSTANTIATE_TEST_SUITE_P(EventBackends, MockDoTEventThreadTest,
                         ::testing::ValuesIn(ares::test::evsys_families),
                         DoTPrintEvsysFamily);

/* Opt-in live tests against real public DoT resolvers.  DISABLED_ so they
 * never run (or flake) in CI -- they need outbound TCP/853 and the system
 * trust store.  Run explicitly, e.g.:
 *   arestest --gtest_also_run_disabled_tests --gtest_filter='*LiveDoT*'
 */
static void LiveDoTQuery(const char *csv)
{
  ares_channel_t *channel = nullptr;
  ASSERT_EQ(ARES_SUCCESS, ares_init(&channel));
  ASSERT_EQ(ARES_SUCCESS, ares_set_servers_csv(channel, csv));

  HostResult result;
  ares_gethostbyname(channel, "example.com", AF_INET, HostCallback, &result);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_) << "server: " << csv;
  EXPECT_FALSE(result.host_.addrs_.empty());

  ares_destroy(channel);
}

TEST_F(LibraryTest, DISABLED_LiveDoTCloudflareStrict)
{
  LiveDoTQuery("dns+tls://1.1.1.1?hostname=one.one.one.one&verify=strict");
}

TEST_F(LibraryTest, DISABLED_LiveDoTGoogleStrict)
{
  LiveDoTQuery("dns+tls://8.8.8.8?hostname=dns.google&verify=strict");
}

TEST_F(LibraryTest, DISABLED_LiveDoTQuad9Strict)
{
  LiveDoTQuery("dns+tls://9.9.9.9?hostname=dns.quad9.net&verify=strict");
}

}  // namespace test
}  // namespace ares

#endif /* CARES_USE_CRYPTO && !CARES_SYMBOL_HIDING */
