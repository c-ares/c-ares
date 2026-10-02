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

/* Standalone tests for the TLS backend used by DNS-over-TLS support */

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

/* The harness requires the OpenSSL crypto backend (the peer end of the
 * socketpair is driven with OpenSSL directly), symbol visibility into the
 * library, and socketpair() (POSIX-only for now; a loopback TCP pair can
 * lift that later) */
#if defined(CARES_USE_CRYPTO) && defined(CARES_CRYPTO_OPENSSL) && \
  !defined(CARES_SYMBOL_HIDING) && !defined(_WIN32)
#  define CARES_TEST_TLS_HARNESS 1
#  include <openssl/ssl.h>
#  include <openssl/pem.h>
#  include <openssl/x509v3.h>
#  include <openssl/evp.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <fcntl.h>
#  include <unistd.h>
#  include <thread>
#  include <atomic>
#  include <vector>
#endif

namespace ares {
namespace test {

/* dns+tls:// server configuration, public API only (all platforms) */
TEST_F(LibraryTest, TLSServerConfigCSV)
{
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

#ifdef CARES_USE_CRYPTO
  EXPECT_EQ(ARES_SUCCESS,
            ares_set_servers_csv(
              channel, "dns+tls://1.2.3.4?hostname=one.example&verify=strict"
                       ",dns://5.6.7.8"));

  char *csv1 = ares_get_servers_csv(channel);
  ASSERT_NE(nullptr, csv1);
  EXPECT_NE(nullptr, strstr(csv1, "dns+tls://1.2.3.4"));
  EXPECT_NE(nullptr, strstr(csv1, "hostname=one.example"));
  EXPECT_NE(nullptr, strstr(csv1, "verify=strict"));
  EXPECT_NE(nullptr, strstr(csv1, "5.6.7.8"));

  /* Emitted form re-parses to the identical canonical form */
  EXPECT_EQ(ARES_SUCCESS, ares_set_servers_csv(channel, csv1));
  char *csv2 = ares_get_servers_csv(channel);
  ASSERT_NE(nullptr, csv2);
  EXPECT_STREQ(csv1, csv2);
  ares_free_string(csv1);
  ares_free_string(csv2);

  /* Same ip:port with different TLS identity is a distinct server */
  EXPECT_EQ(ARES_SUCCESS,
            ares_set_servers_csv(channel,
                                 "dns+tls://1.2.3.4?hostname=one.example"
                                 ",dns+tls://1.2.3.4?hostname=two.example"));
  char *csv3 = ares_get_servers_csv(channel);
  ASSERT_NE(nullptr, csv3);
  EXPECT_NE(nullptr, strstr(csv3, "one.example"));
  EXPECT_NE(nullptr, strstr(csv3, "two.example"));
  ares_free_string(csv3);

  /* Bad verify mode is rejected */
  EXPECT_NE(ARES_SUCCESS,
            ares_set_servers_csv(channel, "dns+tls://1.2.3.4?verify=bogus"));
#else
  /* Without crypto support, TLS server configuration is rejected up front */
  EXPECT_NE(ARES_SUCCESS, ares_set_servers_csv(channel, "dns+tls://1.2.3.4"));
#endif

  ares_destroy(channel);
}

#ifdef CARES_TEST_TLS_HARNESS

/* Drives the client TLS backend over one end of a socketpair against a
 * plain OpenSSL server on the other end, through a minimal fake conn, so
 * the production BIO -> ares_conn_read()/ares_conn_write() path is
 * exercised without requiring any connection-integration code. */

static X509 *TlsTestMkCert(EVP_PKEY *pubkey, EVP_PKEY *signkey, X509 *issuer,
                           long serial, bool is_ca)
{
  X509           *x = X509_new();
  X509_NAME      *name;
  X509_EXTENSION *ext;
  X509V3_CTX      v3ctx;

  if (x == NULL) {
    return NULL;
  }
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
  X509_gmtime_adj(X509_getm_notBefore(x), -60);
  X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60L);
  X509_set_pubkey(x, pubkey);
  /* Build the subject name in a fresh X509_NAME and install it with the
   * setter.  As of OpenSSL 4.0 X509_get_subject_name() returns const, because
   * the cert's internal name must not be mutated in place; the old pattern of
   * adding entries directly to it is invalid there. */
  name = X509_NAME_new();
  if (name == NULL) {
    X509_free(x);
    return NULL;
  }
  X509_NAME_add_entry_by_txt(
    name, "CN", MBSTRING_ASC,
    (const unsigned char *)(is_ca ? "c-ares test CA" : "c-ares test server"),
    -1, -1, 0);
  X509_set_subject_name(x, name);
  /* Self-signed certs use the subject as the issuer.  X509_set_issuer_name()
   * takes a const name and copies it, so the const getter is fine here. */
  X509_set_issuer_name(x,
                       issuer != NULL ? X509_get_subject_name(issuer) : name);
  X509_NAME_free(name);
  X509V3_set_ctx_nodb(&v3ctx);
  X509V3_set_ctx(&v3ctx, issuer != NULL ? issuer : x, x, NULL, NULL, 0);
  ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints,
                            is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
  if (ext != NULL) {
    X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
  }
  /* The server leaf carries a subjectAltName so strict verification against a
   * configured authentication name is actually exercised. */
  if (!is_ca) {
    ext =
      X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_alt_name, "DNS:dot.test");
    if (ext != NULL) {
      X509_add_ext(x, ext, -1);
      X509_EXTENSION_free(ext);
    }
  }
  if (!X509_sign(x, signkey, EVP_sha256())) {
    X509_free(x);
    return NULL;
  }
  return x;
}

class TLSHarness {
public:
  TLSHarness() = default;

  ~TLSHarness()
  {
    if (tls_ != NULL) {
      ares_tlsimp_destroy(tls_);
    }
    if (sssl_ != NULL) {
      SSL_free(sssl_);
    }
    if (sctx_ != NULL) {
      SSL_CTX_free(sctx_);
    }
    CloseFd(0);
    CloseFd(1);
    if (channel_ != NULL) {
      ares_destroy(channel_);
    }
    if (srv_cert_ != NULL) {
      X509_free(srv_cert_);
    }
    if (srv_key_ != NULL) {
      EVP_PKEY_free(srv_key_);
    }
    if (ca_cert_ != NULL) {
      X509_free(ca_cert_);
    }
    if (ca_key_ != NULL) {
      EVP_PKEY_free(ca_key_);
    }
  }

  /* trust_ca == false leaves the generated CA out of the client store, so
   * certificate verification must fail.  max_early > 0 makes the server
   * advertise TLSv1.3 early data support in its session tickets. */
  bool Init(bool trust_ca, unsigned int max_early = 0)
  {
    /* Runtime-generated ECDSA P-256 CA + server cert (P-256 satisfies the
     * backend's security level regardless of where that decision lands) */
    ca_key_  = EVP_EC_gen("P-256");
    srv_key_ = EVP_EC_gen("P-256");
    if (ca_key_ == NULL || srv_key_ == NULL) {
      return false;
    }
    ca_cert_ = TlsTestMkCert(ca_key_, ca_key_, NULL, 1, true);
    if (ca_cert_ == NULL) {
      return false;
    }
    srv_cert_ = TlsTestMkCert(srv_key_, ca_key_, ca_cert_, 2, false);
    if (srv_cert_ == NULL) {
      return false;
    }

    if (ares_init(&channel_) != ARES_SUCCESS) {
      return false;
    }

    if (trust_ca) {
      BIO  *bio = BIO_new(BIO_s_mem());
      char *pem = NULL;
      long  len;
      bool  ok;
      if (bio == NULL || !PEM_write_bio_X509(bio, ca_cert_)) {
        BIO_free(bio);
        return false;
      }
      len = BIO_get_mem_data(bio, &pem);
      ok = ares_tls_set_cadata(channel_->crypto_ctx, (const unsigned char *)pem,
                               (size_t)len) == ARES_SUCCESS;
      BIO_free(bio);
      if (!ok) {
        return false;
      }
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv_) != 0) {
      return false;
    }
    if (fcntl(sv_[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(sv_[1], F_SETFL, O_NONBLOCK) != 0) {
      return false;
    }

    /* Minimal fake server/conn: everything ares_conn_read()/
     * ares_conn_write() and the session-cache key derivation consult */
    memset(&server_, 0, sizeof(server_));
    server_.channel                = channel_;
    server_.addr.family            = AF_INET;
    server_.addr.addr.addr4.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    server_.udp_port               = 853;
    server_.tcp_port               = 853;
    server_.use_tls                = ARES_TRUE;
    /* No authentication name is configured here, so strict is chain-only
     * verification against the injected CA (the cert's SAN is not checked). */
    server_.tls_verify = ARES_TLS_VERIFY_STRICT;

    memset(&conn_, 0, sizeof(conn_));
    conn_.server = &server_;
    conn_.fd     = sv_[0];
    conn_.flags  = (ares_conn_flags_t)(ARES_CONN_FLAG_TCP | ARES_CONN_FLAG_TLS);
    conn_.state_flags = ARES_CONN_STATE_CONNECTED;

    if (ares_tls_create(&tls_, channel_->crypto_ctx, &conn_) != ARES_SUCCESS) {
      return false;
    }
    conn_.tls = tls_;

    /* Plain OpenSSL server on the other end of the pair */
    sctx_ = MakeServerCtx(max_early);
    if (sctx_ == NULL) {
      return false;
    }
    return AttachServerSsl();
  }

  SSL_CTX *MakeServerCtx(unsigned int max_early)
  {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
      return NULL;
    }
    if (SSL_CTX_use_certificate(ctx, srv_cert_) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, srv_key_) != 1) {
      SSL_CTX_free(ctx);
      return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (max_early > 0) {
      SSL_CTX_set_max_early_data(ctx, max_early);
      /* Deterministic 0-RTT acceptance: the client treats sessions as
       * single-use so replay isn't possible from this harness, and the
       * server's anti-replay would otherwise reject the first attempt */
      SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
    }
    return ctx;
  }

  bool AttachServerSsl(void)
  {
    sssl_ = SSL_new(sctx_);
    if (sssl_ == NULL) {
      return false;
    }
    if (SSL_set_fd(sssl_, sv_[1]) != 1) {
      return false;
    }
    SSL_set_accept_state(sssl_);
    return true;
  }

  /* Tear down the client TLS session, server SSL and socketpair -- keeping
   * the channel, certificates and (optionally) the server ctx -- then
   * create a fresh connection to exercise session resumption.  A fresh
   * server ctx has new session-ticket keys, so a cached client session
   * presented to it cannot resume (used to force early-data rejection). */
  bool Reconnect(bool fresh_server_ctx, unsigned int max_early = 0)
  {
    if (tls_ != NULL) {
      /* Close gracefully: an SSL freed without shutdown is treated as a
       * bad connection by OpenSSL and its session is evicted from the
       * cache, which would defeat the resumption this exercises */
      if (ares_tlsimp_get_state(tls_) == ARES_TLS_STATE_ESTABLISHED) {
        (void)ares_tlsimp_shutdown(tls_);
      }
      ares_tlsimp_destroy(tls_);
      tls_      = nullptr;
      conn_.tls = nullptr;
    }
    if (sssl_ != NULL) {
      SSL_free(sssl_);
      sssl_ = nullptr;
    }
    CloseFd(0);
    CloseFd(1);
    srv_done_ = false;
    srv_fail_ = false;

    if (fresh_server_ctx) {
      SSL_CTX_free(sctx_);
      sctx_ = MakeServerCtx(max_early);
      if (sctx_ == NULL) {
        return false;
      }
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv_) != 0) {
      return false;
    }
    if (fcntl(sv_[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(sv_[1], F_SETFL, O_NONBLOCK) != 0) {
      return false;
    }
    conn_.fd = sv_[0];

    if (ares_tls_create(&tls_, channel_->crypto_ctx, &conn_) != ARES_SUCCESS) {
      return false;
    }
    conn_.tls = tls_;
    return AttachServerSsl();
  }

  /* Pump both ends until established or client-side failure.  Returns the
   * last client status. */
  ares_conn_err_t PumpHandshake()
  {
    ares_conn_err_t cerr = ARES_CONN_ERR_WOULDBLOCK;
    int             i;

    for (i = 0; i < 100; i++) {
      if (ares_tlsimp_get_state(tls_) != ARES_TLS_STATE_ESTABLISHED) {
        cerr = ares_tlsimp_connect(tls_);
        if (cerr != ARES_CONN_ERR_SUCCESS && cerr != ARES_CONN_ERR_WOULDBLOCK) {
          return cerr;
        }
      }
      if (!srv_done_) {
        int rv = SSL_accept(sssl_);
        if (rv == 1) {
          srv_done_ = true;
        } else {
          int err = SSL_get_error(sssl_, rv);
          if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            /* Server handshake failed (e.g. client sent a fatal alert);
             * keep pumping so the client surfaces its own error */
            srv_fail_ = true;
          }
        }
      }
      if (srv_done_ &&
          ares_tlsimp_get_state(tls_) == ARES_TLS_STATE_ESTABLISHED) {
        return ARES_CONN_ERR_SUCCESS;
      }
    }
    return ARES_CONN_ERR_CONNTIMEDOUT;
  }

  bool ServerRead(unsigned char *buf, size_t buf_len, size_t *read_len)
  {
    int i;
    for (i = 0; i < 100; i++) {
      int rv = SSL_read_ex(sssl_, buf, buf_len, read_len);
      if (rv == 1) {
        return true;
      }
      int err = SSL_get_error(sssl_, rv);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        return false;
      }
    }
    return false;
  }

  bool ServerWrite(const unsigned char *buf, size_t len)
  {
    size_t written = 0;
    int    i;
    for (i = 0; i < 100; i++) {
      int rv = SSL_write_ex(sssl_, buf, len, &written);
      if (rv == 1) {
        return written == len;
      }
      int err = SSL_get_error(sssl_, rv);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        return false;
      }
    }
    return false;
  }

  ares_conn_err_t ClientRead(unsigned char *buf, size_t *len)
  {
    size_t          want = *len;
    ares_conn_err_t err  = ARES_CONN_ERR_WOULDBLOCK;
    int             i;
    for (i = 0; i < 100; i++) {
      *len = want;
      err  = ares_tlsimp_read(tls_, buf, len);
      if (err != ARES_CONN_ERR_WOULDBLOCK) {
        return err;
      }
    }
    return err;
  }

  /* Read whatever is currently decryptable server-side, appending to out.
   * Returns false on a hard error. */
  bool DrainServer(std::string *out)
  {
    int i;
    for (i = 0; i < 100; i++) {
      unsigned char buf[4096];
      size_t        rb = 0;
      int           rv = SSL_read_ex(sssl_, buf, sizeof(buf), &rb);
      if (rv == 1) {
        out->append(reinterpret_cast<char *>(buf), rb);
        continue;
      }
      int err = SSL_get_error(sssl_, rv);
      return err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE;
    }
    return true;
  }

  /* Pump an early-data handshake: the client has already called
   * ares_tlsimp_earlydata_write().  The server consumes the early-data
   * phase with SSL_read_early_data() until FINISH while the client
   * completes the handshake.  Early data the server actually accepted
   * (none, when it rejects 0-RTT) is appended to early. */
  ares_conn_err_t PumpEarlyHandshake(std::string *early)
  {
    bool finish = false;
    int  i;

    for (i = 0; i < 200; i++) {
      if (ares_tlsimp_get_state(tls_) != ARES_TLS_STATE_ESTABLISHED) {
        ares_conn_err_t cerr = ares_tlsimp_connect(tls_);
        if (cerr != ARES_CONN_ERR_SUCCESS && cerr != ARES_CONN_ERR_WOULDBLOCK) {
          return cerr;
        }
      }
      if (!finish) {
        unsigned char buf[512];
        size_t        rb = 0;
        int           rv = SSL_read_early_data(sssl_, buf, sizeof(buf), &rb);
        if (rv == SSL_READ_EARLY_DATA_SUCCESS) {
          early->append(reinterpret_cast<char *>(buf), rb);
        } else if (rv == SSL_READ_EARLY_DATA_FINISH) {
          finish    = true;
          srv_done_ = true;
        } else {
          int err = SSL_get_error(sssl_, rv);
          if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            srv_fail_ = true;
          }
        }
      }
      if (finish && ares_tlsimp_get_state(tls_) == ARES_TLS_STATE_ESTABLISHED) {
        return ARES_CONN_ERR_SUCCESS;
      }
    }
    return ARES_CONN_ERR_CONNTIMEDOUT;
  }

  void CloseFd(int idx)
  {
    if (sv_[idx] != -1) {
      close(sv_[idx]);
      sv_[idx] = -1;
    }
  }

  ares_channel_t *channel_ = nullptr;
  ares_tls_t     *tls_     = nullptr;
  ares_server_t   server_;
  ares_conn_t     conn_;
  int             sv_[2]    = { -1, -1 };
  SSL_CTX        *sctx_     = nullptr;
  SSL            *sssl_     = nullptr;
  bool            srv_done_ = false;
  bool            srv_fail_ = false;
  EVP_PKEY       *ca_key_   = nullptr;
  X509           *ca_cert_  = nullptr;
  EVP_PKEY       *srv_key_  = nullptr;
  X509           *srv_cert_ = nullptr;
};

TEST_F(LibraryTest, CryptoTLSHandshakeIO)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));

  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());
  EXPECT_EQ(ARES_TLS_STATE_ESTABLISHED, ares_tlsimp_get_state(h.tls_));

  /* client -> server (TCP-framed DNS shape, but the layer is opaque bytes) */
  unsigned char query[] = { 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
  size_t        wlen    = sizeof(query);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, ares_tlsimp_write(h.tls_, query, &wlen));
  EXPECT_EQ(sizeof(query), wlen);

  unsigned char sbuf[64];
  size_t        sread = 0;
  ASSERT_TRUE(h.ServerRead(sbuf, sizeof(sbuf), &sread));
  ASSERT_EQ(sizeof(query), sread);
  EXPECT_EQ(0, memcmp(query, sbuf, sread));

  /* server -> client */
  unsigned char resp[] = { 0x00, 0x03, 'a', 'c', 'k' };
  ASSERT_TRUE(h.ServerWrite(resp, sizeof(resp)));

  unsigned char cbuf[64];
  size_t        clen = sizeof(cbuf);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.ClientRead(cbuf, &clen));
  ASSERT_EQ(sizeof(resp), clen);
  EXPECT_EQ(0, memcmp(resp, cbuf, clen));

  /* graceful shutdown */
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, ares_tlsimp_shutdown(h.tls_));
  EXPECT_EQ(ARES_TLS_STATE_DISCONNECTED, ares_tlsimp_get_state(h.tls_));
}

TEST_F(LibraryTest, CryptoTLSVerifyFail)
{
  TLSHarness h;
  /* CA not trusted by the client: certificate verification must fail and
   * the connection must not silently proceed (strict by default) */
  ASSERT_TRUE(h.Init(false));

  /* Certificate verification failures surface distinguishably from
   * transport errors */
  EXPECT_EQ(ARES_CONN_ERR_SECURITY, h.PumpHandshake());
  EXPECT_EQ(ARES_TLS_STATE_ERROR, ares_tlsimp_get_state(h.tls_));
}

TEST_F(LibraryTest, CryptoTLSWantFlags)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));

  /* First connect: ClientHello flushed, handshake now needs the server's
   * reply, so progressing requires a readable socket for either logical
   * operation */
  EXPECT_EQ(ARES_CONN_ERR_WOULDBLOCK, ares_tlsimp_connect(h.tls_));
  EXPECT_EQ(
    (unsigned int)(ARES_TLS_SF_READ_WANTREAD | ARES_TLS_SF_WRITE_WANTREAD),
    (unsigned int)ares_tlsimp_get_stateflag(h.tls_));

  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());

  /* Established, nothing pending: read wants a readable socket, and the
   * write direction is unaffected */
  unsigned char b[16];
  size_t        blen = sizeof(b);
  EXPECT_EQ(ARES_CONN_ERR_WOULDBLOCK, ares_tlsimp_read(h.tls_, b, &blen));
  EXPECT_EQ((unsigned int)ARES_TLS_SF_READ_WANTREAD,
            (unsigned int)ares_tlsimp_get_stateflag(h.tls_) &
              (unsigned int)ARES_TLS_SF_READ);
  EXPECT_EQ(0, (unsigned int)ares_tlsimp_get_stateflag(h.tls_) &
                 (unsigned int)ARES_TLS_SF_WRITE);

  /* Flood the socketpair until the kernel buffer fills: write must report
   * it wants a writable socket */
  {
    static unsigned char big[4096];
    ares_conn_err_t      werr = ARES_CONN_ERR_SUCCESS;
    int                  i;
    memset(big, 'x', sizeof(big));
    for (i = 0; i < 1000; i++) {
      size_t wl = sizeof(big);
      werr      = ares_tlsimp_write(h.tls_, big, &wl);
      if (werr != ARES_CONN_ERR_SUCCESS) {
        break;
      }
    }
    EXPECT_EQ(ARES_CONN_ERR_WOULDBLOCK, werr);
    EXPECT_TRUE((unsigned int)ares_tlsimp_get_stateflag(h.tls_) &
                (unsigned int)ARES_TLS_SF_WRITE_WANTWRITE);
  }
}

TEST_F(LibraryTest, CryptoTLSPeerClose)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());

  /* Abrupt peer close (no close_notify): reads must surface a hard error,
   * not hang or claim success */
  h.CloseFd(1);

  unsigned char   buf[16];
  size_t          blen = sizeof(buf);
  ares_conn_err_t err  = h.ClientRead(buf, &blen);
  EXPECT_NE(ARES_CONN_ERR_SUCCESS, err);
  EXPECT_NE(ARES_CONN_ERR_WOULDBLOCK, err);
  EXPECT_EQ(ARES_TLS_STATE_ERROR, ares_tlsimp_get_state(h.tls_));
}

TEST_F(LibraryTest, CryptoTLSInterpretEvents)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));

  /* Register the fake conn the same way the production register path does,
   * so ares_conn_from_fd() resolves it */
  ares_llist_t *l = ares_llist_create(NULL);
  ASSERT_NE(nullptr, l);
  ares_llist_node_t *node = ares_llist_insert_last(l, &h.conn_);
  ASSERT_NE(nullptr, node);
  ASSERT_TRUE(
    ares_htable_asvp_insert(h.channel_->connnode_by_socket, h.conn_.fd, node));

  ares_fd_events_t  ev;
  ares_fd_events_t *out = NULL;
  size_t            n;

  /* Handshake blocked wanting read: a readable fd maps to both logical
   * read and write events; a writable fd maps to nothing */
  EXPECT_EQ(ARES_CONN_ERR_WOULDBLOCK, ares_tlsimp_connect(h.tls_));

  ev.fd     = h.conn_.fd;
  ev.events = ARES_FD_EVENT_READ;
  n         = 1;
  ASSERT_EQ(ARES_SUCCESS,
            ares_conn_interpret_events(&out, h.channel_, &ev, &n));
  ASSERT_EQ((size_t)1, n);
  EXPECT_EQ(h.conn_.fd, out[0].fd);
  EXPECT_EQ((unsigned int)(ARES_FD_EVENT_READ | ARES_FD_EVENT_WRITE),
            out[0].events);
  ares_free(out);
  out = NULL;

  /* A writable fd while the handshake wants read maps to no events, so the
   * (zero-events) entry is dropped rather than emitted. */
  ev.events = ARES_FD_EVENT_WRITE;
  n         = 1;
  ASSERT_EQ(ARES_SUCCESS,
            ares_conn_interpret_events(&out, h.channel_, &ev, &n));
  EXPECT_EQ((size_t)0, n);
  ares_free(out);
  out = NULL;

  /* Unknown fd only: no TLS connection involved, so no translation is
   * performed (NULL output = events apply as-is, no allocation) */
  ev.fd     = h.sv_[1];
  ev.events = ARES_FD_EVENT_READ;
  n         = 1;
  ASSERT_EQ(ARES_SUCCESS,
            ares_conn_interpret_events(&out, h.channel_, &ev, &n));
  EXPECT_EQ(nullptr, out);
  EXPECT_EQ((size_t)1, n);

  /* Non-TLS conn: same as-is contract, the hot path must not allocate */
  h.conn_.flags = ARES_CONN_FLAG_TCP;
  ev.fd         = h.conn_.fd;
  ev.events     = ARES_FD_EVENT_READ;
  n             = 1;
  ASSERT_EQ(ARES_SUCCESS,
            ares_conn_interpret_events(&out, h.channel_, &ev, &n));
  EXPECT_EQ(nullptr, out);
  EXPECT_EQ((size_t)1, n);
  h.conn_.flags = (ares_conn_flags_t)(ARES_CONN_FLAG_TCP | ARES_CONN_FLAG_TLS);

  /* Deregister before the channel is destroyed (ares_destroy() asserts the
   * table is empty) */
  ares_htable_asvp_remove(h.channel_->connnode_by_socket, h.conn_.fd);
  ares_llist_destroy(l);
}

TEST_F(LibraryTest, CryptoTLSMidHandshakeClose)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));

  /* ClientHello is out, then the peer vanishes before replying: the
   * handshake must surface a hard error, not spin */
  EXPECT_EQ(ARES_CONN_ERR_WOULDBLOCK, ares_tlsimp_connect(h.tls_));
  h.CloseFd(1);

  ares_conn_err_t err = ARES_CONN_ERR_WOULDBLOCK;
  for (int i = 0; i < 100 && err == ARES_CONN_ERR_WOULDBLOCK; i++) {
    err = ares_tlsimp_connect(h.tls_);
  }
  EXPECT_NE(ARES_CONN_ERR_SUCCESS, err);
  EXPECT_NE(ARES_CONN_ERR_WOULDBLOCK, err);
  EXPECT_EQ(ARES_TLS_STATE_ERROR, ares_tlsimp_get_state(h.tls_));
}

TEST_F(LibraryTest, CryptoTLSPartialWrites)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());

  /* Send a large patterned stream with the server draining only when the
   * client blocks: exercises WOULDBLOCK-and-retry and partial-write
   * accounting.  Every byte reported written must arrive exactly once, in
   * order. */
  std::string   received;
  size_t        total_sent = 0;
  unsigned char chunk[4096];
  bool          blocked = false;

  for (int c = 0; c < 64; c++) {
    size_t j;
    size_t off = 0;
    int    guard;

    for (j = 0; j < sizeof(chunk); j++) {
      chunk[j] = (unsigned char)((total_sent + j) & 0xFF);
    }
    for (guard = 0; guard < 1000 && off < sizeof(chunk); guard++) {
      size_t          wl  = sizeof(chunk) - off;
      ares_conn_err_t err = ares_tlsimp_write(h.tls_, chunk + off, &wl);
      if (err == ARES_CONN_ERR_SUCCESS) {
        off        += wl;
        total_sent += wl;
        continue;
      }
      ASSERT_EQ(ARES_CONN_ERR_WOULDBLOCK, err);
      blocked = true;
      ASSERT_TRUE(h.DrainServer(&received));
    }
    ASSERT_EQ(sizeof(chunk), off);
  }
  EXPECT_TRUE(blocked);

  for (int guard = 0; guard < 1000 && received.size() < total_sent; guard++) {
    ASSERT_TRUE(h.DrainServer(&received));
  }
  ASSERT_EQ(total_sent, received.size());
  for (size_t i = 0; i < received.size(); i++) {
    ASSERT_EQ((char)(i & 0xFF), received[i]) << "corruption at offset " << i;
  }
}

TEST_F(LibraryTest, CryptoTLSSessionResumption)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());

  /* TLSv1.3 tickets arrive post-handshake; a read processes them and the
   * new-session callback populates the cache */
  unsigned char m[] = { 't' };
  ASSERT_TRUE(h.ServerWrite(m, sizeof(m)));
  unsigned char rbuf[16];
  size_t        rlen = sizeof(rbuf);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.ClientRead(rbuf, &rlen));
  ASSERT_NE(nullptr, ares_tls_session_get(h.channel_->crypto_ctx, &h.conn_));

  /* A second connection to the same server consumes the cached session
   * (single-use, per TLSv1.3 guidance) and resumes */
  ASSERT_TRUE(h.Reconnect(false));
  EXPECT_EQ(nullptr, ares_tls_session_get(h.channel_->crypto_ctx, &h.conn_));
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());
  EXPECT_EQ(1, SSL_session_reused(h.sssl_));

  /* The resumed handshake delivers fresh tickets: the cache repopulates */
  ASSERT_TRUE(h.ServerWrite(m, sizeof(m)));
  rlen = sizeof(rbuf);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.ClientRead(rbuf, &rlen));
  EXPECT_NE(nullptr, ares_tls_session_get(h.channel_->crypto_ctx, &h.conn_));
}

/* The session-cache key folds the effective verify mode specifically so an
 * unauthenticated (opportunistic) session can never be resumed by a strict
 * connection -- a silent downgrade.  Every other resumption test is
 * strict->strict, so a regression dropping the verify component from
 * ares_tls_session_key() would leave the key unique-per-test and every test
 * still passing.  ares_tls_session_get() is non-consuming, so probe directly:
 * cache under strict, assert a MISS under opportunistic (different key), then a
 * HIT again under strict. */
TEST_F(LibraryTest, CryptoTLSSessionVerifyModeKeyed)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());

  /* Post-handshake ticket populates the cache, keyed under strict. */
  unsigned char m[] = { 't' };
  ASSERT_TRUE(h.ServerWrite(m, sizeof(m)));
  unsigned char rbuf[16];
  size_t        rlen = sizeof(rbuf);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.ClientRead(rbuf, &rlen));

  ASSERT_EQ(ARES_TLS_VERIFY_STRICT, h.server_.tls_verify);
  EXPECT_NE(nullptr, ares_tls_session_get(h.channel_->crypto_ctx, &h.conn_));

  /* Same ip/port/hostname but opportunistic -> different key -> must miss. */
  h.server_.tls_verify = ARES_TLS_VERIFY_OPPORTUNISTIC;
  EXPECT_EQ(nullptr, ares_tls_session_get(h.channel_->crypto_ctx, &h.conn_));

  /* Back to strict -> the cached session is found again (proves the miss was
   * the key, not eviction). */
  h.server_.tls_verify = ARES_TLS_VERIFY_STRICT;
  EXPECT_NE(nullptr, ares_tls_session_get(h.channel_->crypto_ctx, &h.conn_));
}

TEST_F(LibraryTest, CryptoTLSEarlyDataAccept)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true, 16384));

  /* No session yet: no early-data budget, writes are refused up front */
  EXPECT_EQ((size_t)0, ares_tlsimp_get_earlydata_size(h.tls_));
  unsigned char q[] = { 0x00, 0x03, 'e', 'd', '!' };
  size_t        ql  = sizeof(q);
  EXPECT_EQ(ARES_CONN_ERR_TOOLARGE,
            ares_tlsimp_earlydata_write(h.tls_, q, &ql));

  /* Handshake and cache a session advertising early data */
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());
  unsigned char m[] = { 't' };
  ASSERT_TRUE(h.ServerWrite(m, sizeof(m)));
  unsigned char rbuf[16];
  size_t        rlen = sizeof(rbuf);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.ClientRead(rbuf, &rlen));
  ASSERT_NE(nullptr, ares_tls_session_get(h.channel_->crypto_ctx, &h.conn_));

  /* Reconnect: the resumed session carries the early-data budget and the
   * first flight carries the payload */
  ASSERT_TRUE(h.Reconnect(false));
  EXPECT_EQ((size_t)16384, ares_tlsimp_get_earlydata_size(h.tls_));
  ql = sizeof(q);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, ares_tlsimp_earlydata_write(h.tls_, q, &ql));
  EXPECT_EQ(sizeof(q), ql);

  std::string early;
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpEarlyHandshake(&early));
  EXPECT_EQ(ARES_TRUE, ares_tlsimp_earlydata_accepted(h.tls_));
  ASSERT_EQ(sizeof(q), early.size());
  EXPECT_EQ(0, memcmp(q, early.data(), early.size()));

  /* Connection is fully usable afterwards */
  unsigned char resp[] = { 'o', 'k' };
  ASSERT_TRUE(h.ServerWrite(resp, sizeof(resp)));
  rlen = sizeof(rbuf);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.ClientRead(rbuf, &rlen));
  ASSERT_EQ(sizeof(resp), rlen);
  EXPECT_EQ(0, memcmp(resp, rbuf, rlen));
}

TEST_F(LibraryTest, CryptoTLSEarlyDataReject)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true, 16384));
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());
  unsigned char m[] = { 't' };
  ASSERT_TRUE(h.ServerWrite(m, sizeof(m)));
  unsigned char rbuf[16];
  size_t        rlen = sizeof(rbuf);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.ClientRead(rbuf, &rlen));
  ASSERT_NE(nullptr, ares_tls_session_get(h.channel_->crypto_ctx, &h.conn_));

  /* Fresh server ctx: new ticket keys, so the client's cached session
   * cannot resume and its 0-RTT flight must be rejected */
  ASSERT_TRUE(h.Reconnect(true, 16384));
  unsigned char q[] = { 0x00, 0x03, 'e', 'd', '!' };
  size_t        ql  = sizeof(q);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, ares_tlsimp_earlydata_write(h.tls_, q, &ql));

  std::string early;
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpEarlyHandshake(&early));
  EXPECT_EQ(ARES_FALSE, ares_tlsimp_earlydata_accepted(h.tls_));
  EXPECT_EQ((size_t)0, early.size());

  /* The rejected flight is the caller's to replay through the normal
   * write path; it must arrive exactly once */
  ql = sizeof(q);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, ares_tlsimp_write(h.tls_, q, &ql));
  unsigned char sbuf[64];
  size_t        sread = 0;
  ASSERT_TRUE(h.ServerRead(sbuf, sizeof(sbuf), &sread));
  ASSERT_EQ(sizeof(q), sread);
  EXPECT_EQ(0, memcmp(q, sbuf, sread));
}

TEST_F(LibraryTest, CryptoTLSGracefulClose)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());

  /* Server closes cleanly (close_notify): normal for a DoT server
   * dropping an idle connection -- must surface as a clean close, not an
   * error */
  SSL_shutdown(h.sssl_);

  unsigned char buf[16];
  size_t        blen = sizeof(buf);
  EXPECT_EQ(ARES_CONN_ERR_CONNCLOSED, h.ClientRead(buf, &blen));
  EXPECT_EQ(ARES_TLS_STATE_DISCONNECTED, ares_tlsimp_get_state(h.tls_));
}

TEST_F(LibraryTest, CryptoTLSReadPending)
{
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());

  /* Read-ahead buffers whole TLS records inside OpenSSL: after a partial
   * read the remainder is available with nothing left in the socket, and
   * the pending indicator must say so */
  unsigned char big[2000];
  for (size_t i = 0; i < sizeof(big); i++) {
    big[i] = (unsigned char)(i & 0xFF);
  }
  ASSERT_TRUE(h.ServerWrite(big, sizeof(big)));

  unsigned char rbuf[100];
  size_t        rlen  = sizeof(rbuf);
  size_t        total = 0;
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.ClientRead(rbuf, &rlen));
  EXPECT_EQ(0, memcmp(big, rbuf, rlen));
  total += rlen;

  EXPECT_EQ(ARES_TRUE, ares_tlsimp_get_read_pending(h.tls_));

  /* Drain the rest without any further server or socket activity */
  int guard;
  for (guard = 0; guard < 1000 && total < sizeof(big); guard++) {
    size_t          want = sizeof(rbuf);
    ares_conn_err_t err  = ares_tlsimp_read(h.tls_, rbuf, &want);
    ASSERT_EQ(ARES_CONN_ERR_SUCCESS, err);
    ASSERT_LE(want, sizeof(big) - total);
    EXPECT_EQ(0, memcmp(big + total, rbuf, want));
    total += want;
  }
  EXPECT_EQ(sizeof(big), total);

  /* Fully drained: nothing pending, next read blocks */
  EXPECT_EQ(ARES_FALSE, ares_tlsimp_get_read_pending(h.tls_));
  rlen = sizeof(rbuf);
  EXPECT_EQ(ARES_CONN_ERR_WOULDBLOCK, ares_tlsimp_read(h.tls_, rbuf, &rlen));
}

/* Minimal threaded DoT server: accepts TLS connections on a loopback
 * listener and answers each TCP-framed A query with 1.2.3.4, echoing the
 * request id and question. */
class DoTTestServer {
public:
  DoTTestServer() = default;

  ~DoTTestServer()
  {
    Stop();
    if (sctx_ != NULL) {
      SSL_CTX_free(sctx_);
    }
  }

  bool Start(X509 *cert, EVP_PKEY *key, unsigned int max_early = 0,
             bool reject_early = false)
  {
    struct sockaddr_in sin;
    socklen_t          slen = sizeof(sin);

    want_early_   = (max_early > 0);
    reject_early_ = reject_early;

    sctx_ = SSL_CTX_new(TLS_server_method());
    if (sctx_ == NULL) {
      return false;
    }
    if (SSL_CTX_use_certificate(sctx_, cert) != 1 ||
        SSL_CTX_use_PrivateKey(sctx_, key) != 1) {
      return false;
    }
    SSL_CTX_set_min_proto_version(sctx_, TLS1_2_VERSION);
    if (want_early_) {
      SSL_CTX_set_max_early_data(sctx_, max_early);
      /* Deterministic 0-RTT acceptance for the test (single-use client
       * sessions mean no real replay here) */
      SSL_CTX_set_options(sctx_, SSL_OP_NO_ANTI_REPLAY);
    }

    lfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd_ < 0) {
      return false;
    }
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd_, (struct sockaddr *)&sin, sizeof(sin)) != 0 ||
        listen(lfd_, 2) != 0 ||
        getsockname(lfd_, (struct sockaddr *)&sin, &slen) != 0) {
      return false;
    }
    port_ = ntohs(sin.sin_port);

    thr_ = std::thread(&DoTTestServer::Run, this);
    return true;
  }

  void Stop()
  {
    if (lfd_ != -1) {
      shutdown(lfd_, SHUT_RDWR);
      close(lfd_);
      lfd_ = -1;
    }
    if (thr_.joinable()) {
      thr_.join();
    }
  }

  unsigned short   port_ = 0;
  std::atomic<int> queries_{ 0 };
  std::atomic<int> accepts_{ 0 };
  std::atomic<int> early_queries_{ 0 };

private:
  bool WriteFull(SSL *ssl, const unsigned char *buf, size_t len)
  {
    size_t off = 0;
    while (off < len) {
      size_t wb = 0;
      if (SSL_write_ex(ssl, buf + off, len - off, &wb) != 1) {
        return false;
      }
      off += wb;
    }
    return true;
  }

  bool AnswerQuery(SSL *ssl, const unsigned char *q, size_t qlen)
  {
    ares_dns_record_t  *req  = NULL;
    ares_dns_record_t  *resp = NULL;
    const char         *name = NULL;
    ares_dns_rec_type_t qtype;
    ares_dns_class_t    qclass;
    ares_dns_rr_t      *rr   = NULL;
    unsigned char      *abuf = NULL;
    size_t              alen = 0;
    unsigned char       frame[2];
    bool                ok = false;
    struct ares_addr    addr;

    if (ares_dns_parse(q, qlen, 0, &req) != ARES_SUCCESS) {
      return false;
    }
    if (ares_dns_record_query_get(req, 0, &name, &qtype, &qclass) !=
          ARES_SUCCESS ||
        ares_dns_record_create(&resp, ares_dns_record_get_id(req),
                               ARES_FLAG_QR | ARES_FLAG_RA, ARES_OPCODE_QUERY,
                               ARES_RCODE_NOERROR) != ARES_SUCCESS) {
      goto done;
    }
    if (ares_dns_record_query_add(resp, name, qtype, qclass) != ARES_SUCCESS) {
      goto done;
    }

    memset(&addr, 0, sizeof(addr));
    addr.family            = AF_INET;
    addr.addr.addr4.s_addr = htonl(0x01020304); /* 1.2.3.4 */
    if (ares_dns_record_rr_add(&rr, resp, ARES_SECTION_ANSWER, name,
                               ARES_REC_TYPE_A, ARES_CLASS_IN,
                               60) != ARES_SUCCESS ||
        ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr.addr.addr4) !=
          ARES_SUCCESS) {
      goto done;
    }

    if (ares_dns_write(resp, &abuf, &alen) != ARES_SUCCESS) {
      goto done;
    }

    frame[0] = (unsigned char)((alen >> 8) & 0xFF);
    frame[1] = (unsigned char)(alen & 0xFF);
    ok       = WriteFull(ssl, frame, 2) && WriteFull(ssl, abuf, alen);
    if (ok) {
      queries_++;
    }

done:
    ares_free_string(abuf);
    ares_dns_record_destroy(resp);
    ares_dns_record_destroy(req);
    return ok;
  }

  /* Handle one connection.  Reads the request stream (early data first when
   * enabled, then post-handshake), extracts complete TCP-framed queries,
   * answers each, and counts how many arrived entirely within the early-data
   * region. */
  void HandleConn(int cfd)
  {
    SSL *ssl = SSL_new(sctx_);
    if (ssl == NULL || SSL_set_fd(ssl, cfd) != 1) {
      if (ssl != NULL) {
        SSL_free(ssl);
      }
      close(cfd);
      return;
    }

    std::vector<unsigned char> buf;
    size_t                     early_len = 0;

    /* Reject 0-RTT on the resuming (second and later) connection: the session
     * still resumes, but max_early_data == 0 refuses the early data so the
     * client must re-send the query in the normal stream.  Exercises the
     * ares_conn.c early-data reject reconciliation end-to-end. */
    if (reject_early_ && want_early_ && accepts_.load() >= 2) {
      SSL_set_max_early_data(ssl, 0);
    }

    if (want_early_) {
      for (;;) {
        unsigned char eb[512];
        size_t        n  = 0;
        int           rv = SSL_read_early_data(ssl, eb, sizeof(eb), &n);
        if (rv == SSL_READ_EARLY_DATA_SUCCESS) {
          buf.insert(buf.end(), eb, eb + n);
          early_len += n;
        } else if (rv == SSL_READ_EARLY_DATA_FINISH) {
          break; /* handshake complete */
        } else {
          SSL_free(ssl);
          close(cfd);
          return;
        }
      }
    } else if (SSL_accept(ssl) != 1) {
      SSL_free(ssl);
      close(cfd);
      return;
    }

    /* Handshake complete: extract and answer framed messages, reading more
     * as needed */
    size_t consumed = 0;
    bool   ok       = true;
    for (;;) {
      while (buf.size() - consumed >= 2) {
        unsigned short mlen =
          (unsigned short)((buf[consumed] << 8) | buf[consumed + 1]);
        if (buf.size() - consumed < (size_t)(2 + mlen)) {
          break;
        }
        bool was_early = (consumed + 2 + (size_t)mlen) <= early_len;
        if (!AnswerQuery(ssl, buf.data() + consumed + 2, mlen)) {
          ok = false;
          break;
        }
        if (was_early) {
          early_queries_++;
        }
        consumed += 2 + (size_t)mlen;
      }
      if (!ok) {
        break;
      }

      unsigned char rb[4096];
      size_t        n = 0;
      if (SSL_read_ex(ssl, rb, sizeof(rb), &n) != 1) {
        break;
      }
      buf.insert(buf.end(), rb, rb + n);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(cfd);
  }

  void Run()
  {
    for (;;) {
      int cfd = accept(lfd_, NULL, NULL);
      if (cfd < 0) {
        break;
      }
      accepts_++;
      HandleConn(cfd);
    }
  }

  bool        want_early_   = false;
  bool        reject_early_ = false;
  SSL_CTX    *sctx_         = nullptr;
  int         lfd_          = -1;
  std::thread thr_;
};

/* End-to-end: a real channel configured via dns+tls:// completes real
 * queries against a live TLS server, reusing the connection */
TEST_F(LibraryTest, CryptoDoTQuery)
{
  /* Certs (reuse the harness generator) */
  EVP_PKEY *ca_key  = EVP_EC_gen("P-256");
  EVP_PKEY *srv_key = EVP_EC_gen("P-256");
  ASSERT_NE(nullptr, ca_key);
  ASSERT_NE(nullptr, srv_key);
  X509 *ca_cert = TlsTestMkCert(ca_key, ca_key, NULL, 1, true);
  ASSERT_NE(nullptr, ca_cert);
  X509 *srv_cert = TlsTestMkCert(srv_key, ca_key, ca_cert, 2, false);
  ASSERT_NE(nullptr, srv_cert);

  DoTTestServer srv;
  ASSERT_TRUE(srv.Start(srv_cert, srv_key));

  ares_channel_t     *channel = nullptr;
  struct ares_options opts;
  memset(&opts, 0, sizeof(opts));
  /* STAYOPEN keeps the idle connection between sequential queries so reuse
   * can be asserted */
  opts.flags = ARES_FLAG_EDNS | ARES_FLAG_STAYOPEN;
  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &opts, ARES_OPT_FLAGS));

  /* Trust the test CA */
  {
    BIO  *bio = BIO_new(BIO_s_mem());
    char *pem = NULL;
    long  len;
    ASSERT_NE(nullptr, bio);
    ASSERT_EQ(1, PEM_write_bio_X509(bio, ca_cert));
    len = BIO_get_mem_data(bio, &pem);
    ASSERT_EQ(ARES_SUCCESS,
              ares_tls_set_cadata(channel->crypto_ctx,
                                  (const unsigned char *)pem, (size_t)len));
    BIO_free(bio);
  }

  char csv[128];
  snprintf(csv, sizeof(csv),
           "dns+tls://127.0.0.1:%u?hostname=dot.test&verify=strict",
           (unsigned int)srv.port_);
  EXPECT_EQ(ARES_SUCCESS, ares_set_servers_csv(channel, csv));

  HostResult result1;
  ares_gethostbyname(channel, "dot.test", AF_INET, HostCallback, &result1);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result1.done_);
  EXPECT_EQ(ARES_SUCCESS, result1.status_);
  ASSERT_EQ((size_t)1, result1.host_.addrs_.size());
  EXPECT_EQ("1.2.3.4", result1.host_.addrs_[0]);

  /* Second query rides the same connection: no new accept */
  HostResult result2;
  ares_gethostbyname(channel, "again.test", AF_INET, HostCallback, &result2);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result2.done_);
  EXPECT_EQ(ARES_SUCCESS, result2.status_);

  EXPECT_EQ(2, srv.queries_.load());
  EXPECT_EQ(1, srv.accepts_.load());

  ares_destroy(channel);
  srv.Stop();
  X509_free(srv_cert);
  X509_free(ca_cert);
  EVP_PKEY_free(srv_key);
  EVP_PKEY_free(ca_key);
}

/* Strict verification against an untrusted CA must fail the query, not
 * fall back to plaintext or hang */
TEST_F(LibraryTest, CryptoDoTVerifyFail)
{
  EVP_PKEY *ca_key  = EVP_EC_gen("P-256");
  EVP_PKEY *srv_key = EVP_EC_gen("P-256");
  ASSERT_NE(nullptr, ca_key);
  ASSERT_NE(nullptr, srv_key);
  X509 *ca_cert = TlsTestMkCert(ca_key, ca_key, NULL, 1, true);
  ASSERT_NE(nullptr, ca_cert);
  X509 *srv_cert = TlsTestMkCert(srv_key, ca_key, ca_cert, 2, false);
  ASSERT_NE(nullptr, srv_cert);

  DoTTestServer srv;
  ASSERT_TRUE(srv.Start(srv_cert, srv_key));

  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  char csv[128];
  snprintf(csv, sizeof(csv),
           "dns+tls://127.0.0.1:%u?hostname=dot.test&verify=strict",
           (unsigned int)srv.port_);
  EXPECT_EQ(ARES_SUCCESS, ares_set_servers_csv(channel, csv));

  HostResult result;
  ares_gethostbyname(channel, "dot.test", AF_INET, HostCallback, &result);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result.done_);
  EXPECT_NE(ARES_SUCCESS, result.status_);
  EXPECT_EQ(0, srv.queries_.load());

  ares_destroy(channel);
  srv.Stop();
  X509_free(srv_cert);
  X509_free(ca_cert);
  EVP_PKEY_free(srv_key);
  EVP_PKEY_free(ca_key);
}

/* End-to-end TLSv1.3 Early Data (0-RTT): the first query establishes and
 * caches a session; once that connection goes idle and closes, the next
 * query opens a fresh connection that resumes the session and sends the
 * query in the 0-RTT flight, which the server observes as early data. */
TEST_F(LibraryTest, CryptoDoTEarlyData)
{
  EVP_PKEY *ca_key  = EVP_EC_gen("P-256");
  EVP_PKEY *srv_key = EVP_EC_gen("P-256");
  ASSERT_NE(nullptr, ca_key);
  ASSERT_NE(nullptr, srv_key);
  X509 *ca_cert = TlsTestMkCert(ca_key, ca_key, NULL, 1, true);
  ASSERT_NE(nullptr, ca_cert);
  X509 *srv_cert = TlsTestMkCert(srv_key, ca_key, ca_cert, 2, false);
  ASSERT_NE(nullptr, srv_cert);

  DoTTestServer srv;
  ASSERT_TRUE(srv.Start(srv_cert, srv_key, 16384));

  ares_channel_t *channel = nullptr;
  /* No STAYOPEN: the idle connection between the two queries must close so
   * the second query opens a fresh connection that resumes */
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  {
    BIO  *bio = BIO_new(BIO_s_mem());
    char *pem = NULL;
    long  len;
    ASSERT_NE(nullptr, bio);
    ASSERT_EQ(1, PEM_write_bio_X509(bio, ca_cert));
    len = BIO_get_mem_data(bio, &pem);
    ASSERT_EQ(ARES_SUCCESS,
              ares_tls_set_cadata(channel->crypto_ctx,
                                  (const unsigned char *)pem, (size_t)len));
    BIO_free(bio);
  }

  char csv[128];
  snprintf(csv, sizeof(csv),
           "dns+tls://127.0.0.1:%u?hostname=dot.test&verify=strict",
           (unsigned int)srv.port_);
  EXPECT_EQ(ARES_SUCCESS, ares_set_servers_csv(channel, csv));

  /* First query: full handshake, caches a resumable session with an
   * early-data budget */
  HostResult result1;
  ares_gethostbyname(channel, "first.test", AF_INET, HostCallback, &result1);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result1.done_);
  EXPECT_EQ(ARES_SUCCESS, result1.status_);
  EXPECT_EQ(0, srv.early_queries_.load());

  /* Second query: fresh connection, resumes, and rides 0-RTT */
  HostResult result2;
  ares_gethostbyname(channel, "second.test", AF_INET, HostCallback, &result2);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result2.done_);
  EXPECT_EQ(ARES_SUCCESS, result2.status_);
  ASSERT_EQ((size_t)1, result2.host_.addrs_.size());
  EXPECT_EQ("1.2.3.4", result2.host_.addrs_[0]);

  /* Two separate connections, the second carrying the query as early
   * data, and no query lost or duplicated (2 answered total). */
  EXPECT_EQ(2, srv.accepts_.load());
  EXPECT_EQ(1, srv.early_queries_.load());
  EXPECT_EQ(2, srv.queries_.load());

  ares_destroy(channel);
  srv.Stop();
  X509_free(srv_cert);
  X509_free(ca_cert);
  EVP_PKEY_free(srv_key);
  EVP_PKEY_free(ca_key);
}

/* End-to-end 0-RTT *reject* path (the riskier branch of the early-data
 * reconciliation in ares_conn.c: the resumed connection optimistically sends
 * the query as early data, the server refuses 0-RTT, and the client must
 * re-send the query in the normal stream -- neither dropping nor duplicating
 * it). */
TEST_F(LibraryTest, CryptoDoTEarlyDataReject)
{
  EVP_PKEY *ca_key  = EVP_EC_gen("P-256");
  EVP_PKEY *srv_key = EVP_EC_gen("P-256");
  ASSERT_NE(nullptr, ca_key);
  ASSERT_NE(nullptr, srv_key);
  X509 *ca_cert = TlsTestMkCert(ca_key, ca_key, NULL, 1, true);
  ASSERT_NE(nullptr, ca_cert);
  X509 *srv_cert = TlsTestMkCert(srv_key, ca_key, ca_cert, 2, false);
  ASSERT_NE(nullptr, srv_cert);

  DoTTestServer srv;
  /* Advertise an early-data budget (so the client attempts 0-RTT on resume)
   * but reject it on the resuming connection. */
  ASSERT_TRUE(srv.Start(srv_cert, srv_key, 16384, /* reject_early */ true));

  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  {
    BIO  *bio = BIO_new(BIO_s_mem());
    char *pem = NULL;
    long  len;
    ASSERT_NE(nullptr, bio);
    ASSERT_EQ(1, PEM_write_bio_X509(bio, ca_cert));
    len = BIO_get_mem_data(bio, &pem);
    ASSERT_EQ(ARES_SUCCESS,
              ares_tls_set_cadata(channel->crypto_ctx,
                                  (const unsigned char *)pem, (size_t)len));
    BIO_free(bio);
  }

  char csv[128];
  snprintf(csv, sizeof(csv),
           "dns+tls://127.0.0.1:%u?hostname=dot.test&verify=strict",
           (unsigned int)srv.port_);
  EXPECT_EQ(ARES_SUCCESS, ares_set_servers_csv(channel, csv));

  /* First query: full handshake, caches a resumable session with a budget */
  HostResult result1;
  ares_gethostbyname(channel, "first.test", AF_INET, HostCallback, &result1);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result1.done_);
  EXPECT_EQ(ARES_SUCCESS, result1.status_);

  /* Second query: fresh connection, resumes, sends 0-RTT, the server rejects
   * it, and the client re-sends over the established connection. */
  HostResult result2;
  ares_gethostbyname(channel, "second.test", AF_INET, HostCallback, &result2);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result2.done_);
  EXPECT_EQ(ARES_SUCCESS, result2.status_);
  ASSERT_EQ((size_t)1, result2.host_.addrs_.size());
  EXPECT_EQ("1.2.3.4", result2.host_.addrs_[0]);

  /* 0-RTT was refused (no query arrived as early data) yet both queries were
   * answered exactly once -- the rejected flight was re-sent, not lost or
   * duplicated. */
  EXPECT_EQ(2, srv.accepts_.load());
  EXPECT_EQ(0, srv.early_queries_.load());
  EXPECT_EQ(2, srv.queries_.load());

  ares_destroy(channel);
  srv.Stop();
  X509_free(srv_cert);
  X509_free(ca_cert);
  EVP_PKEY_free(srv_key);
  EVP_PKEY_free(ca_key);
}

/* Only a standard QUERY is replay-safe as 0-RTT early data.  A caller-built
 * non-QUERY (here a NOTIFY, which still carries a question section so the mock
 * server answers it) resumes the session but must NOT ride 0-RTT -- the opcode
 * gate holds it back to the normal post-handshake flight.  Contrast
 * CryptoDoTEarlyData, where a QUERY in the same position rides 0-RTT
 * (early_queries_ == 1). */
TEST_F(LibraryTest, CryptoDoTEarlyDataQueryOpcodeOnly)
{
  EVP_PKEY *ca_key  = EVP_EC_gen("P-256");
  EVP_PKEY *srv_key = EVP_EC_gen("P-256");
  ASSERT_NE(nullptr, ca_key);
  ASSERT_NE(nullptr, srv_key);
  X509 *ca_cert = TlsTestMkCert(ca_key, ca_key, NULL, 1, true);
  ASSERT_NE(nullptr, ca_cert);
  X509 *srv_cert = TlsTestMkCert(srv_key, ca_key, ca_cert, 2, false);
  ASSERT_NE(nullptr, srv_cert);

  DoTTestServer srv;
  /* Advertise an early-data budget so a QUERY *would* ride 0-RTT on resume;
   * the NOTIFY must not. */
  ASSERT_TRUE(srv.Start(srv_cert, srv_key, 16384));

  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  {
    BIO  *bio = BIO_new(BIO_s_mem());
    char *pem = NULL;
    long  len;
    ASSERT_NE(nullptr, bio);
    ASSERT_EQ(1, PEM_write_bio_X509(bio, ca_cert));
    len = BIO_get_mem_data(bio, &pem);
    ASSERT_EQ(ARES_SUCCESS,
              ares_tls_set_cadata(channel->crypto_ctx,
                                  (const unsigned char *)pem, (size_t)len));
    BIO_free(bio);
  }

  char csv[128];
  snprintf(csv, sizeof(csv),
           "dns+tls://127.0.0.1:%u?hostname=dot.test&verify=strict",
           (unsigned int)srv.port_);
  EXPECT_EQ(ARES_SUCCESS, ares_set_servers_csv(channel, csv));

  /* First query (QUERY): full handshake, caches a resumable session. */
  HostResult result1;
  ares_gethostbyname(channel, "first.test", AF_INET, HostCallback, &result1);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result1.done_);
  EXPECT_EQ(ARES_SUCCESS, result1.status_);

  /* Second request is a caller-built NOTIFY (non-QUERY opcode). */
  ares_dns_record_t *notify = nullptr;
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_create(&notify, 0x1234, 0, ARES_OPCODE_NOTIFY,
                                   ARES_RCODE_NOERROR));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_query_add(notify, "notify.test", ARES_REC_TYPE_A,
                                      ARES_CLASS_IN));

  SearchResult result2;
  ares_send_dnsrec(channel, notify, SearchCallbackDnsRec, &result2, nullptr);
  ares_dns_record_destroy(notify);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result2.done_);

  /* The NOTIFY opened a second (resuming) connection but did NOT ride 0-RTT:
   * the opcode gate held it to the normal flight.  (accepts_ == 2 confirms the
   * resumption actually happened, so early_queries_ == 0 is meaningful.) */
  EXPECT_EQ(2, srv.accepts_.load());
  EXPECT_EQ(0, srv.early_queries_.load());

  ares_destroy(channel);
  srv.Stop();
  X509_free(srv_cert);
  X509_free(ca_cert);
  EVP_PKEY_free(srv_key);
  EVP_PKEY_free(ca_key);
}

#endif /* CARES_TEST_TLS_HARNESS */


}  // namespace test
}  // namespace ares
