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

#include "ares_private.h"

#ifdef CARES_CRYPTO_OPENSSL
#  include <openssl/crypto.h>
#  include <openssl/provider.h>
#  include <openssl/ssl.h>
#  include <openssl/bio.h>
#  include <openssl/pem.h>
#  include <openssl/err.h>

#  ifdef __APPLE__
#    include <Security/Security.h>
#  endif
#  ifdef _WIN32
#    include <wincrypt.h>
#  endif

struct ares_cryptoimp_ctx {
  OSSL_LIB_CTX      *ctx;
  OSSL_PROVIDER     *default_provider;
  SSL_CTX           *sslctx;
  BIO_METHOD        *bio_method;
  ares_crypto_ctx_t *parent;
};

struct ares_tls {
  ares_conn_t          *conn;
  ares_cryptoimp_ctx_t *ctx;
  SSL                  *ssl;
  ares_conn_err_t       last_io_error;
  ares_tls_state_t      state;
  ares_tls_stateflag_t  flags;
  size_t                earlydata_sent_len;
};

#  if defined(__APPLE__)
static ares_status_t ares_ossl_load_caroots(SSL_CTX *ctx, OSSL_LIB_CTX *libctx)
{
  CFArrayRef  anchors;
  int         ret;
  CFIndex     i;
  CFIndex     num;
  size_t      count = 0;
  X509_STORE *store;

  (void)libctx;

  if (ctx == NULL) {
    return ARES_EFORMERR;
  }

  ret = SecTrustCopyAnchorCertificates(&anchors);
  if (ret != 0) {
    return ARES_ESERVFAIL;
  }

  store = SSL_CTX_get_cert_store(ctx);
  num   = CFArrayGetCount(anchors);
  for (i = 0; i < num; i++) {
    const void          *ptr = CFArrayGetValueAtIndex(anchors, i);
    SecCertificateRef    cr  = (SecCertificateRef)((void *)((size_t)ptr));
    CFDataRef            dref;
    X509                *x509;
    const unsigned char *data;

    dref = SecCertificateCopyData(cr);
    if (dref == NULL) {
      continue;
    }

    /* DER-encoded
     *
     * CFDataGetLength will be auto converted to long by
     * the compiler (this is not undefined behavior). */
    data = CFDataGetBytePtr(dref);
    x509 = d2i_X509(NULL, &data, CFDataGetLength(dref));
    CFRelease(dref);
    if (x509 == NULL) {
      continue;
    }

    if (X509_STORE_add_cert(store, x509)) {
      count++;
    }

    X509_free(x509);
  }
  CFRelease(anchors);

  if (!count) {
    return ARES_ENOTFOUND;
  }

  return ARES_SUCCESS;
}

#  elif defined(_WIN32)

/* NOTE:  OpenSSL v3.2+ supposedly you can do something like:
 *   X509_STORE *vfy = X509_STORE_new();
 *   X509_STORE_load_store_ex(vfy, "org.openssl.winstore://", (*ctx)->ctx,
 * NULL); SSL_CTX_set1_verify_cert_store(ctx, vfy); X509_STORE_free(vfy);
 */
static ares_status_t ares_ossl_load_caroots(SSL_CTX *ctx, OSSL_LIB_CTX *libctx)
{
  HCERTSTORE     hStore;
  PCCERT_CONTEXT pContext = NULL;
  X509_STORE    *store;
  size_t         count = 0;

  (void)libctx;

  if (ctx == NULL) {
    return ARES_EFORMERR;
  }

  hStore = CertOpenSystemStoreA(0, "ROOT");
  if (hStore == NULL) {
    return ARES_ESERVFAIL;
  }

  store = SSL_CTX_get_cert_store(ctx);

  while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
    /* d2i_X509 advances the pointer it is given; use a local so the
     * enumeration context isn't modified */
    const unsigned char *der = pContext->pbCertEncoded;
    X509 *x509 = d2i_X509(NULL, &der, (long)pContext->cbCertEncoded);
    if (x509) {
      if (X509_STORE_add_cert(store, x509)) {
        count++;
      }
      X509_free(x509);
    }
  }

  CertFreeCertificateContext(pContext);
  CertCloseStore(hStore, 0);

  if (!count) {
    return ARES_ENOTFOUND;
  }

  return ARES_SUCCESS;
}

#  else

static ares_bool_t file_exists(const char *path, ares_bool_t is_directory)
{
#    ifdef HAVE_STAT
  struct stat st;
  if (stat(path, &st) != 0) {
    return ARES_FALSE;
  }
#    else
#      error "Need stat() function for crypto subsystem with OpenSSL."
#    endif
  if (is_directory) {
    if (st.st_mode & S_IFDIR) {
      return ARES_TRUE;
    }
    return ARES_FALSE;
  }
  if (st.st_mode & S_IFREG) {
    return ARES_TRUE;
  }
  return ARES_FALSE;
}

static ares_status_t ares_ossl_load_caroots(SSL_CTX *ctx, OSSL_LIB_CTX *libctx)
{
  static const char * const cafile_paths[] = {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/usr/share/ssl/certs/ca-bundle.crt",
    "/etc/pki/tls/certs/ca-bundle.trust.crt",
    "/usr/local/share/certs/ca-root-nss.crt", /* FreeBSD via port
                                                 security/ca_root_nss */
    NULL
  };
  static const char * const cadirs[] = {
    "/etc/ssl/certs/",               /* Ubuntu */
    "/system/etc/security/cacerts/", /* Android */
    NULL
  };
  size_t      i;
  X509_STORE *x509_store;

  /* Operate on the ctx's own certificate store (like the macOS and Windows
   * paths) so ares_tlsimp_set_cadata() additions land in the same store the
   * verifier consults */
  x509_store = SSL_CTX_get_cert_store(ctx);
  if (x509_store == NULL) {
    return ARES_ESERVFAIL;
  }

  for (i = 0; cadirs[i] != NULL; i++) {
    if (file_exists(cadirs[i], ARES_TRUE) &&
        X509_STORE_load_path(x509_store, cadirs[i]) == 1) {
      return ARES_SUCCESS;
    }
  }

  for (i = 0; cafile_paths[i] != NULL; i++) {
    if (file_exists(cafile_paths[i], ARES_FALSE) &&
        X509_STORE_load_file_ex(x509_store, cafile_paths[i], libctx, NULL) ==
          1) {
      return ARES_SUCCESS;
    }
  }

  return ARES_ENOTFOUND;
}
#  endif

ares_status_t ares_tlsimp_set_cadata(ares_cryptoimp_ctx_t *ctx,
                                     const unsigned char *pem, size_t len)
{
  BIO        *bio;
  X509_STORE *store;
  size_t      count = 0;

  if (ctx == NULL || pem == NULL || len == 0 || len > INT_MAX) {
    return ARES_EFORMERR;
  }

  store = SSL_CTX_get_cert_store(ctx->sslctx);
  if (store == NULL) {
    return ARES_ESERVFAIL; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  bio = BIO_new_mem_buf(pem, (int)len);
  if (bio == NULL) {
    return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  while (1) {
    X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
      /* End of data (or undecodable remainder); either way the PEM parser
       * pushed an error we don't want lingering on the stack */
      ERR_clear_error();
      break;
    }
    if (X509_STORE_add_cert(store, x509)) {
      count++;
    }
    X509_free(x509);
  }
  BIO_free(bio);

  if (count == 0) {
    return ARES_EBADSTR;
  }
  return ARES_SUCCESS;
}

void ares_cryptoimp_ctx_destroy(ares_cryptoimp_ctx_t *ctx)
{
  if (ctx == NULL) {
    return;
  }
  if (ctx->bio_method != NULL) {
    BIO_meth_free(ctx->bio_method);
  }
  if (ctx->sslctx != NULL) {
    SSL_CTX_free(ctx->sslctx);
  }
  if (ctx->default_provider != NULL) {
    OSSL_PROVIDER_unload(ctx->default_provider);
  }
  if (ctx->ctx != NULL) {
    OSSL_LIB_CTX_free(ctx->ctx);
  }
  ares_free(ctx);
}

void ares_cryptoimp_thread_cleanup(ares_cryptoimp_ctx_t *ctx)
{
  if (ctx == NULL || ctx->ctx == NULL) {
    return;
  }
  /* OpenSSL keeps per-thread state tied to a (non-default) OSSL_LIB_CTX that
   * is not released automatically on thread exit; the thread must release it
   * before the library context is freed, or teardown can leak or crash.
   * c-ares calls this on its own event thread. */
  OPENSSL_thread_stop_ex(ctx->ctx);
}

static int ares_ossl_bio_read_ex(BIO *b, char *buf, size_t len,
                                 size_t *readbytes)
{
  ares_tls_t *tls = BIO_get_data(b);
  BIO_clear_retry_flags(b);

  *readbytes = 0;

  /* Defensive: BIO_set_data() always runs before SSL_set_bio(), but
   * ares_ossl_bio_create() inits the data to NULL, so guard against a future
   * ordering change rather than dereferencing NULL. */
  if (tls == NULL) {
    return 0;
  }

  tls->last_io_error = ares_conn_read_raw(tls->conn, buf, len, readbytes);
  if (tls->last_io_error == ARES_CONN_ERR_SUCCESS) {
    return 1;
  }

  if (tls->last_io_error == ARES_CONN_ERR_WOULDBLOCK) {
    /* Error is non-fatal, set the reason as need to retry read events */
    BIO_set_retry_read(b);
  }

  return 0;
}

static int ares_ossl_bio_write_ex(BIO *b, const char *buf, size_t len,
                                  size_t *written)
{
  ares_tls_t *tls = BIO_get_data(b);
  /* Clear any sticky retry bit from a prior WOULDBLOCK: if this write hits a
   * fatal transport error (returns 0 with no retry bit set), a stale
   * BIO_set_retry_write() would make OpenSSL report SSL_ERROR_WANT_WRITE and
   * defer the failure to a timeout instead of failing promptly.  OpenSSL's own
   * sock_write clears at the top of every write for this reason. */
  BIO_clear_retry_flags(b);

  *written = 0;

  if (tls == NULL) {
    return 0; /* see ares_ossl_bio_read_ex */
  }

  tls->last_io_error = ares_conn_write_raw(tls->conn, buf, len, written);
  if (tls->last_io_error == ARES_CONN_ERR_SUCCESS) {
    return 1;
  }

  if (tls->last_io_error == ARES_CONN_ERR_WOULDBLOCK) {
    /* Error is non-fatal, set the reason as need to retry write events */
    BIO_set_retry_write(b);
  }

  return 0;
}

static long ares_ossl_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
  (void)ptr;
  switch (cmd) {
    case BIO_CTRL_GET_CLOSE:
      return (long)BIO_get_shutdown(b);
    case BIO_CTRL_SET_CLOSE:
      BIO_set_shutdown(b, (int)num);
      return 1;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
      /* Required internally by OpenSSL, no-op though */
      return 1;
  }
  return 0;
}

static int ares_ossl_bio_puts(BIO *b, const char *str)
{
  size_t written;
  int    rv;
  rv = ares_ossl_bio_write_ex(b, str, ares_strlen(str), &written);
  if (rv == 0) {
    return -1;
  }
  return (int)written;
}

static int ares_ossl_bio_create(BIO *b)
{
  BIO_set_data(b, NULL);
  BIO_set_init(b, 1);
  BIO_clear_flags(b, INT_MAX);
  return 1;
}

static int ares_ossl_bio_destroy(BIO *b)
{
  if (b == NULL) {
    return 0;
  }

  BIO_set_data(b, NULL);
  BIO_set_init(b, 0);
  BIO_clear_flags(b, INT_MAX);

  return 1;
}

static BIO_METHOD *ares_ossl_create_bio_method(void)
{
  BIO_METHOD *bio_method = BIO_meth_new(
    BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "c-ares tls io glue");
  if (bio_method == NULL) {
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  BIO_meth_set_write_ex(bio_method, ares_ossl_bio_write_ex);
  BIO_meth_set_read_ex(bio_method, ares_ossl_bio_read_ex);
  BIO_meth_set_puts(bio_method, ares_ossl_bio_puts);
  BIO_meth_set_ctrl(bio_method, ares_ossl_bio_ctrl);
  BIO_meth_set_create(bio_method, ares_ossl_bio_create);
  BIO_meth_set_destroy(bio_method, ares_ossl_bio_destroy);

  return bio_method;
}

static int ares_ossl_sslsess_new_cb(SSL *ssl, SSL_SESSION *sess)
{
  ares_tls_t *tls = SSL_get_app_data(ssl);

  if (tls == NULL || tls->conn == NULL) {
    return 0;
  }

  if (ares_tls_session_insert(tls->ctx->parent, tls->conn, sess) !=
      ARES_SUCCESS) {
    return 0;
  }

  return 1;
}

static void ares_ossl_sslsess_remove_cb(SSL_CTX *ctx, SSL_SESSION *sess)
{
  ares_cryptoimp_ctx_t *crypto_ctx = SSL_CTX_get_app_data(ctx);

  if (crypto_ctx == NULL) {
    return;
  }

  ares_tls_session_remove(crypto_ctx->parent, sess);
}

ares_status_t ares_cryptoimp_ctx_init(ares_cryptoimp_ctx_t **ctx,
                                      ares_crypto_ctx_t     *parent)
{
  ares_status_t status;

  *ctx = ares_malloc_zero(sizeof(**ctx));
  if (*ctx == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  (*ctx)->parent = parent;

  /* Create a private library context so c-ares' TLS use is isolated from the
   * host application's OpenSSL configuration.
   *
   * Tradeoffs of a non-default OSSL_LIB_CTX, deliberately accepted here:
   *   - It loads only the "default" provider below, so the host's openssl.cnf
   *     and any system providers (notably FIPS) do not apply -- DoT crypto is
   *     predictable but not FIPS-validated even in a FIPS deployment.
   *   - OpenSSL keeps per-thread state tied to a lib ctx; it must be released
   *     with OPENSSL_thread_stop_ex() on each thread that used this ctx before
   *     the ctx is freed.  c-ares does this on its own event thread (see
   *     ares_cryptoimp_thread_cleanup()).  This private ctx handle is not
   *     exposed, so an application that instead drives c-ares TLS on its own
   *     short-lived threads should reuse one thread for the channel's lifetime
   *     to avoid a small per-thread leak; the event thread handles this
   *     automatically.
   * If host-config/FIPS integration is required, switch this to the default
   * (NULL) library context. */
  (*ctx)->ctx = OSSL_LIB_CTX_new();
  if ((*ctx)->ctx == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }
  /* Load default provider */
  (*ctx)->default_provider = OSSL_PROVIDER_load((*ctx)->ctx, "default");
  if ((*ctx)->default_provider == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  /* Create SSL Client CTX */
  (*ctx)->sslctx = SSL_CTX_new_ex((*ctx)->ctx, NULL, TLS_client_method());
  if ((*ctx)->sslctx == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  /* Load system trust anchors into the client ctx.  Failure is NOT fatal:
   * the crypto context initializes with every channel and the channel may
   * never use TLS, and minimal environments (containers, embedded) often
   * carry no CA bundle at all.  A TLS connection that actually needs
   * verification without trust anchors fails at connect time with
   * ARES_CONN_ERR_SECURITY instead. */
  (void)ares_ossl_load_caroots((*ctx)->sslctx, (*ctx)->ctx);

  SSL_CTX_set_app_data((*ctx)->sslctx, *ctx);
  SSL_CTX_set_min_proto_version((*ctx)->sslctx, TLS1_2_VERSION);
  /* Resumption is fully managed via c-ares' own session htable and an explicit
   * SSL_set_session(), so disable OpenSSL's internal session store: it would
   * otherwise independently retain every negotiated SSL_SESSION (default cap
   * ~20k) and its timeout-driven eviction would fire remove_cb and drop the
   * c-ares entry too.  The new/remove callbacks still fire with the store off.
   */
  SSL_CTX_set_session_cache_mode(
    (*ctx)->sslctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  /* Security level 2 (112-bit minimum; no RC4, no compression).  Level 3
   * would be preferable but it disables session tickets, which TLSv1.3
   * session resumption -- and therefore 0-RTT early data -- is built on,
   * and it rejects the RSA-2048 certificates still common on public
   * resolvers */
  SSL_CTX_set_security_level((*ctx)->sslctx, 2);
  SSL_CTX_set_mode((*ctx)->sslctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                                     SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                                     SSL_MODE_AUTO_RETRY);
  /* A DoT client never needs renegotiation.  Refuse a server-initiated TLS 1.2
   * renegotiation outright (also a known DoS vector; matches the Schannel
   * backend, which refuses rather than re-validating a possibly different
   * cert).  Harmless on TLS 1.3, which has no renegotiation. */
  SSL_CTX_set_options((*ctx)->sslctx, SSL_OP_NO_RENEGOTIATION);
  /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT is a server-side-only flag (ignored on a
   * client), so it would imply an enforcement that does not exist here.  A
   * TLS server is always required to present a certificate, and a missing one
   * fails the handshake regardless. */
  SSL_CTX_set_verify((*ctx)->sslctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_sess_set_new_cb((*ctx)->sslctx, ares_ossl_sslsess_new_cb);
  SSL_CTX_sess_set_remove_cb((*ctx)->sslctx, ares_ossl_sslsess_remove_cb);

  (*ctx)->bio_method = ares_ossl_create_bio_method();
  if ((*ctx)->bio_method == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  status = ARES_SUCCESS;

done:
  if (status != ARES_SUCCESS) {
    ares_cryptoimp_ctx_destroy(*ctx);
    *ctx = NULL;
  }
  return status;
}

ares_status_t ares_tlsimp_create(ares_tls_t          **tls,
                                 ares_cryptoimp_ctx_t *crypto_ctx,
                                 ares_conn_t          *conn)
{
  ares_status_t status = ARES_SUCCESS;
  ares_tls_t   *state  = NULL;
  BIO          *bio    = NULL;
  SSL_SESSION  *sess   = NULL;

  if (tls == NULL || conn == NULL) {
    return ARES_EFORMERR;
  }

  state = ares_malloc_zero(sizeof(*state));
  if (state == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  state->state = ARES_TLS_STATE_INIT;
  state->conn  = conn;
  state->ctx   = crypto_ctx;

  state->ssl = SSL_new(crypto_ctx->sslctx);
  if (state->ssl == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  bio = BIO_new(crypto_ctx->bio_method);
  if (bio == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  BIO_set_data(bio, state);
  /* SSL object owns the bio (both directions) from here on */
  SSL_set_bio(state->ssl, bio, bio);

  /* SNI and peer hostname verification from the server's authentication
   * name, when configured.  Config validation (ares_update_servers.c) requires
   * this to be a DNS hostname and rejects IP literals, so it is safe to use as
   * both an SNI value (RFC 6066 3 forbids an IP-literal SNI) and a dNSName
   * reference identity. */
  if (ares_strlen(conn->server->tls_hostname) > 0) {
    if (SSL_set_tlsext_host_name(state->ssl, conn->server->tls_hostname) != 1 ||
        SSL_set1_host(state->ssl, conn->server->tls_hostname) != 1) {
      status = ARES_ESERVFAIL;
      goto done;
    }
  }

  /* Verification mode.  Opportunistic disables verification; strict/default
   * (default resolves to strict only when an auth name is configured -- which
   * config guarantees for strict) leave OpenSSL's SSL_VERIFY_PEER in force. */
  if (ares_tls_effective_verify(conn) == ARES_TLS_VERIFY_OPPORTUNISTIC) {
    SSL_set_verify(state->ssl, SSL_VERIFY_NONE, NULL);
  }

  /* Session handling */
  sess = ares_tls_session_get(crypto_ctx->parent, conn);
  if (sess != NULL) {
    /* Resumption is an optimization: if the cached session is
     * expired/incompatible, ignore the failure and do a full handshake
     * rather than failing the connection.  The borrowed sess stays in the
     * cache (removed below), so nothing leaks. */
    (void)SSL_set_session(state->ssl, sess);
    /* TLS v1.3 recommends sessions only be used once: drop it from the
     * c-ares cache so the next connection can't reuse it.  Deliberately
     * NOT SSL_CTX_remove_session(): that also marks the session
     * non-resumable, which would defeat the resumption just set up. */
    ares_tls_session_remove(crypto_ctx->parent, sess);
  }

done:
  if (status != ARES_SUCCESS) {
    if (state == NULL) {
      return status;
    }
    if (state->ssl) {
      SSL_free(state->ssl);
    }

    ares_free(state);
    return status;
  }

  SSL_set_app_data(state->ssl, state);
  *tls = state;
  return ARES_SUCCESS;
}

void ares_tlsimp_destroy(ares_tls_t *tls)
{
  if (tls == NULL) {
    return;
  }
  SSL_free(tls->ssl);
  ares_free(tls);
}

ares_conn_err_t ares_tlsimp_connect(ares_tls_t *tls)
{
  int rv;
  int err;

  if (tls == NULL || (tls->state != ARES_TLS_STATE_INIT &&
                      tls->state != ARES_TLS_STATE_EARLYDATA &&
                      tls->state != ARES_TLS_STATE_CONNECT)) {
    return ARES_CONN_ERR_INVALID;
  }

  tls->state  = ARES_TLS_STATE_CONNECT;
  tls->flags &= ~((unsigned int)(ARES_TLS_SF_READ | ARES_TLS_SF_WRITE));

  /* SSL_get_error() requires an empty thread error queue before the op */
  ERR_clear_error();
  rv = SSL_connect(tls->ssl);
  if (rv == 1) {
    tls->state = ARES_TLS_STATE_ESTABLISHED;

    /* If early data was sent, the caller must now consult
     * ares_tlsimp_earlydata_accepted() and re-send the flight through the
     * normal write path if the server rejected it */
    return ARES_CONN_ERR_SUCCESS;
  }

  err = SSL_get_error(tls->ssl, rv);
  /* Progressing the handshake requires the indicated socket direction no
   * matter which logical operation the caller attempts next, so publish
   * both read and write want-flags for ares_conn_interpret_events() */
  if (err == SSL_ERROR_WANT_READ) {
    tls->flags |= ARES_TLS_SF_READ_WANTREAD | ARES_TLS_SF_WRITE_WANTREAD;
    return ARES_CONN_ERR_WOULDBLOCK;
  }
  if (err == SSL_ERROR_WANT_WRITE) {
    tls->flags |= ARES_TLS_SF_READ_WANTWRITE | ARES_TLS_SF_WRITE_WANTWRITE;
    return ARES_CONN_ERR_WOULDBLOCK;
  }

  tls->state = ARES_TLS_STATE_ERROR;

  /* Distinguish certificate verification failures from transport errors:
   * strict-mode diagnosis is impossible if both surface identically.  Only
   * meaningful when verifying -- under SSL_VERIFY_NONE (opportunistic) the
   * chain result is computed but not enforced, so a transport failure with a
   * non-OK chain must not be relabeled a security error.  A server that
   * presented no certificate at all yields X509_V_OK, so check for that
   * explicitly as well. */
  if (SSL_get_verify_mode(tls->ssl) != SSL_VERIFY_NONE &&
      (SSL_get0_peer_certificate(tls->ssl) == NULL ||
       SSL_get_verify_result(tls->ssl) != X509_V_OK)) {
    return ARES_CONN_ERR_SECURITY;
  }

  if (tls->last_io_error == ARES_CONN_ERR_SUCCESS) {
    tls->last_io_error = ARES_CONN_ERR_CONNRESET;
  }
  return tls->last_io_error;
}

ares_conn_err_t ares_tlsimp_shutdown(ares_tls_t *tls)
{
  int rv;
  int err;

  if (tls == NULL || (tls->state != ARES_TLS_STATE_ESTABLISHED &&
                      tls->state != ARES_TLS_STATE_SHUTDOWN)) {
    return ARES_CONN_ERR_INVALID;
  }

  tls->state  = ARES_TLS_STATE_SHUTDOWN;
  tls->flags &= ~((unsigned int)(ARES_TLS_SF_READ | ARES_TLS_SF_WRITE));

  /* SSL_get_error() requires an empty thread error queue before the op */
  ERR_clear_error();
  rv = SSL_shutdown(tls->ssl);
  if (rv >= 0) {
    tls->state = ARES_TLS_STATE_DISCONNECTED;
    return ARES_CONN_ERR_SUCCESS;
  }

  err = SSL_get_error(tls->ssl, rv);
  if (err == SSL_ERROR_WANT_READ) {
    tls->flags |= ARES_TLS_SF_READ_WANTREAD | ARES_TLS_SF_WRITE_WANTREAD;
    return ARES_CONN_ERR_WOULDBLOCK;
  }
  if (err == SSL_ERROR_WANT_WRITE) {
    tls->flags |= ARES_TLS_SF_READ_WANTWRITE | ARES_TLS_SF_WRITE_WANTWRITE;
    return ARES_CONN_ERR_WOULDBLOCK;
  }

  tls->state = ARES_TLS_STATE_ERROR;
  if (tls->last_io_error == ARES_CONN_ERR_SUCCESS) {
    tls->last_io_error = ARES_CONN_ERR_CONNRESET;
  }
  return tls->last_io_error;
}

ares_conn_err_t ares_tlsimp_earlydata_write(ares_tls_t          *tls,
                                            const unsigned char *buf,
                                            size_t              *buf_len)
{
  int rv;
  int err;

  if (tls == NULL || (tls->state != ARES_TLS_STATE_INIT &&
                      tls->state != ARES_TLS_STATE_EARLYDATA)) {
    return ARES_CONN_ERR_INVALID;
  }

  if (tls->earlydata_sent_len + *buf_len >
      ares_tlsimp_get_earlydata_size(tls)) {
    return ARES_CONN_ERR_TOOLARGE;
  }

  tls->state  = ARES_TLS_STATE_EARLYDATA;
  tls->flags &= ~((unsigned int)ARES_TLS_SF_WRITE);

  /* SSL_get_error() requires an empty thread error queue before the op */
  ERR_clear_error();
  rv = SSL_write_early_data(tls->ssl, buf, *buf_len, buf_len);
  if (rv == 1) {
    tls->earlydata_sent_len += *buf_len;
    return ARES_CONN_ERR_SUCCESS;
  }

  err = SSL_get_error(tls->ssl, rv);
  if (err == SSL_ERROR_WANT_READ) {
    tls->flags |= ARES_TLS_SF_WRITE_WANTREAD;
    return ARES_CONN_ERR_WOULDBLOCK;
  }
  if (err == SSL_ERROR_WANT_WRITE) {
    tls->flags |= ARES_TLS_SF_WRITE_WANTWRITE;
    return ARES_CONN_ERR_WOULDBLOCK;
  }

  tls->state = ARES_TLS_STATE_ERROR;
  if (tls->last_io_error == ARES_CONN_ERR_SUCCESS) {
    tls->last_io_error = ARES_CONN_ERR_CONNRESET;
  }
  return tls->last_io_error;
}

ares_conn_err_t ares_tlsimp_write(ares_tls_t *tls, const unsigned char *buf,
                                  size_t *buf_len)
{
  int rv;
  int err;

  if (tls == NULL || tls->state != ARES_TLS_STATE_ESTABLISHED) {
    return ARES_CONN_ERR_INVALID;
  }

  tls->flags &= ~((unsigned int)ARES_TLS_SF_WRITE);

  /* On WOULDBLOCK the caller must retry with the same data: the buffer
   * address may change (moving-write-buffer mode is enabled) but the
   * contents and length of the unsent remainder must be re-presented
   * as-is */
  /* SSL_get_error() requires an empty thread error queue before the op */
  ERR_clear_error();
  rv = SSL_write_ex(tls->ssl, buf, *buf_len, buf_len);
  if (rv == 1) {
    return ARES_CONN_ERR_SUCCESS;
  }

  err = SSL_get_error(tls->ssl, rv);
  if (err == SSL_ERROR_WANT_READ) {
    tls->flags |= ARES_TLS_SF_WRITE_WANTREAD;
    return ARES_CONN_ERR_WOULDBLOCK;
  }
  if (err == SSL_ERROR_WANT_WRITE) {
    tls->flags |= ARES_TLS_SF_WRITE_WANTWRITE;
    return ARES_CONN_ERR_WOULDBLOCK;
  }

  tls->state = ARES_TLS_STATE_ERROR;
  if (tls->last_io_error == ARES_CONN_ERR_SUCCESS) {
    tls->last_io_error = ARES_CONN_ERR_CONNRESET;
  }
  return tls->last_io_error;
}

ares_conn_err_t ares_tlsimp_read(ares_tls_t *tls, unsigned char *buf,
                                 size_t *buf_len)
{
  int rv;
  int err;

  if (tls == NULL || tls->state != ARES_TLS_STATE_ESTABLISHED) {
    return ARES_CONN_ERR_INVALID;
  }

  tls->flags &= ~((unsigned int)ARES_TLS_SF_READ);

  /* SSL_get_error() requires an empty thread error queue before the op */
  ERR_clear_error();
  rv = SSL_read_ex(tls->ssl, buf, *buf_len, buf_len);
  if (rv == 1) {
    return ARES_CONN_ERR_SUCCESS;
  }

  err = SSL_get_error(tls->ssl, rv);
  if (err == SSL_ERROR_ZERO_RETURN) {
    /* Clean TLS-level close (close_notify): normal behavior for a DoT
     * server closing an idle connection, not an error */
    tls->state = ARES_TLS_STATE_DISCONNECTED;
    return ARES_CONN_ERR_CONNCLOSED;
  }
  if (err == SSL_ERROR_WANT_READ) {
    tls->flags |= ARES_TLS_SF_READ_WANTREAD;
    return ARES_CONN_ERR_WOULDBLOCK;
  }
  if (err == SSL_ERROR_WANT_WRITE) {
    tls->flags |= ARES_TLS_SF_READ_WANTWRITE;
    return ARES_CONN_ERR_WOULDBLOCK;
  }

  tls->state = ARES_TLS_STATE_ERROR;
  if (tls->last_io_error == ARES_CONN_ERR_SUCCESS) {
    tls->last_io_error = ARES_CONN_ERR_CONNRESET;
  }
  return tls->last_io_error;
}

ares_bool_t ares_tlsimp_get_read_pending(ares_tls_t *tls)
{
  if (tls == NULL || tls->ssl == NULL) {
    return ARES_FALSE;
  }
  /* SSL_has_pending() is true when OpenSSL holds buffered decrypted data or
   * a complete-but-unprocessed record with nothing left in the socket: the
   * caller must consult this and keep reading rather than wait on socket
   * events when it returns true.  (Read-ahead is not enabled, so on OpenSSL
   * this is rarely set; the connection layer relies on it primarily for the
   * bulk-reading Schannel backend.) */
  return SSL_has_pending(tls->ssl) ? ARES_TRUE : ARES_FALSE;
}

ares_bool_t ares_tlsimp_earlydata_accepted(ares_tls_t *tls)
{
  if (tls == NULL || tls->ssl == NULL) {
    return ARES_FALSE;
  }
  return SSL_get_early_data_status(tls->ssl) == SSL_EARLY_DATA_ACCEPTED
           ? ARES_TRUE
           : ARES_FALSE;
}

size_t ares_tlsimp_get_earlydata_size(ares_tls_t *tls)
{
  const SSL_SESSION *sess;

  if (tls == NULL || (tls->state != ARES_TLS_STATE_INIT &&
                      tls->state != ARES_TLS_STATE_EARLYDATA)) {
    return 0;
  }

  sess = SSL_get0_session(tls->ssl);
  if (sess == NULL) {
    return 0;
  }

  return (size_t)SSL_SESSION_get_max_early_data(sess);
}

ares_tls_state_t ares_tlsimp_get_state(ares_tls_t *tls)
{
  if (tls == NULL) {
    /* Fail safe (and match the no-crypto stub): a caller must not treat a
     * missing session as INIT and try to drive a connect on it. */
    return ARES_TLS_STATE_ERROR;
  }
  return tls->state;
}

ares_tls_stateflag_t ares_tlsimp_get_stateflag(ares_tls_t *tls)
{
  if (tls == NULL) {
    return 0;
  }
  return tls->flags;
}

void ares_tlsimp_session_free(void *arg)
{
  SSL_SESSION *sess = arg;
  if (sess == NULL) {
    return;
  }
  SSL_SESSION_free(sess);
}
#endif
