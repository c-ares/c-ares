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
#include "ares_crypto.h"

struct ares_crypto_ctx {
  /*! Implementation-specific ctx for system initialization */
  ares_cryptoimp_ctx_t *imp_ctx;

  /*! Forward lookups for sessions */
  ares_htable_strvp_t  *sess_fwd;

  /*! Reverse lookups for sessions (for removal) */
  ares_htable_vpstr_t  *sess_rev;
};

ares_status_t ares_crypto_ctx_init(ares_crypto_ctx_t **ctx)
{
  if (ctx == NULL) {
    return ARES_EFORMERR;
  }

  *ctx = ares_malloc_zero(sizeof(**ctx));
  if (*ctx == NULL) {
    return ARES_ENOMEM;
  }

  /* Nothing is created eagerly here.  Both the backend (OpenSSL provider load,
   * client SSL_CTX, and -- expensively on some platforms -- system CA-root
   * enumeration) and the session-cache tables are created lazily on first TLS
   * use.  A channel that never talks to a DoT server -- and the Schannel and
   * no-crypto builds, which never populate the session cache -- pay nothing. */
  return ARES_SUCCESS;
}

/*! Lazily create the backend implementation context on first TLS use */
static ares_status_t ares_crypto_ctx_ensure_backend(ares_crypto_ctx_t *ctx)
{
  if (ctx == NULL) {
    return ARES_EFORMERR;
  }
  if (ctx->imp_ctx != NULL) {
    return ARES_SUCCESS;
  }
  return ares_cryptoimp_ctx_init(&ctx->imp_ctx, ctx);
}

void ares_crypto_ctx_destroy(ares_crypto_ctx_t *ctx)
{
  if (ctx == NULL) {
    return;
  }

  /* The backend must be destroyed first: tearing it down flushes its
   * session cache which calls back into ares_tls_session_remove(), and
   * that dereferences these tables.  Any sessions still held after the
   * backend is gone are released by the table destructors. */
  ares_cryptoimp_ctx_destroy(ctx->imp_ctx);
  ares_htable_strvp_destroy(ctx->sess_fwd);
  ares_htable_vpstr_destroy(ctx->sess_rev);
  ares_free(ctx);
}

void ares_crypto_thread_cleanup(ares_crypto_ctx_t *ctx)
{
  /* No-op unless the backend was actually initialized (lazy on first TLS
   * use) and has per-thread state to release. */
  if (ctx == NULL || ctx->imp_ctx == NULL) {
    return;
  }
  ares_cryptoimp_thread_cleanup(ctx->imp_ctx);
}

/* Resolve DEFAULT to the effective mode (strict with an auth name,
 * opportunistic otherwise).  Shared by the session-cache key and both backend
 * enforcement paths so the "no unverified session resumed under strict"
 * guarantee can't drift from what the backends actually enforce.  MUST stay in
 * lockstep with ares_tls_fold_verify() in ares_update_servers.c (server-
 * identity dedup), which folds the same way but can't share code -- this file
 * is absent from non-crypto builds. */
ares_tls_verify_t ares_tls_effective_verify(const ares_conn_t *conn)
{
  ares_tls_verify_t verify = conn->server->tls_verify;
  if (verify == ARES_TLS_VERIFY_DEFAULT) {
    verify = ares_strlen(conn->server->tls_hostname) > 0
               ? ARES_TLS_VERIFY_STRICT
               : ARES_TLS_VERIFY_OPPORTUNISTIC;
  }
  return verify;
}

static char *ares_tls_session_key(ares_conn_t *conn)
{
  ares_status_t status = ARES_SUCCESS;
  ares_buf_t   *buf;
  char          addr[INET6_ADDRSTRLEN] = "";

  if (conn == NULL) {
    return NULL;
  }

  buf = ares_buf_create();
  if (buf == NULL) {
    return NULL;
  }

  /* Format:  verify;hostname@[ip]:port -- the hostname component is the
   * server's TLS authentication name (blank when none is configured) so the
   * same ip:port with different names never share sessions.  The effective
   * verify mode is included so an unverified (opportunistic) session can
   * never be resumed by a strict connection to the same host/ip/port. */
  status =
    ares_buf_append_num_dec(buf, (size_t)ares_tls_effective_verify(conn), 0);
  if (status != ARES_SUCCESS) {
    goto done;
  }
  status = ares_buf_append_byte(buf, ';');
  if (status != ARES_SUCCESS) {
    goto done;
  }

  if (ares_strlen(conn->server->tls_hostname) > 0) {
    status = ares_buf_append_str(buf, conn->server->tls_hostname);
    if (status != ARES_SUCCESS) {
      goto done;
    }
  }

  status = ares_buf_append_str(buf, "@[");
  if (status != ARES_SUCCESS) {
    goto done;
  }

  if (ares_inet_ntop(conn->server->addr.family, &conn->server->addr.addr, addr,
                     sizeof(addr)) == NULL) {
    /* Never return a partial/ambiguous key */
    status = ARES_EBADSTR;
    goto done;
  }

  status = ares_buf_append_str(buf, addr);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_buf_append_str(buf, "]:");
  if (status != ARES_SUCCESS) {
    goto done;
  }

  /* Port */
  status = ares_buf_append_num_dec(buf, conn->server->tcp_port, 0);
  if (status != ARES_SUCCESS) {
    goto done;
  }

done:
  if (status != ARES_SUCCESS) {
    /* A partial key must never be returned: it could alias another
     * server's sessions */
    ares_buf_destroy(buf);
    return NULL;
  }
  return ares_buf_finish_str(buf, NULL);
}

ares_status_t ares_tls_session_insert(ares_crypto_ctx_t *crypto_ctx,
                                      ares_conn_t *conn, void *sess)
{
  char         *key          = ares_tls_session_key(conn);
  ares_status_t status       = ARES_SUCCESS;
  ares_bool_t   fwd_inserted = ARES_FALSE;
  void         *old_sess;

  if (key == NULL || crypto_ctx == NULL || sess == NULL) {
    ares_free(key);
    return ARES_EFORMERR;
  }

  /* Lazily create the session-cache tables on first insert.  Only the OpenSSL
   * backend inserts, so Schannel / no-crypto / non-DoT channels never allocate
   * them. */
  if (crypto_ctx->sess_fwd == NULL) {
    crypto_ctx->sess_fwd = ares_htable_strvp_create(ares_tlsimp_session_free);
    if (crypto_ctx->sess_fwd == NULL) {
      ares_free(key);
      return ARES_ENOMEM;
    }
  }
  if (crypto_ctx->sess_rev == NULL) {
    crypto_ctx->sess_rev = ares_htable_vpstr_create();
    if (crypto_ctx->sess_rev == NULL) {
      ares_free(key);
      return ARES_ENOMEM;
    }
  }

  /* Replacing an existing session for this key (e.g. a fresh ticket for
   * the same server): the forward insert below releases the old session,
   * so its reverse entry must go too or a later backend removal callback
   * for the old session would tear down the new one's forward entry */
  old_sess = ares_htable_strvp_get_direct(crypto_ctx->sess_fwd, key);
  if (old_sess != NULL) {
    ares_htable_vpstr_remove(crypto_ctx->sess_rev, old_sess);
  }

  if (!ares_htable_strvp_insert(crypto_ctx->sess_fwd, key, sess)) {
    status = ARES_ENOMEM;
    goto done;
  }
  fwd_inserted = ARES_TRUE;

  if (!ares_htable_vpstr_insert(crypto_ctx->sess_rev, sess, key)) {
    status = ARES_ENOMEM;
    goto done;
  }

done:
  if (status != ARES_SUCCESS) {
    /* Only unwind our own forward insert: if it failed, the bucket still
     * holds a prior session whose value destructor must run (claiming it
     * here would evict it without freeing -- a leak). */
    if (fwd_inserted) {
      ares_htable_strvp_claim(crypto_ctx->sess_fwd, key);
    }
    ares_htable_vpstr_remove(crypto_ctx->sess_rev, sess);
  }
  ares_free(key);
  return status;
}

ares_status_t ares_tls_session_remove(ares_crypto_ctx_t *crypto_ctx, void *sess)
{
  const char *key;

  if (crypto_ctx == NULL || sess == NULL) {
    return ARES_EFORMERR;
  }

  /* The cache tables are created lazily on first insert; nothing to remove
   * if they don't exist yet. */
  if (crypto_ctx->sess_rev == NULL) {
    return ARES_ENOTFOUND;
  }

  key = ares_htable_vpstr_get_direct(crypto_ctx->sess_rev, sess);
  if (key == NULL) {
    return ARES_ENOTFOUND;
  }

  /* Remove (not claim) so the cache's reference on the session is released
   * via the table's value destructor.  Callers (the backend's cache-removal
   * callback) hold their own reference for any continued use.  The rev
   * entry owns `key`, so it must be removed second. */
  ares_htable_strvp_remove(crypto_ctx->sess_fwd, key);
  ares_htable_vpstr_remove(crypto_ctx->sess_rev, sess);

  return ARES_SUCCESS;
}

ares_status_t ares_tls_create(ares_tls_t **tls, ares_crypto_ctx_t *crypto_ctx,
                              ares_conn_t *conn)
{
  ares_status_t status;

  if (tls == NULL || crypto_ctx == NULL || conn == NULL) {
    return ARES_EFORMERR;
  }

  status = ares_crypto_ctx_ensure_backend(crypto_ctx);
  if (status != ARES_SUCCESS) {
    return status;
  }

  return ares_tlsimp_create(tls, crypto_ctx->imp_ctx, conn);
}

ares_status_t ares_tls_set_cadata(ares_crypto_ctx_t   *crypto_ctx,
                                  const unsigned char *pem, size_t len)
{
  ares_status_t status;

  if (crypto_ctx == NULL) {
    return ARES_EFORMERR;
  }

  /* Trust anchors may be configured before any connection; make sure the
   * backend (and its certificate store) exists */
  status = ares_crypto_ctx_ensure_backend(crypto_ctx);
  if (status != ARES_SUCCESS) {
    return status;
  }

  return ares_tlsimp_set_cadata(crypto_ctx->imp_ctx, pem, len);
}

void *ares_tls_session_get(ares_crypto_ctx_t *crypto_ctx, ares_conn_t *conn)
{
  char *key;
  void *sess;

  if (crypto_ctx == NULL || conn == NULL || crypto_ctx->sess_fwd == NULL) {
    return NULL;
  }

  key = ares_tls_session_key(conn);
  if (key == NULL) {
    return NULL;
  }

  sess = ares_htable_strvp_get_direct(crypto_ctx->sess_fwd, key);
  ares_free(key);

  return sess;
}
