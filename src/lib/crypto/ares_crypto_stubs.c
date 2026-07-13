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

/* Stubs for c-ares builds without crypto */
#include "ares_private.h"

#ifndef CARES_USE_CRYPTO

ares_status_t ares_cryptoimp_ctx_init(ares_cryptoimp_ctx_t **ctx,
                                      ares_crypto_ctx_t     *parent)
{
  (void)parent;
  *ctx = NULL;
  return ARES_SUCCESS;
}

void ares_cryptoimp_ctx_destroy(ares_cryptoimp_ctx_t *ctx)
{
  (void)ctx;
}

void ares_cryptoimp_thread_cleanup(ares_cryptoimp_ctx_t *ctx)
{
  (void)ctx;
}

ares_status_t ares_tlsimp_set_cadata(ares_cryptoimp_ctx_t *ctx,
                                     const unsigned char *pem, size_t len)
{
  (void)ctx;
  (void)pem;
  (void)len;
  return ARES_ENOTIMP;
}

ares_status_t ares_tlsimp_create(ares_tls_t          **tls,
                                 ares_cryptoimp_ctx_t *crypto_ctx,
                                 ares_conn_t          *conn)
{
  (void)tls;
  (void)crypto_ctx;
  (void)conn;
  return ARES_ENOTIMP;
}

ares_tls_state_t ares_tlsimp_get_state(ares_tls_t *tls)
{
  (void)tls;
  return ARES_TLS_STATE_ERROR;
}

ares_tls_stateflag_t ares_tlsimp_get_stateflag(ares_tls_t *tls)
{
  (void)tls;
  return 0;
}

size_t ares_tlsimp_get_earlydata_size(ares_tls_t *tls)
{
  (void)tls;
  return 0;
}

ares_bool_t ares_tlsimp_earlydata_accepted(ares_tls_t *tls)
{
  (void)tls;
  return ARES_FALSE;
}

ares_bool_t ares_tlsimp_get_read_pending(ares_tls_t *tls)
{
  (void)tls;
  return ARES_FALSE;
}

void ares_tlsimp_destroy(ares_tls_t *tls)
{
  (void)tls;
}

ares_conn_err_t ares_tlsimp_earlydata_write(ares_tls_t          *tls,
                                            const unsigned char *buf,
                                            size_t              *buf_len)
{
  (void)tls;
  (void)buf;
  (void)buf_len;
  return ARES_CONN_ERR_NOTIMP;
}

ares_conn_err_t ares_tlsimp_read(ares_tls_t *tls, unsigned char *buf,
                                 size_t *buf_len)
{
  (void)tls;
  (void)buf;
  (void)buf_len;
  return ARES_CONN_ERR_NOTIMP;
}

ares_conn_err_t ares_tlsimp_write(ares_tls_t *tls, const unsigned char *buf,
                                  size_t *buf_len)
{
  (void)tls;
  (void)buf;
  (void)buf_len;
  return ARES_CONN_ERR_NOTIMP;
}

ares_conn_err_t ares_tlsimp_shutdown(ares_tls_t *tls)
{
  (void)tls;
  return ARES_CONN_ERR_NOTIMP;
}

ares_conn_err_t ares_tlsimp_connect(ares_tls_t *tls)
{
  (void)tls;
  return ARES_CONN_ERR_NOTIMP;
}

void ares_tlsimp_session_free(void *arg)
{
  (void)arg;
}

#endif
