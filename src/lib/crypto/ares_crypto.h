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
#ifndef __ARES_CRYPTO_H
#define __ARES_CRYPTO_H

/*! \addtogroup ares_crypto Cryptographic Subsystem
 *
 * These are implementations for various cryptographic operations needed by
 * c-ares.  Right now this only supports TLS.
 *
 * @{
 */

/*! State of the TLS connection */
typedef enum {
  ARES_TLS_STATE_INIT = 0, /*!< Not yet connected or any writes attempted */
  ARES_TLS_STATE_EARLYDATA    = 1, /*!< Sending TLSv1.3 Early Data */
  ARES_TLS_STATE_CONNECT      = 2, /*!< Connection in progress */
  ARES_TLS_STATE_ESTABLISHED  = 3, /*!< Connection established */
  ARES_TLS_STATE_SHUTDOWN     = 4, /*!< Shutdown in progress */
  ARES_TLS_STATE_DISCONNECTED = 5, /*!< Disconnected */
  ARES_TLS_STATE_ERROR        = 6  /*!< Error */
} ares_tls_state_t;

/*! TLS state flags that help determine flow */
typedef enum {
  ARES_TLS_SF_READ_WANTREAD  = 1 << 0,
  ARES_TLS_SF_READ_WANTWRITE = 1 << 1,
  ARES_TLS_SF_READ = (ARES_TLS_SF_READ_WANTREAD | ARES_TLS_SF_READ_WANTWRITE),
  ARES_TLS_SF_WRITE_WANTREAD  = 1 << 2,
  ARES_TLS_SF_WRITE_WANTWRITE = 1 << 3,
  ARES_TLS_SF_WRITE = (ARES_TLS_SF_WRITE_WANTREAD | ARES_TLS_SF_WRITE_WANTWRITE)
} ares_tls_stateflag_t;

struct ares_crypto_ctx;
typedef struct ares_crypto_ctx ares_crypto_ctx_t;


/*! Initialize the channel-level crypto context (backend init is deferred to
 *  first TLS use).  \param[out] ctx Returned context.  \return ARES_SUCCESS
 *  or an ares_status_t error. */
ares_status_t ares_crypto_ctx_init(ares_crypto_ctx_t **ctx);
/*! Destroy a crypto context created by ares_crypto_ctx_init(). */
void ares_crypto_ctx_destroy(ares_crypto_ctx_t *ctx);

/*! Release any thread-local crypto state the calling thread accumulated for
 *  this context (e.g. OpenSSL per-thread data tied to a private library
 *  context).  Must be called on a thread before that thread exits while the
 *  context is still alive; a no-op if the backend has no per-thread state or
 *  is not yet initialized.  c-ares calls this on its event thread. */
void ares_crypto_thread_cleanup(ares_crypto_ctx_t *ctx);

struct ares_tls;
typedef struct ares_tls ares_tls_t;

/*! Create a TLS session object for a connection using the channel's crypto
 *  context.  This is the generic entry point; it dispatches to the backend
 *  provider implementation.
 *
 *  \param[out] tls        Returned TLS session object
 *  \param[in]  crypto_ctx Channel crypto context
 *  \param[in]  conn       Connection the TLS session operates on
 *  \return ARES_SUCCESS on success, ARES_ENOTIMP if built without crypto
 *          support, otherwise an ares_status_t error
 */
ares_status_t ares_tls_create(ares_tls_t **tls, ares_crypto_ctx_t *crypto_ctx,
                              ares_conn_t *conn);

/*! Add trusted CA certificate(s) in PEM form to the certificate
 *  verification store, supplementing the system roots loaded at context
 *  initialization.  Used for custom-CA configuration and by the test
 *  suite.
 *
 *  \param[in] crypto_ctx Channel crypto context
 *  \param[in] pem        PEM data containing one or more certificates
 *  \param[in] len        Length of pem data in bytes
 *  \return ARES_SUCCESS if at least one certificate was added,
 *          ARES_EBADSTR if none could be parsed, ARES_ENOTIMP if built
 *          without crypto support, otherwise an ares_status_t error
 */
ares_status_t ares_tls_set_cadata(ares_crypto_ctx_t   *crypto_ctx,
                                  const unsigned char *pem, size_t len);

/*! Cache a resumable TLS session for a connection, keyed by the connection's
 *  server identity (address/port + auth name + verify mode).  Takes ownership
 *  of \p sess. */
ares_status_t ares_tls_session_insert(ares_crypto_ctx_t *crypto_ctx,
                                      ares_conn_t *conn, void *sess);
/*! Remove a cached session (releasing the cache's reference on it). */
ares_status_t ares_tls_session_remove(ares_crypto_ctx_t *crypto_ctx,
                                      void              *sess);
/*! Look up a cached resumable session for a connection, or NULL if none. */
void *ares_tls_session_get(ares_crypto_ctx_t *crypto_ctx, ares_conn_t *conn);


/*! \addtogroup ares_crypto_provider Cryptographic Provider Implementation
 *
 * These are functions and data types implemented by the backend cryptographic
 * provider.  Each provider must implement each one of these functions.
 *
 * @{
 */

struct ares_cryptoimp_ctx;
typedef struct ares_cryptoimp_ctx ares_cryptoimp_ctx_t;

/*! Initialize the backend crypto context (SSL_CTX / credential handle, trust
 *  anchors).  \param[out] ctx Returned context; \param[in] parent Owning
 *  channel crypto context.  \return ARES_SUCCESS or an error. */
ares_status_t ares_cryptoimp_ctx_init(ares_cryptoimp_ctx_t **ctx,
                                      ares_crypto_ctx_t     *parent);
/*! Destroy a backend crypto context. */
void ares_cryptoimp_ctx_destroy(ares_cryptoimp_ctx_t *ctx);
/*! Release backend thread-local state for the calling thread (see
 *  ares_crypto_thread_cleanup()); a no-op for backends with none. */
void ares_cryptoimp_thread_cleanup(ares_cryptoimp_ctx_t *ctx);
/*! Add trusted CA certificate(s) in PEM form to the backend trust store.
 *  \return ARES_SUCCESS if at least one was added, else an error. */
ares_status_t ares_tlsimp_set_cadata(ares_cryptoimp_ctx_t *ctx,
                                     const unsigned char *pem, size_t len);


/*! Create a backend TLS session object for a connection. */
ares_status_t ares_tlsimp_create(ares_tls_t          **tls,
                                 ares_cryptoimp_ctx_t *crypto_ctx,
                                 ares_conn_t          *conn);
/*! Current TLS state of the session (see ares_tls_state_t). */
ares_tls_state_t ares_tlsimp_get_state(ares_tls_t *tls);
/*! Current want-read/want-write state flags for event remapping. */
ares_tls_stateflag_t ares_tlsimp_get_stateflag(ares_tls_t *tls);
/*! Maximum TLS 1.3 early-data (0-RTT) the resumed session accepts, or 0 if
 *  none (so the connection layer skips early data). */
size_t ares_tlsimp_get_earlydata_size(ares_tls_t *tls);

/*! Whether the early data sent with ares_tlsimp_earlydata_write() was
 *  accepted by the server.  Only meaningful once the connection has
 *  reached the established state; on rejection the caller must re-send
 *  the data through the normal write path. */
ares_bool_t ares_tlsimp_earlydata_accepted(ares_tls_t *tls);

/*! Whether decrypted data or complete TLS records are buffered inside the
 *  TLS backend, readable without the socket becoming readable again.  When
 *  ARES_TRUE the caller must keep reading instead of waiting on socket
 *  events. */
ares_bool_t ares_tlsimp_get_read_pending(ares_tls_t *tls);
/*! Destroy a backend TLS session object. */
void ares_tlsimp_destroy(ares_tls_t *tls);
/*! Write TLS 1.3 early data (0-RTT) during the handshake.  \param[in,out]
 *  buf_len in: bytes offered; out: bytes consumed.  \return connection error
 *  (WOULDBLOCK to retry with the same data). */
ares_conn_err_t ares_tlsimp_earlydata_write(ares_tls_t          *tls,
                                            const unsigned char *buf,
                                            size_t              *buf_len);
/*! Read decrypted application data.  \param[in,out] buf_len in: capacity;
 *  out: bytes read.  \return connection error (WOULDBLOCK if none ready). */
ares_conn_err_t ares_tlsimp_read(ares_tls_t *tls, unsigned char *buf,
                                 size_t *buf_len);
/*! Encrypt and write application data.  \param[in,out] buf_len in: bytes
 *  offered; out: bytes consumed.  \return connection error. */
ares_conn_err_t ares_tlsimp_write(ares_tls_t *tls, const unsigned char *buf,
                                  size_t *buf_len);
/*! Begin/continue a graceful TLS shutdown (close-notify). */
ares_conn_err_t ares_tlsimp_shutdown(ares_tls_t *tls);
/*! Drive the TLS handshake toward established. \return ARES_CONN_ERR_SUCCESS
 *  once established, WOULDBLOCK while in progress, else an error. */
ares_conn_err_t ares_tlsimp_connect(ares_tls_t *tls);
/*! Release a cached session object (value destructor for the session cache). */
void ares_tlsimp_session_free(void *arg);

/*! @} */

/*! @} */

#endif
