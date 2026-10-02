/* MIT License
 *
 * Copyright (c) Massachusetts Institute of Technology
 * Copyright (c) The c-ares project and its contributors
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

void ares_conn_sock_state_cb_update(ares_conn_t            *conn,
                                    ares_conn_state_flags_t flags)
{
  ares_channel_t *channel = conn->server->channel;

  if ((conn->state_flags & ARES_CONN_STATE_CBFLAGS) != flags &&
      channel->sock_state_cb) {
    channel->sock_state_cb(channel->sock_state_cb_data, conn->fd,
                           flags & ARES_CONN_STATE_READ ? 1 : 0,
                           flags & ARES_CONN_STATE_WRITE ? 1 : 0);
  }

  conn->state_flags &= ~((unsigned int)ARES_CONN_STATE_CBFLAGS);
  conn->state_flags |= flags;
}

ares_conn_err_t ares_conn_read_raw(ares_conn_t *conn, void *data, size_t len,
                                   size_t *read_bytes)
{
  ares_channel_t *channel = conn->server->channel;
  ares_conn_err_t err;

  if (!(conn->flags & ARES_CONN_FLAG_TCP)) {
    struct sockaddr_storage sa_storage;
    ares_socklen_t          salen = sizeof(sa_storage);

    memset(&sa_storage, 0, sizeof(sa_storage));

    err =
      ares_socket_recvfrom(channel, conn->fd, ARES_FALSE, data, len, 0,
                           (struct sockaddr *)&sa_storage, &salen, read_bytes);

#ifdef HAVE_RECVFROM
    if (err == ARES_CONN_ERR_SUCCESS &&
        !ares_sockaddr_addr_eq((struct sockaddr *)&sa_storage,
                               &conn->server->addr)) {
      err = ARES_CONN_ERR_WOULDBLOCK;
    }
#endif
  } else {
    err = ares_socket_recv(channel, conn->fd, ARES_TRUE, data, len, read_bytes);
  }

  /* Toggle connected state if needed */
  if (err == ARES_CONN_ERR_SUCCESS) {
    conn->state_flags |= ARES_CONN_STATE_CONNECTED;
  }

  return err;
}

/* Use like:
 *   struct sockaddr_storage sa_storage;
 *   ares_socklen_t          salen     = sizeof(sa_storage);
 *   struct sockaddr        *sa        = (struct sockaddr *)&sa_storage;
 *   ares_conn_set_sockaddr(conn, sa, &salen);
 */
static ares_status_t ares_conn_set_sockaddr(const ares_conn_t *conn,
                                            struct sockaddr   *sa,
                                            ares_socklen_t    *salen)
{
  const ares_server_t *server = conn->server;
  unsigned short       port =
    conn->flags & ARES_CONN_FLAG_TCP ? server->tcp_port : server->udp_port;
  struct sockaddr_in  *sin;
  struct sockaddr_in6 *sin6;

  switch (server->addr.family) {
    case AF_INET:
      sin = (struct sockaddr_in *)(void *)sa;
      if (*salen < (ares_socklen_t)sizeof(*sin)) {
        return ARES_EFORMERR;
      }
      *salen = sizeof(*sin);
      memset(sin, 0, sizeof(*sin));
      sin->sin_family = AF_INET;
      sin->sin_port   = htons(port);
      memcpy(&sin->sin_addr, &server->addr.addr.addr4, sizeof(sin->sin_addr));
      return ARES_SUCCESS;
    case AF_INET6:
      sin6 = (struct sockaddr_in6 *)(void *)sa;
      if (*salen < (ares_socklen_t)sizeof(*sin6)) {
        return ARES_EFORMERR;
      }
      *salen = sizeof(*sin6);
      memset(sin6, 0, sizeof(*sin6));
      sin6->sin6_family = AF_INET6;
      sin6->sin6_port   = htons(port);
      memcpy(&sin6->sin6_addr, &server->addr.addr.addr6,
             sizeof(sin6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
      sin6->sin6_scope_id = server->ll_scope;
#endif
      return ARES_SUCCESS;
    default:
      break;
  }

  return ARES_EBADFAMILY;
}

static ares_status_t ares_conn_set_self_ip(ares_conn_t *conn, ares_bool_t early)
{
  ares_channel_t         *channel = conn->server->channel;
  struct sockaddr_storage sa_storage;
  int                     rv;
  ares_socklen_t          len = sizeof(sa_storage);

  /* We call this twice on TFO, if we already have the IP we can go ahead and
   * skip processing */
  if (!early && conn->self_ip.family != AF_UNSPEC) {
    return ARES_SUCCESS;
  }

  memset(&sa_storage, 0, sizeof(sa_storage));

  if (channel->sock_funcs.agetsockname == NULL) {
    /* Not specified, we can still use cookies cooked with an empty self_ip */
    memset(&conn->self_ip, 0, sizeof(conn->self_ip));
    return ARES_SUCCESS;
  }
  rv = channel->sock_funcs.agetsockname(conn->fd,
                                        (struct sockaddr *)(void *)&sa_storage,
                                        &len, channel->sock_func_cb_data);
  if (rv != 0) {
    /* During TCP FastOpen, we can't get the IP this early since connect()
     * may not be called.  That's ok, we'll try again later */
    if (early && conn->flags & ARES_CONN_FLAG_TCP &&
        conn->flags & ARES_CONN_FLAG_TFO) {
      memset(&conn->self_ip, 0, sizeof(conn->self_ip));
      return ARES_SUCCESS;
    }
    return ARES_ECONNREFUSED;
  }

  if (!ares_sockaddr_to_ares_addr(&conn->self_ip, NULL,
                                  (struct sockaddr *)(void *)&sa_storage)) {
    return ARES_ECONNREFUSED;
  }

  return ARES_SUCCESS;
}

ares_conn_err_t ares_conn_write_raw(ares_conn_t *conn, const void *data,
                                    size_t len, size_t *written)
{
  ares_channel_t         *channel = conn->server->channel;
  ares_bool_t             is_tfo  = ARES_FALSE;
  ares_conn_err_t         err     = ARES_CONN_ERR_SUCCESS;
  struct sockaddr_storage sa_storage;
  ares_socklen_t          salen = 0;
  struct sockaddr        *sa    = NULL;

  *written = 0;

  /* Don't try to write if not doing initial TFO and not connected */
  if (conn->flags & ARES_CONN_FLAG_TCP &&
      !(conn->state_flags & ARES_CONN_STATE_CONNECTED) &&
      !(conn->flags & ARES_CONN_FLAG_TFO_INITIAL)) {
    return ARES_CONN_ERR_WOULDBLOCK;
  }

  /* On initial write during TFO we need to send an address */
  if (conn->flags & ARES_CONN_FLAG_TFO_INITIAL) {
    salen = sizeof(sa_storage);
    sa    = (struct sockaddr *)&sa_storage;

    conn->flags &= ~((unsigned int)ARES_CONN_FLAG_TFO_INITIAL);
    is_tfo       = ARES_TRUE;

    if (ares_conn_set_sockaddr(conn, sa, &salen) != ARES_SUCCESS) {
      return ARES_CONN_ERR_FAILURE;
    }
  }

  err = ares_socket_write(channel, conn->fd, data, len, written, sa, salen);
  if (err != ARES_CONN_ERR_SUCCESS) {
    goto done;
  }

  if (is_tfo) {
    /* If using TFO, we might not have been able to get an IP earlier, since
     * we hadn't informed the OS of the destination.  When using sendto()
     * now we have so we should be able to fetch it */
    ares_conn_set_self_ip(conn, ARES_FALSE);
    goto done;
  }

done:
  if (err == ARES_CONN_ERR_SUCCESS && len == *written) {
    /* Wrote all data, make sure we're not listening for write events unless
     * using TFO, in which case we'll need a write event to know when
     * we're connected. */
    ares_conn_sock_state_cb_update(
      conn, ARES_CONN_STATE_READ |
              (is_tfo ? ARES_CONN_STATE_WRITE : ARES_CONN_STATE_NONE));
  } else if (err == ARES_CONN_ERR_WOULDBLOCK) {
    /* Need to wait on more buffer space to write */
    ares_conn_sock_state_cb_update(conn, ARES_CONN_STATE_READ |
                                           ARES_CONN_STATE_WRITE);
  }

  return err;
}

/*! Drive the TLS handshake as needed; ARES_CONN_ERR_SUCCESS means the
 *  session is established and application I/O may proceed */
static ares_conn_err_t ares_conn_tls_advance_handshake(ares_conn_t *conn)
{
  switch (ares_tlsimp_get_state(conn->tls)) {
    case ARES_TLS_STATE_INIT:
    case ARES_TLS_STATE_EARLYDATA:
    case ARES_TLS_STATE_CONNECT:
      return ares_tlsimp_connect(conn->tls);
    case ARES_TLS_STATE_ESTABLISHED:
      return ARES_CONN_ERR_SUCCESS;
    case ARES_TLS_STATE_SHUTDOWN:
    case ARES_TLS_STATE_DISCONNECTED:
      return ARES_CONN_ERR_CONNCLOSED;
    case ARES_TLS_STATE_ERROR:
    default:
      return ARES_CONN_ERR_CONNRESET;
  }
}

ares_bool_t ares_conn_tls_read_pending(const ares_conn_t *conn)
{
  /* The TLS backend may hold buffered decrypted data or complete records that
   * won't produce a new socket read event (e.g. Schannel bulk-reads several
   * records in one recv), so the read loop must keep reading while this is
   * true rather than waiting on the fd. */
  if (conn == NULL || !(conn->flags & ARES_CONN_FLAG_TLS) ||
      conn->tls == NULL) {
    return ARES_FALSE;
  }
  return ares_tlsimp_get_read_pending(conn->tls);
}

ares_conn_err_t ares_conn_read(ares_conn_t *conn, void *data, size_t len,
                               size_t *read_bytes)
{
  ares_conn_err_t err;

  if (!(conn->flags & ARES_CONN_FLAG_TLS)) {
    return ares_conn_read_raw(conn, data, len, read_bytes);
  }

  err = ares_conn_tls_advance_handshake(conn);
  if (err != ARES_CONN_ERR_SUCCESS) {
    return err;
  }

  *read_bytes = len;
  err         = ares_tlsimp_read(conn->tls, data, read_bytes);
  if (err != ARES_CONN_ERR_SUCCESS) {
    *read_bytes = 0;
    return err;
  }
  conn->state_flags |= ARES_CONN_STATE_CONNECTED;
  return err;
}

/* Whether a TCP-framed DNS message is a standard QUERY (opcode 0).  DoT is
 * TCP-framed, so `data` begins with the 2-byte length prefix; the DNS header
 * flags high byte (QR + 4-bit opcode + ...) is at offset 4 (2 length + 2 ID)
 * and the opcode is bits 3-6 of it.  A short buffer is treated as not-a-QUERY
 * (fail safe -- it simply won't ride 0-RTT). */
static ares_bool_t ares_conn_framed_is_query(const unsigned char *data,
                                             size_t               len)
{
  if (len < 5) {
    return ARES_FALSE;
  }
  return (((data[4] >> 3) & 0x0F) == (unsigned char)ARES_OPCODE_QUERY)
           ? ARES_TRUE
           : ARES_FALSE;
}

ares_conn_err_t ares_conn_write(ares_conn_t *conn, const void *data, size_t len,
                                size_t *written)
{
  ares_conn_err_t  err;
  ares_tls_state_t state;
  size_t           accepted = 0;
  size_t           w;

  if (!(conn->flags & ARES_CONN_FLAG_TLS)) {
    return ares_conn_write_raw(conn, data, len, written);
  }

  *written = 0;

  /* TLSv1.3 Early Data (0-RTT): while the handshake is still in progress and
   * the resumed session advertises early-data capacity, feed the pending
   * query into the early-data flight.  Bytes sent this way are tracked in
   * conn->tls_earlydata_sent but NOT reported written until the handshake
   * confirms acceptance below, so out_buf keeps them and a rejected flight
   * replays.  DNS queries are idempotent, so 0-RTT replay is safe (same
   * rationale as DoH over GET).
   *
   * A cache miss (no resumable session) reports an early-data size of 0, so
   * this whole block is skipped and the connection does an ordinary 1-RTT
   * handshake.
   *
   * Only a standard QUERY is replay-safe: a caller-built non-QUERY message
   * (e.g. an RFC 2136 UPDATE via ares_send_dnsrec()) is not necessarily
   * idempotent, so it must never ride 0-RTT and is sent in the normal
   * post-handshake flight instead. */
  state = ares_tlsimp_get_state(conn->tls);
  if ((state == ARES_TLS_STATE_INIT || state == ARES_TLS_STATE_EARLYDATA) &&
      ares_conn_framed_is_query((const unsigned char *)data, len)) {
    size_t budget = ares_tlsimp_get_earlydata_size(conn->tls);
    if (budget > conn->tls_earlydata_sent && len > conn->tls_earlydata_sent) {
      size_t off = conn->tls_earlydata_sent;
      size_t ew  = len - off;

      if (ew > budget - off) {
        ew = budget - off;
      }

      err = ares_tlsimp_earlydata_write(conn->tls,
                                        (const unsigned char *)data + off, &ew);
      if (err == ARES_CONN_ERR_SUCCESS) {
        conn->tls_earlydata_sent += ew;
      } else if (err == ARES_CONN_ERR_WOULDBLOCK) {
        return ARES_CONN_ERR_WOULDBLOCK;
      }
      /* Any other early-data error (e.g. budget exhausted) just falls
       * through to the normal handshake + write path. */
    }
  }

  /* Drive the handshake to completion. */
  err = ares_conn_tls_advance_handshake(conn);
  if (err != ARES_CONN_ERR_SUCCESS) {
    return err;
  }

  /* Handshake established.  Reconcile any early data we sent: if the server
   * accepted it, those leading out_buf bytes are delivered and only the
   * remainder needs writing; if it rejected them, everything is re-sent
   * through the normal write path. */
  if (conn->tls_earlydata_sent > 0) {
    if (ares_tlsimp_earlydata_accepted(conn->tls)) {
      accepted = conn->tls_earlydata_sent;
    }
    conn->tls_earlydata_sent = 0;
  }

  if (accepted >= len) {
    *written = accepted;
    return ARES_CONN_ERR_SUCCESS;
  }

  w = len - accepted;
  err =
    ares_tlsimp_write(conn->tls, (const unsigned char *)data + accepted, &w);
  if (err != ARES_CONN_ERR_SUCCESS) {
    /* If early data was delivered but the remainder blocked, report the
     * delivered prefix so it is consumed and the rest retried from the
     * correct offset. */
    if (accepted > 0) {
      *written = accepted;
      return ARES_CONN_ERR_SUCCESS;
    }
    *written = 0;
    return err;
  }

  *written = accepted + w;
  return ARES_CONN_ERR_SUCCESS;
}

ares_status_t ares_conn_flush(ares_conn_t *conn)
{
  const unsigned char *data;
  size_t               data_len;
  size_t               count;
  ares_conn_err_t      err;
  ares_status_t        status;
  ares_bool_t          tfo = ARES_FALSE;

  if (conn == NULL) {
    return ARES_EFORMERR;
  }

  if (conn->flags & ARES_CONN_FLAG_TFO_INITIAL) {
    tfo = ARES_TRUE;
  }

  do {
    if (ares_buf_len(conn->out_buf) == 0) {
      status = ARES_SUCCESS;
      goto done;
    }

    if (conn->flags & ARES_CONN_FLAG_TCP) {
      data = ares_buf_peek(conn->out_buf, &data_len);
    } else {
      unsigned short msg_len;

      /* Read length, then provide buffer without length */
      ares_buf_tag(conn->out_buf);
      status = ares_buf_fetch_be16(conn->out_buf, &msg_len);
      if (status != ARES_SUCCESS) {
        return status;
      }
      ares_buf_tag_rollback(conn->out_buf);

      data = ares_buf_peek(conn->out_buf, &data_len);
      if (data_len < (size_t)(msg_len + 2)) {
        status = ARES_EFORMERR;
        goto done;
      }
      data     += 2;
      data_len  = msg_len;
    }

    err = ares_conn_write(conn, data, data_len, &count);
    if (err != ARES_CONN_ERR_SUCCESS) {
      if (err != ARES_CONN_ERR_WOULDBLOCK) {
        /* Every fatal transport error -- including ARES_CONN_ERR_SECURITY from
         * a failed TLS handshake / certificate verification -- currently
         * collapses to ARES_ECONNREFUSED, so a strict verification failure is
         * retried like a connection refusal.  A distinct terminal status that
         * suppresses retry (and a no-downgrade security tier) is deferred to
         * the follow-up tracked in #1255. */
        status = ARES_ECONNREFUSED;
        goto done;
      }
      status = ARES_SUCCESS;
      goto done;
    }

    /* UDP didn't send the length prefix so augment that here */
    if (!(conn->flags & ARES_CONN_FLAG_TCP)) {
      count += 2;
    }

    /* Strip data written from the buffer */
    ares_buf_consume(conn->out_buf, count);
    status = ARES_SUCCESS;

    /* Loop only for UDP since we have to send per-packet.  We already
     * sent everything we could if using tcp */
  } while (!(conn->flags & ARES_CONN_FLAG_TCP));

done:
  if (status == ARES_SUCCESS) {
    ares_conn_state_flags_t flags = ARES_CONN_STATE_READ;

    /* When using TFO, the we need to enabling waiting on a write event to
     * be notified of when a connection is actually established */
    if (tfo) {
      flags |= ARES_CONN_STATE_WRITE;
    }

    if (conn->flags & ARES_CONN_FLAG_TLS &&
        ares_tlsimp_get_state(conn->tls) != ARES_TLS_STATE_ESTABLISHED) {
      /* While the TLS handshake is still in progress the queued query can't
       * drain until it completes, so buffer-emptiness is the wrong signal for
       * arming the write event: it would keep ARES_CONN_STATE_WRITE set while
       * the handshake is blocked on a *readable* socket, and every
       * level-triggered event loop would then spin at 100% CPU on the
       * persistently-writable fd.  Instead, arm the write event only when the
       * TLS layer actually wants to write.  (When it wants to read, we fall
       * through with just ARES_CONN_STATE_READ, and process_read() re-flushes
       * this buffer once the handshake finishes.) */
      ares_tls_stateflag_t sf = ares_tlsimp_get_stateflag(conn->tls);
      if (sf & (ARES_TLS_SF_READ_WANTWRITE | ARES_TLS_SF_WRITE_WANTWRITE)) {
        flags |= ARES_CONN_STATE_WRITE;
      }
    } else if (conn->flags & ARES_CONN_FLAG_TLS) {
      /* Established TLS: buffer-emptiness is still the wrong signal to arm the
       * write event.  A write can block on a *readable* socket (TLS 1.3
       * post-handshake message or TLS 1.2 renegotiation set
       * ARES_TLS_SF_WRITE_WANTREAD) while the query remains in out_buf; arming
       * WRITE there would spin at 100% CPU on the persistently-writable fd.
       * Arm WRITE only when the TLS layer actually wants to write -- which also
       * covers the ordinary partial-write case (WANT_WRITE on a full socket
       * buffer). */
      ares_tls_stateflag_t sf = ares_tlsimp_get_stateflag(conn->tls);
      if (sf & (ARES_TLS_SF_READ_WANTWRITE | ARES_TLS_SF_WRITE_WANTWRITE)) {
        flags |= ARES_CONN_STATE_WRITE;
      } else if (ares_buf_len(conn->out_buf) > 0 &&
                 !(sf &
                   (ARES_TLS_SF_READ_WANTREAD | ARES_TLS_SF_WRITE_WANTREAD))) {
        /* SSL_MODE_ENABLE_PARTIAL_WRITE lets a write succeed with only part of
         * the record sent (the socket buffer filled), leaving data in out_buf
         * but setting no want-flag.  The socket is genuinely full, so arming
         * WRITE drains the tail without busy-spinning.  Excluded when TLS is
         * blocked on a *read* (renegotiation), where WRITE must stay disarmed.
         */
        flags |= ARES_CONN_STATE_WRITE;
      }
    } else if (conn->flags & ARES_CONN_FLAG_TCP &&
               ares_buf_len(conn->out_buf)) {
      /* If using TCP and not all data was written (partial write), that means
       * we need to also wait on a write event */
      flags |= ARES_CONN_STATE_WRITE;
    }

    ares_conn_sock_state_cb_update(conn, flags);
  }

  return status;
}

static ares_status_t ares_conn_connect(ares_conn_t           *conn,
                                       const struct sockaddr *sa,
                                       ares_socklen_t         salen)
{
  ares_conn_err_t err;

  err = ares_socket_connect(
    conn->server->channel, conn->fd,
    (conn->flags & ARES_CONN_FLAG_TFO) ? ARES_TRUE : ARES_FALSE, sa, salen);

  if (err != ARES_CONN_ERR_WOULDBLOCK && err != ARES_CONN_ERR_SUCCESS) {
    return ARES_ECONNREFUSED;
  }
  return ARES_SUCCESS;
}

ares_status_t ares_open_connection(ares_conn_t   **conn_out,
                                   ares_channel_t *channel,
                                   ares_server_t *server, ares_bool_t is_tcp)
{
  ares_status_t           status;
  struct sockaddr_storage sa_storage;
  ares_socklen_t          salen = sizeof(sa_storage);
  struct sockaddr        *sa    = (struct sockaddr *)&sa_storage;
  ares_conn_t            *conn;
  ares_llist_node_t      *node  = NULL;
  int                     stype = is_tcp ? SOCK_STREAM : SOCK_DGRAM;
  ares_conn_state_flags_t state_flags;

  *conn_out = NULL;

  conn = ares_malloc(sizeof(*conn));
  if (conn == NULL) {
    return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  memset(conn, 0, sizeof(*conn));
  conn->fd              = ARES_SOCKET_BAD;
  conn->server          = server;
  conn->queries_to_conn = ares_llist_create(NULL);
  conn->flags           = is_tcp ? ARES_CONN_FLAG_TCP : ARES_CONN_FLAG_NONE;
  conn->out_buf         = ares_buf_create();
  conn->in_buf          = ares_buf_create();

  if (conn->queries_to_conn == NULL || conn->out_buf == NULL ||
      conn->in_buf == NULL) {
    /* LCOV_EXCL_START: OutOfMemory */
    status = ARES_ENOMEM;
    goto done;
    /* LCOV_EXCL_STOP */
  }

  if (server->use_tls) {
    if (!is_tcp) {
      /* DoT is TLS over TCP; UDP connections must never be requested for a
       * TLS server */
      status = ARES_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
      goto done;              /* LCOV_EXCL_LINE: DefensiveCoding */
    }
    conn->flags |= ARES_CONN_FLAG_TLS;
    status       = ares_tls_create(&conn->tls, channel->crypto_ctx, conn);
    if (status != ARES_SUCCESS) {
      /* ARES_ENOTIMP when built without crypto support */
      goto done;
    }
  }

  /* Try to enable TFO always if using TCP. it will fail later on if its
   * really not supported when we try to enable it on the socket.
   * For TLS this composes with the handshake: the first BIO write (the
   * ClientHello, carrying 0-RTT early data when a session is resumed)
   * rides the SYN via the same ares_conn_write_raw() TFO_INITIAL path,
   * giving true 0-RTT including the TCP round trip.  Falls back to an
   * ordinary connect where TFO is unavailable. */
  if (conn->flags & ARES_CONN_FLAG_TCP) {
    conn->flags |= ARES_CONN_FLAG_TFO;
  }

  /* Convert into the struct sockaddr structure needed by the OS */
  status = ares_conn_set_sockaddr(conn, sa, &salen);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  /* Acquire a socket. */
  if (ares_socket_open(&conn->fd, channel, server->addr.family, stype, 0) !=
      ARES_CONN_ERR_SUCCESS) {
    status = ARES_ECONNREFUSED;
    goto done;
  }

  /* Configure channel configured options */
  status = ares_socket_configure(
    channel, server->addr.family,
    (conn->flags & ARES_CONN_FLAG_TCP) ? ARES_TRUE : ARES_FALSE, conn->fd);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  /* Enable TFO if possible */
  if (conn->flags & ARES_CONN_FLAG_TFO &&
      ares_socket_enable_tfo(channel, conn->fd) != ARES_CONN_ERR_SUCCESS) {
    conn->flags &= ~((unsigned int)ARES_CONN_FLAG_TFO);
  }

  if (channel->sock_config_cb) {
    int err =
      channel->sock_config_cb(conn->fd, stype, channel->sock_config_cb_data);
    if (err < 0) {
      status = ARES_ECONNREFUSED;
      goto done;
    }
  }

  /* Connect */
  status = ares_conn_connect(conn, sa, salen);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  if (channel->sock_create_cb) {
    int err =
      channel->sock_create_cb(conn->fd, stype, channel->sock_create_cb_data);
    if (err < 0) {
      status = ARES_ECONNREFUSED;
      goto done;
    }
  }

  /* Let the connection know we haven't written our first packet yet for TFO */
  if (conn->flags & ARES_CONN_FLAG_TFO) {
    conn->flags |= ARES_CONN_FLAG_TFO_INITIAL;
  }

  /* Need to store our own ip for DNS cookie support */
  status = ares_conn_set_self_ip(conn, ARES_TRUE);
  if (status != ARES_SUCCESS) {
    goto done; /* LCOV_EXCL_LINE: UntestablePath */
  }

  /* TCP connections are thrown to the end as we don't spawn multiple TCP
   * connections. UDP connections are put on front where the newest connection
   * can be quickly pulled */
  if (is_tcp) {
    node = ares_llist_insert_last(server->connections, conn);
  } else {
    node = ares_llist_insert_first(server->connections, conn);
  }
  if (node == NULL) {
    /* LCOV_EXCL_START: OutOfMemory */
    status = ARES_ENOMEM;
    goto done;
    /* LCOV_EXCL_STOP */
  }

  /* Register globally to quickly map event on file descriptor to connection
   * node object */
  if (!ares_htable_asvp_insert(channel->connnode_by_socket, conn->fd, node)) {
    /* LCOV_EXCL_START: OutOfMemory */
    status = ARES_ENOMEM;
    goto done;
    /* LCOV_EXCL_STOP */
  }

  state_flags = ARES_CONN_STATE_READ;

  /* Get notified on connect if using TCP */
  if (conn->flags & ARES_CONN_FLAG_TCP) {
    state_flags |= ARES_CONN_STATE_WRITE;
  }

  /* Dot no attempt to update sock state callbacks on TFO until *after* the
   * initial write is performed.  Due to the notification event, its possible
   * an erroneous read can come in before the attempt to write the data which
   * might be used to set the ip address */
  if (!(conn->flags & ARES_CONN_FLAG_TFO_INITIAL)) {
    ares_conn_sock_state_cb_update(conn, state_flags);
  }

  if (is_tcp) {
    server->tcp_conn = conn;
  }

done:
  if (status != ARES_SUCCESS) {
    ares_llist_node_claim(node);
    ares_llist_destroy(conn->queries_to_conn);
    ares_tlsimp_destroy(conn->tls);
    ares_socket_close(channel, conn->fd);
    ares_buf_destroy(conn->out_buf);
    ares_buf_destroy(conn->in_buf);
    ares_free(conn);
  } else {
    *conn_out = conn;
  }
  return status;
}

ares_conn_t *ares_conn_from_fd(const ares_channel_t *channel, ares_socket_t fd)
{
  ares_llist_node_t *node;

  node = ares_htable_asvp_get_direct(channel->connnode_by_socket, fd);
  if (node == NULL) {
    return NULL;
  }

  return ares_llist_node_val(node);
}

ares_status_t ares_conn_interpret_events(ares_fd_events_t      **out,
                                         ares_channel_t         *channel,
                                         const ares_fd_events_t *events,
                                         size_t                 *nevents)
{
  size_t      i;
  size_t      orig_events;
  size_t      cnt     = 0;
  ares_bool_t has_tls = ARES_FALSE;

  if (nevents == NULL || events == NULL || out == NULL) {
    return ARES_EFORMERR;
  }

  orig_events = *nevents;
  if (orig_events == 0) {
    return ARES_EFORMERR;
  }

  *out = NULL;

  /* Common case: no TLS connections are involved, so the events apply
   * as-is -- indicated by a NULL out with success -- and the hot event
   * path performs no allocation */
  for (i = 0; i < orig_events; i++) {
    ares_conn_t *conn = ares_conn_from_fd(channel, events[i].fd);
    if (conn != NULL && (conn->flags & ARES_CONN_FLAG_TLS)) {
      has_tls = ARES_TRUE;
      break;
    }
  }
  if (!has_tls) {
    return ARES_SUCCESS;
  }

  *out = ares_malloc_zero_array(orig_events, sizeof(**out));
  if (*out == NULL) {
    return ARES_ENOMEM;
  }

  for (i = 0; i < orig_events; i++) {
    ares_tls_stateflag_t sf;
    ares_conn_t         *conn = ares_conn_from_fd(channel, events[i].fd);

    if (conn == NULL || events[i].events == ARES_FD_EVENT_NONE) {
      continue;
    }

    (*out)[cnt].fd = events[i].fd;
    if (!(conn->flags & ARES_CONN_FLAG_TLS)) {
      (*out)[cnt].events = events[i].events;
      cnt++;
      continue;
    }

    /* Want-flags redirect events while an operation is blocked inside the
     * TLS layer (e.g. a logical write needing a readable socket during a
     * handshake).  When an operation's want-group is empty the TLS layer
     * has no opinion and the event passes through with its natural
     * meaning, so pending upper-layer work (like a queued query right
     * after the handshake completes) still gets dispatched. */
    sf = ares_tlsimp_get_stateflag(conn->tls);
    if (events[i].events & ARES_FD_EVENT_READ) {
      if (sf & ARES_TLS_SF_READ_WANTREAD || !(sf & ARES_TLS_SF_READ)) {
        (*out)[cnt].events |= ARES_FD_EVENT_READ;
      }
      if (sf & ARES_TLS_SF_WRITE_WANTREAD) {
        (*out)[cnt].events |= ARES_FD_EVENT_WRITE;
      }
    }
    if (events[i].events & ARES_FD_EVENT_WRITE) {
      if (sf & ARES_TLS_SF_READ_WANTWRITE) {
        (*out)[cnt].events |= ARES_FD_EVENT_READ;
      }
      if (sf & ARES_TLS_SF_WRITE_WANTWRITE || !(sf & ARES_TLS_SF_WRITE)) {
        (*out)[cnt].events |= ARES_FD_EVENT_WRITE;
      }
    }

    /* Before the socket is connected a write event is the connect
     * notification -- with TCP FastOpen, the ack of the SYN that already
     * carried the ClientHello.  The want-flag remapping above can map it to
     * nothing when the just-started handshake is already blocked on read,
     * which would swallow the notification: process_write() would never run to
     * mark the connection connected and re-derive the socket wait-set, so the
     * write event stays armed on a persistently-writable socket and the event
     * loop busy-spins.  Pass a connect-time write event through so the
     * connection makes progress and the wait-set is recomputed. */
    if (!(conn->state_flags & ARES_CONN_STATE_CONNECTED) &&
        (events[i].events & ARES_FD_EVENT_WRITE)) {
      (*out)[cnt].events |= ARES_FD_EVENT_WRITE;
    }

    /* Only keep the entry if the want-flag remapping produced actual event
     * bits; a zero-events entry would inflate nevents for no reason. */
    if ((*out)[cnt].events != ARES_FD_EVENT_NONE) {
      cnt++;
    }
  }

  *nevents = cnt;
  return ARES_SUCCESS;
}
