/* MIT License
 *
 * Copyright (c) 2024 Brad House
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

/* 1 day */
#define COOKIE_CLIENT_TIMEOUT_MS (86400 * 1000)

/* 5 minutes */
#define COOKIE_UNSUPPORTED_TIMEOUT_MS (300 * 1000)

/* 2 minutes */
#define COOKIE_REGRESSION_TIMEOUT_MS (120 * 1000)

#define COOKIE_RESEND_MAX 3

static const unsigned char *
  ares_dns_cookie_fetch(const ares_dns_record_t *dnsrec, size_t *len)
{
  const ares_dns_rr_t *rr  = ares_dns_get_opt_rr_const(dnsrec);
  const unsigned char *val = NULL;
  *len                     = 0;

  if (rr == NULL) {
    return NULL;
  }

  if (!ares_dns_rr_get_opt_byid(rr, ARES_RR_OPT_OPTIONS, ARES_OPT_PARAM_COOKIE,
                                &val, len)) {
    return NULL;
  }

  return val;
}

static ares_bool_t timeval_is_set(const ares_timeval_t *tv)
{
  if (tv->sec != 0 && tv->usec != 0) {
    return ARES_TRUE;
  }
  return ARES_FALSE;
}

static ares_bool_t timeval_expired(const ares_timeval_t *tv,
                                   const ares_timeval_t *now,
                                   unsigned long         millsecs)
{
  ares_int64_t   tvdiff_ms;
  ares_timeval_t tvdiff;
  ares__timeval_diff(&tvdiff, tv, now);

  tvdiff_ms = tv->sec * 1000 + tv->usec / 1000;
  if (tvdiff_ms >= (ares_int64_t)millsecs) {
    return ARES_TRUE;
  }
  return ARES_FALSE;
}

static void ares_cookie_clear(ares_cookie_t *cookie)
{
  memset(cookie, 0, sizeof(*cookie));
  cookie->state = ARES_COOKIE_INITIAL;
}

static void ares_cookie_generate(ares_cookie_t            *cookie,
                                 struct server_connection *conn,
                                 const ares_timeval_t     *now)
{
  ares_channel_t *channel = conn->server->channel;

  ares__rand_bytes(channel->rand_state, cookie->client, sizeof(cookie->client));
  memcpy(&cookie->client_ts, now, sizeof(cookie->client_ts));
  memcpy(&cookie->client_ip, &conn->self_ip, sizeof(cookie->client_ip));
}

static void ares_cookie_clear_server(ares_cookie_t *cookie)
{
  memset(cookie->server, 0, sizeof(cookie->server));
  cookie->server_len = 0;
}

static ares_bool_t ares_addr_equal(const struct ares_addr *addr1,
                                   const struct ares_addr *addr2)
{
  if (addr1->family != addr2->family) {
    return ARES_FALSE;
  }

  switch (addr1->family) {
    case AF_INET:
      if (memcmp(&addr1->addr.addr4, &addr2->addr.addr4,
                 sizeof(addr1->addr.addr4)) == 0) {
        return ARES_TRUE;
      }
      break;
    case AF_INET6:
      if (memcmp(&addr1->addr.addr6, &addr2->addr.addr6,
                 sizeof(addr1->addr.addr6)) == 0) {
        return ARES_TRUE;
      }
      break;
    default:
      break; /* LCOV_EXCL_LINE */
  }

  return ARES_FALSE;
}

ares_status_t ares_cookie_apply(ares_dns_record_t        *dnsrec,
                                struct server_connection *conn,
                                const ares_timeval_t     *now)
{
  struct server_state *server = conn->server;
  ares_cookie_t       *cookie = &server->cookie;
  ares_dns_rr_t       *rr     = ares_dns_get_opt_rr(dnsrec);
  unsigned char        c[40];
  size_t               c_len;

  /* If there is no OPT record, then EDNS isn't supported, and therefore
   * cookies can't be supported */
  if (rr == NULL) {
    return ARES_SUCCESS;
  }

  /* No cookies on TCP, make sure we remove one if one is present */
  if (conn->is_tcp) {
    ares_dns_rr_del_opt_byid(rr, ARES_RR_OPT_OPTIONS, ARES_OPT_PARAM_COOKIE);
    return ARES_SUCCESS;
  }

  /* Look for regression */
  if (cookie->state == ARES_COOKIE_SUPPORTED &&
      timeval_is_set(&cookie->unsupported_ts) &&
      timeval_expired(&cookie->unsupported_ts, now,
                      COOKIE_REGRESSION_TIMEOUT_MS)) {
    ares_cookie_clear(cookie);
  }

  /* Handle unsupported state */
  if (cookie->state == ARES_COOKIE_UNSUPPORTED) {
    /* If timer hasn't expired, just delete any possible cookie and return */
    if (!timeval_expired(&cookie->unsupported_ts, now,
                         COOKIE_REGRESSION_TIMEOUT_MS)) {
      ares_dns_rr_del_opt_byid(rr, ARES_RR_OPT_OPTIONS, ARES_OPT_PARAM_COOKIE);
      return ARES_SUCCESS;
    }

    /* We want to try to "learn" again */
    ares_cookie_clear(cookie);
  }

  /* Generate a new cookie */
  if (cookie->state == ARES_COOKIE_INITIAL) {
    ares_cookie_generate(cookie, conn, now);
    cookie->state = ARES_COOKIE_GENERATED;
  }

  /* Regenerate the cookie and clear the server cookie if the client ip has
   * changed */
  if ((cookie->state == ARES_COOKIE_GENERATED ||
       cookie->state == ARES_COOKIE_SUPPORTED) &&
      !ares_addr_equal(&conn->self_ip, &cookie->client_ip)) {
    ares_cookie_clear_server(cookie);
    ares_cookie_generate(cookie, conn, now);
  }

  /* If the client cookie has reached its maximum time, refresh it */
  if (cookie->state == ARES_COOKIE_SUPPORTED &&
      timeval_expired(&cookie->client_ts, now, COOKIE_CLIENT_TIMEOUT_MS)) {
    ares_cookie_clear_server(cookie);
    ares_cookie_generate(cookie, conn, now);
  }

  /* Generate the full cookie which is the client cookie concatenated with the
   * server cookie (if there is one) and apply it. */
  memcpy(c, cookie->client, sizeof(cookie->client));
  if (cookie->server_len) {
    memcpy(c + sizeof(cookie->client), cookie->server, cookie->server_len);
  }
  c_len = sizeof(cookie->client) + cookie->server_len;

  return ares_dns_rr_set_opt(rr, ARES_RR_OPT_OPTIONS, ARES_OPT_PARAM_COOKIE, c,
                             c_len);
}

ares_status_t ares_cookie_validate(struct query             *query,
                                   const ares_dns_record_t  *dnsresp,
                                   struct server_connection *conn,
                                   const ares_timeval_t     *now)
{
  struct server_state     *server = conn->server;
  ares_cookie_t           *cookie = &server->cookie;
  const ares_dns_record_t *dnsreq = query->query;
  const unsigned char     *resp_cookie;
  size_t                   resp_cookie_len;
  const unsigned char     *req_cookie;
  size_t                   req_cookie_len;

  resp_cookie = ares_dns_cookie_fetch(dnsresp, &resp_cookie_len);

  /* Invalid cookie length, drop */
  if (resp_cookie && (resp_cookie_len < 8 || resp_cookie_len > 40)) {
    return ARES_EBADRESP;
  }

  req_cookie = ares_dns_cookie_fetch(dnsreq, &req_cookie_len);

  /* Didn't request cookies, so we can stop evaluating */
  if (req_cookie == NULL) {
    return ARES_SUCCESS;
  }

  /* If 8-byte prefix for returned cookie doesn't match the requested cookie,
   * drop for spoofing */
  if (resp_cookie && memcmp(req_cookie, resp_cookie, 8) != 0) {
    return ARES_EBADRESP;
  }

  if (resp_cookie && resp_cookie_len > 8) {
    /* Make sure we record that we successfully received a cookie response */
    cookie->state = ARES_COOKIE_SUPPORTED;
    memset(&cookie->unsupported_ts, 0, sizeof(cookie->unsupported_ts));

    /* If client cookie hasn't been rotated, save the returned server cookie */
    if (memcmp(cookie->client, req_cookie, sizeof(cookie->client)) == 0) {
      memcpy(cookie->server, resp_cookie + 8, resp_cookie_len - 8);
    }
  }

  if (ares_dns_record_get_rcode(dnsresp) == ARES_RCODE_BADCOOKIE) {
    /* Illegal to return BADCOOKIE but no cookie, drop */
    if (resp_cookie == NULL) {
      return ARES_EBADRESP;
    }

    /* If we have too many attempts to send a cookie, we need to requeue as
     * tcp */
    query->cookie_try_count++;
    if (query->cookie_try_count >= COOKIE_RESEND_MAX) {
      query->using_tcp = ARES_TRUE;
    }

    /* Resend the request, hopefully it will work the next time as we should
     * have recorded a server cookie */
    return ares__requeue_query(query, now, ARES_SUCCESS,
                               ARES_FALSE /* Don't increment try count */);
  }

  /* We've got a response with a server cookie, and we've done all the
   * evaluation we can, return success */
  if (resp_cookie_len > 8) {
    return ARES_SUCCESS;
  }

  if (cookie->state == ARES_COOKIE_SUPPORTED) {
    /* If we're not currently tracking an error time yet, start */
    if (!timeval_is_set(&cookie->unsupported_ts)) {
      memcpy(&cookie->unsupported_ts, now, sizeof(cookie->unsupported_ts));
    }
    /* Drop it since we expected a cookie */
    return ARES_EBADRESP;
  }

  if (cookie->state == ARES_COOKIE_GENERATED) {
    ares_cookie_clear(cookie);
    cookie->state = ARES_COOKIE_UNSUPPORTED;
    memcpy(&cookie->unsupported_ts, now, sizeof(cookie->unsupported_ts));
  }

  /* Cookie state should be UNSUPPORTED if we're here */
  return ARES_SUCCESS;
}
