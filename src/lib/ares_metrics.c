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

#include "ares_setup.h"
#include "ares.h"
#include "ares_private.h"

/*! Minimum timeout value. Chosen due to it being approximately RTT half-way
 *  around the world */
#define MIN_TIMEOUT_MS         250

/*! Multiplier to apply to average latency to come up with an initial timeout */
#define AVG_TIMEOUT_MULTIPLIER 5

/*! Upper timeout bounds, only used if channel->maxtimeout not set */
#define MAX_TIMEOUT_MS         5000

static time_t ares_metric_timestamp(ares_server_bucket_t bucket,
                                    const ares_timeval_t *now)
{
  time_t divisor;

  switch (bucket) {
    case ARES_METRIC_1MINUTE:
      divisor = 60;
      break;
    case ARES_METRIC_15MINUTES:
      divisor = 15 * 60;
      break;
    case ARES_METRIC_1HOUR:
      divisor = 60 * 60;
      break;
    case ARES_METRIC_1DAY:
      divisor = 24 * 60 * 60;
      break;
    case ARES_METRIC_INCEPTION:
      return 1;
    case ARES_METRIC_COUNT:
      return 0; /* Invalid! */
  }

  return (time_t)(now->sec / divisor);
}

void ares_metrics_record(const struct query *query, struct server_state *server,
                         ares_status_t status, const ares_dns_record_t *dnsrec)
{
  ares_timeval_t       now    = ares__tvnow();
  ares_timeval_t       tvdiff;
  unsigned int         query_ms;
  ares_dns_rcode_t     rcode;
  ares_server_bucket_t i;

  if (status != ARES_SUCCESS) {
    return;
  }

  if (server == NULL) {
    return;
  }

  rcode = ares_dns_record_get_rcode(dnsrec);
  if (rcode != ARES_RCODE_NOERROR && rcode != ARES_RCODE_NXDOMAIN) {
    return;
  }

  ares__timeval_diff(&tvdiff, &query->ts, &now);
  query_ms = (unsigned int)(tvdiff.sec + (tvdiff.usec / 1000));
  if (query_ms == 0) {
    query_ms = 1;
  }

  /* Place in each bucket */
  for (i=0; i<ARES_METRIC_COUNT; i++) {
    time_t ts = ares_metric_timestamp(i, &now);
    if (ts != server->metrics[i].ts) {
      memset(&server->metrics[i], 0, sizeof(server->metrics[i]));
      server->metrics[i].ts = ts;
    }

    if (server->metrics[i].latency_min_ms == 0 ||
        server->metrics[i].latency_min_ms > query_ms) {
      server->metrics[i].latency_min_ms = query_ms;
    }

    if (query_ms > server->metrics[i].latency_max_ms) {
      server->metrics[i].latency_min_ms = query_ms;
    }

    server->metrics[i].total_count++;
    server->metrics[i].total_ms += (ares_uint64_t)query_ms;
  }
}



size_t ares_metrics_server_timeout(const struct server_state *server,
                                   const ares_timeval_t      *now)
{
  const ares_channel_t *channel = server->channel;
  ares_server_bucket_t  i;

  for (i=0; i<ARES_METRIC_COUNT; i++) {
    time_t ts = ares_metric_timestamp(i, now);
    size_t timeout_ms;

    /* This ts has been invalidated, go to the next */
    if (ts != server->metrics[i].ts || server->metrics[i].total_count == 0) {
      continue;
    }

    /* Calculate average time */
    timeout_ms = (size_t)(server->metrics[i].total_ms / server->metrics[i].total_count);

    /* Multiply average by constant to get timeout value */
    timeout_ms *= AVG_TIMEOUT_MULTIPLIER;

    /* don't go below lower bounds */
    if (timeout_ms < MIN_TIMEOUT_MS) {
      timeout_ms = MIN_TIMEOUT_MS;
    }

    /* don't go above upper bounds */
    if (channel->maxtimeout && timeout_ms > channel->maxtimeout) {
      timeout_ms = (size_t)channel->maxtimeout;
    } else if (timeout_ms > MAX_TIMEOUT_MS) {
      timeout_ms = MAX_TIMEOUT_MS;
    }

    return timeout_ms;
  }

  /* If we're here, that means its the first query for the server, so we just
   * use the initial default timeout */
  return channel->timeout;
}
