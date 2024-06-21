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


/* IMPLEMENTATION NOTES
 * ====================
 *
 * With very little effort we should be able to determine fairly proper timeouts
 * we can use based on prior query history.  We can also track in order to
 * auto-scale when network conditions change (e.g. maybe there is a provider
 * failover and timings change due to that).  Apple appears to do this within
 * their system resolver in MacOS.  Obviously we should have a minimum, maximum,
 * and initial value to make sure the algorithm doesn't somehow go off the
 * rails.
 *
 * Values:
 * - Minimum Timeout: 250ms (approximate RTT half-way around the globe)
 * - Maximum Timeout: 5000ms (Recommended timeout in RFC 1123), can be reduced
 *   by ARES_OPT_MAXTIMEOUTMS, but otherwise the bound specified by the option
 *   caps the retry timeout.
 * - Initial Timeout: User-specified via configuration or ARES_OPT_TIMEOUTMS
 * - Average latency multiplier: 5x (a local DNS server returning a cached value
 *   will be quicker than if it needs to recurse so we need to account for this)
 *
 * Per-server buckets for tracking latency over time (these are ephemeral
 * meaning they don't persist once a channel is destroyed).  There will be some
 * skew to prevent most buckets from resetting at the same time:
 * - 1 minute (using 1:01)
 * - 15 minutes (using 15:30)
 * - 1 hr (using 59:00)
 * - 1 day (using 23:58:57)
 * - since inception
 *
 * Each bucket would contain:
 * - timestamp (divided by interval)
 * - minimum latency
 * - maximum latency
 * - total time
 * - count
 * NOTE: average latency is (total time / count), we will calculate this
 *       dynamically when needed
 *
 * Basic algorithm for calculating timeout to use would be:
 * - Scan from most recent bucket to least recent
 * - Check timestamp of bucket, if doesn't match current time, continue to next
 *   bucket
 * - Check count of bucket, if its zero, continue to next bucket
 * - If we reached the end with no bucket match, use "Initial Timeout"
 * - If bucket is selected, take ("total time" / count) as Average latency,
 *   multiply by "Average Latency Multiplier", bound by "Minimum Timeout" and
 *   "Maximum Timeout"
 * NOTE: The timeout calculated may not be the timeout used.  If we are retrying
 * the query on the same server another time, then it will use a larger value
 *
 * On each query reply where the response is legitimate (proper response or
 * NXDOMAIN) and not something like a server error:
 * - Cycle through each bucket in order
 * - Check timestamp of bucket against current timestamp, if out of date clear
 *   all values
 * - Compare current minimum and maximum recorded latency against query time and
 *   adjust if necessary
 * - Increment "count" by 1 and "total time" by the query time
 *
 * Other Notes:
 * - This is always-on, the only user-configurable value is the initial
 *   timeout which will simply re-uses the current option.
 * - Minimum and Maximum latencies for a bucket are currently unused but are
 *   there in case we find a need for them in the future.
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
      divisor = 61; /* 1:01 */
      break;
    case ARES_METRIC_15MINUTES:
      divisor = (15 * 60) + 30; /* 15:30 */
      break;
    case ARES_METRIC_1HOUR:
      divisor = 59 * 60; /* 59:00 */
      break;
    case ARES_METRIC_1DAY:
      divisor = (23 * 60 * 60) + (58 * 60) + 57; /* 23:58:57 */
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
