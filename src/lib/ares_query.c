/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
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

#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#include "ares_nameser.h"

#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

struct qquery {
  ares_callback callback;
  void         *arg;
};

static void qcallback(void *arg, ares_status_t status, size_t timeouts,
                      const ares_dns_record_t *dnsrec)
{
  struct qquery     *qquery = (struct qquery *)arg;
  size_t             ancount;
  ares_dns_rcode_t   rcode;
  unsigned char     *abuf   = NULL;
  size_t             alen   = 0;

  if (dnsrec != NULL) {
    ares_status_t write_status;
    write_status = ares_dns_write(dnsrec, &abuf, &alen);
    if (status == ARES_SUCCESS) {
      status = write_status;
    }
  }

  if (status != ARES_SUCCESS) {
    qquery->callback(qquery->arg, (int)status, (int)timeouts, abuf, (int)alen);
  } else {
    /* Pull the response code and answer count from the packet and convert any
     * errors.
     */
    rcode = ares_dns_record_get_rcode(dnsrec);
    ancount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
    status = ares_dns_query_reply_tostatus(rcode, ancount);
    qquery->callback(qquery->arg, (int)status, (int)timeouts, abuf, (int)alen);
  }
  ares_free(qquery);
  ares_free(abuf);
}

ares_status_t ares_query_qid(ares_channel_t *channel, const char *name,
                             int dnsclass, int type, ares_callback callback,
                             void *arg, unsigned short *qid)
{
  struct qquery     *qquery = NULL;
  ares_status_t      status;
  ares_dns_record_t *dnsrec = NULL;
  ares_dns_flags_t   flags = 0;

  if (name == NULL) {
    status = ARES_EFORMERR;
    callback(arg, (int)status, 0, NULL, 0);
    return status;
  }

  if (!(channel->flags & ARES_FLAG_NORECURSE)) {
    flags |= ARES_FLAG_RD;
  }

  status = ares_dns_record_create_query(&dnsrec, name,
                                        (ares_dns_class_t)dnsclass,
                                        (ares_dns_rec_type_t)type,
                                        0, flags,
                                        (size_t)(channel->flags & ARES_FLAG_EDNS)?channel->ednspsz : 0);
  if (status != ARES_SUCCESS) {
    callback(arg, (int)status, 0, NULL, 0);
    return status;
  }

  /* Allocate and fill in the query structure. */
  qquery = ares_malloc(sizeof(struct qquery));
  if (!qquery) {
    callback(arg, ARES_ENOMEM, 0, NULL, 0);
    return ARES_ENOMEM;
  }

  qquery->callback = callback;
  qquery->arg      = arg;

  /* Send it off.  qcallback will be called when we get an answer. */
  status = ares_send_dnsrec(channel, dnsrec, qcallback, qquery, qid);

  ares_dns_record_destroy(dnsrec);
  return status;
}

void ares_query(ares_channel_t *channel, const char *name, int dnsclass,
                int type, ares_callback callback, void *arg)
{
  if (channel == NULL) {
    return;
  }
  ares__channel_lock(channel);
  ares_query_qid(channel, name, dnsclass, type, callback, arg, NULL);
  ares__channel_unlock(channel);
}


