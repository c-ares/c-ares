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

ares_status_t ares_dns_cookie_set(ares_dns_record_t *dnsrec,
                                  const unsigned char *cookie, size_t len)
{
  ares_dns_rr_t *rr  = ares_dns_get_opt_rr(dnsrec);

  if (rr == NULL) {
    return ARES_EFORMERR;
  }

  return ares_dns_rr_set_opt(rr, ARES_RR_OPT_OPTIONS, ARES_OPT_PARAM_COOKIE,
                             cookie, len);
}

const unsigned char *ares_dns_cookie_fetch(const ares_dns_record_t *dnsrec,
                                           size_t *len)
{
  const ares_dns_rr_t *rr  = ares_dns_get_opt_rr_const(dnsrec);
  const unsigned char *val = NULL;
  *len = 0;

  if (rr == NULL) {
    return NULL;
  }

  if (!ares_dns_rr_get_opt_byid(rr, ARES_RR_OPT_OPTIONS, ARES_OPT_PARAM_COOKIE,
                                &val, len)) {
    return NULL;
  }

  return val;
}

void ares_dns_cookie_delete(ares_dns_record_t *dnsrec)
{
  ares_dns_rr_t *rr  = ares_dns_get_opt_rr(dnsrec);

  if (rr == NULL) {
    return;
  }

  ares_dns_rr_del_opt_byid(rr, ARES_RR_OPT_OPTIONS, ARES_OPT_PARAM_COOKIE);
}

