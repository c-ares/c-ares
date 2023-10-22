/* MIT License
 *
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

/* =============================================================================
 * NOTE:  The below copyright is preserved from the original author.  In
 *        October 2023, there were attempts made to contact the author in order
 *        gain approval for relicensing to the modern MIT license from the
 *        below 1989 variant, but all contact information for the author is
 *        no longer valid.
 *
 * Copyright (c) 2020 <danny.sonnenschein@platynum.ch>
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * =============================================================================
 */

#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#include "ares_nameser.h"

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_data.h"
#include "ares_private.h"
#include "ares_dns_record.h"

int ares_parse_caa_reply(const unsigned char *abuf, int alen_int,
                         struct ares_caa_reply **caa_out)
{
  ares_status_t          status;
  size_t                 alen;
  struct ares_caa_reply *caa_head = NULL;
  struct ares_caa_reply *caa_last = NULL;
  struct ares_caa_reply *caa_curr;
  ares_dns_record_t     *dnsrec   = NULL;
  size_t                 i;

  *caa_out = NULL;

  if (alen_int < 0) {
    return ARES_EBADRESP;
  }

  alen = (size_t)alen_int;

  status = ares_dns_parse(abuf, alen, 0, &dnsrec);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  if (ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER) == 0)
    return ARES_ENODATA;

  for (i=0; i<ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER); i++) {
    const unsigned char *ptr;
    size_t               ptr_len;
    ares_dns_rr_t       *rr = ares_dns_record_rr_get(dnsrec,
                                                     ARES_SECTION_ANSWER, i);
    if (rr == NULL) {
      /* Shouldn't be possible */
      status = ARES_EBADRESP;
      goto done;
    }

    /* XXX: Why do we allow Chaos class? */
    if (ares_dns_rr_get_class(rr) != ARES_CLASS_IN &&
        ares_dns_rr_get_class(rr) != ARES_CLASS_CHAOS) {
      continue;
    }

    /* Only looking for CAA records */
    if (ares_dns_rr_get_type(rr) != ARES_REC_TYPE_CAA) {
      continue;
    }

    /* Allocate storage for this CAA answer appending it to the list */
    caa_curr = ares_malloc_data(ARES_DATATYPE_CAA_REPLY);
    if (caa_curr == NULL) {
      status = ARES_ENOMEM;
      goto done;
    }

    /* Link in the record */
    if (caa_last) {
      caa_last->next = caa_curr;
    } else {
      caa_head = caa_curr;
    }
    caa_last = caa_curr;

    caa_curr->critical = ares_dns_rr_get_u8(rr, ARES_RR_CAA_CRITICAL);
    caa_curr->property = (unsigned char *)ares_strdup(
                           ares_dns_rr_get_str(rr, ARES_RR_CAA_TAG)
                         );
    if (caa_curr->property == NULL) {
      status = ARES_ENOMEM;
      break;
    }
    caa_curr->plength  = ares_strlen((const char *)caa_curr->property);

    ptr = ares_dns_rr_get_bin(rr, ARES_RR_CAA_VALUE, &ptr_len);
    if (ptr == NULL) {
      status = ARES_EBADRESP;
      goto done;
    }

    /* Wants NULL termination for some reason */
    caa_curr->value = ares_malloc(ptr_len + 1);
    if (caa_curr->value == NULL) {
      status = ARES_ENOMEM;
      goto done;
    }
    memcpy(caa_curr->value, ptr, ptr_len);
    caa_curr->value[ptr_len] = 0;
    caa_curr->length         =  ptr_len;
  }

done:
  /* clean up on error */
  if (status != ARES_SUCCESS) {
    if (caa_head) {
      ares_free_data(caa_head);
    }
  } else {
    /* everything looks fine, return the data */
    *caa_out = caa_head;
  }
  ares_dns_record_destroy(dnsrec);
  return (int)status;
}
