/* MIT License
 *
 * Copyright (c) 2023 Brad House
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
#include "ares_dns_record.h"
#include <limits.h>
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

static ares_status_t ares_dns_write_header(const ares_dns_record_t *dnsrec,
                                           ares__buf_t             *buf)
{
  unsigned short u16;
  ares_status_t  status;

  /* ID */
  status = ares__buf_append_be16(buf, dnsrec->id);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* Flags */
  u16 = 0;

  /* QR */
  if (dnsrec->flags & ARES_FLAG_QR) {
    u16 |= 0x8000;
  }

  /* OPCODE */
  u16 |= dnsrec->opcode << 11;

  /* AA */
  if (dnsrec->flags & ARES_FLAG_AA) {
    u16 |= 0x400;
  }

  /* TC */
  if (dnsrec->flags & ARES_FLAG_TC) {
    u16 |= 0x200;
  }

  /* RD */
  if (dnsrec->flags & ARES_FLAG_RD) {
    u16 |= 0x100;
  }

  /* RA */
  if (dnsrec->flags & ARES_FLAG_RA) {
    u16 |= 0x80;
  }

  /* Z -- unused */

  /* AD */
  if (dnsrec->flags & ARES_FLAG_AD) {
    u16 |= 0x20;
  }

  /* CD */
  if (dnsrec->flags & ARES_FLAG_CD) {
    u16 |= 0x10;
  }

  /* RCODE */
  u16 |= dnsrec->rcode;

  status = ares__buf_append_be16(buf, u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* QDCOUNT */
  status = ares__buf_append_be16(buf, (unsigned short)dnsrec->qdcount);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* ANCOUNT */
  status = ares__buf_append_be16(buf, (unsigned short)dnsrec->ancount);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* NSCOUNT */
  status = ares__buf_append_be16(buf, (unsigned short)dnsrec->nscount);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* ARCOUNT */
  status = ares__buf_append_be16(buf, (unsigned short)dnsrec->arcount);
  if (status != ARES_SUCCESS) {
    return status;
  }

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_write_questions(const ares_dns_record_t *dnsrec,
                                              ares__buf_t             *buf)
{

}

static ares_status_t ares_dns_write_rr(const ares_dns_record_t *dnsrec,
                                       ares_dns_section_t       section,
                                       ares__buf_t             *buf)
{

}

ares_status_t ares_dns_write(const ares_dns_record_t *dnsrec,
                             unsigned char **buf, size_t *buf_len)
{
  ares__buf_t  *b = NULL;
  ares_status_t status;

  if (buf == NULL || buf_len == NULL || dnsrec == NULL) {
    return ARES_EFORMERR;
  }

  *buf     = NULL;
  *buf_len = 0;

  b = ares__buf_create();
  if (b == NULL) {
    return ARES_ENOMEM;
  }

  status = ares_dns_write_header(dnsrec, b);
  if (status != ARES_SUCCESS)
    goto done;

  status = ares_dns_write_questions(dnsrec, b);
  if (status != ARES_SUCCESS)
    goto done;

  status = ares_dns_write_rr(dnsrec, ARES_SECTION_ANSWER, b);
  if (status != ARES_SUCCESS)
    goto done;

  status = ares_dns_write_rr(dnsrec, ARES_SECTION_AUTHORITY, b);
  if (status != ARES_SUCCESS)
    goto done;

  status = ares_dns_write_rr(dnsrec, ARES_SECTION_ADDITIONAL, b);
  if (status != ARES_SUCCESS)
    goto done;

done:
  if (status != ARES_SUCCESS) {
    ares__buf_destroy(b);
    return status;
  }

  *buf = ares__buf_finish_bin(b, buf_len);
  return status;
}
