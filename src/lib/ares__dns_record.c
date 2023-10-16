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
#include "ares__dns_record.h"
#include <limits.h>
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

/*! Parse a DNS header from the buffer data stream.
 *
 *  \param[in]  buf         Initialized buffer object
 *  \param[out] header      Pointer to DNS header structure to be filled in
 *  \return ARES_SUCCESS or one of the c-ares error codes
 */
int ares__buf_fetch_dnsheader(ares__buf_t *buf, ares__dns_header_t *header);


int ares__buf_fetch_dnsheader(ares__buf_t *buf, ares__dns_header_t *header)
{
  unsigned char flag   = 0;
  int           status = ARES_EBADRESP;

  if (buf == NULL || header == NULL) {
    status = ARES_EFORMERR; /* No really good error code for misuse */
    goto fail;
  }

/*
 *  RFC 1035 4.1.1. Header section format
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      ID                       |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    QDCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ANCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    NSCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ARCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

  memset(header, 0, sizeof(*header));

  /* ID */
  status = ares__buf_fetch_be16(buf, &header->id);
  if (status != ARES_SUCCESS)
    goto fail;

  /* Flags byte 1 */
  status = ares__buf_fetch_bytes(buf, &flag, 1);
  if (status != ARES_SUCCESS)
    goto fail;

  /* QR */
  header->qr = (flag >> 7) & 0x1;

  /* OPCODE */
  header->opcode = (flag >> 3) & 0xf;

  /* AA */
  header->aa = (flag >> 2) & 0x1;

  /* TC */
  header->tc = (flag >> 1) & 0x1;

  /* RD */
  header->rd = flag & 0x1;

  /* Flags byte 2 */
  status = ares__buf_fetch_bytes(buf, &flag, 1);
  if (status != ARES_SUCCESS)
    goto fail;

  /* RA */
  header->ra = (flag >> 7) & 0x1;

  /* Z */
  header->z = (flag >> 4) & 0x7;

  /* RCODE */
  header->rcode = flag & 0xf;

  /* QDCOUNT */
  status = ares__buf_fetch_be16(buf, &header->qdcount);
  if (status != ARES_SUCCESS)
    goto fail;

  /* ANCOUNT */
  status = ares__buf_fetch_be16(buf, &header->ancount);
  if (status != ARES_SUCCESS)
    goto fail;

  /* NSCOUNT */
  status = ares__buf_fetch_be16(buf, &header->nscount);
  if (status != ARES_SUCCESS)
    goto fail;

  /* ARCOUNT */
  status = ares__buf_fetch_be16(buf, &header->arcount);
  if (status != ARES_SUCCESS)
    goto fail;

  return ARES_SUCCESS;

fail:
  if (header != NULL)
    memset(header, 0, sizeof(*header));
  return status;
}
