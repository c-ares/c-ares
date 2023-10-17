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

static ares_bool_t ares_dns_opcode_isvalid(ares_dns_opcode_t opcode)
{
  switch (opcode) {
    case ARES_OPCODE_QUERY:
    case ARES_OPCODE_IQUERY:
    case ARES_OPCODE_STATUS:
    case ARES_OPCODE_NOTIFY:
    case ARES_OPCODE_UPDATE:
      return ARES_TRUE;
  }
  return ARES_FALSE;
}

static ares_bool_t ares_dns_rcode_isvalid(ares_dns_rcode_t rcode)
{
  switch (rcode) {
    case ARES_RCODE_NOERROR:
    case ARES_RCODE_FORMAT_ERROR:
    case ARES_RCODE_SERVER_FAILURE:
    case ARES_RCODE_NAME_ERROR:
    case ARES_RCODE_NOT_IMPLEMENTED:
    case ARES_RCODE_REFUSED:
      return ARES_TRUE;
  }
  return ARES_FALSE;
}

static ares_bool_t ares_dns_flags_arevalid(unsigned short flags)
{
  unsigned short allflags = ARES_FLAG_QR|ARES_FLAG_AA|ARES_FLAG_TC|
                            ARES_FLAG_RD|ARES_FLAG_RA;

  if (flags & ~(allflags))
    return ARES_FALSE;

  return ARES_TRUE;
}


ares_status_t ares_dns_record_create(ares_dns_record_t **dnsrec,
                                     unsigned short id, unsigned short flags,
                                     ares_dns_opcode_t opcode,
                                     ares_dns_rcode_t rcode)
{
  if (dnsrec == NULL)
    return ARES_EFORMERR;

  *dnsrec = NULL;

  if (!ares_dns_opcode_isvalid(opcode) || !ares_dns_rcode_isvalid(rcode) ||
      !ares_dns_flags_arevalid(flags)) {
    return ARES_EFORMERR;
  }

  *dnsrec = ares_malloc(sizeof(**dnsrec));
  if (*dnsrec == NULL)
    return ARES_ENOMEM;

  memset(*dnsrec, 0, sizeof(**dnsrec));

  (*dnsrec)->id     = id;
  (*dnsrec)->flags  = flags;
  (*dnsrec)->opcode = opcode;
  (*dnsrec)->rcode  = rcode;
  return ARES_SUCCESS;
}

static ares_bool_t ares_dns_rec_type_isvalid(ares_dns_rec_type_t type,
                                             ares_bool_t is_query)
{
  switch (type) {
    case ARES_REC_TYPE_A:
    case ARES_REC_TYPE_NS:
    case ARES_REC_TYPE_CNAME:
    case ARES_REC_TYPE_SOA:
    case ARES_REC_TYPE_PTR:
    case ARES_REC_TYPE_HINFO:
    case ARES_REC_TYPE_MX:
    case ARES_REC_TYPE_TXT:
    case ARES_REC_TYPE_AAAA:
    case ARES_REC_TYPE_SRV:
    case ARES_REC_TYPE_NAPTR:
    case ARES_REC_TYPE_OPT:
    case ARES_REC_TYPE_TLSA:
    case ARES_REC_TYPE_SVBC:
    case ARES_REC_TYPE_HTTPS:
    case ARES_REC_TYPE_ANY:
    case ARES_REC_TYPE_URI:
    case ARES_REC_TYPE_CAA:
      return ARES_TRUE;
    default:
      break;
  }
  return is_query?ARES_FALSE:ARES_TRUE;
}

static ares_bool_t ares_dns_rec_type_isvalid(ares_dns_class_t qclass,
                                             ares_bool_t is_query)
{
  switch (qclass) {
    case ARES_CLASS_IN:
    case ARES_CLASS_CHAOS:
    case ARES_CLASS_HESOID:
      return ARES_TRUE;
    case ARES_CLASS_ANY:
      return is_query?ARES_TRUE:ARES_FALSE;
  }
  return ARES_FALSE;
}

ares_status_t ares_dns_record_query_add(ares_dns_record_t *dnsrec, char *name,
                                        ares_dns_rec_type_t qtype,
                                        ares_dns_class_t qclass)
{
  ares__dns_qd_t *temp = NULL;
  size_t          idx;

  if (dnsrec == NULL || name == NULL ||
      !ares_dns_rec_type_isvalid(qtype, ARES_TRUE) ||
      !ares_dns_class_isvalid(qclass, ARES_TRUE)) {
    return ARES_EFORMERR;
  }

  temp = ares_realloc(dnsrec->qd, sizeof(*temp) * (dnsrec->qdcount + 1));
  if (temp == NULL) {
    return ARES_ENOMEM;
  }

  dnsrec->qd = temp;
  idx        = dnsrec->qdcount;
  memset(&dnsrec->qd[idx], 0, sizeof(*dnsrec->qd));

  dnsrec->qd[idx].name   = ares_strdup(name);
  if (dnsrec->qd[idx].name == NULL) {
    /* No need to clean up anything */
    return ARES_ENOMEM;
  }

  dnsrec->qd[idx].qtype  = qtype;
  dnsrec->qd[idx].qclass = qclass;
  dnsrec->qdcount++;
}

