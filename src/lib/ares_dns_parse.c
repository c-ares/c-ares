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


static ares_status_t ares_dns_parse_header(ares__buf_t *buf,
                                           unsigned int flags,
                                           ares_dns_record_t **dnsrec,
                                           unsigned short *qdcount,
                                           unsigned short *ancount,
                                           unsigned short *nscount,
                                           unsigned short *arcount)
{
  ares_status_t     status = ARES_EBADRESP;
  unsigned short    u16;
  unsigned short    id;
  unsigned short    dns_flags = 0;
  ares_dns_opcode_t opcode;
  ares_dns_rcode_t  rcode;

  (void)flags; /* currently unsed */

  if (buf == NULL || dnsrec == NULL || qdcount == NULL || ancount == NULL ||
      nscount == NULL || arcount == NULL) {
    return ARES_EFORMERR;
  }

  *dnsrec = NULL;

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

  /* ID */
  status = ares__buf_fetch_be16(buf, &id);
  if (status != ARES_SUCCESS)
    goto fail;

  /* Flags */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS)
    goto fail;

  /* QR */
  if (u16 & 0x8000) {
    dns_flags |= ARES_FLAG_QR;
  }

  /* OPCODE */
  opcode = (u16 >> 11) & 0xf;

  /* AA */
  if (u16 & 0x400) {
    dns_flags |= ARES_FLAG_AA;
  }

  /* TC */
  if (u16 & 0x200) {
    dns_flags |= ARES_FLAG_TC;
  }

  /* RD */
  if (u16 & 0x100) {
    dns_flags |= ARES_FLAG_RD;
  }

  /* RA */
  if (u16 & 0x80) {
    dns_flags |= ARES_FLAG_RA;
  }

  /* Z -- unused */

  /* RCODE */
  rcode = u16 & 0xf;

  /* QDCOUNT */
  status = ares__buf_fetch_be16(buf, qdcount);
  if (status != ARES_SUCCESS)
    goto fail;

  /* ANCOUNT */
  status = ares__buf_fetch_be16(buf, ancount);
  if (status != ARES_SUCCESS)
    goto fail;

  /* NSCOUNT */
  status = ares__buf_fetch_be16(buf, nscount);
  if (status != ARES_SUCCESS)
    goto fail;

  /* ARCOUNT */
  status = ares__buf_fetch_be16(buf, arcount);
  if (status != ARES_SUCCESS)
    goto fail;

  status = ares_dns_record_create(dnsrec, id, dns_flags, opcode, rcode);
  if (status != ARES_SUCCESS)
    goto fail;

  return ARES_SUCCESS;

fail:
  ares_dns_record_destroy(*dnsrec);
  *dnsrec  = NULL;
  *qdcount = 0;
  *ancount = 0;
  *nscount = 0;
  *arcount = 0;

  return status;
}

static ares_status_t ares_dns_parse_rr_raw_rr(ares__buf_t *buf,
                                              ares_dns_rr_t *rr,
                                              unsigned short raw_type)
{
  size_t         len   = ares__buf_len(buf);
  ares_status_t  status;
  unsigned char *bytes = NULL;

  if (len == 0)
    return ARES_SUCCESS;

  status = ares__buf_fetch_bytes_dup(buf, len, &bytes);
  if (status != ARES_SUCCESS)
    return status;


  /* Can't fail */
  ares_dns_rr_set_u16(rr, ARES_RR_RAW_RR_TYPE, raw_type);
  ares_dns_rr_set_bin_own(rr, ARES_RR_RAW_RR_DATA, bytes, len);
  return ARES_SUCCESS;
}


static ares_status_t ares_dns_parse_rr_data(ares__buf_t        *buf,
                                            ares_dns_rr_t      *rr,
                                            ares_dns_rec_type_t type,
                                            unsigned short      raw_type)
{
  switch (type) {
    case ARES_REC_TYPE_RAW_RR:
      return ares_dns_parse_rr_raw_rr(buf, rr, raw_type);
  }
  return ARES_EFORMERR;
}


static ares_status_t ares_dns_parse_qd(ares__buf_t *buf,
                                       ares_dns_record_t *dnsrec)
{
  char               *name = NULL;
  unsigned short      u16;
  ares_status_t       status;
  ares_dns_rec_type_t type;
  ares_dns_class_t    qclass;
  /* The question section is used to carry the "question" in most queries,
   * i.e., the parameters that define what is being asked.  The section
   * contains QDCOUNT (usually 1) entries, each of the following format:
   *                                 1  1  1  1  1  1
   *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                                               |
   * /                     QNAME                     /
   * /                                               /
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                     QTYPE                     |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                     QCLASS                    |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */

  /* Name */
  status = ares__buf_parse_dns_name(buf, &name, ARES_FALSE);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  /* Type */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS)
    goto done;
  type     = u16;

  /* Class */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS)
    goto done;
  qclass = u16;

  /* Add question */
  status = ares_dns_record_query_add(dnsrec, name, type, qclass);
  if (status != ARES_SUCCESS)
    goto done;

done:
  ares_free(name);
  return status;
}

static ares_status_t ares_dns_parse_rr(ares__buf_t *buf, unsigned int flags,
                                       ares_dns_section_t sect,
                                       ares_dns_record_t *dnsrec,
                                       ares__buf_t *constbuf)
{
  char               *name = NULL;
  unsigned short      u16;
  unsigned short      raw_type;
  ares_status_t       status;
  ares_dns_rec_type_t type;
  ares_dns_class_t    qclass;
  unsigned int        ttl;
  size_t              rdlength;
  size_t              mylen;
  ares_dns_rr_t      *rr = NULL;

  (void)flags; /* currently unused */

  /* All RRs have the same top level format shown below:
   *                                 1  1  1  1  1  1
   *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                                               |
   * /                                               /
   * /                      NAME                     /
   * |                                               |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                      TYPE                     |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                     CLASS                     |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                      TTL                      |
   * |                                               |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                   RDLENGTH                    |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
   * /                     RDATA                     /
   * /                                               /
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */

  /* Name */
  status = ares__buf_parse_dns_name(buf, &name, ARES_FALSE);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  /* Type */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS)
    goto done;
  type     = u16;
  raw_type = u16; /* Only used for raw rr data */

  /* Class */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS)
    goto done;
  qclass = u16;

  /* TTL */
  status = ares__buf_fetch_be32(buf, &ttl);
  if (status != ARES_SUCCESS)
    goto done;

  /* Length */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS)
    goto done;
  rdlength = u16;

  if (!ares_dns_rec_type_isvalid(type, ARES_FALSE)) {
    type = ARES_REC_TYPE_RAW_RR;
  }

  /* Pull into another buffer for safety */
  if (rdlength > ares__buf_len(buf)) {
    status = ARES_EBADRESP;
    goto done;
  }

  ares__buf_const_replace(constbuf, ares__buf_peek(buf, &mylen), rdlength);

  status = ares__buf_consume(buf, rdlength);
  if (status != ARES_SUCCESS)
    goto done;

  /* Add the base rr */
  status = ares_dns_record_rr_add(&rr, dnsrec, sect, name, type, qclass, ttl);
  if (status != ARES_SUCCESS)
    goto done;

  /* Fill in the data for the rr */
  status = ares_dns_parse_rr_data(constbuf, rr, type, raw_type);
  if (status != ARES_SUCCESS)
    goto done;

done:
  ares_free(name);
  return status;
}


ares_status_t ares_dns_parse(ares__buf_t *buf, unsigned int flags,
                             ares_dns_record_t **dnsrec)
{
  ares_status_t  status;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short nscount;
  unsigned short arcount;
  unsigned short i;
  ares__buf_t   *constbuf = NULL;

  if (buf == NULL || dnsrec == NULL) {
    return ARES_EFORMERR;
  }

  /* All communications inside of the domain protocol are carried in a single
   * format called a message.  The top level format of message is divided
   * into 5 sections (some of which are empty in certain cases) shown below:
   *
   * +---------------------+
   * |        Header       |
   * +---------------------+
   * |       Question      | the question for the name server
   * +---------------------+
   * |        Answer       | RRs answering the question
   * +---------------------+
   * |      Authority      | RRs pointing toward an authority
   * +---------------------+
   * |      Additional     | RRs holding additional information
   * +---------------------+
   */

  /* Parse header */
  status = ares_dns_parse_header(buf, flags, dnsrec, &qdcount, &ancount,
                                 &nscount, &arcount);
  if (status != ARES_SUCCESS) {
    goto fail;
  }

  /* Parse questions */
  for (i=0; i<qdcount; i++) {
    status = ares_dns_parse_qd(buf, *dnsrec);
    if (status != ARES_SUCCESS)
      goto fail;
  }

  /* Create dummy buffer, going to use it for future parser helpers to prevent
   * constant alloc/free */
  constbuf = ares__buf_create_const((const unsigned char *)"", 1);
  if (constbuf == NULL) {
    status = ARES_ENOMEM;
    goto fail;
  }

  /* Parse Answers */
  for (i=0; i<ancount; i++) {
    status = ares_dns_parse_rr(buf, flags, ARES_SECTION_ANSWER, *dnsrec,
                               constbuf);
    if (status != ARES_SUCCESS)
      goto fail;
  }

  /* Parse Authority */
  for (i=0; i<nscount; i++) {
    status = ares_dns_parse_rr(buf, flags, ARES_SECTION_AUTHORITY, *dnsrec,
                               constbuf);
    if (status != ARES_SUCCESS)
      goto fail;
  }

  /* Parse Additional */
  for (i=0; i<arcount; i++) {
    status = ares_dns_parse_rr(buf, flags, ARES_SECTION_ADDITIONAL, *dnsrec,
                               constbuf);
    if (status != ARES_SUCCESS)
      goto fail;
  }

  ares__buf_destroy(constbuf);
  return ARES_SUCCESS;

fail:
  ares__buf_destroy(constbuf);
  ares_dns_record_destroy(*dnsrec);
  *dnsrec = NULL;
  return status;
}
