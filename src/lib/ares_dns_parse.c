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

static size_t ares_dns_rr_remaining_len(ares__buf_t *buf, size_t orig_len,
                                        size_t rdlength)
{
  size_t used_len = orig_len - ares__buf_len(buf);
  if (used_len >= rdlength)
    return 0;
  return rdlength - used_len;
}

static ares_status_t ares_dns_parse_rr_a(ares__buf_t *buf,
                                         ares_dns_rr_t *rr, size_t rdlength)
{
  struct in_addr addr;
  ares_status_t  status;

  (void)rdlength; /* Not needed */

  status = ares__buf_fetch_bytes(buf, (unsigned char *)&addr, sizeof(addr));
  if (status != ARES_SUCCESS)
    return status;

  return ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr);
}

static ares_status_t ares_dns_parse_rr_ns(ares__buf_t *buf,
                                          ares_dns_rr_t *rr, size_t rdlength)
{
  char          *name = NULL;
  ares_status_t  status;

  (void)rdlength; /* Not needed */

  status = ares__buf_parse_dns_name(buf, &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_NS_NSDNAME, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }

  return ARES_SUCCESS;
}


static ares_status_t ares_dns_parse_rr_cname(ares__buf_t *buf,
                                             ares_dns_rr_t *rr, size_t rdlength)
{
  char          *name = NULL;
  ares_status_t  status;

  (void)rdlength; /* Not needed */

  status = ares__buf_parse_dns_name(buf, &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_CNAME_CNAME, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_parse_rr_soa(ares__buf_t *buf,
                                           ares_dns_rr_t *rr, size_t rdlength)
{
  char          *name = NULL;
  ares_status_t  status;
  unsigned int   u32;

  (void)rdlength; /* Not needed */

  /* MNAME */
  status = ares__buf_parse_dns_name(buf, &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_SOA_MNAME, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name   = NULL;

  /* RNAME */
  status = ares__buf_parse_dns_name(buf, &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_SOA_RNAME, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name   = NULL;

  /* SERIAL */
  status = ares__buf_fetch_be32(buf, &u32);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u32(rr, ARES_RR_SOA_SERIAL, u32);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* REFRESH */
  status = ares__buf_fetch_be32(buf, &u32);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u32(rr, ARES_RR_SOA_REFRESH, u32);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* RETRY */
  status = ares__buf_fetch_be32(buf, &u32);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u32(rr, ARES_RR_SOA_RETRY, u32);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* EXPIRE */
  status = ares__buf_fetch_be32(buf, &u32);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u32(rr, ARES_RR_SOA_EXPIRE, u32);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* MINIMUM */
  status = ares__buf_fetch_be32(buf, &u32);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u32(rr, ARES_RR_SOA_MINIMUM, u32);
  if (status != ARES_SUCCESS) {
    return status;
  }

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_parse_rr_ptr(ares__buf_t *buf,
                                           ares_dns_rr_t *rr, size_t rdlength)
{
  char          *name = NULL;
  ares_status_t  status;

  (void)rdlength; /* Not needed */

  status = ares__buf_parse_dns_name(buf, &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_PTR_DNAME, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_parse_rr_hinfo(ares__buf_t *buf,
                                           ares_dns_rr_t *rr, size_t rdlength)
{
  char          *name     = NULL;
  ares_status_t  status;
  size_t         orig_len = ares__buf_len(buf);

  (void)rdlength; /* Not needed */

  /* CPU */
  status = ares__buf_parse_dns_str(buf,
                                   ares_dns_rr_remaining_len(buf, orig_len,
                                                             rdlength),
                                   &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_HINFO_CPU, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name = NULL;

  /* OS */
  status = ares__buf_parse_dns_str(buf,
                                   ares_dns_rr_remaining_len(buf, orig_len,
                                                             rdlength),
                                   &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_HINFO_OS, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  return ARES_SUCCESS;
}

static ares_status_t ares_dns_parse_rr_mx(ares__buf_t *buf,
                                          ares_dns_rr_t *rr, size_t rdlength)
{
  char          *name = NULL;
  ares_status_t  status;
  unsigned short u16;

  (void)rdlength; /* Not needed */

  /* PREFERENCE */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u16(rr, ARES_RR_MX_PREFERENCE, u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* EXCHANGE */
  status = ares__buf_parse_dns_name(buf, &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_MX_EXCHANGE, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name   = NULL;

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_parse_rr_txt(ares__buf_t *buf,
                                           ares_dns_rr_t *rr, size_t rdlength)
{
  char          *txt      = NULL;
  ares_status_t  status;

  status = ares__buf_parse_dns_str(buf, rdlength, &txt, ARES_TRUE);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_str_own(rr, ARES_RR_TXT_DATA, txt);
  if (status != ARES_SUCCESS) {
    ares_free(txt);
    return status;
  }

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_parse_rr_aaaa(ares__buf_t *buf,
                                            ares_dns_rr_t *rr, size_t rdlength)
{
  struct ares_in6_addr addr;
  ares_status_t        status;

  (void)rdlength; /* Not needed */

  status = ares__buf_fetch_bytes(buf, (unsigned char *)&addr, sizeof(addr));
  if (status != ARES_SUCCESS)
    return status;

  return ares_dns_rr_set_addr6(rr, ARES_RR_AAAA_ADDR, &addr);
}

static ares_status_t ares_dns_parse_rr_srv(ares__buf_t *buf,
                                           ares_dns_rr_t *rr, size_t rdlength)
{
  char          *name = NULL;
  ares_status_t  status;
  unsigned short u16;

  (void)rdlength; /* Not needed */

  /* PRIORITY */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u16(rr, ARES_RR_SRV_PRIORITY, u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* WEIGHT */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u16(rr, ARES_RR_SRV_WEIGHT, u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* PORT */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u16(rr, ARES_RR_SRV_PORT, u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* TARGET */
  status = ares__buf_parse_dns_name(buf, &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_SRV_TARGET, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name   = NULL;

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_parse_rr_naptr(ares__buf_t *buf,
                                             ares_dns_rr_t *rr, size_t rdlength)
{
  char          *name = NULL;
  ares_status_t  status;
  unsigned short u16;
  size_t         orig_len = ares__buf_len(buf);

  /* ORDER */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u16(rr, ARES_RR_NAPTR_ORDER, u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* PREFERENCE */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u16(rr, ARES_RR_NAPTR_PREFERENCE, u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* FLAGS */
  status = ares__buf_parse_dns_str(buf,
                                   ares_dns_rr_remaining_len(buf, orig_len,
                                                             rdlength),
                                   &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_NAPTR_FLAGS, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name   = NULL;

  /* SERVICES */
  status = ares__buf_parse_dns_str(buf,
                                   ares_dns_rr_remaining_len(buf, orig_len,
                                                             rdlength),
                                   &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_NAPTR_SERVICES, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name   = NULL;

  /* REGEXP */
  status = ares__buf_parse_dns_str(buf,
                                   ares_dns_rr_remaining_len(buf, orig_len,
                                                             rdlength),
                                   &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_SRV_TARGET, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name   = NULL;

  /* REPLACEMENT */
  status = ares__buf_parse_dns_name(buf, &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_SRV_TARGET, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name   = NULL;

  return ARES_SUCCESS;
}


static ares_status_t ares_dns_parse_rr_opt(ares__buf_t *buf,
                                           ares_dns_rr_t *rr,
                                           size_t rdlength,
                                           unsigned short raw_class,
                                           unsigned int raw_ttl)
{
  ares_status_t status;

  (void)rdlength; /* Not needed */

  status = ares_dns_rr_set_u16(rr, ARES_RR_OPT_UDP_SIZE, raw_class);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u8(rr, ARES_RR_OPT_EXT_RCODE,
                              (unsigned char)(raw_ttl >> 24) & 0xFF);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u8(rr, ARES_RR_OPT_VERSION,
                              (unsigned char)(raw_ttl >> 16) & 0xFF);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u16(rr, ARES_RR_OPT_FLAGS,
                               (unsigned short)(raw_ttl & 0xFFFF));
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* XXX: Support additional message here */
  (void)buf;
  return ARES_SUCCESS;
}


static ares_status_t ares_dns_parse_rr_uri(ares__buf_t *buf,
                                           ares_dns_rr_t *rr, size_t rdlength)
{
  char          *name = NULL;
  ares_status_t  status;
  unsigned short u16;
  size_t         orig_len = ares__buf_len(buf);
  size_t         remaining_len;

  /* PRIORITY */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u16(rr, ARES_RR_URI_PRIORITY, u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* WEIGHT */
  status = ares__buf_fetch_be16(buf, &u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u16(rr, ARES_RR_URI_WEIGHT, u16);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* TARGET -- not in string format, rest of buffer, required to be
   * non-zero length */
  remaining_len = ares_dns_rr_remaining_len(buf, orig_len, rdlength);
  if (remaining_len == 0) {
    status = ARES_EBADRESP;
    return status;
  }

  status = ares__buf_fetch_str_dup(buf, remaining_len, &name);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_URI_TARGET, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name   = NULL;

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_parse_rr_caa(ares__buf_t *buf,
                                           ares_dns_rr_t *rr, size_t rdlength)
{
  char          *name = NULL;
  unsigned char *data = NULL;
  size_t         data_len = 0;
  ares_status_t  status;
  unsigned char  critical;
  size_t         orig_len = ares__buf_len(buf);

  /* CRITICAL */
  status = ares__buf_fetch_bytes(buf, &critical, 1);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_rr_set_u8(rr, ARES_RR_CAA_CRITICAL, critical);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* Tag */
  status = ares__buf_parse_dns_str(buf,
                                   ares_dns_rr_remaining_len(buf, orig_len,
                                                             rdlength),
                                   &name, ARES_FALSE);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_str_own(rr, ARES_RR_CAA_TAG, name);
  if (status != ARES_SUCCESS) {
    ares_free(name);
    return status;
  }
  name   = NULL;

  /* Value - binary! */
  data_len = ares_dns_rr_remaining_len(buf, orig_len, rdlength);
  if (data_len == 0) {
    status = ARES_EBADRESP;
    return status;
  }
  status   = ares__buf_fetch_bytes_dup(buf, data_len, &data);
  if (status != ARES_SUCCESS)
    return status;

  status = ares_dns_rr_set_bin_own(rr, ARES_RR_CAA_VALUE, data, data_len);
  if (status != ARES_SUCCESS) {
    ares_free(data);
    return status;
  }
  data   = NULL;

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_parse_rr_raw_rr(ares__buf_t *buf,
                                              ares_dns_rr_t *rr,
                                              size_t rdlength,
                                              unsigned short raw_type)
{
  ares_status_t  status;
  unsigned char *bytes = NULL;

  if (rdlength == 0)
    return ARES_SUCCESS;

  status = ares__buf_fetch_bytes_dup(buf, rdlength, &bytes);
  if (status != ARES_SUCCESS)
    return status;

  /* Can't fail */
  status = ares_dns_rr_set_u16(rr, ARES_RR_RAW_RR_TYPE, raw_type);
  if (status != ARES_SUCCESS) {
    ares_free(bytes);
    return status;
  }

  status = ares_dns_rr_set_bin_own(rr, ARES_RR_RAW_RR_DATA, bytes, rdlength);
  if (status != ARES_SUCCESS) {
    ares_free(bytes);
    return status;
  }

  return ARES_SUCCESS;
}

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


static ares_status_t ares_dns_parse_rr_data(ares__buf_t        *buf,
                                            size_t              rdlength,
                                            ares_dns_rr_t      *rr,
                                            ares_dns_rec_type_t type,
                                            unsigned short      raw_type,
                                            unsigned short      raw_class,
                                            unsigned int        raw_ttl)
{
  switch (type) {
    case ARES_REC_TYPE_A:
      return ares_dns_parse_rr_a(buf, rr, rdlength);
    case ARES_REC_TYPE_NS:
      return ares_dns_parse_rr_ns(buf, rr, rdlength);
    case ARES_REC_TYPE_CNAME:
      return ares_dns_parse_rr_cname(buf, rr, rdlength);
    case ARES_REC_TYPE_SOA:
      return ares_dns_parse_rr_soa(buf, rr, rdlength);
     case ARES_REC_TYPE_PTR:
      return ares_dns_parse_rr_ptr(buf, rr, rdlength);
    case ARES_REC_TYPE_HINFO:
      return ares_dns_parse_rr_hinfo(buf, rr, rdlength);
    case ARES_REC_TYPE_MX:
      return ares_dns_parse_rr_mx(buf, rr, rdlength);
    case ARES_REC_TYPE_TXT:
      return ares_dns_parse_rr_txt(buf, rr, rdlength);
    case ARES_REC_TYPE_AAAA:
      return ares_dns_parse_rr_aaaa(buf, rr, rdlength);
    case ARES_REC_TYPE_SRV:
      return ares_dns_parse_rr_srv(buf, rr, rdlength);
    case ARES_REC_TYPE_NAPTR:
      return ares_dns_parse_rr_naptr(buf, rr, rdlength);
    case ARES_REC_TYPE_ANY:
      return ARES_EBADRESP;
    case ARES_REC_TYPE_OPT:
      return ares_dns_parse_rr_opt(buf, rr, rdlength, raw_class, raw_ttl);
    case ARES_REC_TYPE_URI:
      return ares_dns_parse_rr_uri(buf, rr, rdlength);
    case ARES_REC_TYPE_CAA:
      return ares_dns_parse_rr_caa(buf, rr, rdlength);
    case ARES_REC_TYPE_RAW_RR:
      return ares_dns_parse_rr_raw_rr(buf, rr, rdlength, raw_type);
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
                                       ares_dns_record_t *dnsrec)
{
  char               *name = NULL;
  unsigned short      u16;
  unsigned short      raw_type;
  ares_status_t       status;
  ares_dns_rec_type_t type;
  ares_dns_class_t    qclass;
  unsigned int        ttl;
  size_t              rdlength;
  ares_dns_rr_t      *rr = NULL;
  size_t              remaining_len = 0;
  size_t              processed_len = 0;

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

  /* Add the base rr */
  status = ares_dns_record_rr_add(&rr, dnsrec, sect, name, type,
    type == ARES_REC_TYPE_OPT?ARES_CLASS_IN:qclass,
    type == ARES_REC_TYPE_OPT?0:ttl);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  /* Record the current remaining length in the buffer so we can tell how
   * much was processed */
  remaining_len = ares__buf_len(buf);

  /* Fill in the data for the rr */
  status = ares_dns_parse_rr_data(buf, rdlength, rr, type, raw_type,
                                  (unsigned short)qclass, ttl);
  if (status != ARES_SUCCESS)
    goto done;


  /* Determine how many bytes were processed */
  processed_len = remaining_len - ares__buf_len(buf);

  /* If too many bytes were processed, error! */
  if (processed_len > rdlength) {
    status = ARES_EBADRESP;
    goto done;
  }

  /* If too few bytes were processed, consume the unprocessed data for this
   * record as the parser may not have wanted/needed to use it */
  if (processed_len < rdlength) {
    ares__buf_consume(buf, rdlength - processed_len);
  }


done:
  ares_free(name);
  return status;
}


ares_status_t ares_dns_parse_buf(ares__buf_t *buf, unsigned int flags,
                                 ares_dns_record_t **dnsrec)
{
  ares_status_t  status;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short nscount;
  unsigned short arcount;
  unsigned short i;

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

  /* Must have questions */
  if (qdcount == 0) {
    status = ARES_EBADRESP;
    goto fail;
  }

  /* XXX: this should be controlled by a flag in case we want to allow
   *      multiple questions.  I think mDNS allows this */
  if (qdcount > 1) {
    status = ARES_EBADRESP;
    goto fail;
  }

  /* Parse questions */
  for (i=0; i<qdcount; i++) {
    status = ares_dns_parse_qd(buf, *dnsrec);
    if (status != ARES_SUCCESS)
      goto fail;
  }

  /* Parse Answers */
  for (i=0; i<ancount; i++) {
    status = ares_dns_parse_rr(buf, flags, ARES_SECTION_ANSWER, *dnsrec);
    if (status != ARES_SUCCESS)
      goto fail;
  }

  /* Parse Authority */
  for (i=0; i<nscount; i++) {
    status = ares_dns_parse_rr(buf, flags, ARES_SECTION_AUTHORITY, *dnsrec);
    if (status != ARES_SUCCESS)
      goto fail;
  }

  /* Parse Additional */
  for (i=0; i<arcount; i++) {
    status = ares_dns_parse_rr(buf, flags, ARES_SECTION_ADDITIONAL, *dnsrec);
    if (status != ARES_SUCCESS)
      goto fail;
  }

  return ARES_SUCCESS;

fail:
  ares_dns_record_destroy(*dnsrec);
  *dnsrec = NULL;
  return status;
}

ares_status_t ares_dns_parse(const unsigned char *buf, size_t buf_len,
                             unsigned int flags, ares_dns_record_t **dnsrec)
{
  ares__buf_t  *parser = NULL;
  ares_status_t status;

   if (buf == NULL || buf_len == 0 || dnsrec == NULL) {
    return ARES_EFORMERR;
  }

  parser = ares__buf_create_const(buf, buf_len);
  if (parser == NULL)
    return ARES_ENOMEM;

  status = ares_dns_parse_buf(parser, flags, dnsrec);
  ares__buf_destroy(parser);

  return status;
}
