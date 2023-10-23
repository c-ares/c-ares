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

unsigned short ares_dns_record_get_id(ares_dns_record_t *dnsrec)
{
  if (dnsrec == NULL)
    return 0;
  return dnsrec->id;
}

unsigned short ares_dns_record_get_flags(ares_dns_record_t *dnsrec)
{
  if (dnsrec == NULL)
    return 0;
  return dnsrec->flags;
}

ares_dns_opcode_t ares_dns_record_get_opcode(ares_dns_record_t *dnsrec)
{
  if (dnsrec == NULL)
    return 0;
  return dnsrec->opcode;
}

ares_dns_rcode_t ares_dns_record_get_rcode(ares_dns_record_t *dnsrec)
{
  if (dnsrec == NULL)
    return 0;
  return dnsrec->rcode;
}

static void ares__dns_rr_free(ares_dns_rr_t *rr)
{
  switch (rr->type) {
    case ARES_REC_TYPE_A:
    case ARES_REC_TYPE_AAAA:
    case ARES_REC_TYPE_ANY:
      /* Nothing to free */
      break;

    case ARES_REC_TYPE_NS:
      ares_free(rr->r.ns.nsdname);
      break;

    case ARES_REC_TYPE_CNAME:
      ares_free(rr->r.cname.cname);
      break;

    case ARES_REC_TYPE_SOA:
      ares_free(rr->r.soa.mname);
      ares_free(rr->r.soa.rname);
      break;

    case ARES_REC_TYPE_PTR:
      ares_free(rr->r.ptr.dname);
      break;

    case ARES_REC_TYPE_HINFO:
      ares_free(rr->r.hinfo.cpu);
      ares_free(rr->r.hinfo.os);
      break;

    case ARES_REC_TYPE_MX:
      ares_free(rr->r.mx.exchange);
      break;

    case ARES_REC_TYPE_TXT:
      ares_free(rr->r.txt.data);
      break;

    case ARES_REC_TYPE_SRV:
      ares_free(rr->r.srv.target);
      break;

    case ARES_REC_TYPE_NAPTR:
      ares_free(rr->r.naptr.flags);
      ares_free(rr->r.naptr.services);
      ares_free(rr->r.naptr.regexp);
      ares_free(rr->r.naptr.replacement);
      break;

    case ARES_REC_TYPE_OPT:
      /* Once we support the attribute/values, we need to free here */
      break;
#if 0
    case ARES_REC_TYPE_TLSA:
      /* Once this record type is supported, need to free here
       * ares_free(rr->r.tlsa.);
       */
      break;

    case ARES_REC_TYPE_SVBC:
      /* Once this record type is supported, need to free here
       * ares_free(rr->r.svbc.);
       */
      break;

    case ARES_REC_TYPE_HTTPS:
      /* Once this record type is supported, need to free here
       * ares_free(rr->r.https.);
       */
      break;
#endif
    case ARES_REC_TYPE_URI:
      ares_free(rr->r.uri.target);
      break;

    case ARES_REC_TYPE_CAA:
      ares_free(rr->r.caa.tag);
      ares_free(rr->r.caa.value);
      break;

    case ARES_REC_TYPE_RAW_RR:
      ares_free(rr->r.raw_rr.data);
      break;
  }
}

void ares_dns_record_destroy(ares_dns_record_t *dnsrec)
{
  size_t i;

  if (dnsrec == NULL)
    return;

  /* Free questions */
  for (i=0; i<dnsrec->qdcount; i++) {
    ares_free(dnsrec->qd[i].name);
  }
  ares_free(dnsrec->qd);

  /* Free answers */
  for (i=0; i<dnsrec->ancount; i++) {
    ares__dns_rr_free(&dnsrec->an[i]);
  }
  ares_free(dnsrec->an);

  /* Free authority */
  for (i=0; i<dnsrec->nscount; i++) {
    ares__dns_rr_free(&dnsrec->ns[i]);
  }
  ares_free(dnsrec->ns);

  /* Free additional */
  for (i=0; i<dnsrec->arcount; i++) {
    ares__dns_rr_free(&dnsrec->ar[i]);
  }
  ares_free(dnsrec->ar);

  ares_free(dnsrec);
}

size_t ares_dns_record_query_cnt(ares_dns_record_t *dnsrec)
{
  if (dnsrec == NULL)
    return 0;
  return dnsrec->qdcount;
}


ares_status_t ares_dns_record_query_add(ares_dns_record_t *dnsrec, char *name,
                                        ares_dns_rec_type_t qtype,
                                        ares_dns_class_t qclass)
{
  ares_dns_qd_t *temp = NULL;
  size_t         idx;

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
  return ARES_SUCCESS;
}


ares_status_t ares_dns_record_query_get(ares_dns_record_t *dnsrec, size_t idx,
                                        const char ** name,
                                        ares_dns_rec_type_t *qtype,
                                        ares_dns_class_t *qclass)
{
  if (dnsrec == NULL || idx >= dnsrec->qdcount)
    return ARES_EFORMERR;

  if (name != NULL)
    *name = dnsrec->qd[idx].name;

  if (qtype != NULL)
    *qtype = dnsrec->qd[idx].qtype;

  if (qclass != NULL)
    *qclass = dnsrec->qd[idx].qclass;

  return ARES_SUCCESS;
}

size_t ares_dns_record_rr_cnt(ares_dns_record_t *dnsrec,
                              ares_dns_section_t sect)
{
  if (dnsrec == NULL || !ares_dns_section_isvalid(sect)) {
    return 0;
  }

  switch (sect) {
    case ARES_SECTION_ANSWER:
      return dnsrec->ancount;
    case ARES_SECTION_AUTHORITY:
      return dnsrec->nscount;
    case ARES_SECTION_ADDITIONAL:
      return dnsrec->arcount;
  }

  return 0;
}

ares_status_t ares_dns_record_rr_add(ares_dns_rr_t **rr_out,
                                     ares_dns_record_t *dnsrec,
                                     ares_dns_section_t sect, char *name,
                                     ares_dns_rec_type_t type,
                                     ares_dns_class_t rclass,
                                     unsigned int ttl)
{
  ares_dns_rr_t  **rr_ptr = NULL;
  ares_dns_rr_t   *rr     = NULL;
  size_t          *rr_len = NULL;
  ares_dns_rr_t   *temp   = NULL;
  size_t           idx;

  if (dnsrec == NULL || name == NULL || rr_out == NULL ||
      !ares_dns_section_isvalid(sect)                  ||
      !ares_dns_rec_type_isvalid(type, ARES_FALSE)     ||
      !ares_dns_class_isvalid(rclass, ARES_FALSE)) {
    return ARES_EFORMERR;
  }

  *rr_out = NULL;

  switch (sect) {
    case ARES_SECTION_ANSWER:
      rr_ptr = &dnsrec->an;
      rr_len = &dnsrec->ancount;
      break;
    case ARES_SECTION_AUTHORITY:
      rr_ptr = &dnsrec->ns;
      rr_len = &dnsrec->nscount;
      break;
    case ARES_SECTION_ADDITIONAL:
      rr_ptr = &dnsrec->ar;
      rr_len = &dnsrec->arcount;
      break;
  }

  temp = ares_realloc(*rr_ptr, sizeof(*temp) * (*rr_len + 1));
  if (temp == NULL) {
    return ARES_ENOMEM;
  }

  *rr_ptr = temp;
  idx     = *rr_len;
  rr      = &(*rr_ptr)[idx];

  memset(rr, 0, sizeof(*rr));

  rr->name   = ares_strdup(name);
  if (rr->name == NULL) {
    /* No need to clean up anything */
    return ARES_ENOMEM;
  }

  rr->type   = type;
  rr->rclass = rclass;
  rr->ttl    = ttl;
  (*rr_len)++;

  *rr_out = rr;

  return ARES_SUCCESS;
}


ares_dns_rr_t *ares_dns_record_rr_get(ares_dns_record_t *dnsrec,
                                      ares_dns_section_t sect,
                                      size_t idx)
{
  ares_dns_rr_t  *rr_ptr = NULL;
  size_t          rr_len = 0;

  if (dnsrec == NULL || !ares_dns_section_isvalid(sect)) {
    return NULL;
  }

  switch (sect) {
    case ARES_SECTION_ANSWER:
      rr_ptr = dnsrec->an;
      rr_len = dnsrec->ancount;
      break;
    case ARES_SECTION_AUTHORITY:
      rr_ptr = dnsrec->ns;
      rr_len = dnsrec->nscount;
      break;
    case ARES_SECTION_ADDITIONAL:
      rr_ptr = dnsrec->ar;
      rr_len = dnsrec->arcount;
      break;
  }

  if (idx >= rr_len) {
    return NULL;
  }

  return &rr_ptr[idx];
}


const char *ares_dns_rr_get_name(ares_dns_rr_t *rr)
{
  if (rr == NULL)
    return NULL;
  return rr->name;
}

ares_dns_rec_type_t ares_dns_rr_get_type(ares_dns_rr_t *rr)
{
  if (rr == NULL)
    return 0;
  return rr->type;
}


ares_dns_class_t ares_dns_rr_get_class(ares_dns_rr_t *rr)
{
  if (rr == NULL)
    return 0;
  return rr->rclass;
}

unsigned int ares_dns_rr_get_ttl(ares_dns_rr_t *rr)
{
  if (rr == NULL)
    return 0;
  return rr->ttl;
}

static void *ares_dns_rr_data_ptr(ares_dns_rr_t *dns_rr,
                                 ares_dns_rr_key_t key, size_t **lenptr)
{
  if (dns_rr == NULL || dns_rr->type != ares_dns_rr_key_to_rec_type(key)) {
    return NULL;
  }

  switch (key) {
    case ARES_RR_A_ADDR:
      return &dns_rr->r.a.addr;

    case ARES_RR_NS_NSDNAME:
      return &dns_rr->r.ns.nsdname;

    case ARES_RR_CNAME_CNAME:
      return &dns_rr->r.cname.cname;

    case ARES_RR_SOA_MNAME:
      return &dns_rr->r.soa.mname;

    case ARES_RR_SOA_RNAME:
      return &dns_rr->r.soa.rname;

    case ARES_RR_SOA_SERIAL:
      return &dns_rr->r.soa.serial;

    case ARES_RR_SOA_REFRESH:
      return &dns_rr->r.soa.refresh;

    case ARES_RR_SOA_RETRY:
      return &dns_rr->r.soa.retry;

    case ARES_RR_SOA_EXPIRE:
      return &dns_rr->r.soa.expire;

    case ARES_RR_SOA_MINIMUM:
      return &dns_rr->r.soa.minimum;

    case ARES_RR_PTR_DNAME:
      return &dns_rr->r.ptr.dname;

    case ARES_RR_AAAA_ADDR:
      return &dns_rr->r.aaaa.addr;

    case ARES_RR_HINFO_CPU:
      return &dns_rr->r.hinfo.cpu;

    case ARES_RR_HINFO_OS:
      return &dns_rr->r.hinfo.os;

    case ARES_RR_MX_PREFERENCE:
      return &dns_rr->r.mx.preference;

    case ARES_RR_MX_EXCHANGE:
      return &dns_rr->r.mx.exchange;

    case ARES_RR_TXT_DATA:
      if (lenptr == NULL)
        return NULL;
      *lenptr = &dns_rr->r.txt.data_len;
      return &dns_rr->r.txt.data;

    case ARES_RR_SRV_PRIORITY:
      return &dns_rr->r.srv.priority;

    case ARES_RR_SRV_WEIGHT:
      return &dns_rr->r.srv.weight;

    case ARES_RR_SRV_PORT:
      return &dns_rr->r.srv.port;

    case ARES_RR_SRV_TARGET:
      return &dns_rr->r.srv.target;

    case ARES_RR_NAPTR_ORDER:
      return &dns_rr->r.naptr.order;

    case ARES_RR_NAPTR_PREFERENCE:
      return &dns_rr->r.naptr.preference;

    case ARES_RR_NAPTR_FLAGS:
      return &dns_rr->r.naptr.flags;

    case ARES_RR_NAPTR_SERVICES:
      return &dns_rr->r.naptr.services;

    case ARES_RR_NAPTR_REGEXP:
      return &dns_rr->r.naptr.regexp;

    case ARES_RR_NAPTR_REPLACEMENT:
      return &dns_rr->r.naptr.replacement;

    case ARES_RR_OPT_UDP_SIZE:
      return &dns_rr->r.opt.udp_size;

    case ARES_RR_OPT_EXT_RCODE:
      return &dns_rr->r.opt.ext_rcode;

    case ARES_RR_OPT_VERSION:
      return &dns_rr->r.opt.version;

    case ARES_RR_OPT_FLAGS:
      return &dns_rr->r.opt.flags;

    case ARES_RR_URI_PRIORITY:
      return &dns_rr->r.uri.priority;

    case ARES_RR_URI_WEIGHT:
      return &dns_rr->r.uri.weight;

    case ARES_RR_URI_TARGET:
      return &dns_rr->r.uri.target;

    case ARES_RR_CAA_CRITICAL:
      return &dns_rr->r.caa.critical;

    case ARES_RR_CAA_TAG:
      return &dns_rr->r.caa.tag;

    case ARES_RR_CAA_VALUE:
      if (lenptr == NULL)
        return NULL;
      *lenptr = &dns_rr->r.caa.value_len;
      return &dns_rr->r.caa.value;

    case ARES_RR_RAW_RR_TYPE:
      return &dns_rr->r.raw_rr.type;

    case ARES_RR_RAW_RR_DATA:
      if (lenptr == NULL)
        return NULL;
      *lenptr = &dns_rr->r.raw_rr.length;
      return &dns_rr->r.raw_rr.data;
  }

  return NULL;
}

struct in_addr *ares_dns_rr_get_addr(ares_dns_rr_t *dns_rr,
                                     ares_dns_rr_key_t key)
{
  struct in_addr *addr;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_INADDR) {
    return NULL;
  }

  addr = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (addr == NULL) {
    return NULL;
  }

  return addr;
}

struct ares_in6_addr *ares_dns_rr_get_addr6(ares_dns_rr_t *dns_rr,
                                            ares_dns_rr_key_t key)
{
  struct ares_in6_addr *addr;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_INADDR6) {
    return NULL;
  }

  addr = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (addr == NULL) {
    return NULL;
  }

  return addr;
}

unsigned char ares_dns_rr_get_u8(ares_dns_rr_t *dns_rr,
                                 ares_dns_rr_key_t key)
{
  unsigned char *u8;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_U8) {
    return 0;
  }

  u8 = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (u8 == NULL) {
    return 0;
  }

  return *u8;
}


unsigned short ares_dns_rr_get_u16(ares_dns_rr_t *dns_rr,
                                   ares_dns_rr_key_t key)
{
 unsigned short *u16;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_U16) {
    return 0;
  }

  u16 = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (u16 == NULL) {
    return 0;
  }

  return *u16;
}


unsigned int ares_dns_rr_get_u32(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key)
{
  unsigned int *u32;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_U32) {
    return 0;
  }

  u32 = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (u32 == NULL) {
    return 0;
  }

  return *u32;
}

const unsigned char *ares_dns_rr_get_bin(ares_dns_rr_t *dns_rr,
                                         ares_dns_rr_key_t key, size_t *len)
{
  unsigned char **bin     = NULL;
  size_t         *bin_len = NULL;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_BIN) {
    return NULL;
  }

  bin = ares_dns_rr_data_ptr(dns_rr, key, &bin_len);
  if (bin == NULL) {
    return 0;
  }

  if (len == NULL)
    return NULL;

  *len = *bin_len;

  return *bin;
}

const char *ares_dns_rr_get_str(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key)
{
  char **str;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_STR) {
    return NULL;
  }

  str = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (str == NULL) {
    return NULL;
  }

  return *str;
}

ares_status_t ares_dns_rr_set_addr(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                   struct in_addr *addr)
{
  struct in_addr *a;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_INADDR || addr == NULL) {
    return ARES_EFORMERR;
  }

  a = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (a == NULL) {
    return ARES_EFORMERR;
  }

  memcpy(a, addr, sizeof(*addr));
  return ARES_SUCCESS;
}


ares_status_t ares_dns_rr_set_addr6(ares_dns_rr_t *dns_rr,
                                    ares_dns_rr_key_t key,
                                    struct ares_in6_addr *addr)
{
  struct ares_in6_addr *a;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_INADDR6 || addr == NULL) {
    return ARES_EFORMERR;
  }

  a = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (a == NULL) {
    return ARES_EFORMERR;
  }

  memcpy(a, addr, sizeof(*addr));
  return ARES_SUCCESS;
}


ares_status_t ares_dns_rr_set_u8(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                 unsigned char val)
{
  unsigned char *u8;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_U8) {
    return ARES_EFORMERR;
  }

  u8 = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (u8 == NULL) {
    return ARES_EFORMERR;
  }

  *u8 = val;
  return ARES_SUCCESS;
}


ares_status_t ares_dns_rr_set_u16(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                  unsigned short val)
{
  unsigned short *u16;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_U16) {
    return ARES_EFORMERR;
  }

  u16 = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (u16 == NULL) {
    return ARES_EFORMERR;
  }

  *u16 = val;
  return ARES_SUCCESS;
}

ares_status_t ares_dns_rr_set_u32(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                  unsigned int val)
{
  unsigned int *u32;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_U32) {
    return ARES_EFORMERR;
  }

  u32 = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (u32 == NULL) {
    return ARES_EFORMERR;
  }

  *u32 = val;
  return ARES_SUCCESS;
}


ares_status_t ares_dns_rr_set_bin_own(ares_dns_rr_t *dns_rr,
                                      ares_dns_rr_key_t key,
                                      unsigned char *val, size_t len)
{
  unsigned char **bin;
  size_t         *bin_len = NULL;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_BIN) {
    return ARES_EFORMERR;
  }

  bin = ares_dns_rr_data_ptr(dns_rr, key, &bin_len);
  if (bin == NULL) {
    return ARES_EFORMERR;
  }

  if (*bin) {
    ares_free(*bin);
  }
  *bin     = val;
  *bin_len = len;

  return ARES_SUCCESS;
}

ares_status_t ares_dns_rr_set_bin(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                      const unsigned char *val, size_t len)
{
  ares_status_t  status;
  unsigned char *temp = ares_malloc(len);

  if (temp == NULL)
    return ARES_ENOMEM;

  memcpy(temp, val, len);

  status = ares_dns_rr_set_bin_own(dns_rr, key, temp, len);
  if (status != ARES_SUCCESS)
    ares_free(temp);

  return status;
}

ares_status_t ares_dns_rr_set_str_own(ares_dns_rr_t *dns_rr,
                                      ares_dns_rr_key_t key, char *val)
{
  char **str;

  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_STR) {
    return ARES_EFORMERR;
  }

  str = ares_dns_rr_data_ptr(dns_rr, key, NULL);
  if (str == NULL) {
    return ARES_EFORMERR;
  }

  if (*str) {
    ares_free(*str);
  }
  *str = val;

  return ARES_SUCCESS;
}


ares_status_t ares_dns_rr_set_str(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                  const char *val)
{
  ares_status_t status;
  char         *temp = NULL;

  if (val != NULL) {
    temp = ares_strdup(val);
    if (temp == NULL) {
      return ARES_ENOMEM;
    }
  }

  status = ares_dns_rr_set_str_own(dns_rr, key, temp);
  if (status != ARES_SUCCESS)
    ares_free(temp);

  return status;
}
