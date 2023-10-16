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
#ifndef __ARES__DNS_RECORD_H
#define __ARES__DNS_RECORD_H

typedef struct {
  char          *name;
  unsigned short qtype;
  unsigned short qclass;
} ares__dns_qd_t;

typedef struct {
  char *cname;
} ares__dns_cname_t;

typedef struct {
  char *cpu;
  char *os;
} ares__dns_hinfo_t;

typedef struct {
  unsigned short preference;
  char          *exchange;
} ares__dns_mx_t;

typedef struct {
  char *nsdname;
} ares__dns_ns_t;

typedef struct {
  char *ptrdname;
} ares__dns_ptr_t;

typedef struct {
  char        *mname;
  char        *rname;
  unsigned int serial;
  unsigned int refresh;
  unsigned int retry;
  unsigned int expire;
  unsigned int minimum;
} ares__dns_soa_t;

typedef struct {
  struct in_addr address;
} ares__dns_a_t;

typedef struct {
  struct ares_in6_addr address;
} ares__dns_aaaa_t;

typedef struct {
  unsigned short priority;
  unsigned short weight;
  unsigned short port;
  char          *target;
} ares__dns_srv_t;

typedef struct {
  unsigned short priority;
  unsigned short weight;
  char          *target;
} ares__dns_uri_t;

typedef struct {
  unsigned char  critical;
  unsigned char *tag;
  unsigned char *value;
} ares__dns_caa_t;

typedef struct {
  unsigned short  order;
  unsigned short  preference;
  char           *flags;
  char           *services;
  char           *regexp;
  char           *replacement;
} ares__dns_naptr_t;

typedef struct {
  unsigned char  *rdata;
  unsigned short  rdlength;
} ares__dns_raw_rr_t;

/*! DNS RR data structure */
typedef struct {
  char          *name;
  unsigned short type;
  unsigned short rclass;
  unsigned int   ttl;

  union {
    ares__dns_cname_t  cname;
    ares__dns_hinfo_t  hinfo;
    ares__dns_mx_t     mx;
    ares__dns_ns_t     ns;
    ares__dns_ptr_t    ptr;
    ares__dns_soa_t    soa;
    ares__dns_a_t      a;
    ares__dns_aaaa_t   aaaa;
    ares__dns_srv_t    srv;
    ares__dns_uri_t    uri;
    ares__dns_caa_t    caa;
    ares__dns_naptr_t  naptr;
    ares__dns_raw_rr_t raw_rr;
  } r;
} ares__dns_rr_t;


/*! DNS data structure */
typedef struct {
  unsigned short  id;
  unsigned short  qr     : 1;
  unsigned short  opcode : 4;
  unsigned short  aa     : 1;
  unsigned short  tc     : 1;
  unsigned short  rd     : 1;
  unsigned short  ra     : 1;
  unsigned short  z      : 3;
  unsigned short  rcode  : 4;

  ares__dns_qd_t *qd;
  unsigned short  qdcount;

  ares__dns_rr_t *an;
  unsigned short  ancount;

  ares__dns_rr_t *ns;
  unsigned short  nscount;

  ares__dns_rr_t *ar;
  unsigned short  arcount;
} ares__dns_record_t;


#endif /* __ARES__DNS_RECORD_H */
