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


/* ----- LIKELY MAKE THESE PUBLIC ----- */

/*! DNS Record types handled by c-ares.  Some record types may only be valid
 *  on requests (e.g. ARES_REC_TYPE_ANY), and some may only be valid on
 *  responses (e.g. ARES_REC_TYPE_OPT) */
typedef enum {
  ARES_REC_TYPE_A        = 1,     /*!< Host address. */
  ARES_REC_TYPE_NS       = 2,     /*!< Authoritative server. */
  ARES_REC_TYPE_CNAME    = 5,     /*!< Canonical name. */
  ARES_REC_TYPE_SOA      = 6,     /*!< Start of authority zone. */
  ARES_REC_TYPE_PTR      = 12,    /*!< Domain name pointer. */
  ARES_REC_TYPE_HINFO    = 13,    /*!< Host information. */
  ARES_REC_TYPE_MX       = 15,    /*!< Mail routing information. */
  ARES_REC_TYPE_TXT      = 16,    /*!< Text strings. */
  ARES_REC_TYPE_AAAA     = 28,    /*!< Ip6 Address. */
  ARES_REC_TYPE_SRV      = 33,    /*!< Server Selection. */
  ARES_REC_TYPE_NAPTR    = 35,    /*!< Naming Authority Pointer */
  ARES_REC_TYPE_OPT      = 41,    /*!< EDNS0 option (meta-RR) */
  ARES_REC_TYPE_TLSA     = 52,    /*!< DNS-Based Authentication of Named
                                   *   Entities (DANE) Transport Layer Security
                                   *   (TLS) Protocol: TLSA */
  ARES_REC_TYPE_SVBC     = 64,    /*!< General Purpose Service Binding */
  ARES_REC_TYPE_HTTPS    = 65,    /*!< Service Binding type for use with HTTP */
  ARES_REC_TYPE_ANY      = 255,   /*!< Wildcard match.  Not response RR. */
  ARES_REC_TYPE_URI      = 256,   /*!< Uniform Resource Identifier (RFC7553) */
  ARES_REC_TYPE_CAA      = 257,   /*!< Certification Authority Authorization. */
  ARES_REC_TYPE_RAW_RR   = 65536  /*!< Used as an indicator that the RR record
                                   *   is not parsed, but provided in wire
                                   *   format */
} ares_rec_type_t;


/*! DNS Classes for requests and responses.  */
typedef enum  {
  ARES_CLASS_IN      = 1,  /*<! Internet */
  ARES_CLASS_CHAOS   = 3,  /*<! CHAOS */
  ARES_CLASS_HESOID  = 4,  /*<! Hesoid [Dyer 87] */
  ARES_CLASS_ANY     = 255 /*<! Any class (requests only) */
} ares_class_t;

/*! Opaque data type representing a DNS RR (Resource Record) */
struct ares_dns_rr;

/*! Typedef for opaque data type representing a DNS RR (Resource Record) */
typedef struct ares_dns_rr ares_dns_rr_t;

/*! Opaque data type representing a DNS Packet */
struct ares_dns_record;

/*! Typedef for opaque data type representing a DNS Packet */
typedef struct ares_dns_record ares_dns_record_t;



/* ---- PRIVATE BELOW ----- */


typedef struct {
  char           *name;
  ares_rec_type_t qtype;
  ares_class_t    qclass;
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

/*! Raw, unparsed RR data */
typedef struct {
  unsigned short  type;     /*!< Not ares_rec_type_t because it likely isn't one
                             *   of those values since it wasn't parsed */
  unsigned char  *rdata;    /*!< Raw RR data */
  unsigned short  rdlength; /*!< Length of raw RR data */
} ares__dns_raw_rr_t;


/*! DNS RR data structure */
struct ares_dns_rr {
  char           *name;
  ares_rec_type_t type;
  ares_class_t    rclass;
  unsigned int    ttl;

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
};


/*! DNS data structure */
struct ares_dns_record {
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

  ares_dns_rr_t  *an;
  unsigned short  ancount;

  ares_dns_rr_t  *ns;
  unsigned short  nscount;

  ares_dns_rr_t  *ar;
  unsigned short  arcount;
};


#endif /* __ARES__DNS_RECORD_H */
