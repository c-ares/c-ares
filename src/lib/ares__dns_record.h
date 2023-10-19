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
 *  responses */
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
} ares_dns_rec_type_t;


/*! DNS Classes for requests and responses.  */
typedef enum  {
  ARES_CLASS_IN      = 1,  /*<! Internet */
  ARES_CLASS_CHAOS   = 3,  /*<! CHAOS */
  ARES_CLASS_HESOID  = 4,  /*<! Hesoid [Dyer 87] */
  ARES_CLASS_ANY     = 255 /*<! Any class (requests only) */
} ares_dns_class_t;

/*! DNS RR Section type */
typedef enum {
  ARES_SECTION_ANSWER     = 1, /*!< Answer section */
  ARES_SECTION_AUTHORITY  = 2, /*!< Authority section */
  ARES_SECTION_ADDITIONAL = 3  /*!< Additional information section */
} ares_dns_section_t;

/*! DNS Header opcodes */
typedef enum {
  ARES_OPCODE_QUERY  = 0, /* Standard query */
  ARES_OPCODE_IQUERY = 1, /* Inverse query */
  ARES_OPCODE_STATUS = 2, /* Name server status query */
  ARES_OPCODE_NOTIFY = 4, /* Zone change notification (RFC 1996) */
  ARES_OPCODE_UPDATE = 5, /* Zone update message (RFC2136) */
} ares_dns_opcode_t;

/*! DNS Header flags */
typedef enum {
  ARES_FLAG_QR = 1 << 0, /*! QR. If set, is a response */
  ARES_FLAG_AA = 1 << 1, /*! Authoritative Answer. If set, is authoritative */
  ARES_FLAG_TC = 1 << 2, /*! Truncation. If set, is truncated response */
  ARES_FLAG_RD = 1 << 3, /*! Recursion Desired. If set, recursion is desired */
  ARES_FLAG_RA = 1 << 4, /*! Recursion Available. If set, server supports
                          *  recursion */
} ares_dns_flags_t;

/*! DNS Response Codes from server */
typedef enum {
  ARES_RCODE_NOERROR         = 0, /*!< Success */
  ARES_RCODE_FORMAT_ERROR    = 1, /*!< Format error. The name server was unable
                                   *   to interpret the query. */
  ARES_RCODE_SERVER_FAILURE  = 2, /*!< Server Failure. The name server was
                                   *   unable to process this query due to a
                                   *   problem with the nameserver */
  ARES_RCODE_NAME_ERROR      = 3, /*!< Name Error.  Meaningful only for
                                   *   responses from an authoritative name
                                   *   server, this code signifies that the
                                   *   domain name referenced in the query does
                                   *   not exist. */
  ARES_RCODE_NOT_IMPLEMENTED = 4, /*!< Not implemented.  The name server does
                                   *   not support the requested kind of
                                   *   query */
  ARES_RCODE_REFUSED         = 5  /*!< Refused. The name server refuses to
                                   *   perform the speciied operation for
                                   *   policy reasons. */
} ares_dns_rcode_t;

/*! Data types used */
typedef enum {
  ARES_DATATYPE_INADDR  = 1,
  ARES_DATATYPE_INADDR6 = 2,
  ARES_DATATYPE_U8      = 3,
  ARES_DATATYPE_U16     = 4,
  ARES_DATATYPE_U32     = 5,
  ARES_DATATYPE_STR     = 6,
  ARES_DATATYPE_BIN     = 7
} ares_dns_datatype_t;

/*! Keys used for all RR Types.  We take the record type and multiply by 100
 *  to ensure we have a proper offset between keys so we can keep these sorted
 */
typedef enum {
  ARES_RR_A_ADDR            = (ARES_REC_TYPE_A      * 100) + 1,
  ARES_RR_NS_NSDNAME        = (ARES_REC_TYPE_NS     * 100) + 1,
  ARES_RR_CNAME_CNAME       = (ARES_REC_TYPE_CNAME  * 100) + 1,
  ARES_RR_SOA_MNAME         = (ARES_REC_TYPE_SOA    * 100) + 1,
  ARES_RR_SOA_RNAME         = (ARES_REC_TYPE_SOA    * 100) + 2,
  ARES_RR_SOA_SERIAL        = (ARES_REC_TYPE_SOA    * 100) + 3,
  ARES_RR_SOA_REFRESH       = (ARES_REC_TYPE_SOA    * 100) + 4,
  ARES_RR_SOA_RETRY         = (ARES_REC_TYPE_SOA    * 100) + 5,
  ARES_RR_SOA_EXPIRE        = (ARES_REC_TYPE_SOA    * 100) + 6,
  ARES_RR_SOA_MINIMUM       = (ARES_REC_TYPE_SOA    * 100) + 7,
  ARES_RR_PTR_DNAME         = (ARES_REC_TYPE_PTR    * 100) + 1,
  ARES_RR_HINFO_CPU         = (ARES_REC_TYPE_HINFO  * 100) + 1,
  ARES_RR_HINFO_OS          = (ARES_REC_TYPE_HINFO  * 100) + 2,
  ARES_RR_MX_PREFERENCE     = (ARES_REC_TYPE_MX     * 100) + 1,
  ARES_RR_MX_EXCHANGE       = (ARES_REC_TYPE_MX     * 100) + 2,
  ARES_RR_TXT_DATA          = (ARES_REC_TYPE_TXT    * 100) + 1,
  ARES_RR_AAAA_ADDR         = (ARES_REC_TYPE_AAAA   * 100) + 1,
  ARES_RR_SRV_PRIORITY      = (ARES_REC_TYPE_SRV    * 100) + 2,
  ARES_RR_SRV_WEIGHT        = (ARES_REC_TYPE_SRV    * 100) + 3,
  ARES_RR_SRV_PORT          = (ARES_REC_TYPE_SRV    * 100) + 4,
  ARES_RR_SRV_TARGET        = (ARES_REC_TYPE_SRV    * 100) + 5,
  ARES_RR_NAPTR_ORDER       = (ARES_REC_TYPE_NAPTR  * 100) + 1,
  ARES_RR_NAPTR_PREFERENCE  = (ARES_REC_TYPE_NAPTR  * 100) + 2,
  ARES_RR_NAPTR_FLAGS       = (ARES_REC_TYPE_NAPTR  * 100) + 3,
  ARES_RR_NAPTR_SERVICES    = (ARES_REC_TYPE_NAPTR  * 100) + 4,
  ARES_RR_NAPTR_REGEXP      = (ARES_REC_TYPE_NAPTR  * 100) + 5,
  ARES_RR_NAPTR_REPLACEMENT = (ARES_REC_TYPE_NAPTR  * 100) + 6,
  ARES_RR_OPT_UDP_SIZE      = (ARES_REC_TYPE_OPT    * 100) + 1,
  ARES_RR_OPT_EXT_RCODE     = (ARES_REC_TYPE_OPT    * 100) + 2,
  ARES_RR_OPT_VERSION       = (ARES_REC_TYPE_OPT    * 100) + 3,
  ARES_RR_OPT_FLAGS         = (ARES_REC_TYPE_OPT    * 100) + 4,
  ARES_RR_URI_PRIORITY      = (ARES_REC_TYPE_URI    * 100) + 1,
  ARES_RR_URI_WEIGHT        = (ARES_REC_TYPE_URI    * 100) + 2,
  ARES_RR_URI_TARGET        = (ARES_REC_TYPE_URI    * 100) + 3,
  ARES_RR_CAA_CRITICAL      = (ARES_REC_TYPE_CAA    * 100) + 1,
  ARES_RR_CAA_TAG           = (ARES_REC_TYPE_CAA    * 100) + 2,
  ARES_RR_CAA_VALUE         = (ARES_REC_TYPE_CAA    * 100) + 3,
  ARES_RR_RAW_RR_TYPE       = (ARES_REC_TYPE_RAW_RR * 100) + 1,
  ARES_RR_RAW_RR_DATA       = (ARES_REC_TYPE_RAW_RR * 100) + 2,
} ares_dns_rr_key_t;

/*! Opaque data type representing a DNS RR (Resource Record) */
struct ares_dns_rr;

/*! Typedef for opaque data type representing a DNS RR (Resource Record) */
typedef struct ares_dns_rr ares_dns_rr_t;

/*! Opaque data type representing a DNS Query Data QD Packet */
struct ares_dns_qd;

/*! Typedef for opaque data type representing a DNS Query Data QD Packet */
typedef struct ares_dns_qd ares_dns_qd_t;

/*! Opaque data type representing a DNS Packet */
struct ares_dns_record;

/*! Typedef for opaque data type representing a DNS Packet */
typedef struct ares_dns_record ares_dns_record_t;


ares_status_t ares_dns_record_create(ares_dns_record_t **dnsrec,
                                     unsigned short id, unsigned short flags,
                                     ares_dns_opcode_t opcode,
                                     ares_dns_rcode_t rcode);

void ares_dns_record_destroy(ares_dns_record_t *dnsrec);
ares_status_t ares_dns_record_query_add(ares_dns_record_t *dnsrec, char *name,
                                        ares_dns_rec_type_t qtype,
                                        ares_dns_class_t qclass);
size_t ares_dns_record_query_cnt(ares_dns_record_t *dnsrec);
ares_status_t ares_dns_record_query_get(ares_dns_record_t *dnsrec, size_t idx,
                                        const char ** name,
                                        ares_dns_rec_type_t *qtype,
                                        ares_dns_class_t *qclass);
size_t ares_dns_record_rr_cnt(ares_dns_record_t *dnsrec,
                              ares_dns_section_t sect);
ares_status_t ares_dns_record_rr_add(ares_dns_rr_t **rr_out,
                                     ares_dns_record_t *dnsrec,
                                     ares_dns_section_t sect, char *name,
                                     ares_dns_rec_type_t type,
                                     ares_dns_class_t rclass,
                                     unsigned int ttl);
ares_dns_rr_t *ares_dns_record_rr_get(ares_dns_record_t *dnsrec,
                                      ares_dns_section_t sect,
                                      size_t idx);

const ares_dns_rr_key_t *ares_dns_rr_get_keys(ares_dns_rec_type_t type,
                                              size_t *cnt);

ares_dns_datatype_t ares_dns_rr_key_datatype(ares_dns_rr_key_t key);

ares_status_t ares_dns_rr_set_str(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                  const char *val);
ares_status_t ares_dns_rr_set_u8(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                 unsigned char val);
ares_status_t ares_dns_rr_set_u16(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                  unsigned short val);
ares_status_t ares_dns_rr_set_u32(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                  unsigned int val);
ares_status_t ares_dns_rr_set_bin(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key,
                                  const unsigned char *val, size_t len);


const char *ares_dns_rr_get_str(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key);
unsigned char ares_dns_rr_get_u8(ares_dns_rr_t *dns_rr,
                                 ares_dns_rr_key_t key);
unsigned short ares_dns_rr_get_u16(ares_dns_rr_t *dns_rr,
                                   ares_dns_rr_key_t key);
unsigned int ares_dns_rr_get_u32(ares_dns_rr_t *dns_rr, ares_dns_rr_key_t key);
const unsigned char *ares_dns_rr_get_bin(ares_dns_rr_t *dns_rr,
                                         ares_dns_rr_key_t key, size_t *len);



/* ---- PRIVATE BELOW ----- */


struct ares_dns_qd {
  char               *name;
  ares_dns_rec_type_t qtype;
  ares_dns_class_t    qclass;
};

typedef struct {
  struct in_addr address;
} ares__dns_a_t;

typedef struct {
  char *nsdname;
} ares__dns_ns_t;

typedef struct {
  char *cname;
} ares__dns_cname_t;

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
  char *ptrdname;
} ares__dns_ptr_t;

typedef struct {
  char *cpu;
  char *os;
} ares__dns_hinfo_t;

typedef struct {
  unsigned short preference;
  char          *exchange;
} ares__dns_mx_t;

typedef struct {
  char *data;
} ares__dns_txt_t;

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
  unsigned short  order;
  unsigned short  preference;
  char           *flags;
  char           *services;
  char           *regexp;
  char           *replacement;
} ares__dns_naptr_t;

typedef struct {
  unsigned short udp_size; /*!< taken from class */
  unsigned char  extenended_rcode; /*!< Taken from first 8 bits of ttl */
  unsigned char  version;  /*!< taken from bits 8-16 of ttl */
  unsigned short flags;    /*!< Flags, remaining 16 bits, though only 1
                            *   currently defined */
  /* Remaining data can be multiple:
   *   16bit attribute/code, 16bit length, data
   * not currently supported */
} ares__dns_opt_t;

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


/*! Raw, unparsed RR data */
typedef struct {
  unsigned short  type;     /*!< Not ares_rec_type_t because it likely isn't one
                             *   of those values since it wasn't parsed */
  unsigned char  *rdata;    /*!< Raw RR data */
  unsigned short  rdlength; /*!< Length of raw RR data */
} ares__dns_raw_rr_t;


/*! DNS RR data structure */
struct ares_dns_rr {
  char               *name;
  ares_dns_rec_type_t type;
  ares_dns_class_t    rclass;
  unsigned int        ttl;

  union {
    ares__dns_a_t      a;
    ares__dns_ns_t     ns;
    ares__dns_cname_t  cname;
    ares__dns_soa_t    soa;
    ares__dns_ptr_t    ptr;
    ares__dns_hinfo_t  hinfo;
    ares__dns_mx_t     mx;
    ares__dns_txt_t    txt;
    ares__dns_aaaa_t   aaaa;
    ares__dns_srv_t    srv;
    ares__dns_naptr_t  naptr;
    ares__dns_opt_t    opt;
    ares__dns_uri_t    uri;
    ares__dns_caa_t    caa;
    ares__dns_raw_rr_t raw_rr;
  } r;
};


/*! DNS data structure */
struct ares_dns_record {
  unsigned short    id;     /*!< DNS query id */
  unsigned short    flags;  /*!< One or more ares_dns_flags_t */
  ares_dns_opcode_t opcode; /*!< DNS Opcode */
  ares_dns_rcode_t  rcode;  /*!< DNS RCODE */

  ares_dns_qd_t *qd;
  size_t         qdcount;

  ares_dns_rr_t *an;
  size_t         ancount;

  ares_dns_rr_t *ns;
  size_t         nscount;

  ares_dns_rr_t *ar;
  size_t         arcount;
};


#endif /* __ARES__DNS_RECORD_H */
