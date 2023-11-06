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

typedef struct {
  char  *name;
  size_t name_len;
  size_t idx;
} ares_nameoffset_t;

static void ares__nameoffset_free(void *arg)
{
  ares_nameoffset_t *off = arg;
  if (off == NULL) {
    return;
  }
  ares_free(off->name);
  ares_free(off);
}

static ares_status_t ares__nameoffset_create(ares__llist_t **list,
                                             const char *name, size_t idx)
{
  ares_status_t      status;
  ares_nameoffset_t *off = NULL;

  if (list == NULL || name == NULL || ares_strlen(name) == 0 ||
      ares_strlen(name) > 255) {
    return ARES_EFORMERR;
  }

  if (*list == NULL) {
    *list = ares__llist_create(ares__nameoffset_free);
  }
  if (*list == NULL) {
    status = ARES_ENOMEM;
    goto fail;
  }

  off = ares_malloc_zero(sizeof(*off));
  if (off == NULL) {
    return ARES_ENOMEM;
  }

  off->name     = ares_strdup(name);
  off->name_len = ares_strlen(off->name);
  off->idx      = idx;

  if (ares__llist_insert_last(*list, off) == NULL) {
    status = ARES_ENOMEM;
    goto fail;
  }

  status = ARES_SUCCESS;

fail:
  ares__nameoffset_free(off);
  return status;
}

static const ares_nameoffset_t *ares__nameoffset_find(ares__llist_t *list,
                                                      const char    *name)
{
  size_t                   name_len = ares_strlen(name);
  ares__llist_node_t      *node;
  const ares_nameoffset_t *longest_match = NULL;

  if (list == NULL || name == NULL || name_len == 0) {
    return NULL;
  }

  for (node = ares__llist_node_first(list); node != NULL;
       node = ares__llist_node_next(node)) {
    const ares_nameoffset_t *val = ares__llist_node_val(node);
    size_t                   prefix_len;

    /* Can't be a match if the stored name is longer */
    if (val->name_len > name_len) {
      continue;
    }

    /* Can't be the longest match if our existing longest match is longer */
    if (longest_match != NULL && longest_match->name_len > val->name_len) {
      continue;
    }

    prefix_len = name_len - val->name_len;

    if (strcasecmp(val->name, name + prefix_len) != 0) {
      continue;
    }

    /* We need to make sure if `val->name` is "example.com" that name is
     * is separated by a label, e.g. "myexample.com" is not ok, however
     * "my.example.com" is, so we look for the preceding "." */
    if (prefix_len != 0 && name[prefix_len - 1] != '.') {
      continue;
    }

    longest_match = val;
  }

  return longest_match;
}

static ares_status_t ares_dns_write_name(ares__buf_t *buf, ares__llist_t **list,
                                         ares_bool_t validate_hostname,
                                         const char *name)
{
  const ares_nameoffset_t *off      = NULL;
  size_t                   name_len = ares_strlen(name);
  size_t                   pos      = ares__buf_get_position(buf);
  char                     name_copy[256];
  char                   **labels     = NULL;
  size_t                   num_labels = 0;
  ares_status_t            status;

  if (buf == NULL || name == NULL) {
    return ARES_EFORMERR;
  }

  if (name_len > sizeof(name_copy) - 1) {
    return ARES_EBADNAME;
  }

  name_len = ares_strcpy(name_copy, name, sizeof(name_copy));

  /* Remove trailing period */
  if (name_len > 0 && name_copy[name_len - 1] == '.') {
    name_copy[name_len - 1] = 0;
    name_len--;
  }

  /* XXX: validate name format!
   *  1) must not start with a '.'
   *  2) only printable characters
   *  3) if a hostname only hostname characters
   *  4) each label must be between 1 and 63 characters (inclusive)
   *  4) since we stripped trailing '.' should not have a trailing '.'
   *  5) A real '.' can be escaped by a '\' and therefore means a '\' must be
   *     escaped by a slash.  This is to support the SOA RNAME format mostly,
   *     think of   tech.support@example.com   in the RNAME, this would be
   *     encoded as   tech\.support.example.com, otherwise if it was encoded
   *     as  tech.support.example.com, it would be interpreted as
   *     tech@support.example.com.
   */
  if (*name_copy == '.') {
    return ARES_EBADNAME;
  }

  /* Find longest match */
  if (list != NULL) {
    off = ares__nameoffset_find(*list, name_copy);
    if (off != NULL && off->name_len != name_len) {
      /* truncate */
      name_len                -= (off->name_len + 1);
      name_copy[name_len - 1]  = 0;
    }
  }

  /* Output labels */
  if (off == NULL || off->name_len != name_len) {
    size_t i;

    if (name_len > 0) {
      labels = ares__strsplit(name_copy, ".", &num_labels);
      if (labels == NULL || num_labels == 0) {
        status = ARES_ENOMEM;
        goto done;
      }

      for (i = 0; i < num_labels; i++) {
        size_t len = ares_strlen(labels[i]);

        status = ares__buf_append_byte(buf, (unsigned char)(len & 0xFF));
        if (status != ARES_SUCCESS) {
          goto done;
        }

        status = ares__buf_append(buf, (unsigned char *)labels[i], len);
        if (status != ARES_SUCCESS) {
          goto done;
        }
      }
    }

    /* If we are NOT jumping to another label, output terminator */
    if (off == NULL) {
      status = ares__buf_append_byte(buf, 0);
      if (status != ARES_SUCCESS) {
        goto done;
      }
    }
  }

  /* Output name compression offset jump */
  if (off != NULL) {
    unsigned short u16 = 0xC000 | (off->idx & 0x3FFF);
    status             = ares__buf_append_be16(buf, u16);
    if (status != ARES_SUCCESS) {
      goto done;
    }
  }

  /* Store pointer for future jumps as long as its not an exact match for
   * a prior entry */
  if (list != NULL && off != NULL && off->name_len != name_len && name_len > 0) {
    status = ares__nameoffset_create(list, name_copy, pos);
    if (status != ARES_SUCCESS) {
      goto done;
    }
  }

  status = ARES_SUCCESS;

done:
  ares__strsplit_free(labels, num_labels);
  return status;
}

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
                                              ares__llist_t          **namelist,
                                              ares__buf_t             *buf)
{
  size_t i;

  for (i = 0; i < ares_dns_record_query_cnt(dnsrec); i++) {
    ares_status_t       status;
    const char         *name = NULL;
    ares_dns_rec_type_t qtype;
    ares_dns_class_t    qclass;

    status = ares_dns_record_query_get(dnsrec, i, &name, &qtype, &qclass);
    if (status != ARES_SUCCESS) {
      return status;
    }

    /* Name */
    status = ares_dns_write_name(buf, namelist, ARES_TRUE, name);
    if (status != ARES_SUCCESS) {
      return status;
    }

    /* Type */
    status = ares__buf_append_be16(buf, (unsigned short)qtype);
    if (status != ARES_SUCCESS) {
      return status;
    }

    /* Class */
    status = ares__buf_append_be16(buf, (unsigned short)qclass);
    if (status != ARES_SUCCESS) {
      return status;
    }
  }

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_write_rr_name(ares__buf_t         *buf,
                                            const ares_dns_rr_t *rr,
                                            ares__llist_t      **namelist,
                                            ares_bool_t       validate_hostname,
                                            ares_dns_rr_key_t key)
{
  const char *name;

  name = ares_dns_rr_get_str(rr, key);
  if (name == NULL) {
    return ARES_EFORMERR;
  }

  return ares_dns_write_name(buf, namelist, validate_hostname, name);
}

static ares_status_t ares_dns_write_rr_str(ares__buf_t         *buf,
                                           const ares_dns_rr_t *rr,
                                           ares_dns_rr_key_t    key)
{
  const char   *str;
  size_t        len;
  ares_status_t status;

  str = ares_dns_rr_get_str(rr, key);
  if (str == NULL || (len = ares_strlen(str)) > 255) {
    return ARES_EFORMERR;
  }

  /* Write 1 byte length */
  status = ares__buf_append_byte(buf, (unsigned char)(len & 0xFF));
  if (status != ARES_SUCCESS) {
    return status;
  }

  if (len == 0) {
    return ARES_SUCCESS;
  }

  /* Write string */
  return ares__buf_append(buf, (unsigned char *)str, len);
}

static ares_status_t ares_dns_write_rr_strs(ares__buf_t         *buf,
                                            const ares_dns_rr_t *rr,
                                            ares_dns_rr_key_t    key)
{
  const char   *str;
  const char   *ptr;
  ares_status_t status;

  str = ares_dns_rr_get_str(rr, key);
  if (str == NULL) {
    return ARES_EFORMERR;
  }

  /* split into possible multiple 255-byte or less length strings */
  ptr = str;
  do {
    size_t ptr_len = ares_strlen(ptr);
    if (ptr_len > 255) {
      ptr_len = 255;
    }

    /* Length */
    status = ares__buf_append_byte(buf, (unsigned char)(ptr_len & 0xFF));
    if (status != ARES_SUCCESS) {
      return status;
    }

    /* String */
    if (ptr_len) {
      status = ares__buf_append(buf, (unsigned char *)ptr, ptr_len);
      if (status != ARES_SUCCESS) {
        return status;
      }
    }

    ptr += ptr_len;
  } while (*ptr != 0);

  return ARES_SUCCESS;
}

static ares_status_t ares_dns_write_rr_be32(ares__buf_t         *buf,
                                            const ares_dns_rr_t *rr,
                                            ares_dns_rr_key_t    key)
{
  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_U32) {
    return ARES_EFORMERR;
  }
  return ares__buf_append_be32(buf, ares_dns_rr_get_u32(rr, key));
}

static ares_status_t ares_dns_write_rr_be16(ares__buf_t         *buf,
                                            const ares_dns_rr_t *rr,
                                            ares_dns_rr_key_t    key)
{
  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_U16) {
    return ARES_EFORMERR;
  }
  return ares__buf_append_be16(buf, ares_dns_rr_get_u16(rr, key));
}

static ares_status_t ares_dns_write_rr_u8(ares__buf_t         *buf,
                                          const ares_dns_rr_t *rr,
                                          ares_dns_rr_key_t    key)
{
  if (ares_dns_rr_key_datatype(key) != ARES_DATATYPE_U8) {
    return ARES_EFORMERR;
  }
  return ares__buf_append_byte(buf, ares_dns_rr_get_u8(rr, key));
}

static ares_status_t ares_dns_write_rr_a(ares__buf_t         *buf,
                                         const ares_dns_rr_t *rr,
                                         ares__llist_t      **namelist)
{
  const struct in_addr *addr;
  (void)namelist;

  addr = ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR);
  if (addr == NULL) {
    return ARES_EFORMERR;
  }

  return ares__buf_append(buf, (unsigned char *)&addr, sizeof(*addr));
}

static ares_status_t ares_dns_write_rr_ns(ares__buf_t         *buf,
                                          const ares_dns_rr_t *rr,
                                          ares__llist_t      **namelist)
{
  return ares_dns_write_rr_name(buf, rr, namelist, ARES_FALSE,
                                ARES_RR_NS_NSDNAME);
}

static ares_status_t ares_dns_write_rr_cname(ares__buf_t         *buf,
                                             const ares_dns_rr_t *rr,
                                             ares__llist_t      **namelist)
{
  return ares_dns_write_rr_name(buf, rr, namelist, ARES_FALSE,
                                ARES_RR_CNAME_CNAME);
}

static ares_status_t ares_dns_write_rr_soa(ares__buf_t         *buf,
                                           const ares_dns_rr_t *rr,
                                           ares__llist_t      **namelist)
{
  ares_status_t status;

  /* MNAME */
  status =
    ares_dns_write_rr_name(buf, rr, namelist, ARES_FALSE, ARES_RR_SOA_MNAME);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* RNAME */
  status =
    ares_dns_write_rr_name(buf, rr, namelist, ARES_FALSE, ARES_RR_SOA_RNAME);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* SERIAL */
  status = ares_dns_write_rr_be32(buf, rr, ARES_RR_SOA_SERIAL);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* REFRESH */
  status = ares_dns_write_rr_be32(buf, rr, ARES_RR_SOA_REFRESH);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* RETRY */
  status = ares_dns_write_rr_be32(buf, rr, ARES_RR_SOA_RETRY);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* EXPIRE */
  status = ares_dns_write_rr_be32(buf, rr, ARES_RR_SOA_EXPIRE);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* MINIMUM */
  return ares_dns_write_rr_be32(buf, rr, ARES_RR_SOA_MINIMUM);
}

static ares_status_t ares_dns_write_rr_ptr(ares__buf_t         *buf,
                                           const ares_dns_rr_t *rr,
                                           ares__llist_t      **namelist)
{
  return ares_dns_write_rr_name(buf, rr, namelist, ARES_FALSE,
                                ARES_RR_PTR_DNAME);
}

static ares_status_t ares_dns_write_rr_hinfo(ares__buf_t         *buf,
                                             const ares_dns_rr_t *rr,
                                             ares__llist_t      **namelist)
{
  ares_status_t status;

  (void)namelist;

  /* CPU */
  status = ares_dns_write_rr_str(buf, rr, ARES_RR_HINFO_CPU);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* OS */
  return ares_dns_write_rr_str(buf, rr, ARES_RR_HINFO_OS);
}

static ares_status_t ares_dns_write_rr_mx(ares__buf_t         *buf,
                                          const ares_dns_rr_t *rr,
                                          ares__llist_t      **namelist)
{
  ares_status_t status;

  /* PREFERENCE */
  status = ares_dns_write_rr_be16(buf, rr, ARES_RR_MX_PREFERENCE);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* EXCHANGE */
  return ares_dns_write_rr_name(buf, rr, namelist, ARES_FALSE,
                                ARES_RR_MX_EXCHANGE);
}

static ares_status_t ares_dns_write_rr_txt(ares__buf_t         *buf,
                                           const ares_dns_rr_t *rr,
                                           ares__llist_t      **namelist)
{
  (void)namelist;
  return ares_dns_write_rr_strs(buf, rr, ARES_RR_TXT_DATA);
}

static ares_status_t ares_dns_write_rr_aaaa(ares__buf_t         *buf,
                                            const ares_dns_rr_t *rr,
                                            ares__llist_t      **namelist)
{
  const struct ares_in6_addr *addr;
  (void)namelist;

  addr = ares_dns_rr_get_addr6(rr, ARES_RR_AAAA_ADDR);
  if (addr == NULL) {
    return ARES_EFORMERR;
  }

  return ares__buf_append(buf, (unsigned char *)&addr, sizeof(*addr));
}

static ares_status_t ares_dns_write_rr_srv(ares__buf_t         *buf,
                                           const ares_dns_rr_t *rr,
                                           ares__llist_t      **namelist)
{
  ares_status_t status;

  /* PRIORITY */
  status = ares_dns_write_rr_be16(buf, rr, ARES_RR_SRV_PRIORITY);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* WEIGHT */
  status = ares_dns_write_rr_be16(buf, rr, ARES_RR_SRV_WEIGHT);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* PORT */
  status = ares_dns_write_rr_be16(buf, rr, ARES_RR_SRV_PORT);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* TARGET */
  return ares_dns_write_rr_name(buf, rr, namelist, ARES_FALSE,
                                ARES_RR_SRV_TARGET);
}

static ares_status_t ares_dns_write_rr_naptr(ares__buf_t         *buf,
                                             const ares_dns_rr_t *rr,
                                             ares__llist_t      **namelist)
{
  ares_status_t status;

  /* ORDER */
  status = ares_dns_write_rr_be16(buf, rr, ARES_RR_NAPTR_ORDER);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* PREFERENCE */
  status = ares_dns_write_rr_be16(buf, rr, ARES_RR_NAPTR_PREFERENCE);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* FLAGS */
  status = ares_dns_write_rr_str(buf, rr, ARES_RR_NAPTR_FLAGS);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* SERVICES */
  status = ares_dns_write_rr_str(buf, rr, ARES_RR_NAPTR_SERVICES);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* REGEXP */
  status = ares_dns_write_rr_str(buf, rr, ARES_RR_NAPTR_REGEXP);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* REPLACEMENT */
  return ares_dns_write_rr_name(buf, rr, namelist, ARES_FALSE,
                                ARES_RR_NAPTR_REPLACEMENT);
}

static ares_status_t ares_dns_write_rr_opt(ares__buf_t         *buf,
                                           const ares_dns_rr_t *rr,
                                           ares__llist_t      **namelist)
{
  size_t               len = ares__buf_len(buf);
  ares_status_t        status;
  unsigned int         ttl      = 0;

  (void)namelist;

  /* We need to go back and overwrite the class and ttl that were emitted as
   * the OPT record overloads them for its own use (yes, very strange!) */
  status = ares__buf_set_length(buf, len - 2 /* RDLENGTH */
                                         - 4 /* TTL */
                                         - 2 /* CLASS */);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* Class -> UDP Size */
  status = ares_dns_write_rr_be16(buf, rr, ARES_RR_OPT_UDP_SIZE);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* TTL -> rcode (u8) << 24 | version (u8) << 16 | flags (u16) */
  ttl |= (unsigned int)ares_dns_rr_get_u8(rr, ARES_RR_OPT_EXT_RCODE) << 24;
  ttl |= (unsigned int)ares_dns_rr_get_u8(rr, ARES_RR_OPT_VERSION) << 16;
  ttl |= (unsigned int)ares_dns_rr_get_u16(rr, ARES_RR_OPT_FLAGS);

  status = ares__buf_append_be32(buf, ttl);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* Now go back to real end */
  status = ares__buf_set_length(buf, len);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* TODO: handle additional opt messages here */
  return ARES_SUCCESS;
}

static ares_status_t ares_dns_write_rr_uri(ares__buf_t         *buf,
                                           const ares_dns_rr_t *rr,
                                           ares__llist_t      **namelist)
{
  ares_status_t status;
  const char   *target;

  (void)namelist;

  /* PRIORITY */
  status = ares_dns_write_rr_be16(buf, rr, ARES_RR_URI_PRIORITY);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* WEIGHT */
  status = ares_dns_write_rr_be16(buf, rr, ARES_RR_URI_WEIGHT);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* TARGET -- not in DNS string format, rest of buffer, required to be
   * non-zero length */
  target = ares_dns_rr_get_str(rr, ARES_RR_URI_TARGET);
  if (target == NULL || ares_strlen(target) == 0) {
    return ARES_EFORMERR;
  }

  return ares__buf_append(buf, (unsigned char *)target, ares_strlen(target));
}

static ares_status_t ares_dns_write_rr_caa(ares__buf_t         *buf,
                                           const ares_dns_rr_t *rr,
                                           ares__llist_t      **namelist)
{
  const unsigned char *data     = NULL;
  size_t               data_len = 0;
  ares_status_t        status;

  (void)namelist;

  /* CRITICAL */
  status = ares_dns_write_rr_u8(buf, rr, ARES_RR_CAA_CRITICAL);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* Tag */
  status = ares_dns_write_rr_str(buf, rr, ARES_RR_CAA_TAG);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* Value - binary! (remaining buffer */
  data = ares_dns_rr_get_bin(rr, ARES_RR_CAA_VALUE, &data_len);
  if (data == NULL || data_len == 0) {
    return ARES_EFORMERR;
  }

  return ares__buf_append(buf, data, data_len);
}

static ares_status_t ares_dns_write_rr_raw_rr(ares__buf_t         *buf,
                                              const ares_dns_rr_t *rr,
                                              ares__llist_t      **namelist)
{
  size_t               len = ares__buf_len(buf);
  ares_status_t        status;
  const unsigned char *data     = NULL;
  size_t               data_len = 0;

  (void)namelist;

  /* We need to go back and overwrite the type that was emitted by the parent
   * function */
  status = ares__buf_set_length(buf, len - 2 /* RDLENGTH */
                                       - 4   /* TTL */
                                       - 2   /* CLASS */
                                       - 2 /* TYPE */);
  if (status != ARES_SUCCESS) {
    return status;
  }

  status = ares_dns_write_rr_be16(buf, rr, ARES_RR_RAW_RR_TYPE);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* Now go back to real end */
  status = ares__buf_set_length(buf, len);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* Output raw data */
  data = ares_dns_rr_get_bin(rr, ARES_RR_RAW_RR_DATA, &data_len);
  if (data == NULL) {
    return ARES_EFORMERR;
  }

  if (data_len == 0) {
    return ARES_SUCCESS;
  }

  return ares__buf_append(buf, data, data_len);
}

static ares_status_t ares_dns_write_rr(ares_dns_record_t *dnsrec,
                                       ares__llist_t    **namelist,
                                       ares_dns_section_t section,
                                       ares__buf_t       *buf)
{
  size_t i;

  for (i = 0; i < ares_dns_record_rr_cnt(dnsrec, section); i++) {
    ares_dns_rr_t      *rr;
    ares_dns_rec_type_t type;
    ares_bool_t         allow_compress;
    ares__llist_t     **namelistptr = NULL;
    size_t              pos_len;
    ares_status_t       status;
    size_t              rdlength;
    size_t              end_length;

    rr = ares_dns_record_rr_get(dnsrec, section, i);
    if (rr == NULL) {
      return ARES_EFORMERR;
    }

    type           = ares_dns_rr_get_type(rr);
    allow_compress = ares_dns_rec_type_allow_name_compression(type);
    if (allow_compress) {
      namelistptr = namelist;
    }

    /* Name */
    status =
      ares_dns_write_name(buf, namelist, ARES_TRUE, ares_dns_rr_get_name(rr));
    if (status != ARES_SUCCESS) {
      return status;
    }

    /* Type */
    status = ares__buf_append_be16(buf, (unsigned short)type);
    if (status != ARES_SUCCESS) {
      return status;
    }

    /* Class */
    status =
      ares__buf_append_be16(buf, (unsigned short)ares_dns_rr_get_class(rr));
    if (status != ARES_SUCCESS) {
      return status;
    }

    /* TTL */
    status = ares__buf_append_be32(buf, ares_dns_rr_get_ttl(rr));
    if (status != ARES_SUCCESS) {
      return status;
    }

    /* Length */
    pos_len = ares__buf_len(buf); /* Save to write real length later */
    status  = ares__buf_append_be16(buf, 0);
    if (status != ARES_SUCCESS) {
      return status;
    }

    /* Data */
    switch (type) {
      case ARES_REC_TYPE_A:
        status = ares_dns_write_rr_a(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_NS:
        status = ares_dns_write_rr_ns(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_CNAME:
        status = ares_dns_write_rr_cname(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_SOA:
        status = ares_dns_write_rr_soa(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_PTR:
        status = ares_dns_write_rr_ptr(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_HINFO:
        status = ares_dns_write_rr_hinfo(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_MX:
        status = ares_dns_write_rr_mx(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_TXT:
        status = ares_dns_write_rr_txt(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_AAAA:
        status = ares_dns_write_rr_aaaa(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_SRV:
        status = ares_dns_write_rr_srv(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_NAPTR:
        status = ares_dns_write_rr_naptr(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_ANY:
        status = ARES_EFORMERR;
        break;
      case ARES_REC_TYPE_OPT:
        status = ares_dns_write_rr_opt(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_URI:
        status = ares_dns_write_rr_uri(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_CAA:
        status = ares_dns_write_rr_caa(buf, rr, namelistptr);
        break;
      case ARES_REC_TYPE_RAW_RR:
        status = ares_dns_write_rr_raw_rr(buf, rr, namelistptr);
        break;
    }

    if (status != ARES_SUCCESS) {
      return status;
    }

    /* Back off write pointer, write real length, then go back to proper
     * position */
    end_length = ares__buf_len(buf);
    rdlength   = end_length - pos_len - 2;

    status = ares__buf_set_length(buf, pos_len);
    if (status != ARES_SUCCESS) {
      return status;
    }

    status = ares__buf_append_be16(buf, (unsigned short)(rdlength & 0xFFFF));
    if (status != ARES_SUCCESS) {
      return status;
    }

    status = ares__buf_set_length(buf, end_length);
    if (status != ARES_SUCCESS) {
      return status;
    }
  }

  return ARES_SUCCESS;
}

ares_status_t ares_dns_write(ares_dns_record_t *dnsrec, unsigned char **buf,
                             size_t *buf_len)
{
  ares__buf_t   *b = NULL;
  ares_status_t  status;
  ares__llist_t *namelist = NULL;

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
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_dns_write_questions(dnsrec, &namelist, b);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_dns_write_rr(dnsrec, &namelist, ARES_SECTION_ANSWER, b);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_dns_write_rr(dnsrec, &namelist, ARES_SECTION_AUTHORITY, b);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_dns_write_rr(dnsrec, &namelist, ARES_SECTION_ADDITIONAL, b);
  if (status != ARES_SUCCESS) {
    goto done;
  }

done:
  ares__llist_destroy(namelist);

  if (status != ARES_SUCCESS) {
    ares__buf_destroy(b);
    return status;
  }

  *buf = ares__buf_finish_bin(b, buf_len);
  return status;
}
