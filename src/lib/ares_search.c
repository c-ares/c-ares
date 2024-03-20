/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) The c-ares project and its contributors
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

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#include "ares.h"
#include "ares_private.h"
#include "ares_dns.h"

struct search_query {
  /* Arguments passed to ares_search() */
  ares_channel_t *channel;
  ares_callback   callback;
  void           *arg;

  /* DNS record passed to ares_search(), encoded in string format */
  unsigned char  *buf;
  size_t          buflen;

  /* Duplicate of channel domains for ares_reinit() safety */
  char          **domains;
  size_t          ndomains;

  /* State tracking progress through the search query */
  int             status_as_is;    /* error status from trying as-is */
  size_t          next_domain;     /* next search domain to try */
  ares_bool_t     trying_as_is;    /* current query is for name as-is */
  size_t          timeouts;        /* number of timeouts we saw for this request */
  ares_bool_t     ever_got_nodata; /* did we ever get ARES_ENODATA along the way? */
};

/* Callback argument structure passed to ares__dnsrec_convert_cb(). */
struct dnsrec_convert_arg {
  ares_callback_dnsrec callback;
  void                *arg;
};

static void search_callback(void *arg, int status, int timeouts,
                            unsigned char *abuf, int alen);
static ares_status_t ares__write_and_send_query(ares_channel_t *channel,
                                                ares_dns_record_t *dnsrec,
                                                char *altname,
                                                ares_callback callback,
                                                void *arg);
static void end_squery(struct search_query *squery, ares_status_t status,
                       unsigned char *abuf, size_t alen);
static void ares__dnsrec_convert_cb(void *arg, int status, int timeouts,
                                    unsigned char *abuf, int alen);

static void ares_search_int(ares_channel_t *channel, ares_dns_record_t *dnsrec,
                            ares_callback callback, void *arg)
{
  struct search_query *squery;
  const char          *name;
  char                *s = NULL;
  const char          *p;
  ares_status_t        status;
  size_t               ndots;

  /* Extract the name for the search. Note that searches are only supported for
   * DNS records containing a single query.
   */
  if (ares_dns_record_query_cnt(dnsrec) != 1) {
    callback(arg, ARES_EBADQUERY, 0, NULL, 0);
    return;
  }
  status = ares_dns_record_query_get(dnsrec, 0, &name, NULL, NULL);
  if (status != ARES_SUCCESS) {
    callback(arg, (int)status, 0, NULL, 0);
    return;
  }

  /* Per RFC 7686, reject queries for ".onion" domain names with NXDOMAIN. */
  if (ares__is_onion_domain(name)) {
    callback(arg, ARES_ENOTFOUND, 0, NULL, 0);
    return;
  }

  /* If name only yields one domain to search, then we don't have
   * to keep extra state, so just do an ares_send().
   */
  status = ares__single_domain(channel, name, &s);
  if (status != ARES_SUCCESS) {
    callback(arg, (int)status, 0, NULL, 0);
    return;
  } else if (s != NULL) {
    /* We only have a single domain to search, so do it here. */
    status = ares__write_and_send_query(channel, dnsrec, s, callback, arg);
    ares_free(s);
    if (status != ARES_SUCCESS) {
      callback(arg, (int)status, 0, NULL, 0);
    }
    return;
  }

  /* Allocate a search_query structure to hold the state necessary for
   * doing multiple lookups.
   */
  squery = ares_malloc_zero(sizeof(*squery));
  if (!squery) {
    callback(arg, ARES_ENOMEM, 0, NULL, 0);
    return;
  }
  squery->channel = channel;

  /* We pass the DNS record through the search_query structure by encoding it
   * into a buffer and then later decoding it back.
   */
  status = ares_dns_write(dnsrec, &squery->buf, &squery->buflen);
  if (status != ARES_SUCCESS) {
    ares_free(squery);
    callback(arg, (int)status, 0, NULL, 0);
    return;
  }

  /* Duplicate domains for safety during ares_reinit() */
  if (channel->ndomains) {
    squery->domains =
      ares__strsplit_duplicate(channel->domains, channel->ndomains);
    if (squery->domains == NULL) {
      ares_free(squery->buf);
      ares_free(squery);
      callback(arg, ARES_ENOMEM, 0, NULL, 0);
      return;
    }
    squery->ndomains = channel->ndomains;
  }

  squery->status_as_is    = -1;
  squery->callback        = callback;
  squery->arg             = arg;
  squery->timeouts        = 0;
  squery->ever_got_nodata = ARES_FALSE;

  /* Count the number of dots in name. */
  ndots = 0;
  for (p = name; *p; p++) {
    if (*p == '.') {
      ndots++;
    }
  }

  /* If ndots is at least the channel ndots threshold (usually 1),
   * then we try the name as-is first.  Otherwise, we try the name
   * as-is last.
   */
  if (ndots >= channel->ndots || squery->ndomains == 0) {
    /* Try the name as-is first. */
    squery->next_domain  = 0;
    squery->trying_as_is = ARES_TRUE;
    ares_send(channel, squery->buf, (int)squery->buflen, search_callback,
              squery);
  } else {
    /* Try the name as-is last; start with the first search domain. */
    status = ares__cat_domain(name, squery->domains[0], &s);
    if (status == ARES_SUCCESS) {
      squery->next_domain  = 1;
      squery->trying_as_is = ARES_FALSE;
      status = ares__write_and_send_query(channel, dnsrec, s, search_callback,
                                          squery);
      ares_free(s);
    }
    /* Handle any errors. */
    if (status != ARES_SUCCESS) {
      end_squery(squery, status, NULL, 0);
    }
  }
}

/* Search for a DNS name with given class and type. Wrapper around
 * ares_search_int() where the DNS record to search is first constructed.
 */
void ares_search(ares_channel_t *channel, const char *name, int dnsclass,
                 int type, ares_callback callback, void *arg)
{
  ares_status_t      status;
  ares_dns_record_t *dnsrec = NULL;
  size_t             max_udp_size;
  ares_dns_flags_t   rd_flag;

  if ((channel == NULL) || (name == NULL)) {
    return;
  }

  rd_flag = !(channel->flags & ARES_FLAG_NORECURSE) ? ARES_FLAG_RD: 0;
  max_udp_size = (channel->flags & ARES_FLAG_EDNS) ? channel->ednspsz : 0;
  status = ares_dns_record_create_query(&dnsrec, name,
                                        (ares_dns_class_t)dnsclass,
                                        (ares_dns_rec_type_t)type,
                                        0, rd_flag, max_udp_size);
  if (status != ARES_SUCCESS) {
    callback(arg, (int)status, 0, NULL, 0);
    return;
  }

  ares__channel_lock(channel);
  ares_search_int(channel, dnsrec, callback, arg);
  ares__channel_unlock(channel);

  ares_dns_record_destroy(dnsrec);
}

/* Search for a DNS record. Wrapper around ares_search_int(). */
void ares_search_dnsrec(ares_channel_t *channel, ares_dns_record_t *dnsrec,
                        ares_callback_dnsrec callback, void *arg)
{
  struct dnsrec_convert_arg *carg;

  if ((channel == NULL) || (dnsrec == NULL)) {
    return;
  }

  /* For now, ares_search_int() uses the ares_callback prototype. We need to
   * wrap the callback passed to this function in ares__dnsrec_convert_cb, to
   * convert from ares_callback_dnsrec to ares_callback. Allocate the convert
   * arg structure here.
   */
  carg = ares_malloc_zero(sizeof(*carg));
  if (carg == NULL) {
    callback(arg, ARES_ENOMEM, 0, NULL);
    return;
  }
  carg->callback = callback;
  carg->arg = arg;

  ares__channel_lock(channel);
  ares_search_int(channel, dnsrec, ares__dnsrec_convert_cb, carg);
  ares__channel_unlock(channel);
}

static void search_callback(void *arg, int status, int timeouts,
                            unsigned char *abuf, int alen)
{
  struct search_query *squery  = (struct search_query *)arg;
  ares_channel_t      *channel = squery->channel;
  ares_dns_record_t   *dnsrep = NULL;
  ares_dns_rcode_t     rcode;
  size_t               ancount;
  ares_dns_record_t   *dnsrec = NULL;
  const char          *name;
  char                *s = NULL;
  ares_status_t        mystatus;

  squery->timeouts += (size_t)timeouts;

  if (status != ARES_SUCCESS) {
    end_squery(squery, (ares_status_t)status, abuf, (size_t)alen);
    return;
  }

  /* Convert the rcode and ancount from the response into an ares_status_t
   * value. Stop searching unless we got a non-fatal error.
   */
  mystatus = ares_dns_parse(abuf, (size_t)alen, 0, &dnsrep);
  if (mystatus != ARES_SUCCESS) {
    end_squery(squery, mystatus, abuf, (size_t)alen);
    return;
  }
  rcode = ares_dns_record_get_rcode(dnsrep);
  ancount = ares_dns_record_rr_cnt(dnsrep, ARES_SECTION_ANSWER);
  ares_dns_record_destroy(dnsrep);
  mystatus = ares_dns_query_reply_tostatus(rcode, ancount);

  if ((mystatus != ARES_ENODATA) && (mystatus != ARES_ESERVFAIL) &&
      (mystatus != ARES_ENOTFOUND)) {
    end_squery(squery, mystatus, abuf, (size_t)alen);
  } else {
    /* Save the status if we were trying as-is. */
    if (squery->trying_as_is) {
      squery->status_as_is = (int)mystatus;
    }

    /* If we ever get ARES_ENODATA along the way, record that; if the search
     * should run to the very end and we got at least one ARES_ENODATA,
     * then callers like ares_gethostbyname() may want to try a T_A search
     * even if the last domain we queried for T_AAAA resource records
     * returned ARES_ENOTFOUND.
     */
    if (mystatus == ARES_ENODATA) {
      squery->ever_got_nodata = ARES_TRUE;
    }

    if (squery->next_domain < squery->ndomains) {
      /* Try the next domain.
       *
       * First parse the encoded DNS record in the search_query structure, so
       * that we can append the next domain to it.
       */
      mystatus = ares_dns_parse(squery->buf, squery->buflen, 0, &dnsrec);
      if (mystatus != ARES_SUCCESS) {
        end_squery(squery, mystatus, NULL, 0);
      } else {
        /* Concatenate the name with the search domain and query using that. */
        if (ares_dns_record_query_cnt(dnsrec) != 1) {
          mystatus = ARES_EBADQUERY;
        } else {
          mystatus = ares_dns_record_query_get(dnsrec, 0, &name, NULL, NULL);
          if (mystatus == ARES_SUCCESS) {
            mystatus = ares__cat_domain(name,
                                        squery->domains[squery->next_domain],
                                        &s);
            if (mystatus == ARES_SUCCESS) {
              squery->trying_as_is = ARES_FALSE;
              squery->next_domain++;
              mystatus = ares__write_and_send_query(channel, dnsrec, s,
                                                    search_callback, arg);
              ares_free(s);
            }
          }
        }
        /* Clean up the DNS record object and handle any errors. */
        ares_dns_record_destroy(dnsrec);
        if (mystatus != ARES_SUCCESS) {
          end_squery(squery, mystatus, NULL, 0);
        }
      }
    } else if (squery->status_as_is == -1) {
      /* Try the name as-is at the end. */
      squery->trying_as_is = ARES_TRUE;
      ares_send(channel, squery->buf, (int)squery->buflen, search_callback,
                squery);
    } else {
      /* We have no more domains to search, return an appropriate response. */
      if (squery->status_as_is == ARES_ENOTFOUND && squery->ever_got_nodata) {
        end_squery(squery, ARES_ENODATA, NULL, 0);
      } else {
        end_squery(squery, (ares_status_t)squery->status_as_is, NULL, 0);
      }
    }
  }
}

/* Write and send a DNS record on a channel. The DNS record must represent a
 * query for a single name. An alternative name can be specified to temporarily
 * overwrite the name on the DNS record before doing so. Note that this only
 * affects the name in the question section; RRs are not affected.
 * This is used as a helper function in ares_search().
 */
static ares_status_t ares__write_and_send_query(ares_channel_t *channel,
                                                ares_dns_record_t *dnsrec,
                                                char *altname,
                                                ares_callback callback,
                                                void *arg)
{
  ares_status_t  status;
  unsigned char *buf;
  size_t         buflen;

  status = ares_dns_write_query_altname(dnsrec, altname, &buf, &buflen);
  if (status != ARES_SUCCESS) {
    return status;
  }

  ares_send(channel, buf, (int)buflen, callback, arg);
  ares_free(buf);
  return ARES_SUCCESS;
}


/* End a search query by invoking the user callback and freeing the
 * search_query structure.
 */
static void end_squery(struct search_query *squery, ares_status_t status,
                       unsigned char *abuf, size_t alen)
{
  squery->callback(squery->arg, (int)status, (int)squery->timeouts, abuf,
                   (int)alen);
  ares__strsplit_free(squery->domains, squery->ndomains);
  ares_free(squery->buf);
  ares_free(squery);
}

/* Concatenate two domains. */
ares_status_t ares__cat_domain(const char *name, const char *domain, char **s)
{
  size_t nlen = ares_strlen(name);
  size_t dlen = ares_strlen(domain);

  *s = ares_malloc(nlen + 1 + dlen + 1);
  if (!*s) {
    return ARES_ENOMEM;
  }
  memcpy(*s, name, nlen);
  (*s)[nlen] = '.';
  if (strcmp(domain, ".") == 0) {
    /* Avoid appending the root domain to the separator, which would set *s to
       an ill-formed value (ending in two consecutive dots). */
    dlen = 0;
  }
  memcpy(*s + nlen + 1, domain, dlen);
  (*s)[nlen + 1 + dlen] = 0;
  return ARES_SUCCESS;
}

static ares_status_t ares__lookup_hostaliases(const char *name, char **alias)
{
  ares_status_t       status      = ARES_SUCCESS;
  const char         *hostaliases = getenv("HOSTALIASES");
  ares__buf_t        *buf         = NULL;
  ares__llist_t      *lines       = NULL;
  ares__llist_node_t *node;

  *alias = NULL;

  if (hostaliases == NULL) {
    status = ARES_ENOTFOUND;
    goto done;
  }

  buf = ares__buf_create();
  if (buf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  status = ares__buf_load_file(hostaliases, buf);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  /* The HOSTALIASES file is structured as one alias per line.  The first
   * field in the line is the simple hostname with no periods, followed by
   * whitespace, then the full domain name, e.g.:
   *
   * c-ares  www.c-ares.org
   * curl    www.curl.se
   */

  status = ares__buf_split(buf, (const unsigned char *)"\n", 1,
                           ARES_BUF_SPLIT_TRIM, 0, &lines);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  for (node = ares__llist_node_first(lines); node != NULL;
       node = ares__llist_node_next(node)) {
    ares__buf_t *line         = ares__llist_node_val(node);
    char         hostname[64] = "";
    char         fqdn[256]    = "";

    /* Pull off hostname */
    ares__buf_tag(line);
    ares__buf_consume_nonwhitespace(line);
    if (ares__buf_tag_fetch_string(line, hostname, sizeof(hostname)) !=
        ARES_SUCCESS) {
      continue;
    }

    /* Match hostname */
    if (strcasecmp(hostname, name) != 0) {
      continue;
    }

    /* consume whitespace */
    ares__buf_consume_whitespace(line, ARES_TRUE);

    /* pull off fqdn */
    ares__buf_tag(line);
    ares__buf_consume_nonwhitespace(line);
    if (ares__buf_tag_fetch_string(line, fqdn, sizeof(fqdn)) != ARES_SUCCESS ||
        ares_strlen(fqdn) == 0) {
      continue;
    }

    /* Validate characterset */
    if (!ares__is_hostname(fqdn)) {
      continue;
    }

    *alias = ares_strdup(fqdn);
    if (*alias == NULL) {
      status = ARES_ENOMEM;
      goto done;
    }

    /* Good! */
    status = ARES_SUCCESS;
    goto done;
  }

  status = ARES_ENOTFOUND;

done:
  ares__buf_destroy(buf);
  ares__llist_destroy(lines);

  return status;
}

/* Determine if this name only yields one query.  If it does, set *s to
 * the string we should query, in an allocated buffer.  If not, set *s
 * to NULL.
 */
ares_status_t ares__single_domain(const ares_channel_t *channel,
                                  const char *name, char **s)
{
  size_t        len = ares_strlen(name);
  ares_status_t status;

  *s = NULL;

  /* If the name contains a trailing dot, then the single query is the name
   * sans the trailing dot.
   */
  if ((len > 0) && (name[len - 1] == '.')) {
    *s = ares_strdup(name);
    return (*s) ? ARES_SUCCESS : ARES_ENOMEM;
  }

  if (!(channel->flags & ARES_FLAG_NOALIASES) && !strchr(name, '.')) {
    status = ares__lookup_hostaliases(name, s);
    if (status != ARES_ENOTFOUND) {
      return status;
    }
  }

  if (channel->flags & ARES_FLAG_NOSEARCH || channel->ndomains == 0) {
    /* No domain search to do; just try the name as-is. */
    *s = ares_strdup(name);
    return (*s) ? ARES_SUCCESS : ARES_ENOMEM;
  }

  *s = NULL;
  return ARES_SUCCESS;
}

/* Callback function used to convert from the ares_callback prototype to the
 * ares_callback_dnsrec prototype, by parsing the result and passing that to
 * the inner callback.
 */
static void ares__dnsrec_convert_cb(void *arg, int status, int timeouts,
                                    unsigned char *abuf, int alen)
{
  struct dnsrec_convert_arg *carg = (struct dnsrec_convert_arg *)arg;
  ares_dns_record_t         *dnsrec = NULL;
  ares_status_t              mystatus;

  if (status != ARES_SUCCESS) {
    carg->callback(carg->arg, (ares_status_t)status, (size_t)timeouts, NULL);
  } else {
    /* Parse the result. */
    mystatus = ares_dns_parse(abuf, (size_t)alen, 0, &dnsrec);
    if (mystatus != ARES_SUCCESS) {
      carg->callback(carg->arg, mystatus, (size_t)timeouts, NULL);
    } else {
      carg->callback(carg->arg, ARES_SUCCESS, (size_t)timeouts, dnsrec);
      ares_dns_record_destroy(dnsrec);
    }
  }
  ares_free(carg);
}
