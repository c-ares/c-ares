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

static void search_callback(void *arg, int status, int timeouts,
                            unsigned char *abuf, int alen);
static void end_squery(struct search_query *squery, ares_status_t status,
                       unsigned char *abuf, size_t alen);

static void ares_search_int(ares_channel_t *channel, ares_dns_record_t *dnsrec,
                            ares_callback callback, void *arg)
{
  struct search_query *squery;
  const char          *name;
  char                *s = NULL;
  char                *qname;
  unsigned char       *buf = NULL;
  size_t               buflen;
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
  ares_dns_record_query_get(dnsrec, 0, &name, NULL, NULL);

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
    /* We only have a single domain to search, so do it here. The domain to
     * search may be different to the name passed in, so temporarily
     * overwrite it before encoding the DNS record.
     *
     * TODO: Temporarily overwriting the name should be a helper function.
     *       Modifying the ares_dns_record_t structure internals should not be
     *       done here.
     */
    qname = dnsrec->qd[0].name;
    dnsrec->qd[0].name = s;
    status = ares_dns_write(dnsrec, &buf, &buflen);
    dnsrec->qd[0].name = qname;
    ares_free(s);
    if (status != ARES_SUCCESS) {
      callback(arg, (int)status, 0, NULL, 0);
      return;
    }

    ares_send(channel, buf, (int)buflen, callback, arg);
    ares_free_string(buf);
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
      ares_free_string(squery->buf);
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
    /* Try the name as-is last; start with the first search domain.
     *
     * Concatenate the name with the first search domain and temporarily
     * overwrite the original name before encoding the DNS record.
     */
    status = ares__cat_domain(name, squery->domains[0], &s);
    if (status != ARES_SUCCESS) {
      end_squery(squery, status, NULL, 0);
      return;
    }
    qname = dnsrec->qd[0].name;
    dnsrec->qd[0].name = s;
    status = ares_dns_write(dnsrec, &buf, &buflen);
    dnsrec->qd[0].name = qname;
    ares_free(s);
    if (status != ARES_SUCCESS) {
      end_squery(squery, status, NULL, 0);
      return;
    }

    squery->next_domain  = 1;
    squery->trying_as_is = ARES_FALSE;
    ares_send(channel, buf, (int)buflen, callback, arg);
    ares_free_string(buf);
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
  int                max_udp_size;
  int                rd;

  if ((channel == NULL) || (name == NULL)) {
    return;
  }

  rd = !(channel->flags & ARES_FLAG_NORECURSE);
  max_udp_size = (channel->flags & ARES_FLAG_EDNS) ? (int)channel->ednspsz : 0;
  status = ares_dns_record_create_query(&dnsrec, name, dnsclass, type, 0, rd,
                                        max_udp_size);
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
                        ares_callback callback, void *arg)
{
  if ((channel == NULL) || (dnsrec == NULL)) {
    return;
  }
  ares__channel_lock(channel);
  ares_search_int(channel, dnsrec, callback, arg);
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
  char                *qname;
  unsigned char       *buf = NULL;
  size_t               buflen;
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
  mystatus = ares_dns_query_reply_tostatus(rcode, ancount);
  ares_dns_record_destroy(dnsrep);
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
        /* Concatenate the name with the search domain and temporarily
         * overwrite the original name before re-encoding the DNS record.
         */
        if (ares_dns_record_query_cnt(dnsrec) != 1) {
          end_squery(squery, ARES_EBADQUERY, NULL, 0);
          ares_dns_record_destroy(dnsrec);
          return;
        }
        ares_dns_record_query_get(dnsrec, 0, &name, NULL, NULL);
        mystatus = ares__cat_domain(name, squery->domains[squery->next_domain],
                                    &s);
        if (mystatus != ARES_SUCCESS) {
          end_squery(squery, mystatus, NULL, 0);
          ares_dns_record_destroy(dnsrec);
          return;
        }
        qname = dnsrec->qd[0].name;
        dnsrec->qd[0].name = s;
        mystatus = ares_dns_write(dnsrec, &buf, &buflen);
        dnsrec->qd[0].name = qname;
        ares_free(s);
        if (mystatus != ARES_SUCCESS) {
          end_squery(squery, mystatus, NULL, 0);
          ares_dns_record_destroy(dnsrec);
          return;
        }

        squery->trying_as_is = ARES_FALSE;
        squery->next_domain++;
        ares_send(channel, buf, (int)buflen, search_callback, arg);
        ares_free_string(buf);
        ares_dns_record_destroy(dnsrec);
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

/* End a search query by invoking the user callback and freeing the
 * search_query structure.
 */
static void end_squery(struct search_query *squery, ares_status_t status,
                       unsigned char *abuf, size_t alen)
{
  squery->callback(squery->arg, (int)status, (int)squery->timeouts, abuf,
                   (int)alen);
  ares__strsplit_free(squery->domains, squery->ndomains);
  ares_free_string(squery->buf);
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

/* Determine if this name only yields one query.  If it does, set *s to
 * the string we should query, in an allocated buffer.  If not, set *s
 * to NULL.
 */
ares_status_t ares__single_domain(const ares_channel_t *channel,
                                  const char *name, char **s)
{
  size_t        len = ares_strlen(name);
  const char   *hostaliases;
  FILE         *fp;
  char         *line = NULL;
  ares_status_t status;
  size_t        linesize;
  const char   *p;
  const char   *q;
  int           error;

  /* If the name contains a trailing dot, then the single query is the name
   * sans the trailing dot.
   */
  if ((len > 0) && (name[len - 1] == '.')) {
    *s = ares_strdup(name);
    return (*s) ? ARES_SUCCESS : ARES_ENOMEM;
  }

  if (!(channel->flags & ARES_FLAG_NOALIASES) && !strchr(name, '.')) {
    /* The name might be a host alias. */
    hostaliases = getenv("HOSTALIASES");
    if (hostaliases) {
      fp = fopen(hostaliases, "r");
      if (fp) {
        while ((status = ares__read_line(fp, &line, &linesize)) ==
               ARES_SUCCESS) {
          if (strncasecmp(line, name, len) != 0 || !ISSPACE(line[len])) {
            continue;
          }
          p = line + len;
          while (ISSPACE(*p)) {
            p++;
          }
          if (*p) {
            q = p + 1;
            while (*q && !ISSPACE(*q)) {
              q++;
            }
            *s = ares_malloc((size_t)(q - p + 1));
            if (*s) {
              memcpy(*s, p, (size_t)(q - p));
              (*s)[q - p] = 0;
            }
            ares_free(line);
            fclose(fp);
            return (*s) ? ARES_SUCCESS : ARES_ENOMEM;
          }
        }
        ares_free(line);
        fclose(fp);
        if (status != ARES_SUCCESS && status != ARES_EOF) {
          return status;
        }
      } else {
        error = ERRNO;
        switch (error) {
          case ENOENT:
          case ESRCH:
            break;
          default:
            DEBUGF(fprintf(stderr, "fopen() failed with error: %d %s\n", error,
                           strerror(error)));
            DEBUGF(fprintf(stderr, "Error opening file: %s\n", hostaliases));
            *s = NULL;
            return ARES_EFILE;
        }
      }
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
