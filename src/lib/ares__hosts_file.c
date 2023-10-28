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
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif
#include <time.h>

struct ares_hosts_file;
typedef struct ares_hosts_file ares_hosts_file_t;

struct ares_hosts_file {
  time_t                ts;
  /*! iphash is the owner of the 'entry' object as there is only ever a single
   *  match to the object. */
  ares__htable_strvp_t *iphash;
  /*! hosthash does not own the entry so won't free on destruction */
  ares__htable_strvp_t *hosthash;
};

typedef struct {
  char          *ipaddr;
  ares__llist_t *hosts;
} ares_hosts_file_entry_t;


static ares_status_t ares__read_file_into_buf(const char *filename, ares__buf_t *buf)
{
  FILE          *fp      = NULL;
  unsigned char *ptr     = NULL;
  size_t         len     = 0;
  size_t         ptr_len = 0;
  ares_status_t  status;

  if (filename == NULL || buf == NULL)
    return ARES_EFORMERR;

  fp = fopen(filename, "rb");
  if (fp == NULL) {
    int error = ERRNO;
    switch (error) {
      case ENOENT:
      case ESRCH:
        status = ARES_ENOTFOUND;
        goto done;
      default:
        DEBUGF(fprintf(stderr, "fopen() failed with error: %d %s\n", error,
                       strerror(error)));
        DEBUGF(fprintf(stderr, "Error opening file: %s\n", filename));
        status = ARES_EFILE;
        goto done;
    }
  }

  /* Get length portably, fstat() is POSIX, not C */
  if (fseek(fp, 0, SEEK_END) != 0) {
    status = ARES_EFILE;
    goto done;
  }
  len = (size_t)ftell(fp);
  if (fseek(fp, 0, SEEK_SET) != 0) {
    status = ARES_EFILE;
    goto done;
  }

 if (len == 0) {
    status = ARES_SUCCESS;
    goto done;
  }

  /* Read entire data into buffer */
  ptr_len = len;
  ptr     = ares__buf_append_start(buf, &ptr_len);
  if (ptr == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  ptr_len = fread(ptr, 1, len, fp);
  if (ptr_len != len) {
    status = ARES_EFILE;
    goto done;
  }

  ares__buf_append_finish(buf, len);
  status = ARES_SUCCESS;

done:
  fclose(fp);
  return status;
}

static ares_bool_t ares__is_hostname(const char *str)
{
  size_t i;
  for (i=0; str[i] != 0; i++) {
    if (!ares__is_hostnamech(str[i]))
      return ARES_FALSE;
  }
  return ARES_TRUE;
}


static ares_bool_t ares__normalize_ipaddr(const char *ipaddr, char *out,
                                          size_t out_len)
{
  struct in_addr       addr4;
  struct ares_in6_addr addr6;
  int                  family = AF_UNSPEC;
  const void          *addr;

  if (ares_inet_pton(AF_INET, ipaddr, &addr4) > 0) {
    family = AF_INET;
    addr   = &addr4;
  } else if (ares_inet_pton(AF_INET6, ipaddr, &addr6) > 0) {
    family = AF_INET6;
    addr   = &addr6;
  } else {
    return ARES_FALSE;
  }

  if (!ares_inet_ntop(family, addr, out, (ares_socklen_t)out_len)) {
    return ARES_FALSE;
  }
  return ARES_TRUE;
}

static void ares__hosts_file_entry_destroy(ares_hosts_file_entry_t *entry)
{
  if (entry == NULL)
    return;

  ares__llist_destroy(entry->hosts);
  ares_free(entry->ipaddr);
  ares_free(entry);
}

static void ares__hosts_file_entry_destroy_cb(void *entry)
{
  ares__hosts_file_entry_destroy(entry);
}

static void ares__hosts_file_destroy(ares_hosts_file_t *hf)
{
  if (hf == NULL)
    return;

  ares__htable_strvp_destroy(hf->hosthash);
  ares__htable_strvp_destroy(hf->iphash);
  ares_free(hf);
}

static ares_hosts_file_t *ares__hosts_file_create(void)
{
  ares_hosts_file_t *hf = ares_malloc_zero(sizeof(*hf));
  if (hf == NULL) {
    goto fail;
  }

  hf->ts = time(NULL);

  hf->iphash = ares__htable_strvp_create(ares__hosts_file_entry_destroy_cb);
  if (hf->iphash == NULL) {
    goto fail;
  }

  hf->hosthash = ares__htable_strvp_create(NULL);
  if (hf->hosthash == NULL) {
    goto fail;
  }

fail:
  ares__hosts_file_destroy(hf);
  return NULL;
}

static ares_status_t ares__hosts_file_merge_entry(
  ares_hosts_file_entry_t *existing, ares_hosts_file_entry_t *entry)
{
  ares__llist_node_t *node;
  while ((node = ares__llist_node_first(entry->hosts)) != NULL) {
    char         *hostname = ares__llist_node_claim(node);

    if (ares__llist_insert_last(existing->hosts, hostname) == NULL) {
      ares_free(hostname);
      return ARES_ENOMEM;
    }
  }
  ares__hosts_file_entry_destroy(entry);
  return ARES_SUCCESS;
}

/*! entry is invalidated upon calling this function, always, even on error */
static ares_status_t ares__hosts_file_add(ares_hosts_file_t *hosts,
                                          ares_hosts_file_entry_t *entry)
{
  ares_hosts_file_entry_t *existing;
  ares_status_t            status = ARES_SUCCESS;
  ares__llist_node_t      *node;

  existing = ares__htable_strvp_get_direct(hosts->iphash, entry->ipaddr);
  if (existing != NULL) {
    status = ares__hosts_file_merge_entry(existing, entry);
    if (status != ARES_SUCCESS) {
      ares__hosts_file_entry_destroy(entry);
      return status;
    }
    /* entry was invalidated above by merging */
    entry = existing;
  } else {
    if (!ares__htable_strvp_insert(hosts->iphash, entry->ipaddr, entry)) {
      ares__hosts_file_entry_destroy(entry);
      return ARES_ENOMEM;
    }
  }

  for (node = ares__llist_node_first(entry->hosts); node != NULL;
       node = ares__llist_node_next(node)) {
    const char *val = ares__llist_node_val(node);

    /* First match wins, if its already there, skip */
    if (ares__htable_strvp_get(hosts->hosthash, val, NULL))
      continue;

    if (!ares__htable_strvp_insert(hosts->hosthash, val, entry)) {
      return ARES_ENOMEM;
    }
  }

  return ARES_SUCCESS;
}

static ares_status_t ares__parse_hosts_hostnames(ares__buf_t *buf,
                                                 ares_hosts_file_entry_t *entry)
{
  entry->hosts = ares__llist_create(ares_free);
  if (entry->hosts == NULL)
    return ARES_ENOMEM;

  /* Parse hostnames and aliases */
  while (ares__buf_len(buf)) {
    char          hostname[256];
    char         *temp;
    ares_status_t status;
    unsigned char comment = '#';

    ares__buf_consume_whitespace(buf, ARES_FALSE);

    if (ares__buf_len(buf) == 0)
      break;

    /* See if it is a comment, if so stop processing */
    if (ares__buf_begins_with(buf, &comment, 1)) {
      break;
    }

    ares__buf_tag(buf);

    /* Must be at end of line */
    if (ares__buf_consume_nonwhitespace(buf) == 0)
      break;

    status = ares__buf_tag_fetch_string(buf, hostname, sizeof(hostname));
    if (status != ARES_SUCCESS) {
      /* Bad entry, just ignore as long as its not the first.  If its the first,
       * it must be valid */
      if (ares__llist_len(entry->hosts) == 0)
        return ARES_EBADSTR;

      continue;
    }

    /* Validate it is a valid hostname characterset */
    if (!ares__is_hostname(hostname))
      continue;

    /* Add to list */
    temp = ares_strdup(hostname);
    if (temp == NULL)
      return ARES_ENOMEM;

    if (ares__llist_insert_last(entry->hosts, temp) == NULL) {
      ares_free(temp);
      return ARES_ENOMEM;
    }
  }

  /* Must have at least 1 entry */
  if (ares__llist_len(entry->hosts) == 0)
    return ARES_EBADSTR;

  return ARES_SUCCESS;
}


static ares_status_t ares__parse_hosts(const char *filename,
                                       ares_hosts_file_t **out)
{
  ares__buf_t       *buf     = NULL;
  ares_status_t      status  = ARES_EBADRESP;
  ares_hosts_file_t *hf      = NULL;

  *out = NULL;

  buf     = ares__buf_create();
  if (buf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  status = ares__read_file_into_buf(filename, buf);
  if (status != ARES_SUCCESS)
    goto done;

  hf = ares__hosts_file_create();
  if (hf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  while (ares__buf_len(buf)) {
    char                     addr[INET6_ADDRSTRLEN];
    ares_hosts_file_entry_t *entry = NULL;
    unsigned char            comment = '#';

    /* -- Start of new line here -- */

    /* Consume any leading whitespace */
    ares__buf_consume_whitespace(buf, ARES_FALSE);

    if (ares__buf_len(buf) == 0)
      break;

    /* See if it is a comment, if so, consume remaining line */
    if (ares__buf_begins_with(buf, &comment, 1)) {
      ares__buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    /* Pull off ip address */
    ares__buf_tag(buf);
    ares__buf_consume_nonwhitespace(buf);
    status = ares__buf_tag_fetch_string(buf, addr, sizeof(addr));
    if (status != ARES_SUCCESS) {
      /* Bad line, consume and go onto next */
      ares__buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    /* Validate and normalize the ip address format */
    if (!ares__normalize_ipaddr(addr, addr, sizeof(addr))) {
      /* Bad line, consume and go onto next */
      ares__buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    entry = ares_malloc_zero(sizeof(*entry));
    if (entry == NULL) {
      status = ARES_ENOMEM;
      goto done;
    }

    entry->ipaddr = ares_strdup(addr);
    if (entry->ipaddr == NULL) {
      status = ARES_ENOMEM;
      goto done;
    }

    status = ares__parse_hosts_hostnames(buf, entry);
    if (status == ARES_ENOMEM) {
      ares__hosts_file_entry_destroy(entry);
      goto done;
    } else if (status != ARES_SUCCESS) {
      /* Bad line, consume and go onto next */
      ares__hosts_file_entry_destroy(entry);
      ares__buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    status = ares__hosts_file_add(hf, entry);
    entry  = NULL; /* is always invalidated by this function, even on error */
    if (status != ARES_SUCCESS) {
      goto done;
    }

    /* Go to next line */
    ares__buf_consume_line(buf, ARES_TRUE);
  }

done:
  ares__buf_destroy(buf);
  if (status != ARES_SUCCESS) {
    ares__hosts_file_destroy(hf);
  } else {
    *out = hf;
  }
  return status;
}


static ares_bool_t ares__hosts_expired(const char *filename, const ares_hosts_file_t *hf)
{
  time_t mod_ts = 0;

#ifdef HAVE_STAT
  struct stat st;
  if (stat(filename, &st) == 0) {
    mod_ts = st.st_mtime;
  }
#elif WIN32
  struct _stat st;
  if (_stat(filename, &st) == 0) {
    mod_ts = st.st_mtime;
  }
#endif

  /* Expire every 60s if we can't get a time */
  if (mod_ts == 0) {
    mod_ts = time(NULL) - 60;
  }
  if (hf->ts <= mod_ts)
    return ARES_TRUE;

  return ARES_FALSE;
}

