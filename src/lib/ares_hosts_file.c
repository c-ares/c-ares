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
#include "ares_private.h"
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#include <time.h>

#ifdef USE_WINSOCK
#  define DATABASEPATH         "DatabasePath"
#  define WIN_PATH_HOSTS       "\\hosts"
#endif

/* HOSTS FILE PROCESSING OVERVIEW
 * ==============================
 * The hosts file on the system contains static entries to be processed locally
 * rather than querying the nameserver.  Each row is an IP address followed by
 * a list of space delimited hostnames that match the ip address.  This is used
 * for both forward and reverse lookups.
 *
 * We are caching the entire parsed hosts file for performance reasons.  Some
 * files may be quite sizable and as per Issue #458 can approach 1/2MB in size,
 * and the parse overhead on a rapid succession of queries can be quite large.
 * The entries are stored in forwards and backwards hashtables so we can get
 * O(1) performance on lookup.  The file is cached until the file modification
 * timestamp changes.
 *
 * The hosts file processing is quite unique. It has to merge all related hosts
 * and ips into a single entry due to file formatting requirements.  For
 * instance take the below:
 *
 * 127.0.0.1    localhost.localdomain localhost
 * ::1          localhost.localdomain localhost
 * 192.168.1.1  host.example.com host
 * 192.168.1.5  host.example.com host
 * 2620:1234::1 host.example.com host6.example.com host6 host
 *
 * STORAGE MODEL: BIPARTITE ADJACENCY
 * ----------------------------------
 * The hosts file is stored as a bipartite adjacency between hostnames and
 * addresses.  Every (hostname, address) edge that appears on any line is
 * recorded in both directions:
 *   - hosthash: hostname -> ares_llist_t of the addresses that hostname
 *     appeared on a line with (file-ordered, de-duplicated)
 *   - iphash:   address  -> ares_llist_t of the hostnames that appeared on a
 *     line with that address (file-ordered, de-duplicated)
 *
 * A forward lookup (by name) or reverse lookup (by ip) builds a transient,
 * fully address-scoped result entry from the relevant adjacency list.  Aliases
 * are address-scoped: they are exactly the hostnames that share an address with
 * the queried name.  Recording every edge is correct by construction -- it does
 * not drop "bridge" lines (a line whose ip already belongs to one hostname and
 * whose hostname belongs to another), which the older merged store did,
 * silently losing addresses (Issue #1049).
 *
 * Memory tradeoff: keeping a hostname->address list plus an address->hostname
 * list for every edge roughly doubles memory versus a naive merged store on
 * very large hosts files (e.g. StevenBlack/hosts, ~80k hostnames).  We accept
 * this deliberately in exchange for correct, leak-free results.
 */

struct ares_hosts_file {
  time_t               ts;
  /*! cache the filename so we know if the filename changes it automatically
   *  invalidates the cache */
  char                *filename;
  /*! address (normalized str) -> ares_llist_t of hostname strings that appeared
   *  on a line with that address (file-ordered, de-duplicated).  Owns the
   *  llist values via ares_hosts_list_destroy_cb. */
  ares_htable_strvp_t *iphash;
  /*! hostname (str) -> ares_llist_t of address strings that hostname appeared
   *  on a line with (file-ordered, de-duplicated).  Owns the llist values via
   *  ares_hosts_list_destroy_cb. */
  ares_htable_strvp_t *hosthash;
};

struct ares_hosts_entry {
  ares_llist_t *ips;
  ares_llist_t *hosts;
};

const void *ares_dns_pton(const char *ipaddr, struct ares_addr *addr,
                          size_t *out_len)
{
  const void *ptr     = NULL;
  size_t      ptr_len = 0;

  if (ipaddr == NULL || addr == NULL || out_len == NULL) {
    return NULL; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *out_len = 0;

  if (addr->family == AF_INET &&
      ares_inet_pton(AF_INET, ipaddr, &addr->addr.addr4) > 0) {
    ptr     = &addr->addr.addr4;
    ptr_len = sizeof(addr->addr.addr4);
  } else if (addr->family == AF_INET6 &&
             ares_inet_pton(AF_INET6, ipaddr, &addr->addr.addr6) > 0) {
    ptr     = &addr->addr.addr6;
    ptr_len = sizeof(addr->addr.addr6);
  } else if (addr->family == AF_UNSPEC) {
    if (ares_inet_pton(AF_INET, ipaddr, &addr->addr.addr4) > 0) {
      addr->family = AF_INET;
      ptr          = &addr->addr.addr4;
      ptr_len      = sizeof(addr->addr.addr4);
    } else if (ares_inet_pton(AF_INET6, ipaddr, &addr->addr.addr6) > 0) {
      addr->family = AF_INET6;
      ptr          = &addr->addr.addr6;
      ptr_len      = sizeof(addr->addr.addr6);
    }
  }

  *out_len = ptr_len;
  return ptr;
}

static ares_bool_t ares_normalize_ipaddr(const char *ipaddr, char *out,
                                         size_t out_len)
{
  struct ares_addr data;
  const void      *addr;
  size_t           addr_len = 0;

  memset(&data, 0, sizeof(data));
  data.family = AF_UNSPEC;

  addr = ares_dns_pton(ipaddr, &data, &addr_len);
  if (addr == NULL) {
    return ARES_FALSE;
  }

  if (!ares_inet_ntop(data.family, addr, out, (ares_socklen_t)out_len)) {
    return ARES_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  return ARES_TRUE;
}

void ares_hosts_entry_destroy(ares_hosts_entry_t *entry)
{
  if (entry == NULL) {
    return;
  }

  ares_llist_destroy(entry->hosts);
  ares_llist_destroy(entry->ips);
  ares_free(entry);
}

/* htable value destructor: each value is an ares_llist_t (of ip or hostname
 * strings) */
static void ares_hosts_list_destroy_cb(void *arg)
{
  ares_llist_destroy(arg);
}

void ares_hosts_file_destroy(ares_hosts_file_t *hf)
{
  if (hf == NULL) {
    return;
  }

  ares_free(hf->filename);
  ares_htable_strvp_destroy(hf->hosthash);
  ares_htable_strvp_destroy(hf->iphash);
  ares_free(hf);
}

static ares_hosts_file_t *ares_hosts_file_create(const char *filename)
{
  ares_hosts_file_t *hf = ares_malloc_zero(sizeof(*hf));
  if (hf == NULL) {
    goto fail;
  }

  hf->ts = time(NULL);

  hf->filename = ares_strdup(filename);
  if (hf->filename == NULL) {
    goto fail;
  }

  hf->iphash = ares_htable_strvp_create(ares_hosts_list_destroy_cb);
  if (hf->iphash == NULL) {
    goto fail;
  }

  hf->hosthash = ares_htable_strvp_create(ares_hosts_list_destroy_cb);
  if (hf->hosthash == NULL) {
    goto fail;
  }

  return hf;

fail:
  ares_hosts_file_destroy(hf);
  return NULL;
}

/* Case-insensitive membership test for an ip/host string list */
static ares_bool_t ares_hosts_iplist_contains(ares_llist_t *list,
                                              const char   *ipaddr)
{
  ares_llist_node_t *node;

  for (node = ares_llist_node_first(list); node != NULL;
       node = ares_llist_node_next(node)) {
    if (ares_strcaseeq(ares_llist_node_val(node), ipaddr)) {
      return ARES_TRUE;
    }
  }

  return ARES_FALSE;
}

/*! entry represents a single parsed line (one ip, its hostnames).  It is always
 *  invalidated (destroyed) upon calling this function, even on error.  Each
 *  (hostname, ipaddress) edge is recorded in both directions. */
static ares_status_t ares_hosts_file_add(ares_hosts_file_t  *hosts,
                                         ares_hosts_entry_t *entry)
{
  const char        *ipaddr = ares_llist_first_val(entry->ips);
  ares_llist_node_t *node;
  ares_status_t      status = ARES_SUCCESS;

  for (node = ares_llist_node_first(entry->hosts); node != NULL;
       node = ares_llist_node_next(node)) {
    const char   *host = ares_llist_node_val(node);
    ares_llist_t *fwd;
    ares_llist_t *rev;
    char         *tmp;

    /* Forward edge: hostname -> ip */
    fwd = ares_htable_strvp_get_direct(hosts->hosthash, host);
    if (fwd == NULL) {
      fwd = ares_llist_create(ares_free);
      if (fwd == NULL) {
        status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
      if (!ares_htable_strvp_insert(hosts->hosthash, host, fwd)) {
        ares_llist_destroy(fwd); /* LCOV_EXCL_LINE: OutOfMemory */
        status = ARES_ENOMEM;    /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;               /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }

    /* De-dupe this (host, ip) edge against the (usually tiny) forward list.  If
     * the edge already exists, so does its reverse, so skip both. */
    if (ares_hosts_iplist_contains(fwd, ipaddr)) {
      continue;
    }

    tmp = ares_strdup(ipaddr);
    if (tmp == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
    if (ares_llist_insert_last(fwd, tmp) == NULL) {
      ares_free(tmp);       /* LCOV_EXCL_LINE: OutOfMemory */
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* Reverse edge: ip -> hostname.  The edge was new above, so 'host' is not
     * yet in the reverse list either. */
    rev = ares_htable_strvp_get_direct(hosts->iphash, ipaddr);
    if (rev == NULL) {
      rev = ares_llist_create(ares_free);
      if (rev == NULL) {
        status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
      if (!ares_htable_strvp_insert(hosts->iphash, ipaddr, rev)) {
        ares_llist_destroy(rev); /* LCOV_EXCL_LINE: OutOfMemory */
        status = ARES_ENOMEM;    /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;               /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }

    tmp = ares_strdup(host);
    if (tmp == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
    if (ares_llist_insert_last(rev, tmp) == NULL) {
      ares_free(tmp);       /* LCOV_EXCL_LINE: OutOfMemory */
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

done:
  ares_hosts_entry_destroy(entry);
  return status;
}

static ares_bool_t ares_hosts_entry_isdup(ares_hosts_entry_t *entry,
                                          const char         *host)
{
  ares_llist_node_t *node;

  for (node = ares_llist_node_first(entry->hosts); node != NULL;
       node = ares_llist_node_next(node)) {
    const char *myhost = ares_llist_node_val(node);
    if (ares_strcaseeq(myhost, host)) {
      return ARES_TRUE;
    }
  }

  return ARES_FALSE;
}

static ares_status_t ares_parse_hosts_hostnames(ares_buf_t         *buf,
                                                ares_hosts_entry_t *entry)
{
  entry->hosts = ares_llist_create(ares_free);
  if (entry->hosts == NULL) {
    return ARES_ENOMEM;
  }

  /* Parse hostnames and aliases */
  while (ares_buf_len(buf)) {
    char          hostname[256];
    char         *temp;
    ares_status_t status;
    unsigned char comment = '#';

    ares_buf_consume_whitespace(buf, ARES_FALSE);

    if (ares_buf_len(buf) == 0) {
      break;
    }

    /* See if it is a comment, if so stop processing */
    if (ares_buf_begins_with(buf, &comment, 1)) {
      break;
    }

    ares_buf_tag(buf);

    /* Must be at end of line */
    if (ares_buf_consume_nonwhitespace(buf) == 0) {
      break;
    }

    status = ares_buf_tag_fetch_string(buf, hostname, sizeof(hostname));
    if (status != ARES_SUCCESS) {
      /* Bad entry, just ignore as long as its not the first.  If its the first,
       * it must be valid */
      if (ares_llist_len(entry->hosts) == 0) {
        return ARES_EBADSTR;
      }

      continue;
    }

    /* Validate it is a valid hostname characterset */
    if (!ares_is_hostname(hostname)) {
      continue;
    }

    /* Don't add a duplicate to the same entry */
    if (ares_hosts_entry_isdup(entry, hostname)) {
      continue;
    }

    /* Add to list */
    temp = ares_strdup(hostname);
    if (temp == NULL) {
      return ARES_ENOMEM;
    }

    if (ares_llist_insert_last(entry->hosts, temp) == NULL) {
      ares_free(temp);
      return ARES_ENOMEM;
    }
  }

  /* Must have at least 1 entry */
  if (ares_llist_len(entry->hosts) == 0) {
    return ARES_EBADSTR;
  }

  return ARES_SUCCESS;
}

static ares_status_t ares_parse_hosts_ipaddr(ares_buf_t          *buf,
                                             ares_hosts_entry_t **entry_out)
{
  char                addr[INET6_ADDRSTRLEN];
  char               *temp;
  ares_hosts_entry_t *entry = NULL;
  ares_status_t       status;

  *entry_out = NULL;

  ares_buf_tag(buf);
  ares_buf_consume_nonwhitespace(buf);
  status = ares_buf_tag_fetch_string(buf, addr, sizeof(addr));
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* Validate and normalize the ip address format */
  if (!ares_normalize_ipaddr(addr, addr, sizeof(addr))) {
    return ARES_EBADSTR;
  }

  entry = ares_malloc_zero(sizeof(*entry));
  if (entry == NULL) {
    return ARES_ENOMEM;
  }

  entry->ips = ares_llist_create(ares_free);
  if (entry->ips == NULL) {
    ares_hosts_entry_destroy(entry);
    return ARES_ENOMEM;
  }

  temp = ares_strdup(addr);
  if (temp == NULL) {
    ares_hosts_entry_destroy(entry);
    return ARES_ENOMEM;
  }

  if (ares_llist_insert_first(entry->ips, temp) == NULL) {
    ares_free(temp);
    ares_hosts_entry_destroy(entry);
    return ARES_ENOMEM;
  }

  *entry_out = entry;

  return ARES_SUCCESS;
}

static ares_status_t ares_parse_hosts(const char         *filename,
                                      ares_hosts_file_t **out)
{
  ares_buf_t         *buf    = NULL;
  ares_status_t       status = ARES_EBADRESP;
  ares_hosts_file_t  *hf     = NULL;
  ares_hosts_entry_t *entry  = NULL;

  *out = NULL;

  buf = ares_buf_create();
  if (buf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  status = ares_buf_load_file(filename, buf);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  hf = ares_hosts_file_create(filename);
  if (hf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  while (ares_buf_len(buf)) {
    unsigned char comment = '#';

    /* -- Start of new line here -- */

    /* Consume any leading whitespace */
    ares_buf_consume_whitespace(buf, ARES_FALSE);

    if (ares_buf_len(buf) == 0) {
      break;
    }

    /* See if it is a comment, if so, consume remaining line */
    if (ares_buf_begins_with(buf, &comment, 1)) {
      ares_buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    /* Pull off ip address */
    status = ares_parse_hosts_ipaddr(buf, &entry);
    if (status == ARES_ENOMEM) {
      goto done;
    }
    if (status != ARES_SUCCESS) {
      /* Bad line, consume and go onto next */
      ares_buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    /* Parse of the hostnames */
    status = ares_parse_hosts_hostnames(buf, entry);
    if (status == ARES_ENOMEM) {
      goto done;
    } else if (status != ARES_SUCCESS) {
      /* Bad line, consume and go onto next */
      ares_hosts_entry_destroy(entry);
      entry = NULL;
      ares_buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    /* Append the successful entry to the hosts file */
    status = ares_hosts_file_add(hf, entry);
    entry  = NULL; /* is always invalidated by this function, even on error */
    if (status != ARES_SUCCESS) {
      goto done;
    }

    /* Go to next line */
    ares_buf_consume_line(buf, ARES_TRUE);
  }

  status = ARES_SUCCESS;

done:
  ares_hosts_entry_destroy(entry);
  ares_buf_destroy(buf);
  if (status != ARES_SUCCESS) {
    ares_hosts_file_destroy(hf);
  } else {
    *out = hf;
  }
  return status;
}

static ares_bool_t ares_hosts_expired(const char              *filename,
                                      const ares_hosts_file_t *hf)
{
  time_t mod_ts = 0;

#ifdef HAVE_STAT
  struct stat st;
  if (stat(filename, &st) == 0) {
    mod_ts = st.st_mtime;
  }
#elif defined(_WIN32)
  struct _stat st;
  if (_stat(filename, &st) == 0) {
    mod_ts = st.st_mtime;
  }
#else
  (void)filename;
#endif

  if (hf == NULL) {
    return ARES_TRUE;
  }

  /* Expire every 60s if we can't get a time */
  if (mod_ts == 0) {
    mod_ts =
      time(NULL) - 60; /* LCOV_EXCL_LINE: only on systems without stat() */
  }

  /* If filenames are different, its expired */
  if (!ares_strcaseeq(hf->filename, filename)) {
    return ARES_TRUE;
  }

  if (hf->ts <= mod_ts) {
    return ARES_TRUE;
  }

  return ARES_FALSE;
}

static ares_status_t ares_hosts_path(const ares_channel_t *channel,
                                     ares_bool_t use_env, char **path)
{
  char *path_hosts = NULL;

  *path = NULL;

  if (channel->hosts_path) {
    path_hosts = ares_strdup(channel->hosts_path);
    if (!path_hosts) {
      return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  if (use_env) {
    if (path_hosts) {
      ares_free(path_hosts);
    }

    path_hosts = ares_strdup(getenv("CARES_HOSTS"));
    if (!path_hosts) {
      return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  if (!path_hosts) {
#if defined(USE_WINSOCK)
    char  PATH_HOSTS[MAX_PATH] = "";
    char  tmp[MAX_PATH];
    HKEY  hkeyHosts;
    DWORD dwLength = sizeof(tmp);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, WIN_NS_NT_KEY, 0, KEY_READ,
                      &hkeyHosts) != ERROR_SUCCESS) {
      return ARES_ENOTFOUND;
    }
    RegQueryValueExA(hkeyHosts, DATABASEPATH, NULL, NULL, (LPBYTE)tmp,
                     &dwLength);
    ExpandEnvironmentStringsA(tmp, PATH_HOSTS, MAX_PATH);
    RegCloseKey(hkeyHosts);
    if (strlen(PATH_HOSTS)+strlen(WIN_PATH_HOSTS) >= MAX_PATH) {
      return ARES_ENOTFOUND;
    }
    strcat(PATH_HOSTS, WIN_PATH_HOSTS);
#elif defined(WATT32)
    const char *PATH_HOSTS = _w32_GetHostsFile();

    if (!PATH_HOSTS) {
      return ARES_ENOTFOUND;
    }
#endif
    path_hosts = ares_strdup(PATH_HOSTS);
    if (!path_hosts) {
      return ARES_ENOMEM;
    }
  }

  *path = path_hosts;
  return ARES_SUCCESS;
}

static ares_status_t ares_hosts_update(ares_channel_t *channel,
                                       ares_bool_t     use_env)
{
  ares_status_t status;
  char         *filename = NULL;

  status = ares_hosts_path(channel, use_env, &filename);
  if (status != ARES_SUCCESS) {
    return status;
  }

  if (!ares_hosts_expired(filename, channel->hf)) {
    ares_free(filename);
    return ARES_SUCCESS;
  }

  ares_hosts_file_destroy(channel->hf);
  channel->hf = NULL;

  status = ares_parse_hosts(filename, &channel->hf);
  ares_free(filename);
  return status;
}

ares_status_t ares_hosts_search_ipaddr(ares_channel_t *channel,
                                       ares_bool_t use_env, const char *ipaddr,
                                       ares_hosts_entry_t **entry)
{
  ares_status_t       status;
  char                addr[INET6_ADDRSTRLEN];
  ares_llist_t       *names;
  ares_hosts_entry_t *e = NULL;
  ares_llist_node_t  *node;
  char               *tmp;

  *entry = NULL;

  status = ares_hosts_update(channel, use_env);
  if (status != ARES_SUCCESS) {
    return status;
  }

  if (channel->hf == NULL) {
    return ARES_ENOTFOUND; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (!ares_normalize_ipaddr(ipaddr, addr, sizeof(addr))) {
    return ARES_EBADNAME;
  }

  names = ares_htable_strvp_get_direct(channel->hf->iphash, addr);
  if (names == NULL) {
    return ARES_ENOTFOUND;
  }

  /* Build a transient result entry scoped to this address */
  e = ares_malloc_zero(sizeof(*e));
  if (e == NULL) {
    return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  e->ips   = ares_llist_create(ares_free);
  e->hosts = ares_llist_create(ares_free);
  if (e->ips == NULL || e->hosts == NULL) {
    ares_hosts_entry_destroy(e); /* LCOV_EXCL_LINE: OutOfMemory */
    return ARES_ENOMEM;          /* LCOV_EXCL_LINE: OutOfMemory */
  }

  tmp = ares_strdup(addr);
  if (tmp == NULL) {
    ares_hosts_entry_destroy(e); /* LCOV_EXCL_LINE: OutOfMemory */
    return ARES_ENOMEM;          /* LCOV_EXCL_LINE: OutOfMemory */
  }
  if (ares_llist_insert_last(e->ips, tmp) == NULL) {
    ares_free(tmp);              /* LCOV_EXCL_LINE: OutOfMemory */
    ares_hosts_entry_destroy(e); /* LCOV_EXCL_LINE: OutOfMemory */
    return ARES_ENOMEM;          /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* All hostnames that appeared on a line with this address, in file order.
   * Cap at 101 (canonical + 100 aliases). */
  for (node = ares_llist_node_first(names); node != NULL;
       node = ares_llist_node_next(node)) {
    const char *nm = ares_llist_node_val(node);

    if (ares_llist_len(e->hosts) >= 101) {
      break; /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    tmp = ares_strdup(nm);
    if (tmp == NULL) {
      ares_hosts_entry_destroy(e); /* LCOV_EXCL_LINE: OutOfMemory */
      return ARES_ENOMEM;          /* LCOV_EXCL_LINE: OutOfMemory */
    }
    if (ares_llist_insert_last(e->hosts, tmp) == NULL) {
      ares_free(tmp);              /* LCOV_EXCL_LINE: OutOfMemory */
      ares_hosts_entry_destroy(e); /* LCOV_EXCL_LINE: OutOfMemory */
      return ARES_ENOMEM;          /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  *entry = e;
  return ARES_SUCCESS;
}

ares_status_t ares_hosts_search_host(ares_channel_t *channel,
                                     ares_bool_t use_env, const char *host,
                                     ares_hosts_entry_t **entry)
{
  ares_status_t       status;
  ares_llist_t       *iplist;
  ares_hosts_entry_t *e = NULL;
  ares_llist_node_t  *ipnode;
  char               *tmp;

  *entry = NULL;

  status = ares_hosts_update(channel, use_env);
  if (status != ARES_SUCCESS) {
    return status;
  }

  if (channel->hf == NULL) {
    return ARES_ENOTFOUND; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  iplist = ares_htable_strvp_get_direct(channel->hf->hosthash, host);
  if (iplist == NULL) {
    return ARES_ENOTFOUND;
  }

  /* Build a transient result entry scoped to this hostname */
  e = ares_malloc_zero(sizeof(*e));
  if (e == NULL) {
    return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  e->ips   = ares_llist_create(ares_free);
  e->hosts = ares_llist_create(ares_free);
  if (e->ips == NULL || e->hosts == NULL) {
    ares_hosts_entry_destroy(e); /* LCOV_EXCL_LINE: OutOfMemory */
    return ARES_ENOMEM;          /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* E->ips = the addresses this hostname appeared with, in file order */
  for (ipnode = ares_llist_node_first(iplist); ipnode != NULL;
       ipnode = ares_llist_node_next(ipnode)) {
    tmp = ares_strdup(ares_llist_node_val(ipnode));
    if (tmp == NULL) {
      ares_hosts_entry_destroy(e); /* LCOV_EXCL_LINE: OutOfMemory */
      return ARES_ENOMEM;          /* LCOV_EXCL_LINE: OutOfMemory */
    }
    if (ares_llist_insert_last(e->ips, tmp) == NULL) {
      ares_free(tmp);              /* LCOV_EXCL_LINE: OutOfMemory */
      ares_hosts_entry_destroy(e); /* LCOV_EXCL_LINE: OutOfMemory */
      return ARES_ENOMEM;          /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  /* E->hosts = address-scoped alias list, canonical first.  Iterate E->ips in
   * order; for each ip iterate iphash[ip] names in order, appending each name
   * not already present (case-insensitive).  'host' itself will appear (it is a
   * name on each of its ips).  Cap at 101 (canonical + 100 aliases) to bound
   * the StevenBlack blocklist case. */
  for (ipnode = ares_llist_node_first(e->ips); ipnode != NULL;
       ipnode = ares_llist_node_next(ipnode)) {
    const char   *ip    = ares_llist_node_val(ipnode);
    ares_llist_t *names = ares_htable_strvp_get_direct(channel->hf->iphash, ip);
    ares_llist_node_t *nnode;

    if (ares_llist_len(e->hosts) >= 101) {
      break; /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    for (nnode = ares_llist_node_first(names); nnode != NULL;
         nnode = ares_llist_node_next(nnode)) {
      const char *nm = ares_llist_node_val(nnode);

      if (ares_hosts_iplist_contains(e->hosts, nm)) {
        continue;
      }
      if (ares_llist_len(e->hosts) >= 101) {
        break; /* LCOV_EXCL_LINE: DefensiveCoding */
      }

      tmp = ares_strdup(nm);
      if (tmp == NULL) {
        ares_hosts_entry_destroy(e); /* LCOV_EXCL_LINE: OutOfMemory */
        return ARES_ENOMEM;          /* LCOV_EXCL_LINE: OutOfMemory */
      }
      if (ares_llist_insert_last(e->hosts, tmp) == NULL) {
        ares_free(tmp);              /* LCOV_EXCL_LINE: OutOfMemory */
        ares_hosts_entry_destroy(e); /* LCOV_EXCL_LINE: OutOfMemory */
        return ARES_ENOMEM;          /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  *entry = e;
  return ARES_SUCCESS;
}

static ares_status_t
  ares_hosts_ai_append_cnames(const ares_hosts_entry_t    *entry,
                              struct ares_addrinfo_cname **cnames_out)
{
  struct ares_addrinfo_cname *cname       = NULL;
  struct ares_addrinfo_cname *cnames      = NULL;
  const char                 *primaryhost = ares_llist_first_val(entry->hosts);
  ares_llist_node_t          *node;
  ares_status_t               status;
  size_t                      cnt = 0;

  /* Canonical name is the first host (in file order); aliases are the rest. */
  node = ares_llist_node_next(ares_llist_node_first(entry->hosts));

  while (node != NULL) {
    const char *host = ares_llist_node_val(node);

    /* Cap at 100 aliases, some people use
     * https://github.com/StevenBlack/hosts and we don't need 200k+ aliases */
    cnt++;
    if (cnt > 100) {
      break; /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    cname = ares_append_addrinfo_cname(&cnames);
    if (cname == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    cname->alias = ares_strdup(host);
    if (cname->alias == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    cname->name = ares_strdup(primaryhost);
    if (cname->name == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    node = ares_llist_node_next(node);
  }

  /* No entries, add only primary */
  if (cnames == NULL) {
    cname = ares_append_addrinfo_cname(&cnames);
    if (cname == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    cname->name = ares_strdup(primaryhost);
    if (cname->name == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }
  status = ARES_SUCCESS;

done:
  if (status != ARES_SUCCESS) {
    ares_freeaddrinfo_cnames(cnames); /* LCOV_EXCL_LINE: DefensiveCoding */
    return status;                    /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *cnames_out = cnames;
  return ARES_SUCCESS;
}

ares_status_t ares_hosts_entry_to_addrinfo(const ares_hosts_entry_t *entry,
                                           const char *name, int family,
                                           unsigned short        port,
                                           ares_bool_t           want_cnames,
                                           struct ares_addrinfo *ai)
{
  ares_status_t               status  = ARES_ENOTFOUND;
  struct ares_addrinfo_cname *cnames  = NULL;
  struct ares_addrinfo_node  *ainodes = NULL;
  ares_llist_node_t          *node;

  switch (family) {
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      break;
    default:                  /* LCOV_EXCL_LINE: DefensiveCoding */
      return ARES_EBADFAMILY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (name != NULL) {
    ares_free(ai->name);
    ai->name = ares_strdup(name);
    if (ai->name == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  for (node = ares_llist_node_first(entry->ips); node != NULL;
       node = ares_llist_node_next(node)) {
    struct ares_addr addr;
    const void      *ptr     = NULL;
    size_t           ptr_len = 0;
    const char      *ipaddr  = ares_llist_node_val(node);

    memset(&addr, 0, sizeof(addr));
    addr.family = family;
    ptr         = ares_dns_pton(ipaddr, &addr, &ptr_len);

    if (ptr == NULL) {
      continue;
    }

    status = ares_append_ai_node(addr.family, port, 0, ptr, &ainodes);
    if (status != ARES_SUCCESS) {
      goto done; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  }

  /* Might be ARES_ENOTFOUND here if no ips matched requested address family */
  if (status != ARES_SUCCESS) {
    goto done;
  }

  if (want_cnames) {
    status = ares_hosts_ai_append_cnames(entry, &cnames);
    if (status != ARES_SUCCESS) {
      goto done; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  }

  status = ARES_SUCCESS;

done:
  if (status != ARES_SUCCESS) {
    /* LCOV_EXCL_START: defensive coding */
    ares_freeaddrinfo_cnames(cnames);
    ares_freeaddrinfo_nodes(ainodes);
    ares_free(ai->name);
    ai->name = NULL;
    return status;
    /* LCOV_EXCL_STOP */
  }
  ares_addrinfo_cat_cnames(&ai->cnames, cnames);
  ares_addrinfo_cat_nodes(&ai->nodes, ainodes);

  return status;
}

ares_status_t ares_hosts_entry_to_hostent(const ares_hosts_entry_t *entry,
                                          int family, struct hostent **hostent)
{
  ares_status_t         status;
  struct ares_addrinfo *ai = ares_malloc_zero(sizeof(*ai));

  *hostent = NULL;

  if (ai == NULL) {
    return ARES_ENOMEM;
  }

  status = ares_hosts_entry_to_addrinfo(entry, NULL, family, 0, ARES_TRUE, ai);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_addrinfo2hostent(ai, family, hostent);
  if (status != ARES_SUCCESS) {
    goto done;
  }

done:
  ares_freeaddrinfo(ai);
  if (status != ARES_SUCCESS) {
    ares_free_hostent(*hostent);
    *hostent = NULL;
  }

  return status;
}
