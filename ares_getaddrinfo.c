
/* Copyright 1998, 2011, 2013 by the Massachusetts Institute of Technology.
 * Copyright (C) 2017 - 2018 by Christian Ammer
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
#else
#  include "nameser.h"
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#  include <arpa/nameser_compat.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <assert.h>

#include "ares.h"
#include "bitncmp.h"
#include "ares_private.h"

#ifdef WATT32
#undef WIN32
#endif
#ifdef WIN32
#  include "ares_platform.h"
#endif

struct host_query {
  /* Arguments passed to ares_getaddrinfo */
  ares_channel channel;
  char *name;
  ares_addr_callback callback;
  void *arg;
  int sent_family;   /* this family is what was is being used */
  int ai_family;     /* this family is what is asked for in the API */
  int timeouts;      /* number of timeouts we saw for this request */
  int next_domain;   /* next search domain to try */
  int single_domain; /* do not check other domains */
  int status;
  int remaining;
  struct ares_addrinfo* ai;
};

static void host_callback(void *arg, int status, int timeouts,
                          unsigned char *abuf, int alen);
static void end_hquery(struct host_query *hquery, int status);
static int file_lookup(const char *name, int family,
                       struct ares_addrinfo **ai);
static void sort_addresses(struct hostent *host,
                           const struct apattern *sortlist, int nsort);
static void sort6_addresses(struct hostent *host,
                            const struct apattern *sortlist, int nsort);
static int get_address_index(const struct in_addr *addr,
                             const struct apattern *sortlist, int nsort);
static int get6_address_index(const struct ares_in6_addr *addr,
                              const struct apattern *sortlist, int nsort);
static int as_is_first(const struct host_query *hquery);
static int add_to_addrinfo(struct ares_addrinfo** ai,
                           const struct hostent* host);
static void next_dns_lookup(struct host_query *hquery);
static int is_implemented(const int family);


void ares_getaddrinfo(ares_channel channel,
                      const char* node, const char* service,
                      const struct ares_addrinfo* hints,
                      ares_addr_callback callback, void* arg) {
  struct host_query *hquery;
  char *single = NULL;
  int ai_family;

  ai_family = hints ? hints->ai_family : AF_UNSPEC;
  if (!is_implemented(ai_family)) {
    callback(arg, ARES_ENOTIMP, NULL);
    return;
  }

  /* Allocate and fill in the host query structure. */
  hquery = ares_malloc(sizeof(struct host_query));
  if (!hquery) {
    callback(arg, ARES_ENOMEM, NULL);
    return;
  }
  hquery->ai = NULL;
  hquery->channel = channel;
  hquery->name = single != NULL ? single : ares_strdup(node);
  hquery->single_domain = single != NULL;
  hquery->ai_family = ai_family;
  hquery->sent_family = -1; /* nothing is sent yet */
  if (!hquery->name) {
    ares_free(hquery);
    callback(arg, ARES_ENOMEM, NULL);
    return;
  }
  hquery->callback = callback;
  hquery->arg = arg;
  hquery->timeouts = 0;
  hquery->next_domain = 0;
  hquery->remaining = 0;

  /* Host file lookup */
  if (file_lookup(hquery->name, ai_family, &hquery->ai) == ARES_SUCCESS) {
    end_hquery(hquery, ARES_SUCCESS);
  }
  else {
    next_dns_lookup(hquery);
  }
}

void ares_freeaddrinfo(struct ares_addrinfo* ai) {
  struct ares_addrinfo* ai_free;
  while (ai) {
    ai_free = ai;
    ai = ai->ai_next;
    ares_free(ai_free->ai_addr);
    ares_free(ai_free);
  }
}

static int is_implemented(const int family) {
  return
    family == AF_INET ||
    family == AF_INET6 ||
    family == AF_UNSPEC;
}

static int file_lookup(const char *name, int family, struct ares_addrinfo **ai) {
  FILE *fp;
  char **alias;
  int status;
  int error;
  struct hostent *host = NULL;

#ifdef WIN32
  char PATH_HOSTS[MAX_PATH];
  win_platform platform;

  PATH_HOSTS[0] = '\0';

  platform = ares__getplatform();

  if (platform == WIN_NT) {
    char tmp[MAX_PATH];
    HKEY hkeyHosts;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, WIN_NS_NT_KEY, 0, KEY_READ,
                     &hkeyHosts) == ERROR_SUCCESS) {
      DWORD dwLength = MAX_PATH;
      RegQueryValueEx(hkeyHosts, DATABASEPATH, NULL, NULL, (LPBYTE)tmp,
                      &dwLength);
      ExpandEnvironmentStrings(tmp, PATH_HOSTS, MAX_PATH);
      RegCloseKey(hkeyHosts);
    }
  }
  else if (platform == WIN_9X) {
    GetWindowsDirectory(PATH_HOSTS, MAX_PATH);
  }
  else {
    return ARES_ENOTFOUND;
  }

  strcat(PATH_HOSTS, WIN_PATH_HOSTS);

#elif defined(WATT32)
  extern const char *_w32_GetHostsFile (void);
  const char *PATH_HOSTS = _w32_GetHostsFile();

  if (!PATH_HOSTS) {
    return ARES_ENOTFOUND;
  }
#endif

  fp = fopen(PATH_HOSTS, "r");
  if (!fp) {
    error = ERRNO;
    switch(error) {
      case ENOENT:
      case ESRCH:
        return ARES_ENOTFOUND;
      default:
        DEBUGF(fprintf(stderr, "fopen() failed with error: %d %s\n",
                       error, strerror(error)));
        DEBUGF(fprintf(stderr, "Error opening file: %s\n",
                       PATH_HOSTS));
        host = NULL;
        return ARES_EFILE;
    }
  }
  status = ARES_ENOTFOUND;
  while (status != ARES_ENOMEM &&
      ares__get_hostent(fp, family, &host) == ARES_SUCCESS) {
    if (strcasecmp(host->h_name, name) == 0) {
      status = add_to_addrinfo(ai, host);
    }
    else {
      for (alias = host->h_aliases; *alias; alias++) {
        if (strcasecmp(*alias, name) == 0) {
          status = add_to_addrinfo(ai, host);
          break;
        }
      }
    }
    ares_free_hostent(host);
  }
  fclose(fp);
  return status;
}

static int add_to_addrinfo(struct ares_addrinfo** ai,
		            const struct hostent* host) {
  static const struct ares_addrinfo EmptyAddrinfo; 
  struct ares_addrinfo* front;
  char** p;
  if (!host || (host->h_addrtype != AF_INET && host->h_addrtype != AF_INET6)) {
    return ARES_SUCCESS;
  }
  for (p = host->h_addr_list; *p; ++p) {
    front = ares_malloc(sizeof(struct ares_addrinfo));
    if (!front) goto nomem;
    *front = EmptyAddrinfo;
    front->ai_next = *ai; /* insert at front */
    *ai = front;
    if (host->h_addrtype == AF_INET) {
      front->ai_protocol = IPPROTO_UDP;
      front->ai_family = AF_INET;
      front->ai_addr = ares_malloc(sizeof(struct sockaddr_in));
      if (!front->ai_addr) goto nomem;
      memcpy(&((struct sockaddr_in*)(front->ai_addr))->sin_addr, *p,
        host->h_length);
    }
    else {
      front->ai_protocol = IPPROTO_UDP;
      front->ai_family = AF_INET6;
      front->ai_addr = ares_malloc(sizeof(struct sockaddr_in6));
      if (!front->ai_addr) goto nomem;
      memcpy(&((struct sockaddr_in6*)(front->ai_addr))->sin6_addr, *p,
        host->h_length);
    }
  }
  return ARES_SUCCESS;
nomem:
  ares_freeaddrinfo(*ai);
  return ARES_ENOMEM;
}

static void next_dns_lookup(struct host_query *hquery) {
  char *s = NULL;
  int is_s_allocated = 0;
  int status;

  if (( as_is_first(hquery) && hquery->next_domain == 0) ||
      (!as_is_first(hquery) && hquery->next_domain ==
       hquery->channel->ndomains)) {
    s = hquery->name;
  }

  if (!s && hquery->next_domain < hquery->channel->ndomains) {
    status = ares__cat_domain(
      hquery->name,
      hquery->channel->domains[hquery->next_domain++],
      &s);
    if (status == ARES_SUCCESS) {
      is_s_allocated = 1;
    }
  }

  if (s) {
    if (hquery->ai_family == AF_INET || hquery->ai_family == AF_UNSPEC) {
      ares_query(hquery->channel, s, C_IN, T_A, host_callback, hquery);
      hquery->remaining++;
    }
    if (hquery->ai_family == AF_INET6 || hquery->ai_family == AF_UNSPEC) {
      ares_query(hquery->channel, s, C_IN, T_AAAA, host_callback, hquery);
      hquery->remaining++;
    }
    if (is_s_allocated) {
      ares_free(s);
    }
  }
  else {
    assert(!hquery->ai);
    end_hquery(hquery, ARES_ENOTFOUND);
  }
}

static void end_hquery(struct host_query *hquery, int status) {
  hquery->callback(hquery->arg, status, hquery->ai);
  ares_free(hquery->name);
  ares_free(hquery);
}

static void host_callback(void *arg, int status, int timeouts,
                          unsigned char *abuf, int alen) {
  struct host_query *hquery = (struct host_query*)arg;
  ares_channel channel = hquery->channel;
  struct hostent *host = NULL;
  int qtype;
  int qtypestatus;
  int addinfostatus = ARES_SUCCESS;
  hquery->timeouts += timeouts;

  hquery->remaining--;

  if (status == ARES_SUCCESS) {
    qtypestatus = ares__parse_qtype_reply(abuf, alen, &qtype);
    if (qtypestatus == ARES_SUCCESS && qtype == T_A) {
      /* Can ares_parse_a_reply be unsuccessful (after parse_qtype) */
      ares_parse_a_reply(abuf, alen, &host, NULL, NULL);
      if (host && channel->nsort) {
        sort_addresses(host, channel->sortlist, channel->nsort);
      }
      addinfostatus = add_to_addrinfo(&hquery->ai, host);
      ares_free_hostent(host);
    }
    else if (qtypestatus == ARES_SUCCESS && qtype == T_AAAA) {
      /* Can ares_parse_a_reply be unsuccessful (after parse_qtype) */
      ares_parse_aaaa_reply(abuf, alen, &host, NULL, NULL);
      if (host && channel->nsort) {
        sort6_addresses(host, channel->sortlist, channel->nsort);
      }
      addinfostatus = add_to_addrinfo(&hquery->ai, host);
      ares_free_hostent(host);
    }
  }

  if (!hquery->remaining) {
    if (addinfostatus != ARES_SUCCESS) {
      /* no memory */
      end_hquery(hquery, addinfostatus);
    }
    else if (hquery->ai) {
      /* at least one query ended with ARES_SUCCESS */
      end_hquery(hquery, ARES_SUCCESS);
    }
    else if (status == ARES_ENOTFOUND) {
      next_dns_lookup(hquery);
    }
    else {
      end_hquery(hquery, status);
    }
  }

  /* at this point we keep on waiting for the next query to finish */
}

static void sort_addresses(struct hostent *host,
                           const struct apattern *sortlist, int nsort) {
  struct in_addr a1, a2;
  int i1, i2, ind1, ind2;

  /* This is a simple insertion sort, not optimized at all.  i1 walks
   * through the address list, with the loop invariant that everything
   * to the left of i1 is sorted.  In the loop body, the value at i1 is moved
   * back through the list (via i2) until it is in sorted order.
   */
  for (i1 = 0; host->h_addr_list[i1]; i1++) {
    memcpy(&a1, host->h_addr_list[i1], sizeof(struct in_addr));
    ind1 = get_address_index(&a1, sortlist, nsort);
    for (i2 = i1 - 1; i2 >= 0; i2--) {
      memcpy(&a2, host->h_addr_list[i2], sizeof(struct in_addr));
      ind2 = get_address_index(&a2, sortlist, nsort);
      if (ind2 <= ind1) {
        break;
      }
      memcpy(host->h_addr_list[i2 + 1], &a2, sizeof(struct in_addr));
    }
    memcpy(host->h_addr_list[i2 + 1], &a1, sizeof(struct in_addr));
  }
}

/* Find the first entry in sortlist which matches addr.  Return nsort
 * if none of them match.
 */
static int get_address_index(const struct in_addr *addr,
                             const struct apattern *sortlist,
                             int nsort) {
  int i;

  for (i = 0; i < nsort; i++) {
    if (sortlist[i].family != AF_INET) {
      continue;
    }
    if (sortlist[i].type == PATTERN_MASK) {
      if ((addr->s_addr & sortlist[i].mask.addr4.s_addr) ==
          sortlist[i].addrV4.s_addr) {
        break;
      }
    }
    else {
      if (!ares__bitncmp(&addr->s_addr, &sortlist[i].addrV4.s_addr,
          sortlist[i].mask.bits)) {
        break;
      }
    }
  }
  return i;
}

static void sort6_addresses(struct hostent *host,
                            const struct apattern *sortlist, int nsort) {
  struct ares_in6_addr a1, a2;
  int i1, i2, ind1, ind2;

  /* This is a simple insertion sort, not optimized at all.  i1 walks
   * through the address list, with the loop invariant that everything
   * to the left of i1 is sorted.  In the loop body, the value at i1 is moved
   * back through the list (via i2) until it is in sorted order.
   */
  for (i1 = 0; host->h_addr_list[i1]; i1++) {
    memcpy(&a1, host->h_addr_list[i1], sizeof(struct ares_in6_addr));
    ind1 = get6_address_index(&a1, sortlist, nsort);
    for (i2 = i1 - 1; i2 >= 0; i2--) {
      memcpy(&a2, host->h_addr_list[i2], sizeof(struct ares_in6_addr));
      ind2 = get6_address_index(&a2, sortlist, nsort);
      if (ind2 <= ind1) {
        break;
      }
      memcpy(host->h_addr_list[i2 + 1], &a2, sizeof(struct ares_in6_addr));
    }
    memcpy(host->h_addr_list[i2 + 1], &a1, sizeof(struct ares_in6_addr));
  }
}

/* Find the first entry in sortlist which matches addr.  Return nsort
 * if none of them match.
 */
static int get6_address_index(const struct ares_in6_addr *addr,
                              const struct apattern *sortlist,
                              int nsort) {
  int i;

  for (i = 0; i < nsort; i++) {
    if (sortlist[i].family != AF_INET6)
      continue;
    if (!ares__bitncmp(addr, &sortlist[i].addrV6, sortlist[i].mask.bits))
      break;
  }
  return i;
}

static int as_is_first(const struct host_query* hquery) {
  char* p;
  int ndots = 0;
  for (p = hquery->name; *p; p++) {
    if (*p == '.') {
      ndots++;
    }
  }
  return ndots >= hquery->channel->ndots;
}

