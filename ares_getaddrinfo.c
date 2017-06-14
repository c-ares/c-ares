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

#include "ares.h"
#include "ares_inet_net_pton.h"
#include "bitncmp.h"
#include "ares_platform.h"
#include "ares_nowarn.h"
#include "ares_private.h"

#ifdef WATT32
#undef WIN32
#endif

struct host_query {
  /* Arguments passed to ares_gethostbyname() */
  ares_channel channel;
  char *name;
  ares_addr_callback callback;
  void *arg;
  int sent_family; /* this family is what was is being used */
  int ai_family; /* this family is what is asked for in the API */
  int timeouts;      /* number of timeouts we saw for this request */
  int next_domain;   /* next search domain to try */
  int single_domain; /* do not check other domains */
  int status;
  int remaining;
  struct addrinfo* ai;
};

static void host_callback(void *arg, int status, int timeouts,
                          unsigned char *abuf, int alen);
/*static void end_hquery(struct host_query *hquery, int status,
                       struct hostent *host);*/
/*static int fake_hostent(const char *name, int family,
                        ares_host_callback callback, void *arg);*/
static int file_lookup(const char *name, int family, struct addrinfo **ai);
static void sort_addresses(struct hostent *host,
                           const struct apattern *sortlist, int nsort);
static void sort6_addresses(struct hostent *host,
                            const struct apattern *sortlist, int nsort);
static int get_address_index(const struct in_addr *addr,
                             const struct apattern *sortlist, int nsort);
static int get6_address_index(const struct ares_in6_addr *addr,
                              const struct apattern *sortlist, int nsort);
static int as_is_first(const struct host_query *hquery);
/*static void invoke_callback(struct host_query *hquery, int status,
  struct hostent* host);*/
static void add_to_addrinfo(struct addrinfo** ai, const struct hostent* host);
static void next_dns_lookup(struct host_query *hquery);


static int is_implemented(const int family) {
  return
    family == AF_INET ||
    family == AF_INET6 ||
    family == AF_UNSPEC;
}

void ares_getaddrinfo(ares_channel channel,
                      const char* node, const char* service,
                      const struct addrinfo* hints,
                      ares_addr_callback callback, void* arg) {
  struct host_query *hquery;
  char *single = NULL;
  int ai_family;

  ai_family = hints ? hints->ai_family : AF_UNSPEC;
  if (!is_implemented(ai_family)) {
    callback(arg, ARES_ENOTIMP, NULL);
    return;
  }

  /*if (fake_hostent(name, family, callback, arg))
    return;*/
  /*status = ares__single_domain(channel, node, &single);
  if (status != ARES_SUCCESS) {
      callback(arg, status, NULL);
      return;
  }*/

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
  hquery->remaining = ai_family == AF_UNSPEC ? 2 : 1;

  /* Host file lookup */
  if (file_lookup(hquery->name, ai_family, &hquery->ai) == ARES_SUCCESS)
    hquery->callback(hquery->arg, ARES_SUCCESS, &hquery->ai);
  else
    next_dns_lookup(hquery);
  //free_hquery(hquery);
  //next_dns_lookup(hquery, status_code);
  //return;
}

static int file_lookup(const char *name, int family, struct addrinfo **ai)
{
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
                     &hkeyHosts) == ERROR_SUCCESS)
    {
      DWORD dwLength = MAX_PATH;
      RegQueryValueEx(hkeyHosts, DATABASEPATH, NULL, NULL, (LPBYTE)tmp,
                      &dwLength);
      ExpandEnvironmentStrings(tmp, PATH_HOSTS, MAX_PATH);
      RegCloseKey(hkeyHosts);
    }
  }
  else if (platform == WIN_9X)
    GetWindowsDirectory(PATH_HOSTS, MAX_PATH);
  else
    return ARES_ENOTFOUND;

  strcat(PATH_HOSTS, WIN_PATH_HOSTS);

#elif defined(WATT32)
  extern const char *_w32_GetHostsFile (void);
  const char *PATH_HOSTS = _w32_GetHostsFile();

  if (!PATH_HOSTS)
    return ARES_ENOTFOUND;
#endif

  fp = fopen(PATH_HOSTS, "r");
  if (!fp)
    {
      error = ERRNO;
      switch(error)
        {
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
  while (ares__get_hostent(fp, family, &host) == ARES_SUCCESS) {
    if (strcasecmp(host->h_name, name) == 0) {
      add_to_addrinfo(ai, host);
      ares_free_hostent(host);
      status = ARES_SUCCESS;
      continue;
    }
    for (alias = host->h_aliases; *alias; alias++) {
      if (strcasecmp(*alias, name) == 0) {
        add_to_addrinfo(ai, host);
        ares_free_hostent(host);
        status = ARES_SUCCESS;
        break;
      }
    }
  }
  fclose(fp);
  return status;
}

/*if (ai_family == AF_UNSPEC || ai_family == AF_INET6) {
    host = NULL;
    status = ares__get_hostent(fp, AF_INET6, &host);
    add_to_addrinfo(&hquery->ai, host);
    free_host(&host);
}
if (ai_family == AF_UNSPEC || ai_family == AF_INET) {
    host = NULL;
    status = ares__get_hostent(fp, AF_INET, &host);
    add_to_addrinfo(&hquery->ai, host);
    free_host(&host);
}*/


static void add_to_addrinfo(struct addrinfo** ai, const struct hostent* host) {
  struct addrinfo* next_ai;
  if (!host || (host->h_addrtype != AF_INET && host->h_addrtype != AF_INET6))
    return;
  next_ai = ares_malloc(sizeof(struct addrinfo));
  memset(next_ai, 0, sizeof(*next_ai));
  if (!(*ai))
    *ai = next_ai;
  else
    (*ai)->ai_next = next_ai;
  if (host->h_addrtype == AF_INET) {
    next_ai->ai_protocol = IPPROTO_UDP;
    next_ai->ai_family = AF_INET;
    next_ai->ai_addr = ares_malloc(sizeof(struct sockaddr_in));
    memcpy(&((struct sockaddr_in*)(next_ai->ai_addr))->sin_addr,
      host->h_addr_list[0], host->h_length);
  }
  else {
    next_ai->ai_protocol = IPPROTO_UDP;
    next_ai->ai_family = AF_INET6;
    next_ai->ai_addr = ares_malloc(sizeof(struct sockaddr_in6));
    memcpy(&((struct sockaddr_in6*)(next_ai->ai_addr))->sin6_addr,
      host->h_addr_list[0], host->h_length);
  }
}

static void next_dns_lookup(struct host_query *hquery) {
  char *s = NULL;
  int is_s_allocated = 0;
  int status;

  if (( as_is_first(hquery) && hquery->next_domain == 0) ||
      (!as_is_first(hquery) && hquery->next_domain == hquery->channel->ndomains))
    s = hquery->name;

  if (!s && hquery->next_domain < hquery->channel->ndomains) {
    status = ares__cat_domain(
      hquery->name,
      hquery->channel->domains[hquery->next_domain++],
      &s);
    if (status == ARES_SUCCESS)
      is_s_allocated = 1;
  }

  if (s) {
    if (hquery->ai_family == AF_INET || hquery->ai_family == AF_UNSPEC)
      ares_query(hquery->channel, s, C_IN, T_A, host_callback, hquery);
    if (hquery->ai_family == AF_INET6 || hquery->ai_family == AF_UNSPEC)
      ares_query(hquery->channel, s, C_IN, T_AAAA, host_callback, hquery);
    if (is_s_allocated)
      ares_free(s);
  }
  else
    hquery->callback(hquery->arg, ARES_ENOTFOUND, NULL);
}

static void host_callback(void *arg, int status, int timeouts,
                          unsigned char *abuf, int alen) {
  struct host_query *hquery = (struct host_query*)arg;
  ares_channel channel = hquery->channel;
  struct hostent *host = NULL;
  int qtype;
  hquery->timeouts += timeouts;

  if (status == ARES_SUCCESS) {
    status = ares__parse_qtype_reply(abuf, alen, &qtype);
    if (status == ARES_SUCCESS && qtype == T_A) {
      status = ares_parse_a_reply(abuf, alen, &host, NULL, NULL);
      if (host && channel->nsort)
        sort_addresses(host, channel->sortlist, channel->nsort);
      add_to_addrinfo(&hquery->ai, host);
      ares_free_hostent(host);
      if (!--hquery->remaining)
        hquery->callback(hquery->arg, ARES_SUCCESS, &hquery->ai);
    }
    else if (status == ARES_SUCCESS && qtype == T_AAAA) {
      status = ares_parse_aaaa_reply(abuf, alen, &host, NULL, NULL);
      if (host && channel->nsort)
        sort6_addresses(host, channel->sortlist, channel->nsort);
      add_to_addrinfo(&hquery->ai, host);
      ares_free_hostent(host);
      if (!--hquery->remaining)
        hquery->callback(hquery->arg, ARES_SUCCESS, &hquery->ai);
    }
    else
      hquery->callback(hquery->arg, status, NULL);
  }
  else
    next_dns_lookup(hquery);
}

/*static void invoke_callback(struct host_query *hquery, int status,
  struct hostent* host) {
  hquery->callback(hquery->arg, status, NULL);
  hquery->callback_called = 1;
}*/



/* If the name looks like an IP address, fake up a host entry, end the
 * query immediately, and return true.  Otherwise return false.
 */
/*static int fake_hostent(const char *name, int family,
                        ares_host_callback callback, void *arg) {
  struct hostent hostent;
  char *aliases[1] = { NULL };
  char *addrs[2];
  int result = 0;
  struct in_addr in;
  struct ares_in6_addr in6;

  if (family == AF_INET || family == AF_INET6)
    {
      /* It only looks like an IP address if it's all numbers and dots. * /
      int numdots = 0, valid = 1;
      const char *p;
      for (p = name; *p; p++)
        {
          if (!ISDIGIT(*p) && *p != '.') {
            valid = 0;
            break;
          } else if (*p == '.') {
            numdots++;
          }
        }

      /* if we don't have 3 dots, it is illegal
       * (although inet_addr doesn't think so).
       * /
      if (numdots != 3 || !valid)
        result = 0;
      else
        result = ((in.s_addr = inet_addr(name)) == INADDR_NONE ? 0 : 1);

      if (result)
        family = AF_INET;
    }
  if (family == AF_INET6)
    result = (ares_inet_pton(AF_INET6, name, &in6) < 1 ? 0 : 1);

  if (!result)
    return 0;

  if (family == AF_INET)
    {
      hostent.h_length = (int)sizeof(struct in_addr);
      addrs[0] = (char *)&in;
    }
  else if (family == AF_INET6)
    {
      hostent.h_length = (int)sizeof(struct ares_in6_addr);
      addrs[0] = (char *)&in6;
    }
  /* Duplicate the name, to avoid a constness violation. * /
  hostent.h_name = ares_strdup(name);
  if (!hostent.h_name)
    {
      callback(arg, ARES_ENOMEM, 0, NULL);
      return 1;
    }

  /* Fill in the rest of the host structure and terminate the query. * /
  addrs[1] = NULL;
  hostent.h_aliases = aliases;
  hostent.h_addrtype = aresx_sitoss(family);
  hostent.h_addr_list = addrs;
  callback(arg, ARES_SUCCESS, 0, &hostent);

  ares_free((char *)(hostent.h_name));
  return 1;
}
*/
/*static int file_lookup(const char *name, int family, struct hostent **host) {
  FILE *fp;
  char **alias;
  int status;
  int error;

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
  else if (platform == WIN_9X)
    GetWindowsDirectory(PATH_HOSTS, MAX_PATH);
  else
    return ARES_ENOTFOUND;
  strcat(PATH_HOSTS, WIN_PATH_HOSTS);
#elif defined(WATT32)
  extern const char *_w32_GetHostsFile (void);
  const char *PATH_HOSTS = _w32_GetHostsFile();
  if (!PATH_HOSTS)
    return ARES_ENOTFOUND;
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
          *host = NULL;
          return ARES_EFILE;
        }
  }
  while ((status = ares__get_hostent(fp, family, host)) == ARES_SUCCESS) {
      if (strcasecmp((*host)->h_name, name) == 0)
        break;
      for (alias = (*host)->h_aliases; *alias; alias++) {
          if (strcasecmp(*alias, name) == 0)
            break;
      }
      if (*alias)
        break;
      ares_free_hostent(*host);
    }
  fclose(fp);
  if (status == ARES_EOF)
    status = ARES_ENOTFOUND;
  if (status != ARES_SUCCESS)
    *host = NULL;
  return status;
}
*/
static void sort_addresses(struct hostent *host,
                           const struct apattern *sortlist, int nsort) {
  struct in_addr a1, a2;
  int i1, i2, ind1, ind2;

  /* This is a simple insertion sort, not optimized at all.  i1 walks
   * through the address list, with the loop invariant that everything
   * to the left of i1 is sorted.  In the loop body, the value at i1 is moved
   * back through the list (via i2) until it is in sorted order.
   */
  for (i1 = 0; host->h_addr_list[i1]; i1++)
    {
      memcpy(&a1, host->h_addr_list[i1], sizeof(struct in_addr));
      ind1 = get_address_index(&a1, sortlist, nsort);
      for (i2 = i1 - 1; i2 >= 0; i2--)
        {
          memcpy(&a2, host->h_addr_list[i2], sizeof(struct in_addr));
          ind2 = get_address_index(&a2, sortlist, nsort);
          if (ind2 <= ind1)
            break;
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

  for (i = 0; i < nsort; i++)
    {
      if (sortlist[i].family != AF_INET)
        continue;
      if (sortlist[i].type == PATTERN_MASK)
        {
          if ((addr->s_addr & sortlist[i].mask.addr4.s_addr)
              == sortlist[i].addrV4.s_addr)
            break;
        }
      else
        {
          if (!ares__bitncmp(&addr->s_addr, &sortlist[i].addrV4.s_addr,
                             sortlist[i].mask.bits))
            break;
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
  for (i1 = 0; host->h_addr_list[i1]; i1++)
    {
      memcpy(&a1, host->h_addr_list[i1], sizeof(struct ares_in6_addr));
      ind1 = get6_address_index(&a1, sortlist, nsort);
      for (i2 = i1 - 1; i2 >= 0; i2--)
        {
          memcpy(&a2, host->h_addr_list[i2], sizeof(struct ares_in6_addr));
          ind2 = get6_address_index(&a2, sortlist, nsort);
          if (ind2 <= ind1)
            break;
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

  for (i = 0; i < nsort; i++)
    {
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
  for (p = hquery->name; *p; p++)
    {
      if (*p == '.')
        ndots++;
    }
  return ndots >= hquery->channel->ndots;
}
