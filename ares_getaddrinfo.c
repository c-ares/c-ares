/* Copyright 1998, 2011, 2013 by the Massachusetts Institute of Technology.
 * Copyright (C) 2017 - 2018 by Christian Ammer
 * Copyright 2018 by Andrew Selivanov
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

#ifdef HAVE_GETSERVBYNAME_R
#  if !defined(GETSERVBYNAME_R_ARGS) || \
     (GETSERVBYNAME_R_ARGS < 4) || (GETSERVBYNAME_R_ARGS > 6)
#    error "you MUST specifiy a valid number of arguments for getservbyname_r"
#  endif
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
#include <assert.h>

#ifdef WATT32
#undef WIN32
#endif

struct host_query
{
  ares_channel channel;
  char *name;
  unsigned short port; /* in host order */
  ares_addrinfo_callback callback;
  void *arg;
  struct ares_addrinfo hints;
  int sent_family; /* this family is what was is being used */
  int timeouts;    /* number of timeouts we saw for this request */
  const char *remaining_lookups; /* types of lookup we need to perform ("fb" by
                                    default, file and dns respectively) */
  struct ares_addrinfo *ai; /* store results between lookups */
};

static void next_lookup(struct host_query *hquery, int status_code);
static void host_callback(void *arg, int status, int timeouts,
                          unsigned char *abuf, int alen);
static void end_hquery(struct host_query *hquery, int status);
static int fake_addrinfo(const char *name,
                         unsigned short port,
                         const struct ares_addrinfo *hints,
                         ares_addrinfo_callback callback,
                         void *arg);
static int file_lookup(struct host_query *hquery);
static unsigned short lookup_service(const char *service, int flags);

static int is_implemented(int family)
{
  return family == AF_INET || family == AF_INET6 || family == AF_UNSPEC;
}

static const struct ares_addrinfo default_hints =
{
    0,         /* ai_flags */
    AF_UNSPEC, /* ai_family */
    0,         /* ai_socktype */
    0,         /* ai_protocol */
    0,         /* ai_addrlen */
    NULL,      /* ai_addr */
    NULL,      /* ai_canoname */
    NULL       /* ai_next */
};

void ares_getaddrinfo(ares_channel channel,
                      const char *name,
                      const char *service,
                      const struct ares_addrinfo *hints,
                      ares_addrinfo_callback callback,
                      void *arg)
{
  unsigned short port = 0;
  struct host_query *hquery;

  if (!hints)
    {
      hints = &default_hints;
    }

  /* Right now we only know how to look up Internet addresses - and unspec
     means try both basically. */
  if (!is_implemented(hints->ai_family))
    {
      callback(arg, ARES_ENOTIMP, 0, NULL);
      return;
    }

  if (service)
    {
      if (hints->ai_flags & ARES_AI_NUMERICSERV)
        {
          port = (unsigned short)strtoul(service, NULL, 0);
          if (!port)
            {
              callback(arg, ARES_ESERVICE, 0, NULL);
              return;
            }
        }
      else
        {
          port = lookup_service(service, 0);
          if (!port)
            {
              port = (unsigned short)strtoul(service, NULL, 0);
              if (!port)
                {
                  callback(arg, ARES_ESERVICE, 0, NULL);
                  return;
                }
            }
        }
    }
  if (fake_addrinfo(name, port, hints, callback, arg))
    return;

  /* Allocate and fill in the host query structure. */
  hquery = ares_malloc(sizeof(struct host_query));
  if (!hquery)
    {
      callback(arg, ARES_ENOMEM, 0, NULL);
      return;
    }
  hquery->name = ares_strdup(name);
  if (!hquery->name)
    {
      ares_free(hquery);
      callback(arg, ARES_ENOMEM, 0, NULL);
      return;
    }
  hquery->port = port;
  hquery->channel = channel;
  hquery->hints = *hints;
  hquery->sent_family = -1; /* nothing is sent yet */
  hquery->callback = callback;
  hquery->arg = arg;
  hquery->remaining_lookups = channel->lookups;
  hquery->timeouts = 0;
  hquery->ai = NULL;

  /* Start performing lookups according to channel->lookups. */
  next_lookup(hquery, ARES_ECONNREFUSED /* initial error code */);
}

static void next_lookup(struct host_query *hquery, int status_code)
{
  const char *p;
  int status = status_code;

  for (p = hquery->remaining_lookups; *p; p++)
    {
      switch (*p)
        {
        case 'b':
          /* DNS lookup */
          hquery->remaining_lookups = p + 1;
          if ((hquery->hints.ai_family == AF_INET6) ||
              (hquery->hints.ai_family == AF_UNSPEC)) {
            /* if inet6 or unspec, start out with AAAA */
            hquery->sent_family = AF_INET6;
            ares_search(hquery->channel, hquery->name, C_IN, T_AAAA,
                        host_callback, hquery);
          }
          else {
            hquery->sent_family = AF_INET;
            ares_search(hquery->channel, hquery->name, C_IN, T_A,
                        host_callback, hquery);
          }
          return;

        case 'f':
          /* Host file lookup */
          status = file_lookup(hquery);

          /* this status check below previously checked for !ARES_ENOTFOUND,
             but we should not assume that this single error code is the one
             that can occur, as that is in fact no longer the case */
          if (status == ARES_SUCCESS)
            {
              end_hquery(hquery, status);
              return;
            }
          status = status_code;   /* Use original status code */
          break;
        }
    }
  end_hquery(hquery, status);
}

static int file_lookup(struct host_query *hquery)
{
  FILE *fp;
  int error;
  int status;

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
          return ARES_EFILE;
        }
    }
  status = ares__get_addrinfo(fp, hquery->name, hquery->port, &hquery->hints, &hquery->ai);
  fclose(fp);
  return status;
}

/* Resolve service name into port number given in host byte order.
 * If not resolved, return 0.
 */
static unsigned short lookup_service(const char *service, int flags)
{
  const char *proto;
  struct servent *sep;
#ifdef HAVE_GETSERVBYNAME_R
  struct servent se;
  char tmpbuf[4096];
#endif

  if (service)
    {
      if (flags & ARES_NI_UDP)
        proto = "udp";
      else if (flags & ARES_NI_SCTP)
        proto = "sctp";
      else if (flags & ARES_NI_DCCP)
        proto = "dccp";
      else
        proto = "tcp";
#ifdef HAVE_GETSERVBYNAME_R
      memset(&se, 0, sizeof(se));
      sep = &se;
      memset(tmpbuf, 0, sizeof(tmpbuf));
#if GETSERVBYNAME_R_ARGS == 6
      if (getservbyname_r(service, proto, &se, (void *)tmpbuf, sizeof(tmpbuf),
                          &sep) != 0)
        sep = NULL; /* LCOV_EXCL_LINE: buffer large so this never fails */
#elif GETSERVBYNAME_R_ARGS == 5
      sep = getservbyname_r(service, proto, &se, (void *)tmpbuf, sizeof(tmpbuf));
#elif GETSERVBYNAME_R_ARGS == 4
      if (getservbyname_r(service, proto, &se, (void *)tmpbuf) != 0)
        sep = NULL;
#else
      /* Lets just hope the OS uses TLS! */
      sep = getservbyname(service, proto);
#endif
#else
        /* Lets just hope the OS uses TLS! */
#if (defined(NETWARE) && !defined(__NOVELL_LIBC__))
      sep = getservbyname(service, (char *)proto);
#else
      sep = getservbyname(service, proto);
#endif
#endif
      return (sep ? ntohs((unsigned short)sep->s_port) : 0);
    }
  return 0;
}

/* If the name looks like an IP address, fake up a host entry, end the
 * query immediately, and return true.  Otherwise return false.
 */
static int fake_addrinfo(const char *name,
                         unsigned short port,
                         const struct ares_addrinfo *hints,
                         ares_addrinfo_callback callback,
                         void *arg)
{
  struct ares_addrinfo *ai;
  ares_sockaddr addr;
  size_t addrlen;
  int result = 0;
  int family = hints->ai_family;
  if (family == AF_INET || family == AF_INET6 || family == AF_UNSPEC)
    {
      /* It only looks like an IP address if it's all numbers and dots. */
      int numdots = 0, valid = 1;
      const char *p;
      for (p = name; *p; p++)
        {
          if (!ISDIGIT(*p) && *p != '.')
            {
              valid = 0;
              break;
            }
          else if (*p == '.')
            {
              numdots++;
            }
        }

      memset(&addr, 0, sizeof(addr));

      /* if we don't have 3 dots, it is illegal
       * (although inet_addr doesn't think so).
       */
      if (numdots != 3 || !valid)
        result = 0;
      else
        result =
            ((addr.sa4.sin_addr.s_addr = inet_addr(name))
             == INADDR_NONE ? 0 : 1);

      if (result)
        {
          family = addr.sa.sa_family = AF_INET;
          addr.sa4.sin_port = htons(port);
          addrlen = sizeof(addr.sa4);
        }
    }

  if (family == AF_INET6 || family == AF_UNSPEC)
    {
      result = (ares_inet_pton(AF_INET6, name, &addr.sa6.sin6_addr) < 1 ? 0 : 1);
      addr.sa6.sin6_family = AF_INET6;
      addr.sa6.sin6_port = htons(port);
      addrlen = sizeof(addr.sa6);
    }

  if (!result)
    return 0;

  ai = ares__malloc_addrinfo();
  if (!ai)
    {
      callback(arg, ARES_ENOMEM, 0, NULL);
      return 1;
    }

  ai->ai_addr = ares_malloc(addrlen);
  if (!ai->ai_addr)
    {
      ares_free(ai);
      callback(arg, ARES_ENOMEM, 0, NULL);
      return 1;
    }

  ai->ai_addrlen = (unsigned int)addrlen;
  ai->ai_family = addr.sa.sa_family;
  if (addr.sa.sa_family == AF_INET)
    memcpy(ai->ai_addr, &addr.sa4, sizeof(addr.sa4));
  else
    memcpy(ai->ai_addr, &addr.sa6, sizeof(addr.sa6));

  if (hints->ai_flags & ARES_AI_CANONNAME)
    {
      /* Duplicate the name, to avoid a constness violation. */
      ai->ai_canonname = ares_strdup(name);
      if (!ai->ai_canonname)
        {
          ares_free(ai->ai_addr);
          ares_free(ai);
          callback(arg, ARES_ENOMEM, 0, NULL);
          return 1;
        }
    }

  callback(arg, ARES_SUCCESS, 0, ai);
  return 1;
}

static void host_callback(void *arg, int status, int timeouts,
                          unsigned char *abuf, int alen)
{
  struct host_query *hquery = (struct host_query *) arg;
  hquery->timeouts += timeouts;
  if (status == ARES_SUCCESS)
    {
      if (hquery->sent_family == AF_INET)
        {
          status = ares__parse_a_reply(abuf, alen, NULL, &hquery->ai, NULL, NULL);
        }
      else if (hquery->sent_family == AF_INET6)
        {
          status = ares__parse_aaaa_reply(abuf, alen, NULL, &hquery->ai, NULL, NULL);
          if (hquery->hints.ai_family == AF_UNSPEC)
            {
              /* Now look for A records and append them to existing results. */
              hquery->sent_family = AF_INET;
              ares_search(hquery->channel, hquery->name, C_IN, T_A,
                          host_callback, hquery);
              return;
            }
        }
      end_hquery(hquery, status);
    }
  else if ((status == ARES_ENODATA || status == ARES_EBADRESP ||
            status == ARES_ETIMEOUT) && (hquery->sent_family == AF_INET6 &&
            hquery->hints.ai_family == AF_UNSPEC))
    {
      /* The AAAA query yielded no useful result.  Now look up an A instead. */
      hquery->sent_family = AF_INET;
      ares_search(hquery->channel, hquery->name, C_IN, T_A, host_callback,
                  hquery);
    }
  else if (status == ARES_EDESTRUCTION)
    end_hquery(hquery, status);
  else
    next_lookup(hquery, status);
}

static void end_hquery(struct host_query *hquery, int status)
{
  struct ares_addrinfo *next = hquery->ai;
  if (status == ARES_SUCCESS)
    {
      /* Free canonname if we are not asked for it. */
      if (!(hquery->hints.ai_flags & ARES_AI_CANONNAME))
        {
          ares_free(hquery->ai->ai_canonname);
          hquery->ai->ai_canonname = NULL;
        }
      while (next)
        {
          if (next->ai_family == AF_INET)
            {
              ((struct sockaddr_in *)next->ai_addr)->sin_port = htons(hquery->port);
            }
          else
            {
              ((struct sockaddr_in6 *)next->ai_addr)->sin6_port = htons(hquery->port);
            }
          next = next->ai_next;
        }
    }
  else
    {
      /* Clean up what we have collected by so far. */
      ares_freeaddrinfo(hquery->ai);
      hquery->ai = NULL;
    }

  hquery->callback(hquery->arg, status, hquery->timeouts, hquery->ai);
  ares_free(hquery->name);
  ares_free(hquery);
}
