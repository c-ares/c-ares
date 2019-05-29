
/* Copyright 1998 by the Massachusetts Institute of Technology.
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
#  include <strings.h>
#endif

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

int ares_parse_a_reply(const unsigned char *abuf, int alen,
                       struct hostent **host,
                       struct ares_addrttl *addrttls, int *naddrttls)
{
  struct ares_addrinfo ai;
  struct ares_addrinfo_node *next;
  struct ares_addrinfo_cname *next_cname;
  char *hostname;
  char **aliases;
  struct in_addr *addrs = NULL;
  struct hostent *hostent = NULL;
  int naliases = 0, naddrs = 0, alias = 0, i;
  int status = ares__parse_into_addrinfo(abuf, alen, &ai);
  if (status != ARES_SUCCESS)
    {
      return status;
    }

  hostent = ares_malloc(sizeof(struct hostent));
  if (!hostent)
    {
      goto enomem;
    }

  next = ai.nodes;
  while (next)
    {
      ++naddrs;
      next = next->ai_next;
    }

  next_cname = ai.cnames;
  while (next_cname)
    {
      if(next_cname->alias)
        ++naliases;
      next_cname = next_cname->next;
    }

  if (ai.cnames)
    {
      hostname = ai.cnames->next->name;
    }

  if (naliases)
    {
      aliases = ares_malloc((naliases + 1) * sizeof(char *));
      if (!aliases)
        {
          goto enomem;
        }
      next_cname = ai.cnames;
      while (next_cname)
        {
          if(next_cname->alias)
            aliases[alias++] = strdup(next_cname->alias);
          next_cname = next_cname->next;
        }
    }

  if (naddrs)
    {
      hostent->h_addr_list = ares_malloc((naddrs + 1) * sizeof(char *));
      if (!hostent->h_addr_list)
        {
          goto enomem;
        }
      /* Fill in the hostent and return successfully. */
      hostent->h_name = hostname;
      hostent->h_aliases = aliases;
      hostent->h_addrtype = AF_INET;
      hostent->h_length = sizeof(struct in_addr);
      for (i = 0; i < naddrs; i++)
        hostent->h_addr_list[i] = (char *)&addrs[i];
      hostent->h_addr_list[naddrs] = NULL;
    }

  *host = hostent;

  ares__freeaddrinfo_cnames(ai.cnames);
  ares__freeaddrinfo_nodes(ai.nodes);
  return ARES_SUCCESS;

enomem:
  ares_free(aliases);
  ares_free(hostent);
  ares__freeaddrinfo_cnames(ai.cnames);
  ares__freeaddrinfo_nodes(ai.nodes);
  return ARES_ENOMEM;
}

