/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright 2005 Dominick Meglio
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
#include "ares_inet_net_pton.h"
#include "ares_private.h"

int ares__parse_aaaa_reply(const unsigned char *abuf, int alen,
                           struct hostent **host, struct ares_addrinfo **ai,
                           struct ares_addr6ttl *addrttls, int *naddrttls)
{
  unsigned int qdcount, ancount;
  int status, i, rr_type, rr_class, rr_len, rr_ttl, naddrs;
  int cname_ttl = INT_MAX;  /* the TTL imposed by the CNAME chain */
  int naliases;
  long len;
  const unsigned char *aptr;
  char *hostname, *rr_name, *rr_data, **aliases;
  struct ares_in6_addr *addrs;
  struct hostent *hostent;
  struct ares_addrinfo *nested_ai, *head_ai = NULL;
  const int max_addr_ttls = (addrttls && naddrttls) ? *naddrttls : 0;

  /* Set *host to NULL for all failure cases. */
  if (host)
    *host = NULL;
  /* Same with *naddrttls. */
  if (naddrttls)
    *naddrttls = 0;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT(abuf);
  ancount = DNS_HEADER_ANCOUNT(abuf);
  if (qdcount != 1)
    return ARES_EBADRESP;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares__expand_name_for_response(aptr, abuf, alen, &hostname, &len);
  if (status != ARES_SUCCESS)
    return status;
  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      ares_free(hostname);
      return ARES_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  /* Allocate addresses and aliases; ancount gives an upper bound for both. */
  if (host)
    {
      addrs = ares_malloc(ancount * sizeof(struct ares_in6_addr));
      if (!addrs)
        {
          ares_free(hostname);
          return ARES_ENOMEM;
        }
      aliases = ares_malloc((ancount + 1) * sizeof(char *));
      if (!aliases)
        {
          ares_free(hostname);
          ares_free(addrs);
          return ARES_ENOMEM;
        }
    }
  /* Allocate addresses; ancount gives an upper bound. */
  else if (ai)
    {
      addrs = ares_malloc(ancount * sizeof(struct ares_in6_addr));
      if (!addrs)
        {
          ares_free(hostname);
          return ARES_ENOMEM;
        }
      aliases = NULL;
    }
  else
    {
      addrs = NULL;
      aliases = NULL;
    }
  naddrs = 0;
  naliases = 0;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < (int)ancount; i++)
    {
      /* Decode the RR up to the data field. */
      status = ares__expand_name_for_response(aptr, abuf, alen, &rr_name, &len);
      if (status != ARES_SUCCESS)
        break;
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
        {
          ares_free(rr_name);
          status = ARES_EBADRESP;
          break;
        }
      rr_type = DNS_RR_TYPE(aptr);
      rr_class = DNS_RR_CLASS(aptr);
      rr_len = DNS_RR_LEN(aptr);
      rr_ttl = DNS_RR_TTL(aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          ares_free(rr_name);
          status = ARES_EBADRESP;
          break;
        }

      if (rr_class == C_IN && rr_type == T_AAAA
          && rr_len == sizeof(struct ares_in6_addr)
          && strcasecmp(rr_name, hostname) == 0)
        {
          if (addrs)
            {
              if (aptr + sizeof(struct ares_in6_addr) > abuf + alen)
              {  /* LCOV_EXCL_START: already checked above */
                ares_free(rr_name);
                status = ARES_EBADRESP;
                break;
              }  /* LCOV_EXCL_STOP */
              memcpy(&addrs[naddrs], aptr, sizeof(struct ares_in6_addr));
            }
          if (naddrs < max_addr_ttls)
            {
              struct ares_addr6ttl * const at = &addrttls[naddrs];
              if (aptr + sizeof(struct ares_in6_addr) > abuf + alen)
              {  /* LCOV_EXCL_START: already checked above */
                ares_free(rr_name);
                status = ARES_EBADRESP;
                break;
              }  /* LCOV_EXCL_STOP */
              memcpy(&at->ip6addr, aptr,  sizeof(struct ares_in6_addr));
              at->ttl = rr_ttl;
            }
          naddrs++;
          status = ARES_SUCCESS;
        }

      if (rr_class == C_IN && rr_type == T_CNAME)
        {
          /* Record the RR name as an alias. */
          if (aliases)
            aliases[naliases] = rr_name;
          else
            ares_free(rr_name);
          naliases++;

          /* Decode the RR data and replace the hostname with it. */
          status = ares__expand_name_for_response(aptr, abuf, alen, &rr_data,
                                                  &len);
          if (status != ARES_SUCCESS)
            break;
          ares_free(hostname);
          hostname = rr_data;

          /* Take the min of the TTLs we see in the CNAME chain. */
          if (cname_ttl > rr_ttl)
            cname_ttl = rr_ttl;
        }
      else
        ares_free(rr_name);

      aptr += rr_len;
      if (aptr > abuf + alen)
        {  /* LCOV_EXCL_START: already checked above */
          status = ARES_EBADRESP;
          break;
        }  /* LCOV_EXCL_STOP */
    }

  /* the check for naliases to be zero is to make sure CNAME responses
     don't get caught here */
  if (status == ARES_SUCCESS && naddrs == 0 && naliases == 0)
    status = ARES_ENODATA;
  if (status == ARES_SUCCESS)
    {
      /* We got our answer. */
      if (naddrttls)
        {
          const int n = naddrs < max_addr_ttls ? naddrs : max_addr_ttls;
          for (i = 0; i < n; i++)
            {
              /* Ensure that each A TTL is no larger than the CNAME TTL. */
              if (addrttls[i].ttl > cname_ttl)
                addrttls[i].ttl = cname_ttl;
            }
          *naddrttls = n;
        }
      if (aliases)
        aliases[naliases] = NULL;
      if (host)
        {
          /* Allocate memory to build the host entry. */
          hostent = ares_malloc(sizeof(struct hostent));
          if (hostent)
            {
              hostent->h_addr_list = ares_malloc((naddrs + 1) * sizeof(char *));
              if (hostent->h_addr_list)
                {
                  /* Fill in the hostent and return successfully. */
                  hostent->h_name = hostname;
                  hostent->h_aliases = aliases;
                  hostent->h_addrtype = AF_INET6;
                  hostent->h_length = sizeof(struct ares_in6_addr);
                  for (i = 0; i < naddrs; i++)
                    hostent->h_addr_list[i] = (char *) &addrs[i];
                  hostent->h_addr_list[naddrs] = NULL;
                  if (!naddrs && addrs)
                    ares_free(addrs);
                  *host = hostent;
                  return ARES_SUCCESS;
                }
              ares_free(hostent);
            }
          status = ARES_ENOMEM;
        }
      else if (ai)
        {
          /* Allocate memory to build the addrinfo entry. */
          head_ai = nested_ai = ares__malloc_addrinfo();
          if (!head_ai)
            {
              status = ARES_ENOMEM;
              goto failed_stat;
            }

          /* Fill in the head_ai and return successfully. */
          if (naddrs > 0)
            {
              struct sockaddr_in6 *sin =
                  ares_malloc(sizeof(struct sockaddr_in6));
              if (!sin)
                {
                  status = ARES_ENOMEM;
                  goto failed_stat;
                }

              memset(sin, 0, sizeof(struct sockaddr_in6));
              memcpy(&sin->sin6_addr.s6_addr, &addrs[0],
                     sizeof(struct ares_in6_addr));
              sin->sin6_family = AF_INET6;

              head_ai->ai_addr = (struct sockaddr *)sin;
              head_ai->ai_family = AF_INET6;
              head_ai->ai_addrlen = sizeof(struct sockaddr_in6);
              for (i = 1; i < naddrs; i++)
                {
                  nested_ai->ai_next = ares__malloc_addrinfo();
                  if (!nested_ai->ai_next)
                    {
                      status = ARES_ENOMEM;
                      goto failed_stat;
                    }

                  nested_ai = nested_ai->ai_next;

                  sin = ares_malloc(sizeof(struct sockaddr_in6));
                  if (!sin)
                    {
                      status = ARES_ENOMEM;
                      goto failed_stat;
                    }

                  memset(sin, 0, sizeof(struct sockaddr_in6));
                  memcpy(&sin->sin6_addr.s6_addr, &addrs[i],
                         sizeof(struct ares_in6_addr));
                  sin->sin6_family = AF_INET6;

                  nested_ai->ai_addr = (struct sockaddr *)sin;
                  nested_ai->ai_family = AF_INET6;
                  nested_ai->ai_addrlen = sizeof(struct sockaddr_in6);
                }
            }

          /* Append to existing addrinfo or set it if there are none.  */
          if (*ai)
            {
              ares_free(hostname);
              (*ai)->ai_next = head_ai;
            }
          else
            {
              /* Copy canonname in case we need it later */
              head_ai->ai_canonname = hostname;
              *ai = head_ai;
            }

          ares_free(addrs);
          return ARES_SUCCESS;
        }
    }

failed_stat:
  if (aliases)
    {
      for (i = 0; i < naliases; i++)
        ares_free(aliases[i]);
      ares_free(aliases);
    }
  ares_free(addrs);
  ares_free(hostname);
  ares_freeaddrinfo(head_ai);
  return status;
}

int ares_parse_aaaa_reply(const unsigned char *abuf, int alen,
                          struct hostent **host,
                          struct ares_addr6ttl *addrttls, int *naddrttls)
{
  return ares__parse_aaaa_reply(abuf, alen, host, NULL, addrttls, naddrttls);
}
