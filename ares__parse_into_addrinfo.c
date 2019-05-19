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

int ares__parse_into_addrinfo(const unsigned char *abuf,
                              int alen,
                              struct ares_addrinfo **head_ai)
{
  unsigned int qdcount, ancount;
  int status, i, rr_type, rr_class, rr_len, rr_ttl;
  int got_a = 0, got_aaaa = 0, got_cname = 0;
  long len;
  const unsigned char *aptr;
  char *hostname, *rr_name, *rr_data;
  struct ares_addrinfo *ai;

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

      if (rr_class == C_IN && rr_type == T_A
          && rr_len == sizeof(struct in_addr)
          && strcasecmp(rr_name, hostname) == 0)
        {
          got_a = 1;
          if (aptr + sizeof(struct in_addr) > abuf + alen)
          {  /* LCOV_EXCL_START: already checked above */
            ares_free(rr_name);
            status = ARES_EBADRESP;
            break;
          }  /* LCOV_EXCL_STOP */

          ai = ares__append_addrinfo(head_ai);
          if (!ai)
            {
              status = ARES_ENOMEM;
              goto failed_stat;
            }

          struct sockaddr_in *sin = ares_malloc(sizeof(struct sockaddr_in));
          if (!sin)
            {
              status = ARES_ENOMEM;
              goto failed_stat;
            }
          memset(sin, 0, sizeof(struct sockaddr_in));
          memcpy(&sin->sin_addr.s_addr, aptr, sizeof(struct in_addr));
          sin->sin_family = AF_INET;

          ai->ai_addr = (struct sockaddr *)sin;
          ai->ai_family = AF_INET;
          ai->ai_addrlen = sizeof(struct sockaddr_in);

          /* Ensure that each A TTL is no larger than the CNAME TTL. */
          if (rr_ttl < (*head_ai)->ai_cname_ttl)
            ai->ai_ttl = rr_ttl;
          else
            ai->ai_ttl = (*head_ai)->ai_cname_ttl;

          status = ARES_SUCCESS;
        }
      else if (rr_class == C_IN && rr_type == T_AAAA
          && rr_len == sizeof(struct ares_in6_addr)
          && strcasecmp(rr_name, hostname) == 0)
        {
          got_aaaa = 1;
          if (aptr + sizeof(struct ares_in6_addr) > abuf + alen)
          {  /* LCOV_EXCL_START: already checked above */
            ares_free(rr_name);
            status = ARES_EBADRESP;
            break;
          }  /* LCOV_EXCL_STOP */

          ai = ares__append_addrinfo(head_ai);
          if (!ai)
            {
              status = ARES_ENOMEM;
              goto failed_stat;
            }

          struct sockaddr_in6 *sin = ares_malloc(sizeof(struct sockaddr_in6));
          if (!sin)
            {
              status = ARES_ENOMEM;
              goto failed_stat;
            }

          memset(sin, 0, sizeof(struct sockaddr_in6));
          memcpy(&sin->sin6_addr.s6_addr, aptr, sizeof(struct ares_in6_addr));
          sin->sin6_family = AF_INET6;

          ai->ai_addr = (struct sockaddr *)sin;
          ai->ai_family = AF_INET6;
          ai->ai_addrlen = sizeof(struct sockaddr_in6);

          /* Ensure that each A TTL is no larger than the CNAME TTL. */
          if (rr_ttl < (*head_ai)->ai_cname_ttl)
            ai->ai_ttl = rr_ttl;
          else
            ai->ai_ttl = (*head_ai)->ai_cname_ttl;

          status = ARES_SUCCESS;
        }
      else if (rr_class == C_IN && rr_type == T_CNAME)
        {
          got_cname = 1;
          /* Decode the RR data and replace the hostname with it. */
          status = ares__expand_name_for_response(aptr, abuf, alen, &rr_data,
                                                  &len);
          if (status != ARES_SUCCESS)
            break;

          ares_free(hostname);
          hostname = rr_data;
          if (*head_ai == NULL)
            {
              ai = ares__append_addrinfo(head_ai);
              if (!ai)
                {
                  status = ARES_ENOMEM;
                  goto failed_stat;
                }
            }
          /* Take the min of the TTLs we see in the CNAME chain. */
          if ((*head_ai)->ai_cname_ttl > rr_ttl)
            (*head_ai)->ai_cname_ttl = rr_ttl;
        }

      ares_free(rr_name);

      aptr += rr_len;
      if (aptr > abuf + alen)
        {  /* LCOV_EXCL_START: already checked above */
          status = ARES_EBADRESP;
          break;
        }  /* LCOV_EXCL_STOP */
    }

  if (status == ARES_SUCCESS)
    {
      if (got_cname)
        {
          ares_free((*head_ai)->ai_canonname);
          (*head_ai)->ai_canonname = hostname;
        }
      else if (got_a == 0 && got_aaaa == 0)
        {
          /* the check for naliases to be zero is to make sure CNAME responses
             don't get caught here */
          status = ARES_ENODATA;
        }
    }

  return status;

failed_stat:
  ares_free(hostname);
  ares_freeaddrinfo(*head_ai);
  return status;
}
