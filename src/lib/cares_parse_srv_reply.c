
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2009 by Jakub Hrozek <jhrozek@redhat.com>
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

#include "ares_nameser.h"

#include "ares.h"
#include "ares_dns.h"
#include "ares_data.h"
#include "ares_private.h"
#include "cares_free_container.h"
#include "stdio.h"

int
cares_parse_srv_reply (const unsigned char *abuf, int alen,
                          cares_srv_reply_container **srv_out)
{
  unsigned int qdcount, ancount, i, count = 0;
  const unsigned char *aptr, *vptr;
  int status, rr_type, rr_class, rr_len;
  unsigned int rr_ttl;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  char* srv_host = NULL;
  // cares_srv_reply *srv_head = NULL;
  // cares_srv_reply *srv_last = NULL;
  cares_srv_reply *srv_curr;
  cares_srv_reply **srv_replies = NULL;

  /* Set *srv_out to NULL for all failure cases. */
  *srv_out = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT (abuf);
  ancount = DNS_HEADER_ANCOUNT (abuf);
  if (qdcount != 1)
    return ARES_EBADRESP;
  if (ancount == 0)
    return ARES_ENODATA;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares_expand_name (aptr, abuf, alen, &hostname, &len);
  if (status != ARES_SUCCESS)
    return status;

  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      ares_free (hostname);
      return ARES_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  printf("before srv_replies malloc, ancount: %d\n", ancount);
  printf("ancount * sizeof(**srv_replies): %lu\n", ancount * sizeof(**srv_replies));
  srv_replies = ares_malloc(ancount * sizeof(**srv_replies));
  printf("after srv_replies malloc\n");
  if (srv_replies == NULL)
  {
    ares_free (hostname);
    return ARES_ENOMEM;
  }
  
  for (i = 0; i < ancount; ++i)
  {
    srv_replies[i] = NULL;
  }

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < ancount; i++)
    {
      printf("start loop cares_parse_srv_reply\n");
      /* Decode the RR up to the data field. */
      status = ares_expand_name (aptr, abuf, alen, &rr_name, &len);
      if (status != ARES_SUCCESS)
        {
          break;
        }
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }
      rr_type = DNS_RR_TYPE (aptr);
      rr_class = DNS_RR_CLASS (aptr);
      rr_ttl = DNS_RR_TTL (aptr);
      rr_len = DNS_RR_LEN (aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }

      /* Check if we are really looking at a SRV record */
      if (rr_class == C_IN && rr_type == T_SRV)
        {
          /* parse the SRV record itself */
          if (rr_len < 6)
            {
              status = ARES_EBADRESP;
              break;
            }

          /* Allocate storage for this SRV answer appending it to the list */
          srv_curr = ares_malloc_data(CARES_DATATYPE_SRV_REPLY);
          if (!srv_curr)
            {
              status = ARES_ENOMEM;
              break;
            }

          vptr = aptr;
          cares_srv_reply_set_priority(srv_curr, DNS__16BIT(vptr));
          vptr += sizeof(unsigned short);
          cares_srv_reply_set_weight(srv_curr, DNS__16BIT(vptr));
          vptr += sizeof(unsigned short);
          cares_srv_reply_set_port(srv_curr, DNS__16BIT(vptr));
          vptr += sizeof(unsigned short);
          cares_srv_reply_set_ttl(srv_curr, rr_ttl);

          status = ares_expand_name (vptr, abuf, alen, &srv_host, &len);
          if (status != ARES_SUCCESS)
            break;
          cares_srv_reply_set_host(srv_curr, srv_host);
          printf("srv_curr->host: %p; host: %s\n", (void *)srv_curr->host, srv_curr->host);
          printf("before assign to srv_replies[count]; count: %u; srv_curr: %p\n", count, (void *)srv_curr);
          srv_replies[count] = srv_curr;
          printf("after assign to srv_replies[count]: %p; srv_replies[count]->host: %p\n", (void *)srv_replies[count], (void *)srv_replies[count]->host);
          count++;
        }
      else if (rr_type != T_CNAME)
        {
          /* wrong record type */
          status = ARES_ENODATA;
          break;
        }

      /* Don't lose memory in the next iteration */
      ares_free (rr_name);
      rr_name = NULL;

      /* Move on to the next record */
      aptr += rr_len;
    }
  if (hostname)
    ares_free (hostname);
  if (rr_name)
    ares_free (rr_name);

  /* clean up on error */
  if (status != ARES_SUCCESS)
    {
      if (srv_replies)
      {
        for(i = 0; i < count; ++i) {
          if (srv_replies[i])
          {
            printf("before ares_free_data srv_replies[i] in cares_parse_srv: %p\n", (void *)srv_replies[i]);
            ares_free_data(srv_replies[i]);
            printf("after ares_free_data srv_replies[i] in cares_parse_srv\n");
          }

        }
        printf("before ares_free srv_replies in cares_parse_srv\n");
        ares_free(srv_replies);
        printf("after ares_free srv_replies in cares_parse_srv\n");
      }
      return status;
    }

  printf("before cares_malloc_container\n");
  *srv_out = cares_malloc_container(CARES_CONTAINER_SRV_REPLY_CONTAINER);
  printf("after cares_malloc_container\n");
  if (*srv_out == NULL)
    return ARES_ENOMEM;

  /* everything looks fine, return the data */
  (*srv_out)->replies = srv_replies;
  printf("before set count\n");
  cares_srv_reply_container_set_count(*srv_out, count);
  printf("after set count\n");
  return ARES_SUCCESS;
}
