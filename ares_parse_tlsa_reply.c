
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2009 by Jakub Hrozek <jhrozek@redhat.com>
 * Copyright (C) 2014 Red Hat
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

#include <ares.h>
#include <ares_dns.h> 
#include <ares_data.h>

/* AIX portability check */
#ifndef T_TLSA
#  define T_TLSA 52 /* server selection */
#endif

int
ares_parse_tlsa_reply (const unsigned char *abuf, int alen,
                       struct ares_tlsa_reply **tlsa_out)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr, *vptr;
  char *hostname = NULL, *rr_name = NULL;
  int status, rr_type, rr_class, rr_len;
  long len;
  struct ares_tlsa_reply *tlsa_head = NULL;
  struct ares_tlsa_reply *tlsa_last = NULL;
  struct ares_tlsa_reply *tlsa_curr;

  /* Set *tlsa_out to NULL for all failure cases. */
  *tlsa_out = NULL;

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
      free (hostname);
      return ARES_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < ancount; i++)
    {
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
      rr_len = DNS_RR_LEN (aptr);

      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }

      /* Check if we are really looking at a TLSA record */
      if (rr_class == C_IN && rr_type == T_TLSA)
        {
          /* parse the SRV record itself */
          if (rr_len < 4)
            {
              status = ARES_EBADRESP;
              break;
            }

          /* Allocate storage for this SRV answer appending it to the list */
          tlsa_curr = ares_malloc_data(ARES_DATATYPE_TLSA_REPLY);
          if (!tlsa_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (tlsa_last)
            {
              tlsa_last->next = tlsa_curr;
            }
          else
            {
              tlsa_head = tlsa_curr;
            }
          tlsa_last = tlsa_curr;

          vptr = aptr;
          tlsa_curr->usage = vptr[0];
          vptr += 1;
          tlsa_curr->selector = vptr[0];
          vptr += 1;
          tlsa_curr->mtype = vptr[0];
          vptr += 1;

          tlsa_curr->data = malloc(rr_len-3);
          if (tlsa_curr->data == NULL)
            {
              status = ARES_ENOMEM;
              break;
            }
          tlsa_curr->data_size = rr_len-3;
          memcpy(tlsa_curr->data, vptr, rr_len-3);
        }

      /* Don't lose memory in the next iteration */
      free (rr_name);
      rr_name = NULL;

      /* Move on to the next record */
      aptr += rr_len;
    }

  if (hostname)
    free (hostname);
  if (rr_name)
    free (rr_name);

  /* clean up on error */
  if (status != ARES_SUCCESS)
    {
      if (tlsa_head)
        ares_free_data (tlsa_head);
      return status;
    }

  /* everything looks fine, return the data */
  *tlsa_out = tlsa_head;

  return ARES_SUCCESS;
}
