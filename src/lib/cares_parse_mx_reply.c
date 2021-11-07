
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2010 Jeremy Lal <kapouer@melix.org>
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

int
cares_parse_mx_reply (const unsigned char *abuf, int alen,
                      cares_mx_reply **mx_out)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr, *vptr;
  char* mx_host = NULL;
  int status, rr_type, rr_class, rr_len;
  unsigned int rr_ttl;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  cares_mx_reply *mx_head = NULL;
  cares_mx_reply *mx_last = NULL;
  cares_mx_reply *mx_curr;

  /* Set *mx_out to NULL for all failure cases. */
  *mx_out = NULL;

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
      rr_ttl = DNS_RR_TTL(aptr);
      rr_len = DNS_RR_LEN (aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }

      /* Check if we are really looking at a MX record */
      if (rr_class == C_IN && rr_type == T_MX)
        {

          /* parse the MX record itself */
          if (rr_len < 2)
            {
              status = ARES_EBADRESP;
              break;
            }

          /* Allocate storage for this MX answer appending it to the list */
          mx_curr = ares_malloc_data(CARES_DATATYPE_MX_REPLY);
          if (!mx_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (mx_last)
            {
              cares_mx_reply_set_next(mx_last, mx_curr);
            }
          else
            {
              mx_head = mx_curr;
            }
          mx_last = mx_curr;

          vptr = aptr;
          cares_mx_reply_set_priority(mx_curr, DNS__16BIT(vptr));
          cares_mx_reply_set_ttl(mx_curr, rr_ttl);
          vptr += sizeof(unsigned short);

          status = ares_expand_name (vptr, abuf, alen, &mx_host, &len);
          if (status != ARES_SUCCESS)
            break;

          cares_mx_reply_set_host(mx_curr, mx_host);
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
      if (mx_head)
        ares_free_data (mx_head);
      return status;
    }

  /* everything looks fine, return the data */
  *mx_out = mx_head;

  return ARES_SUCCESS;
}
