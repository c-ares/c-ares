
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

#include "ares_nameser.h"

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_nowarn.h"
#include "ares_data.h"
#include "ares_private.h"

int cares_parse_ns_reply(const unsigned char *abuf, int alen,
                         cares_ns_reply **ns_out)
{
  unsigned int qdcount, ancount;
  int status, i, rr_type, rr_class, rr_len;
  unsigned int rr_ttl;
  long len;
  const unsigned char *aptr;
  char *nsname = NULL, *rr_name = NULL;
  char* ns_host = NULL;
  cares_ns_reply *ns_head = NULL;
  cares_ns_reply *ns_last = NULL;
  cares_ns_reply *ns_curr = NULL;

  /* Set *ns_out to NULL for all failure cases. */
  *ns_out = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT(abuf);
  ancount = DNS_HEADER_ANCOUNT(abuf);
  if (qdcount != 1)
    return ARES_EBADRESP;
  if (ancount == 0)
    return ARES_ENODATA;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares__expand_name_for_response(aptr, abuf, alen, &nsname, &len, 0);
  if (status != ARES_SUCCESS)
    return status;
  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      ares_free(nsname);
      return ARES_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < (int)ancount; i++)
    {
      /* Decode the RR up to the data field. */
      status = ares__expand_name_for_response(aptr, abuf, alen, &rr_name, &len, 0);
      if (status != ARES_SUCCESS)
        break;
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }
      rr_type = DNS_RR_TYPE(aptr);
      rr_class = DNS_RR_CLASS(aptr);
      rr_ttl = DNS_RR_TTL(aptr);
      rr_len = DNS_RR_LEN(aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }

      if (rr_class == C_IN && rr_type == T_NS)
        {
          /* Allocate storage for this NS answer appending it to the list */
          ns_curr = ares_malloc_data(CARES_DATATYPE_NS_REPLY);
          if (!ns_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (ns_last)
            {
              cares_ns_reply_set_next(ns_last, ns_curr);
            }
          else
            {
              ns_head = ns_curr;
            }
          ns_last = ns_curr;

          /* Decode the RR data and set hostname to it. */
          status = ares__expand_name_for_response(aptr, abuf, alen, &ns_host,
                                                  &len, 1);
          if (status != ARES_SUCCESS)
            {
              break;
            }

          cares_ns_reply_set_host(ns_curr, ns_host);
          cares_ns_reply_set_ttl(ns_curr, rr_ttl);
        }
      else if (rr_type != T_CNAME)
        {
          /* wrong record type */
          status = ARES_ENODATA;
          break;
        }

      /* Don't lose memory in the next iteration */
      ares_free(rr_name);
      rr_name = NULL;

      /* Move on to the next record */
      aptr += rr_len;
      if (aptr > abuf + alen)
        {  /* LCOV_EXCL_START: already checked above */
          status = ARES_EBADRESP;
          break;
        }  /* LCOV_EXCL_STOP */
    }

  if (nsname)
    ares_free(nsname);
  if (rr_name)
    ares_free(rr_name);

  /* clean up on error */
  if (status != ARES_SUCCESS)
    {
      if (ns_head)
      {
        ares_free_data(ns_head);
      }
      return status;
    }

  /* everything looks fine, return the data */
  *ns_out = ns_head;
  return ARES_SUCCESS;
}
