
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

int cares_parse_ptr_reply(const unsigned char *abuf, int alen,
                          cares_ptr_reply **ptr_out)
{
  unsigned int qdcount, ancount;
  int status, i, rr_type, rr_class, rr_len;
  unsigned int rr_ttl;
  long len;
  const unsigned char *aptr;
  char *ptrname = NULL, *rr_name = NULL;
  char* ptr_host = NULL;
  cares_ptr_reply *ptr_head = NULL;
  cares_ptr_reply *ptr_last = NULL;
  cares_ptr_reply *ptr_curr;

  /* Set *ptr_out to NULL for all failure cases. */
  *ptr_out = NULL;

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
  status = ares__expand_name_for_response(aptr, abuf, alen, &ptrname, &len);
  if (status != ARES_SUCCESS)
    return status;
  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      ares_free(ptrname);
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

      if (rr_class == C_IN && rr_type == T_PTR)
        {
          if (strcasecmp(rr_name, ptrname) != 0)
          {
            /* question and answer don't match */
            status = ARES_ENODATA;
            break;
          }
          /* Allocate storage for this PTR answer appending it to the list */
          ptr_curr = ares_malloc_data(ARES_DATATYPE_CPTR_REPLY);
          if (!ptr_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (ptr_last)
            {
              cares_ptr_reply_set_next(ptr_last, ptr_curr);
            }
          else
            {
              ptr_head = ptr_curr;
            }
          ptr_last = ptr_curr;

          /* Decode the RR data and set hostname to it. */
          status = ares__expand_name_for_response(aptr, abuf, alen, &ptr_host,
                                                  &len);
          if (status != ARES_SUCCESS)
            {
              break;
            }

          cares_ptr_reply_set_host(ptr_curr, ptr_host);
          cares_ptr_reply_set_ttl(ptr_curr, rr_ttl);
        }
      else if (rr_class == C_IN && rr_type == T_CNAME)
        {
          /* Decode the RR data and replace ptrname with it. */
          ares_free(ptrname);
          ptrname = NULL;
          status = ares__expand_name_for_response(aptr, abuf, alen, &ptrname,
                                                  &len);
          if (status != ARES_SUCCESS)
            {
              break;
            }
        }
      else
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
  if (ptrname)
    ares_free(ptrname);
  if (rr_name)
    ares_free(rr_name);

  /* clean up on error */
  if (status != ARES_SUCCESS)
    {
      if (ptr_head)
      {
        ares_free_data (ptr_head);
      }
      return status;
    }

  /* everything looks fine, return the data */
  *ptr_out = ptr_head;
  return ARES_SUCCESS;
}
