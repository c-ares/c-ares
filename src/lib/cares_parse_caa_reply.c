
/* Copyright 2020 by <danny.sonnenschein@platynum.ch>
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

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_data.h"
#include "ares_private.h"

int
cares_parse_caa_reply (const unsigned char *abuf, int alen,
                      cares_caa_reply **caa_out)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr;
  const unsigned char *strptr;
  int status, rr_type, rr_class, rr_len;
  unsigned int rr_ttl;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  cares_caa_reply *caa_head = NULL;
  cares_caa_reply *caa_last = NULL;
  cares_caa_reply *caa_curr;

  /* Set *caa_out to NULL for all failure cases. */
  *caa_out = NULL;

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
      rr_ttl = DNS_RR_TTL (aptr);
      rr_len = DNS_RR_LEN (aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }

      /* Check if we are really looking at a CAA record */
      if ((rr_class == C_IN || rr_class == C_CHAOS) && rr_type == T_CAA)
        {
          unsigned char* property;
          unsigned char* value;
          strptr = aptr;

          /* Allocate storage for this CAA answer appending it to the list */
          caa_curr = ares_malloc_data(CARES_DATATYPE_CAA_REPLY);
          if (!caa_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (caa_last)
            {
              cares_caa_reply_set_next(caa_last, caa_curr);
            }
          else
            {
              caa_head = caa_curr;
            }
          caa_last = caa_curr;
          if (rr_len < 2)
            {
              status = ARES_EBADRESP;
              break;
            }
          cares_caa_reply_set_critical(caa_curr, (int)*strptr++);
          cares_caa_reply_set_plength(caa_curr, (int)*strptr++);
          if (cares_caa_reply_get_plength(caa_curr) <= 0 || (int)cares_caa_reply_get_plength(caa_curr) >= rr_len - 2)
            {
              status = ARES_EBADRESP;
              break;
            }
          property = ares_malloc (cares_caa_reply_get_plength(caa_curr) + 1/* Including null byte */);
          if (property == NULL)
            {
              status = ARES_ENOMEM;
              break;
            }
          memcpy ((char *) property, strptr, cares_caa_reply_get_plength(caa_curr));
          /* Make sure we NULL-terminate */
          property[cares_caa_reply_get_plength(caa_curr)] = 0;
          cares_caa_reply_set_property(caa_curr, property);
          strptr += cares_caa_reply_get_plength(caa_curr);

          cares_caa_reply_set_length(caa_curr, rr_len - cares_caa_reply_get_plength(caa_curr) - 2);
          if (cares_caa_reply_get_length(caa_curr) <= 0)
            {
              status = ARES_EBADRESP;
              break;
            }
          value = ares_malloc (cares_caa_reply_get_length(caa_curr) + 1/* Including null byte */);
          if (value == NULL)
            {
              status = ARES_ENOMEM;
              break;
            }
          memcpy ((char *) value, strptr, cares_caa_reply_get_length(caa_curr));
          /* Make sure we NULL-terminate */
          value[caa_curr->length] = 0;
          cares_caa_reply_set_value(caa_curr, value);
          cares_caa_reply_set_ttl(caa_curr, rr_ttl);
        }
      else if (rr_type != T_CNAME)
        {
          /* wrong record type */
          status = ARES_ENODATA;
          break;
        }

      /* Propagate any failures */
      if (status != ARES_SUCCESS)
        {
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
      if (caa_head)
        ares_free_data (caa_head);
      return status;
    }

  /* everything looks fine, return the data */
  *caa_out = caa_head;

  return ARES_SUCCESS;
}
