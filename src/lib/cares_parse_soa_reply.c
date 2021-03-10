
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2012 Marko Kreen <markokr@gmail.com>
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
cares_parse_soa_reply(const unsigned char *abuf, int alen,
		     struct cares_soa_reply **soa_out)
{
  const unsigned char *aptr;
  long len;
  char *qname = NULL, *rr_name = NULL;
  struct cares_soa_reply *soa = NULL;
  int qdcount, ancount, qclass;
  int status, i, rr_type, rr_class, rr_len;
  unsigned int rr_ttl;

  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  /* parse message header */
  qdcount = DNS_HEADER_QDCOUNT(abuf);
  ancount = DNS_HEADER_ANCOUNT(abuf);

  if (qdcount != 1)
    return ARES_EBADRESP;
  if (ancount == 0)
    return ARES_EBADRESP;

  aptr = abuf + HFIXEDSZ;

  /* query name */
  status = ares__expand_name_for_response(aptr, abuf, alen, &qname, &len);
  if (status != ARES_SUCCESS)
    return status;

  if (alen <= len + HFIXEDSZ + 1)
    return ARES_EBADRESP;
  aptr += len;

  qclass = DNS_QUESTION_TYPE(aptr);

  /* skip qtype & qclass */
  if (aptr + QFIXEDSZ > abuf + alen)
  {
    ares_free(qname);
    return ARES_EBADRESP;
  }
  aptr += QFIXEDSZ;

  /* qclass of SOA with multiple answers */
  if (qclass == T_SOA && ancount > 1)
  {
    ares_free(qname);
    return ARES_EBADRESP;
  }

  /* examine all the records, break and return if found soa */
  for (i = 0; i < ancount; i++)
  {
    rr_name = NULL;
    status  = ares__expand_name_for_response (aptr, abuf, alen, &rr_name, &len);
    if (status != ARES_SUCCESS)
    {
      break;
    }

    aptr += len;
    if ( aptr + RRFIXEDSZ > abuf + alen )
    {
      status = ARES_EBADRESP;
      break;
    }
    rr_type = DNS_RR_TYPE( aptr );
    rr_class = DNS_RR_CLASS( aptr );
    rr_ttl = DNS_RR_TTL(aptr);
    rr_len = DNS_RR_LEN( aptr );
    aptr += RRFIXEDSZ;
    if (aptr + rr_len > abuf + alen)
      {
        status = ARES_EBADRESP;
        break;
      }
    if ( rr_class == C_IN && rr_type == T_SOA )
    {
      /* allocate result struct */
      soa = ares_malloc_data(ARES_DATATYPE_CSOA_REPLY);
      if (!soa)
        {
          status = ARES_ENOMEM;
          break;
        }

      /* nsname */
      char* nsname;
      status = ares__expand_name_for_response(aptr, abuf, alen, &nsname,
                                               &len);
      if (status != ARES_SUCCESS)
        break;
      cares_soa_reply_set_nsname(soa, nsname);
      aptr += len;

      /* hostmaster */
      char* hostmaster;
      status = ares__expand_name_for_response(aptr, abuf, alen,
                                              &hostmaster, &len);
      if (status != ARES_SUCCESS)
        break;
      cares_soa_reply_set_hostmaster(soa, hostmaster);
      aptr += len;

      /* integer fields */
      if (aptr + 5 * 4 > abuf + alen)
       {
         status = ARES_EBADRESP;
         break;
       }
      cares_soa_reply_set_serial(soa, DNS__32BIT(aptr + 0 * 4));
      cares_soa_reply_set_refresh(soa, DNS__32BIT(aptr + 1 * 4));
      cares_soa_reply_set_retry(soa, DNS__32BIT(aptr + 2 * 4));
      cares_soa_reply_set_expire(soa, DNS__32BIT(aptr + 3 * 4));
      cares_soa_reply_set_minttl(soa, DNS__32BIT(aptr + 4 * 4));
      cares_soa_reply_set_ttl(soa, rr_ttl);
      break;
    }
    aptr += rr_len;

    ares_free(rr_name);
    rr_name = NULL;

    if (aptr > abuf + alen)
    {
      status = ARES_EBADRESP;
      break;
    }
  }

  if (status == ARES_SUCCESS && !soa)
  {
    /* no SOA record found */
    status = ARES_EBADRESP;
  }

  if (qname)
    ares_free(qname);
  if(rr_name)
    ares_free(rr_name);

  if (status != ARES_SUCCESS)
  {
    /* no SOA record found */
    if (soa)
      ares_free_data(soa);
    return status;
  }

  *soa_out = soa;

  return ARES_SUCCESS;
}
