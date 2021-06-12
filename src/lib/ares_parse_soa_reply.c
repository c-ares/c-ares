
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
ares_parse_soa_reply(const unsigned char *abuf, int alen,
		     struct ares_soa_reply **soa_out)
{
  int status;
  char* nsname = NULL;
  char* hostmaster = NULL;
  cares_soa_reply *csoa_out = NULL;
  struct ares_soa_reply *soa = NULL;

  /* Set *soa_out to NULL for all failure cases. */
  *soa_out = NULL;

  status = cares_parse_soa_reply(abuf, alen, &csoa_out);

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    if (csoa_out)
      ares_free_data (csoa_out);
    return status;
  }
  soa = ares_malloc_data(ARES_DATATYPE_SOA_REPLY);

  nsname = ares_strdup(cares_soa_reply_get_nsname(csoa_out));
  if (!nsname)
  {
    status = ARES_ENOMEM;
    if (soa)
    {
      ares_free_data (soa);
    }
    if (csoa_out)
    {
      ares_free_data (csoa_out);
    }
    return status;
  }
  soa->nsname = nsname;

  hostmaster = ares_strdup(cares_soa_reply_get_hostmaster(csoa_out));
  if (!hostmaster)
  {
    status = ARES_ENOMEM;
    if (soa)
    {
      ares_free_data (soa);
    }
    if (csoa_out)
    {
      ares_free_data (csoa_out);
    }
    return status;
  }
  soa->hostmaster = hostmaster;

  soa->serial = cares_soa_reply_get_serial(csoa_out);
  soa->refresh = cares_soa_reply_get_refresh(csoa_out);
  soa->retry = cares_soa_reply_get_retry(csoa_out);
  soa->expire = cares_soa_reply_get_expire(csoa_out);
  soa->minttl = cares_soa_reply_get_minttl(csoa_out);

  if (csoa_out)
  {
    ares_free_data (csoa_out);
  }
  /* everything looks fine, return the data */
  *soa_out = soa;

  return ARES_SUCCESS;
}
