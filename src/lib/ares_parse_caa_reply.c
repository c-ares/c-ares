
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
#include <stdio.h>

int
ares_parse_caa_reply (const unsigned char *abuf, int alen,
                      struct ares_caa_reply **caa_out)
{
  int status;
  struct ares_caa_reply *caa_head = NULL;
  struct ares_caa_reply *caa_last = NULL;
  struct ares_caa_reply *caa_curr;
  cares_caa_reply *ccaa_curr = NULL;
  cares_caa_reply *ccaa_out = NULL;

  /* Set *caa_out to NULL for all failure cases. */
  *caa_out = NULL;

  status = cares_parse_caa_reply(abuf, alen, &ccaa_out);

  if (status != ARES_SUCCESS)
  {
    if (ccaa_out)
      ares_free_data(ccaa_out);
    return status;
  }

  /* iterate through the cares_caa_reply list and
   * create a new ares_caa_reply */
  for(ccaa_curr = ccaa_out; ccaa_curr;
      ccaa_curr = cares_caa_reply_get_next(ccaa_curr))
  {
    const unsigned char* property;
    const unsigned char* value;
    caa_curr = ares_malloc_data(ARES_DATATYPE_CAA_REPLY);
    if (!caa_curr)
    {
      status = ARES_ENOMEM;
      break;
    }
    if (caa_last)
    {
      caa_last->next = caa_curr;
    }
    else {
      caa_head = caa_curr;
    }
    caa_last = caa_curr;

    /* fill in the ares_caa_reply fields */
    caa_curr->critical = cares_caa_reply_get_critical(ccaa_curr);

    property = cares_caa_reply_get_property(ccaa_curr);
    caa_curr->property = ares_malloc(cares_caa_reply_get_plength(ccaa_curr) + 1);
    if (!caa_curr->property)
    {
      status = ARES_ENOMEM;
      break;
    }
    memcpy(caa_curr->property, property, cares_caa_reply_get_plength(ccaa_curr));
    /* Make sure we NULL-terminate */
    caa_curr->property[cares_caa_reply_get_plength(ccaa_curr)] = 0;

    caa_curr->plength = cares_caa_reply_get_plength(ccaa_curr);

    value = cares_caa_reply_get_value(ccaa_curr);
    caa_curr->value = ares_malloc(cares_caa_reply_get_length(ccaa_curr) + 1);
    if (!caa_curr->value)
    {
      status = ARES_ENOMEM;
      break;
    }
    memcpy(caa_curr->value, value, cares_caa_reply_get_length(ccaa_curr));
    /* Make sure we NULL-terminate */
    caa_curr->value[cares_caa_reply_get_length(ccaa_curr)] = 0;

    caa_curr->length = cares_caa_reply_get_length(ccaa_curr);
  }

  if (ccaa_out)
  {
    ares_free_data(ccaa_out);
  }

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    if (caa_head)
      ares_free_data(caa_head);
    return status;
  }

  *caa_out = caa_head;

  return ARES_SUCCESS;
}
