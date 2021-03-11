
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

int
ares_parse_naptr_reply (const unsigned char *abuf, int alen,
                        struct ares_naptr_reply **naptr_out)
{
  int status;
  const unsigned char* flags = NULL;
  const unsigned char* service = NULL;
  const unsigned char* regexp = NULL;
  char* replacement = NULL;
  unsigned long len;
  struct ares_naptr_reply *naptr_head = NULL;
  struct ares_naptr_reply *naptr_last = NULL;
  struct ares_naptr_reply *naptr_curr;
  cares_naptr_reply *cnaptr_curr = NULL;
  cares_naptr_reply *cnaptr_out = NULL;

  /* Set *naptr_out to NULL for all failure cases. */
  *naptr_out = NULL;

  status = cares_parse_naptr_reply(abuf, alen, &cnaptr_out);

  if (status != ARES_SUCCESS)
  {
    if (cnaptr_out)
      ares_free_data(cnaptr_out);
    return status;
  }

  /* iterate through the cares_naptr_reply list and
   * create a new ares_naptr_reply */
  for(cnaptr_curr = cnaptr_out; cnaptr_curr;
      cnaptr_curr = cares_naptr_reply_get_next(cnaptr_curr))
  {
    naptr_curr = ares_malloc_data(ARES_DATATYPE_NAPTR_REPLY);
    if (!naptr_curr)
    {
      status = ARES_ENOMEM;
      break;
    }
    if (naptr_last)
    {
      naptr_last->next = naptr_curr;
    }
    else {
      naptr_head = naptr_curr;
    }
    naptr_last = naptr_curr;

    /* fill in the ares_naptr_reply fields */
    naptr_curr->order = cares_naptr_reply_get_order(cnaptr_curr);
    naptr_curr->preference = cares_naptr_reply_get_preference(cnaptr_curr);

    flags = cares_naptr_reply_get_flags(cnaptr_curr);
    len = strlen((char *)flags);
    naptr_curr->flags = ares_malloc(len + 1);
    if (!naptr_curr->flags)
    {
      status = ARES_ENOMEM;
      break;
    }
    memcpy(naptr_curr->flags, flags, len);
    /* Make sure we NULL-terminate */
    naptr_curr->flags[len] = 0;

    service = cares_naptr_reply_get_service(cnaptr_curr);
    len = strlen((char *)service);
    naptr_curr->service = ares_malloc(len + 1);
    if (!naptr_curr->service)
    {
      status = ARES_ENOMEM;
      break;
    }
    memcpy(naptr_curr->service, service, len);
    /* Make sure we NULL-terminate */
    naptr_curr->service[len] = 0;

    regexp = cares_naptr_reply_get_regexp(cnaptr_curr);
    len = strlen((char *)regexp);
    naptr_curr->regexp = ares_malloc(len + 1);
    if (!naptr_curr->regexp)
    {
      status = ARES_ENOMEM;
      break;
    }
    memcpy(naptr_curr->regexp, regexp, len);
    /* Make sure we NULL-terminate */
    naptr_curr->regexp[len] = 0;

    replacement = ares_strdup(
                        cares_naptr_reply_get_replacement(cnaptr_curr));
    if (!replacement) {
      status = ARES_ENOMEM;
      break;
    }

    naptr_curr->replacement = replacement;
  }

  if (cnaptr_out)
  {
    ares_free_data(cnaptr_out);
  }

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    if (naptr_head)
      ares_free_data(naptr_head);
    return status;
  }

  *naptr_out = naptr_head;

  return ARES_SUCCESS;
}
