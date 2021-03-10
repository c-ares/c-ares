
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
#include "ares_strdup.h"

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
ares_parse_mx_reply (const unsigned char *abuf, int alen,
                      struct ares_mx_reply **mx_out)
{

  /* call cares_parse_mx_reply, iterate through the result and
   * create a linked list of struct ares_mx_reply to return */

  int status;
  struct ares_mx_reply *mx_head = NULL;
  struct ares_mx_reply *mx_curr = NULL;
  struct ares_mx_reply *mx_last = NULL;
  cares_mx_reply *cmx_curr = NULL;
  cares_mx_reply *cmx_out = NULL;

  /* Set *mx_out to NULL for all failure cases. */
  *mx_out = NULL;

  status = cares_parse_mx_reply(abuf, alen, &cmx_out);

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    if (cmx_out)
      ares_free_data (cmx_out);
    return status;
  }

  /* iterate through the cares_mx_reply list and
   * create a new ares_mx_reply */
  for (cmx_curr = cmx_out; cmx_curr;
    cmx_curr = cares_mx_reply_get_next(cmx_curr))
  {
    mx_curr = ares_malloc_data(ARES_DATATYPE_MX_REPLY);
    if (!mx_curr)
    {
      status = ARES_ENOMEM;
      break;
    }
    if (mx_last)
    {
      mx_last->next = mx_curr;
    }
    else
    {
      mx_head = mx_curr;
    }
    mx_last = mx_curr;

    /* copy the host to newhost so we can free cmx_out */
    char *newhost = ares_strdup(cares_mx_reply_get_host(cmx_curr));
    if (!newhost) {
      status = ARES_ENOMEM;
      break;
    }

    mx_curr->host = newhost;
    mx_curr->priority = cares_mx_reply_get_priority(cmx_curr);
  }

  if (cmx_out)
  {
    ares_free_data (cmx_out);
  }

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
