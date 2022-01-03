
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
#include "stdio.h"

int
ares_parse_srv_reply (const unsigned char *abuf, int alen,
                      struct ares_srv_reply **srv_out)
{

  /* call cares_parse_srv_reply, iterate through the result and
   * create a linked list of struct ares_srv_reply to return */

  int status;
  char* newhost = NULL;
  struct ares_srv_reply *srv_head = NULL;
  struct ares_srv_reply *srv_curr = NULL;
  struct ares_srv_reply *srv_last = NULL;
  const cares_srv_reply *csrv_curr = NULL;
  cares_srv_reply_container *csrv_out = NULL;

  /* Set *srv_out to NULL for all failure cases. */
  *srv_out = NULL;

  status = cares_parse_srv_reply(abuf, alen, &csrv_out);
  printf("status after cares_parse_srv_reply: %d\n", status);

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    if (csrv_out)
    {
      cares_free_container(csrv_out);
    }
    return status;
  }

  /* iterate through the cares_srv_reply_container and
   * create a new ares_srv_reply */
  for (csrv_curr = cares_srv_reply_container_get_first(csrv_out);
    !cares_srv_reply_container_at_end(csrv_out);
    csrv_curr = cares_srv_reply_container_get_next(csrv_out))
  {
    srv_curr = ares_malloc_data(ARES_DATATYPE_SRV_REPLY);
    if (!srv_curr)
    {
      status = ARES_ENOMEM;
      break;
    }
    if (srv_last)
    {
      srv_last->next = srv_curr;
    }
    else
    {
      srv_head = srv_curr;
    }
    srv_last = srv_curr;

    /* copy the host to newhost so we can free csrv_out */
    newhost = ares_strdup(cares_srv_reply_get_host(csrv_curr));
    if (!newhost) {
      status = ARES_ENOMEM;
      break;
    }

    srv_curr->host = newhost;
    srv_curr->priority = cares_srv_reply_get_priority(csrv_curr);
    srv_curr->weight = cares_srv_reply_get_weight(csrv_curr);
    srv_curr->port = cares_srv_reply_get_port(csrv_curr);
  }

  if (csrv_out)
  {
    printf("free container in ares_parse\n");
    cares_free_container(csrv_out);
  }

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    printf("free srv_head in ares_parse\n");
    if (srv_head)
      ares_free_data (srv_head);
    return status;
  }

  /* everything looks fine, return the data */
  *srv_out = srv_head;

  return ARES_SUCCESS;
}
