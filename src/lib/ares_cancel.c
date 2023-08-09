
/* Copyright (C) 2004 by Daniel Stenberg et al
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * SPDX-License-Identifier: MIT
 */

#include "ares_setup.h"
#include <assert.h>

#include "ares.h"
#include "ares_private.h"

/*
 * ares_cancel() cancels all ongoing requests/resolves that might be going on
 * on the given channel. It does NOT kill the channel, use ares_destroy() for
 * that.
 */
void ares_cancel(ares_channel channel)
{
  if (ares__llist_len(channel->all_queries) > 0)
  {
    ares__llist_node_t *node = NULL;
    ares__llist_node_t *next = NULL;

    /* Swap list heads, so that only those queries which were present on entry
     * into this function are cancelled. New queries added by callbacks of
     * queries being cancelled will not be cancelled themselves.
     */
    ares__llist_t *list_copy = channel->all_queries;
    channel->all_queries = ares__llist_create(NULL);

    /* Out of memory, this function doesn't return a result code though so we
     * can't report to caller */
    if (channel->all_queries == NULL) {
      channel->all_queries = list_copy;
      return;
    }

    node = ares__llist_node_first(list_copy);
    while (node != NULL) {
      struct query *query;

      /* Cache next since this node is being deleted */
      next = ares__llist_node_next(node);

      query = ares__llist_node_claim(node);
      query->node_all_queries = NULL;

      /* NOTE: its possible this may enqueue new queries */
      query->callback(query->arg, ARES_ECANCELLED, 0, NULL, 0);

      ares__free_query(query);

      node = next;
    }

    ares__llist_destroy(list_copy);
  }

  if (!(channel->flags & ARES_FLAG_STAYOPEN) && ares__llist_len(channel->all_queries) == 0)
  {
    if (channel->servers)
    {
      int i;
      for (i = 0; i < channel->nservers; i++)
        ares__close_sockets(channel, &channel->servers[i]);
    }
  }
}
