
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2004-2011 by Daniel Stenberg
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
 *
 * SPDX-License-Identifier: MIT
 */

#include "ares_setup.h"

#include <assert.h>

#include "ares.h"
#include "ares_private.h"

void ares_destroy_options(struct ares_options *options)
{
  int i;

  if(options->servers)
    ares_free(options->servers);
  for (i = 0; i < options->ndomains; i++)
    ares_free(options->domains[i]);
  if(options->domains)
    ares_free(options->domains);
  if(options->sortlist)
    ares_free(options->sortlist);
  if(options->lookups)
    ares_free(options->lookups);
  if(options->resolvconf_path)
    ares_free(options->resolvconf_path);
  if(options->hosts_path)
    ares_free(options->hosts_path);
}

void ares_destroy(ares_channel channel)
{
  int                 i;
  ares__llist_node_t *node = NULL;

  if (!channel)
    return;

  node = ares__llist_node_first(channel->all_queries);
  while (node != NULL) {
    ares__llist_node_t *next  = ares__llist_node_next(node);
    struct query       *query = ares__llist_node_claim(node);

    query->node_all_queries = NULL;
    query->callback(query->arg, ARES_EDESTRUCTION, 0, NULL, 0);
    ares__free_query(query);

    node = next;
  }
  
#ifndef NDEBUG
  /* Freeing the query should remove it from all the lists in which it sits,
   * so all query lists should be empty now.
   */
  assert(ares__llist_len(channel->all_queries) == 0);
  assert(ares__htable_stvp_num_keys(channel->queries_by_qid) == 0);
  assert(ares__slist_len(channel->queries_by_timeout) == 0);
#endif

  ares__destroy_servers_state(channel);

  if (channel->domains) {
    for (i = 0; i < channel->ndomains; i++)
      ares_free(channel->domains[i]);
    ares_free(channel->domains);
  }

  ares__llist_destroy(channel->all_queries);
  ares__slist_destroy(channel->queries_by_timeout);
  ares__htable_stvp_destroy(channel->queries_by_qid);

  if(channel->sortlist)
    ares_free(channel->sortlist);

  if (channel->lookups)
    ares_free(channel->lookups);

  if (channel->resolvconf_path)
    ares_free(channel->resolvconf_path);

  if (channel->hosts_path)
    ares_free(channel->hosts_path);

  if (channel->rand_state)
    ares__destroy_rand_state(channel->rand_state);

  ares_free(channel);
}

void ares__destroy_servers_state(ares_channel channel)
{
  struct server_state *server;
  int i;

  if (channel->servers)
    {
      for (i = 0; i < channel->nservers; i++)
        {
          server = &channel->servers[i];
          ares__close_sockets(channel, server);
          assert(ares__llist_len(server->queries_to_server) == 0);
          ares__llist_destroy(server->queries_to_server);
        }
      ares_free(channel->servers);
      channel->servers = NULL;
    }
  channel->nservers = -1;
}
