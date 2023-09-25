
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
 *
 * SPDX-License-Identifier: MIT
 */

#include "ares_setup.h"

#include "ares.h"
#include "ares_nowarn.h"
#include "ares_private.h"

int ares_fds(ares_channel channel, fd_set *read_fds, fd_set *write_fds)
{
  struct server_state *server;
  ares_socket_t nfds;
  int i;

  /* Are there any active queries? */
  size_t active_queries = ares__llist_len(channel->all_queries);

  nfds = 0;
  for (i = 0; i < channel->nservers; i++) {
    server = &channel->servers[i];

    ares__llist_node_t *node;

    for (node = ares__llist_node_first(server->connections);
         node != NULL;
         node = ares__llist_node_next(node)) {
      struct server_connection *conn = ares__llist_node_val(node);

      /* We only need to register interest in UDP sockets if we have
       * outstanding queries.
       */
      if (active_queries || conn->is_tcp) {
        FD_SET(conn->fd, read_fds);
        if (conn->fd >= nfds)
          nfds = conn->fd + 1;
      }

      if (conn->is_tcp && server->qhead) {
        FD_SET(conn->fd, write_fds);
      }
    }
  }

  return (int)nfds;
}
