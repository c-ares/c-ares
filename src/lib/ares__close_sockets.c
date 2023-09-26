
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
#include "ares_private.h"
#include <assert.h>


void ares__close_connection(struct server_connection *conn)
{
  struct server_state *server  = conn->server;
  ares_channel         channel = server->channel;

  if (conn->is_tcp) {
    struct send_request *sendreq;

    /* Free all pending output buffers. */
    while (server->qhead) {
      /* Advance server->qhead; pull out query as we go. */
      sendreq = server->qhead;
      server->qhead = sendreq->next;
      if (sendreq->data_storage != NULL)
        ares_free(sendreq->data_storage);
      ares_free(sendreq);
    }
    server->qtail = NULL;

    /* Reset any existing input buffer. */
    ares__parser_consume(server->tcp_parser,
                         ares__parser_len(server->tcp_parser));

    server->tcp_connection_generation = ++channel->tcp_connection_generation;
    server->tcp_conn = NULL;
  }


  SOCK_STATE_CALLBACK(channel, conn->fd, 0, 0);
  ares__close_socket(channel, conn->fd);
  ares__llist_node_claim(
    ares__htable_asvp_get_direct(channel->connnode_by_socket, conn->fd)
  );
  ares__htable_asvp_remove(channel->connnode_by_socket, conn->fd);

#ifndef NDEBUG
  assert(ares__llist_len(conn->queries_to_conn) == 0);
#endif
  ares__llist_destroy(conn->queries_to_conn);
  ares_free(conn);
}

void ares__close_sockets(struct server_state *server)
{
  ares__llist_node_t  *node;

  while ((node = ares__llist_node_first(server->connections)) != NULL) {
    struct server_connection *conn = ares__llist_node_val(node);
    ares__close_connection(conn);
  }
}

void ares__check_cleanup_conn(ares_channel channel, ares_socket_t fd)
{
  ares__llist_node_t       *node;
  struct server_connection *conn;
  int                       do_cleanup = 0;

  node = ares__htable_asvp_get_direct(channel->connnode_by_socket, fd);
  if (node == NULL) {
    return;
  }

  conn = ares__llist_node_val(node);

  if (ares__llist_len(conn->queries_to_conn)) {
    return;
  }

  /* If we are configured not to stay open, close it out */
  if (!(channel->flags & ARES_FLAG_STAYOPEN)) {
    do_cleanup = 1;
  }

  /* If the udp connection hit its max queries, always close it */
  if (!conn->is_tcp && channel->udp_max_queries > 0 &&
      conn->total_queries >= (size_t)channel->udp_max_queries) {
    do_cleanup = 1;
  }

  if (do_cleanup) {
    ares__close_connection(conn);
  }
}
