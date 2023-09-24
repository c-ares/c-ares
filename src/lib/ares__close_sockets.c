
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

/* This isn't optimal, we should consider how to make this O(1).  Maybe like
 * making channel->conns_by_socket return a node pointer, but that would mean
 * we'd need to have the tcp connection and udp connections in the same list. */
static void ares_remove_conn(struct server_connection *conn)
{
  ares__llist_node_t *node;

  for (node = ares__llist_node_first(conn->server->connections);
       node != NULL;
       node = ares__llist_node_next(node)) {
    if (ares__llist_node_val(node) != conn)
      continue;

    ares__llist_node_claim(node);
    break;
  }
}

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
    if (server->tcp_buffer)
      ares_free(server->tcp_buffer);
    server->tcp_buffer = NULL;
    server->tcp_lenbuf_pos = 0;
    server->tcp_connection_generation = ++channel->tcp_connection_generation;
    server->tcp_conn = NULL;
  }

  if (conn->fd != ARES_SOCKET_BAD) {
    SOCK_STATE_CALLBACK(channel, conn->fd, 0, 0);
    ares__close_socket(channel, conn->fd);
    ares__htable_asvp_remove(channel->conns_by_socket, conn->fd);
  }
#ifndef NDEBUG
  assert(ares__llist_len(conn->queries_to_conn) == 0);
#endif
  ares__llist_destroy(conn->queries_to_conn);
  ares_remove_conn(conn);
  ares_free(conn);
}

void ares__close_sockets(struct server_state *server)
{
  ares__llist_node_t  *node;

  while ((node = ares__llist_node_first(server->connections)) != NULL) {
    struct server_connection *conn = ares__llist_node_claim(node);
    ares__close_connection(conn);
  }
}

void ares__check_cleanup_conn(ares_channel channel, ares_socket_t fd)
{
  struct server_connection *conn;
  int                       do_cleanup = 0;

  conn = ares__htable_asvp_get_direct(channel->conns_by_socket, fd);
  if (conn == NULL) {
    return;
  }

  if (ares__llist_len(conn->queries_to_conn)) {
    return;
  }

  /* If we are configured not to stay open, close it out */
  if (!(channel->flags & ARES_FLAG_STAYOPEN)) {
    do_cleanup = 1;
  }

  /* If the udp connection hit its max queries, always close it */
  if (!conn->is_tcp && channel->udp_max_queries > 0 &&
      conn->total_queries >= channel->udp_max_queries) {
    do_cleanup = 1;
  }

  if (do_cleanup) {
    ares__close_connection(conn);
  }
}
