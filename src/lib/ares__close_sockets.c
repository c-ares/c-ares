
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

void ares__close_sockets(ares_channel channel, struct server_state *server)
{
  struct send_request *sendreq;
  ares__llist_node_t  *node;

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

  /* Reset brokenness */
  server->is_broken = 0;

  /* Close the TCP and UDP sockets. */
  if (server->tcp_socket.fd != ARES_SOCKET_BAD) {
    ares__htable_asvp_remove(channel->conns_by_socket,
                             server->tcp_socket.fd);
    SOCK_STATE_CALLBACK(channel, server->tcp_socket.fd, 0, 0);
    ares__close_socket(channel, server->tcp_socket.fd);
    server->tcp_socket.fd = ARES_SOCKET_BAD;
    server->tcp_connection_generation = ++channel->tcp_connection_generation;
  }

  node = ares__llist_node_first(server->udp_sockets);
  while (node != NULL) {
    ares__llist_node_t       *next = ares__llist_node_next(node);
    struct server_connection *conn = ares__llist_node_val(node);

    if (conn->fd != ARES_SOCKET_BAD) {
      SOCK_STATE_CALLBACK(channel, conn->fd, 0, 0);
      ares__close_socket(channel, conn->fd);
      ares__htable_asvp_remove(channel->conns_by_socket, conn->fd);
    }
    ares_free(conn);

    ares__llist_node_destroy(node);
    node = next;
  }

}
