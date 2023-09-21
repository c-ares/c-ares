
/* Copyright (C) 2005 - 2010, Daniel Stenberg
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

#include "ares.h"
#include "ares_private.h"

int ares_getsock(ares_channel channel,
                 ares_socket_t *socks,
                 int numsocks) /* size of the 'socks' array */
{
  struct server_state *server;
  int i;
  int sockindex=0;
  int bitmap = 0;
  unsigned int setbits = 0xffffffff;

  /* Are there any active queries? */
  size_t active_queries = ares__llist_len(channel->all_queries);

  for (i = 0; i < channel->nservers; i++) {
    server = &channel->servers[i];
    /* We only need to register interest in UDP sockets if we have
     * outstanding queries.
     */
    if (active_queries) {
      ares__llist_node_t *node;
      for (node = ares__llist_node_first(server->udp_sockets);
           node != NULL;
           node = ares__llist_node_next(node)) {

        struct server_connection *conn = ares__llist_node_val(node);

        if(sockindex >= numsocks || sockindex >= ARES_GETSOCK_MAXNUM)
          break;

        socks[sockindex] = conn->fd;
        bitmap |= ARES_GETSOCK_READABLE(setbits, sockindex);
        sockindex++;
      }
    }

    /* We always register for TCP events, because we want to know
     * when the other side closes the connection, so we don't waste
     * time trying to use a broken connection.
     */
    if (server->tcp_socket.fd != ARES_SOCKET_BAD) {
      if(sockindex >= numsocks || sockindex >= ARES_GETSOCK_MAXNUM)
       break;

      socks[sockindex] = server->tcp_socket.fd;
      bitmap |= ARES_GETSOCK_READABLE(setbits, sockindex);

      if (server->qhead && active_queries) {
       /* then the tcp socket is also writable! */
       bitmap |= ARES_GETSOCK_WRITABLE(setbits, sockindex);
      }
      sockindex++;
    }
  }
  return bitmap;
}
