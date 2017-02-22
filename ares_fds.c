
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

#include "ares.h"
#include "ares_nowarn.h"
#include "ares_private.h"

int ares_fds(ares_channel channel, fd_set *read_fds, fd_set *write_fds)
{
  struct server_state *server;
  ares_socket_t nfds;
  int i;

  /* Are there any active queries? */
  int active_queries = !ares__is_list_empty(&(channel->all_queries));

  nfds = 0;
  for (i = 0; i < channel->nservers; i++)
    {
      server = &channel->servers[i];
      /* We only need to register interest in UDP sockets if we have
       * outstanding queries.
       */
      if (active_queries && server->udp_socket != ARES_SOCKET_BAD)
        {
          FD_SET(server->udp_socket, read_fds);
          if (server->udp_socket >= nfds)
            nfds = server->udp_socket + 1;
        }
      /* We always register for TCP events, because we want to know
       * when the other side closes the connection, so we don't waste
       * time trying to use a broken connection.
       */
      if (server->tcp_socket != ARES_SOCKET_BAD)
       {
         FD_SET(server->tcp_socket, read_fds);
         if (server->qhead)
           FD_SET(server->tcp_socket, write_fds);
         if (server->tcp_socket >= nfds)
           nfds = server->tcp_socket + 1;
       }
    }
  return (int)nfds;
}


int ares_fds_array(ares_channel channel, ares_socket_t **read_fds, ares_socket_t **write_fds)
{
  struct server_state *server;
  int i;
  int r_cnt = 0;
  int w_cnt = 0;
  int r_size = 128;
  int w_size = 128;

  *read_fds = (ares_socket_t *)malloc(r_size * sizeof(ares_socket_t));
  *write_fds = (ares_socket_t *)malloc(w_size * sizeof(ares_socket_t));

  /* Are there any active queries? */
  int active_queries = !ares__is_list_empty(&(channel->all_queries));

  for (i = 0; i < channel->nservers; i++)
    {
      server = &channel->servers[i];
      /* We only need to register interest in UDP sockets if we have
       * outstanding queries.
       */
      if (active_queries && server->udp_socket != ARES_SOCKET_BAD)
      {
        *(*read_fds + r_cnt++) = server->udp_socket;
      }
      /* We always register for TCP events, because we want to know
       * when the other side closes the connection, so we don't waste
       * time trying to use a broken connection.
       */
      if (server->tcp_socket != ARES_SOCKET_BAD)
       {
         *(*read_fds + r_cnt++) = server->tcp_socket;
         if (server->qhead)
         {
           *(*write_fds + w_cnt++) = server->tcp_socket;
         }
       }
      if (r_cnt >= r_size - 2)
        {
          r_size *= 2;
          *read_fds = (ares_socket_t *)realloc(*read_fds, r_size * sizeof(ares_socket_t));
        }

      if (w_cnt >= w_size - 2)
        {
          w_size *= 2;
          *write_fds = (ares_socket_t *)realloc(*write_fds, w_size * sizeof(ares_socket_t));
        }

    }

  *(*read_fds + r_cnt) = ARES_SOCKET_BAD;
  *(*write_fds + w_cnt) = ARES_SOCKET_BAD;

  return r_cnt + w_cnt;
}
