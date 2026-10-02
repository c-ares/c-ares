/* MIT License
 *
 * Copyright (c) 2004 Daniel Stenberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

#include "ares_private.h"

/*
 * ares_cancel() cancels all ongoing requests/resolves that might be going on
 * on the given channel. It does NOT kill the channel, use ares_destroy() for
 * that.
 */
void ares_cancel(ares_channel_t *channel)
{
  if (channel == NULL) {
    return;
  }

  ares_channel_lock(channel);

  if (ares_llist_len(channel->all_queries) > 0) {
    ares_llist_node_t *node = NULL;
    ares_llist_node_t *next = NULL;

    /* Move the current queries to the cancellation list, so that only those
     * queries which were present on entry into this function are cancelled.
     * New queries added by callbacks of queries being cancelled will not be
     * cancelled themselves unless a callback calls ares_cancel() again.
     *
     * Nodes moved to queries_being_cancelled intentionally keep each query's
     * node_all_queries pointer. It remains the removal handle for the query's
     * channel-owned query list node until the cancel loop claims that node.
     */
    node = ares_llist_move_all_last(channel->queries_being_cancelled,
                                    channel->all_queries);

    while (node != NULL) {
      ares_query_t *query;

      /* Cache next since this node is being deleted */
      next = ares_llist_node_next(node);

      query                   = ares_llist_node_claim(node);
      query->node_all_queries = NULL;

      /* NOTE: its possible this may enqueue new queries */
      query->callback(query->arg, ARES_ECANCELLED, 0, NULL);
      ares_free_query(query);

      node = next;
    }
  }

  /* See if the connections should be cleaned up */
  ares_check_cleanup_conns(channel);

  ares_queue_notify_empty(channel);
  ares_channel_unlock(channel);
}
