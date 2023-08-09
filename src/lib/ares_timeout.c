
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

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include "ares.h"
#include "ares_private.h"

/* return time offset between now and (future) check, in milliseconds */
static long timeoffset(struct timeval *now, struct timeval *check)
{
  return (check->tv_sec - now->tv_sec)*1000 +
         (check->tv_usec - now->tv_usec)/1000;
}

struct timeval *ares_timeout(ares_channel channel, struct timeval *maxtv,
                             struct timeval *tvbuf)
{
  struct query       *query;
  ares__slist_node_t *node;
  struct timeval      now;
  long                offset;

printf("%s(): %zu nodes\n", __FUNCTION__, ares__slist_len(channel->queries_by_timeout));
  /* The minimum timeout of all queries is always the first entry in
   * channel->queries_by_timeout */
  node = ares__slist_node_first(channel->queries_by_timeout);
  /* no queries/timeout */
  if (node == NULL) {
    return maxtv; /* <-- maxtv can be null though, hrm */
  }

  query = ares__slist_node_val(node);

  now = ares__tvnow();
printf("%s(): first timeout tv_sec=%ld, tv_usec=%ld (now %ld, %ld)\n", __FUNCTION__, (long)query->timeout.tv_sec, (long)query->timeout.tv_usec, (long)now.tv_sec, (long)now.tv_usec);

  offset = timeoffset(&now, &query->timeout);
  if (offset < 0)
    offset = 0;
  if (offset > (long)INT_MAX)
    offset = INT_MAX;

  tvbuf->tv_sec = offset / 1000;
  tvbuf->tv_usec = (offset % 1000) * 1000;

  if (maxtv == NULL)
    return tvbuf;

  /* Return the minimum time between maxtv and tvbuf */

  if (tvbuf->tv_sec > maxtv->tv_sec)
    return maxtv;
  if (tvbuf->tv_sec < maxtv->tv_sec)
    return tvbuf;

  if (tvbuf->tv_usec > maxtv->tv_usec)
    return maxtv;

  return tvbuf;
}
