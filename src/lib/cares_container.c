/* Copyright (C) 2021 by Kyle Evans
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
 */

#include "ares_setup.h"
#include "ares.h"
#include "ares_private.h"


const cares_srv_reply*
cares_srv_reply_container_get_first(const cares_srv_reply_container* container)
{
  return &container[0];
}

const cares_srv_reply*
cares_srv_reply_container_get_next(const cares_srv_reply_container* container)
{
  if (cares_srv_reply_container_get_count(container) == 0)
  {
    return container->replies;
  }

  if (container->curr == cares_srv_reply_container_get_count(container) - 1)
  {
    return &container->replies[cares_srv_reply_container_get_count(container) - 1];
  }

  cares_srv_reply_container_set_curr(container,
    cares_srv_reply_container_get_curr(container) + 1);
    
  return &container->replies[container->curr];
}

const cares_srv_reply*
cares_srv_reply_container_get_last(const cares_srv_reply_container* container)
{
  if (cares_srv_reply_container_get_count(container) == 0)
  {
    return container->replies;
  }

  return &container->replies[cares_srv_reply_container_get_count(container) - 1];
}

const int
cares_srv_reply_container_get_count(const cares_srv_reply_container* container)
{
  return container->count;
}

const int
cares_srv_reply_container_get_curr(const cares_srv_reply_container* container)
{
  return container->curr;
}

const bool
cares_srv_reply_container_at_end(const cares_srv_reply_container* container)
{
  return cares_srv_reply_get_curr(container) == cares_srv_reply_get_count(container);
}

void cares_srv_reply_container_set_replies(cares_srv_reply_container* container,
                                           cares_srv_reply* replies)
{
  container->replies = replies;
}

void cares_srv_reply_container_set_curr(cares_srv_reply_container* container,
                                        const unsigned int index)
{
  container->curr = index;
}

void cares_srv_reply_container_set_count(cares_srv_reply_container* container,
                                         const unsigned int count)
{
  container->count = count;
}