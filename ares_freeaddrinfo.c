
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2019 by Andrew Selivanov
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

#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif

#include "ares.h"
#include "ares_private.h"

void ares__freeaddrinfo_nodes(struct ares_addrinfo_node *ai_node)
{
  struct ares_addrinfo_node *ai_free;
  while (ai_node)
    {
      ai_free = ai_node;
      ai_node = ai_node->ai_next;
      ares_free(ai_free->ai_addr);
      ares_free(ai_free);
    }
}

void ares_freeaddrinfo(struct ares_addrinfo *ai)
{
  ares__freeaddrinfo_nodes(ai->nodes);
  ares_free(ai->cname.name);
  ares_free(ai);
}
