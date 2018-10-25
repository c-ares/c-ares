
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

#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif

#include "ares.h"
#include "ares_private.h"

void ares_freeaddrinfo(struct ares_addrinfo *ai)
{
  struct ares_addrinfo *ai_free;
  while (ai)
    {
      ai_free = ai;
      ai = ai->ai_next;
      ares_free(ai_free->ai_canonname);
      ares_free(ai_free->ai_addr);
      ares_free(ai_free);
    }
}
