
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2007-2013 by Daniel Stenberg
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
#ifdef DEBUGBUILD
#include "ares.h"
#include "ares_private.h"
#include <stdarg.h>
#include <stdio.h>

void ares_debug(ares_channel channel, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  if (channel->debug_cb) {
    channel->debug_cb(channel->debug_cb_data, format, args);
  } else {
    vfprintf(stderr, format, args);
  }
  va_end(args);
}

#endif
