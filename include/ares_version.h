/*
 * Copyright (C) Daniel Stenberg
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

#ifndef ARES__VERSION_H
#define ARES__VERSION_H

/* This is the global package copyright */
#define ARES_COPYRIGHT "2004 - 2023 Daniel Stenberg, <daniel@haxx.se>."

#define ARES_VERSION_MAJOR 1
#define ARES_VERSION_MINOR 19
#define ARES_VERSION_PATCH 1
#define ARES_VERSION ((ARES_VERSION_MAJOR<<16)|\
                       (ARES_VERSION_MINOR<<8)|\
                       (ARES_VERSION_PATCH))
#define ARES_VERSION_STR "1.19.1"

#if (ARES_VERSION >= 0x010700)
#  define CARES_HAVE_ARES_LIBRARY_INIT 1
#  define CARES_HAVE_ARES_LIBRARY_CLEANUP 1
#else
#  undef CARES_HAVE_ARES_LIBRARY_INIT
#  undef CARES_HAVE_ARES_LIBRARY_CLEANUP
#endif

#endif
