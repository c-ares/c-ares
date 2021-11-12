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
#include "cares_memdup.h"
#include "ares_private.h"
#include "string.h"

unsigned char* cares_memdup(const unsigned char* data, size_t sz)
{
    unsigned char* data2;
    data2 = ares_malloc(sz + 1);
    if (!data2)
    {
      return (unsigned char*)NULL;
    }
    memcpy(data2, data, sz);
    /* Make sure we NULL-terminate */
    data2[sz] = 0;

    return data2;
}
