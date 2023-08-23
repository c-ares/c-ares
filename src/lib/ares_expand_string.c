
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

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#include "ares_nameser.h"

#include "ares.h"
#include "ares_private.h" /* for the memdebug */

/* Simply decodes a length-encoded character string. The first byte of the
 * input is the length of the string to be returned and the bytes thereafter
 * are the characters of the string. The returned result will be NULL
 * terminated.
 */
int ares_expand_string(const unsigned char *encoded,
                       const unsigned char *abuf,
                       size_t alen,
                       unsigned char **s,
                       size_t *enclen)
{
  unsigned char *q;
  size_t elen;

  if (encoded == abuf+alen)
    return ARES_EBADSTR;

  elen = *encoded;
  if (encoded+elen+1 > abuf+alen)
    return ARES_EBADSTR;

  encoded++;

  *s = ares_malloc(elen+1);
  if (*s == NULL)
    return ARES_ENOMEM;
  q = *s;
  strncpy((char *)q, (char *)encoded, elen);
  q[elen] = '\0';

  *s = q;

  *enclen = elen+1;

  return ARES_SUCCESS;
}

