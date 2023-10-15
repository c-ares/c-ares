/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) The c-ares project and its contributors
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
ares_status_t ares_expand_string_ex(const unsigned char *encoded,
                                    const unsigned char *abuf,
                                    size_t alen,
                                    unsigned char **s,
                                    size_t *enclen)
{
  unsigned char *q;
  size_t         len;

  if (encoded == abuf+alen)
    return ARES_EBADSTR;

  len = *encoded;
  if (encoded + len + 1 > abuf + alen)
    return ARES_EBADSTR;

  encoded++;

  *s = ares_malloc(len+1);
  if (*s == NULL)
    return ARES_ENOMEM;
  q = *s;
  ares_strcpy((char *)q, (char *)encoded, len+1);
  q[len] = '\0';

  *s = q;

  *enclen = len+1;

  return ARES_SUCCESS;
}


int ares_expand_string(const unsigned char *encoded,
                       const unsigned char *abuf,
                       int alen,
                       unsigned char **s,
                       long *enclen)
{
  ares_status_t status;
  size_t        temp_enclen = 0;

  if (alen < 0)
    return ARES_EBADRESP;

  status = ares_expand_string_ex(encoded, abuf, (size_t)alen, s, &temp_enclen);

  *enclen = (long)temp_enclen;
  return (int)status;
}

