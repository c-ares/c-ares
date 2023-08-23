
/* Copyright 1998, 2011 by the Massachusetts Institute of Technology.
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
#include "ares_nowarn.h"
#include "ares_private.h" /* for the memdebug */

/* Maximum number of indirections allowed for a name */
#define MAX_INDIRS 50

static int compute_lengths(const unsigned char *encoded,
                           const unsigned char *abuf,
                           size_t alen, int is_hostname,
                           size_t *name_length, size_t *enclen);

/* Reserved characters for names that need to be escaped */
static int is_reservedch(int ch)
{
  switch (ch) {
    case '"':
    case '.':
    case ';':
    case '\\':
    case '(':
    case ')':
    case '@':
    case '$':
      return 1;
    default:
      break;
  }

  return 0;
}

static int ares__isprint(int ch)
{
  if (ch >= 0x20 && ch <= 0x7E)
    return 1;
  return 0;
}

/* Character set allowed by hostnames.  This is to include the normal
 * domain name character set plus:
 *  - underscores which are used in SRV records.
 *  - Forward slashes such as are used for classless in-addr.arpa 
 *    delegation (CNAMEs)
 *  - Asterisks may be used for wildcard domains in CNAMEs as seen in the
 *    real world.
 * While RFC 2181 section 11 does state not to do validation,
 * that applies to servers, not clients.  Vulnerabilities have been
 * reported when this validation is not performed.  Security is more
 * important than edge-case compatibility (which is probably invalid
 * anyhow). */
static int is_hostnamech(int ch)
{
  /* [A-Za-z0-9-*._/]
   * Don't use isalnum() as it is locale-specific
   */
  if (ch >= 'A' && ch <= 'Z')
    return 1;
  if (ch >= 'a' && ch <= 'z')
    return 1;
  if (ch >= '0' && ch <= '9')
    return 1;
  if (ch == '-' || ch == '.' || ch == '_' || ch == '/' || ch == '*')
    return 1;

  return 0;
}

/* Expand an RFC1035-encoded domain name given by encoded.  The
 * containing message is given by abuf and alen.  The result given by
 * *s, which is set to a NUL-terminated allocated buffer.  *enclen is
 * set to the length of the encoded name (not the length of the
 * expanded name; the goal is to tell the caller how many bytes to
 * move forward to get past the encoded name).
 *
 * In the simple case, an encoded name is a series of labels, each
 * composed of a one-byte length (limited to values between 0 and 63
 * inclusive) followed by the label contents.  The name is terminated
 * by a zero-length label.
 *
 * In the more complicated case, a label may be terminated by an
 * indirection pointer, specified by two bytes with the high bits of
 * the first byte set to 11.  With the two high bits of the first byte
 * stripped off, the indirection pointer gives an offset from the
 * beginning of the containing message with more labels to decode.
 * Indirection can happen an arbitrary number of times, so we have to
 * detect loops.
 *
 * Since the expanded name uses '.' as a label separator, we use
 * backslashes to escape periods or backslashes in the expanded name.
 *
 * If the result is expected to be a hostname, then no escaped data is
 * allowed and will return the error ARES_EBADNAME. If memory
 * allocation fails, the error ARES_ENOMEM is returned.
 */
int ares__expand_name_validated(const unsigned char *encoded,
                                const unsigned char *abuf,
                                size_t alen, char **s, size_t *enclen,
                                int is_hostname) {
  char *name = NULL;
  size_t length, offset, n = 0;
  int c, type, first_label = 1;
  char high, low;
  if(compute_lengths(encoded, abuf, alen, is_hostname, &length, enclen) < 0)
    return ARES_EBADNAME;
  if((name = ares_malloc(length + 1)) == NULL)
    return ARES_ENOMEM;
  while(n < length) {
    type = encoded[0] >> 6; /* the two highest bits */
    high = encoded[0] & 63; /* 63 is 00111111 in binary */
    low = encoded[1];
    if(type == 0) {
      /* The case of a label.
         @high is the length of the label.
      */
      encoded++;
      if(first_label)
        first_label = 0;
      else
        name[n++] = '.';
      while(high--) {
        c = *encoded;
        if (!ares__isprint(c)) {
          /* If we encounter such a character, then we know that
             is_hostname is false since the previous call to
             compute_lengths() has not returned in error.

             Output as \DDD for consistency with RFC1035 5.1, except
             for the special case of a root name response.
          */
          if(!(length == 1 && c == 0)) {
            name[n++] = '\\';
            name[n++] = '0' + c / 100;
            name[n++] = '0' + (c % 100) / 10;
            name[n++] = '0' + c % 10;
          }
        }
        else if (is_reservedch(c)) {
          name[n++] = '\\';
          name[n++] = c;
        } else {
          name[n++] = c;
        }
        encoded++;
      }
    } else {
      /* The case of a pointer.
         @high and @low must be combined to form the offset.
       */
      offset = high << 8 | low;
      encoded = &abuf[offset];
    }
  }
  name[n] = '\0';
  *s = name;
  return ARES_SUCCESS;
}

int ares_expand_name(const unsigned char *encoded, const unsigned char *abuf,
                     size_t alen, char **s, size_t *enclen)
{
  return ares__expand_name_validated(encoded, abuf, alen, s, enclen, 0);
}

/* Store the decoded length in @name_length and the number of bytes
 * that must be skipped by the callee to continue processing in
 * @enclen.
 *
 * If the encoding is invalid, the values pointed to by @name_length
 * and @enclen are indeterminate, and -1 is returned. If successful,
 * returns 0.
 */
static int compute_lengths(const unsigned char *encoded,
                           const unsigned char *abuf,
                           size_t alen, int is_hostname,
                           size_t *name_length, size_t *enclen) {
  size_t offset, n = 0, bytes_processed = 0;
  int c, type, first_label = 1, indirections = 0;
  char high, low;
  if(encoded >= abuf + alen)
    return -1;
  while(*encoded != '\0') {
    type = encoded[0] >> 6; /* the two highest bits */
    high = encoded[0] & 63; /* 63 is 00111111 in binary */
    switch(type) {
    case 0:
      /* The case of a label.
         @high is the length of the label.
      */
      if(encoded + high + 1 >= abuf + alen)
        return -1;
      bytes_processed += high + 1;
      encoded++;
      if(first_label)
        first_label = 0;
      else
        n++; /* accounting for the dot '.' */
      while(high--) {
        c = *encoded;
        if (!ares__isprint(c)) {
          if (is_hostname)
            return -1;
          else if (n == 0 && high == 0 && c == 0) {
            /* root name of empty string */
            *enclen = 3;
            *name_length = 0;
            return 0;
          }
          n += 4;
        }
        else if (is_reservedch(c)) {
          if (is_hostname)
            return -1;
          n += 2;
        }
        else {
          if (is_hostname && !is_hostnamech(c))
            return -1;
          n += 1;
        }
        encoded++;
      }
      break;
    case 3:
      /* The case of a pointer.
         @high and @low must be combined to form the offset.
       */
      if(encoded + 1 >= abuf + alen)
        return -1;
      low = encoded[1];
      offset = high << 8 | low;
      if(offset >= alen)
        return -1;
      encoded = &abuf[offset];
      /* we have processed the pointer */
      bytes_processed += 2;
      if(indirections++ == 0)
        *enclen = bytes_processed;
      if(indirections >= MAX_INDIRS)
        return -1;
      break;
    default:
      /* RFU */
      return -1;
    }
  }
  *name_length = n;
  if(indirections == 0)
    *enclen = bytes_processed + 1; /* we end in a zero byte */
  return 0;
}

/* Like ares_expand_name_validated  but returns EBADRESP in case of invalid
 * input. */
int ares__expand_name_for_response(const unsigned char *encoded,
                                   const unsigned char *abuf, size_t alen,
                                   char **s, size_t *enclen, int is_hostname)
{
  int status = ares__expand_name_validated(encoded, abuf, alen, s, enclen,
    is_hostname);
  if (status == ARES_EBADNAME)
    status = ARES_EBADRESP;
  return status;
}
