/* Copyright 1998, 2011 by the Massachusetts Institute of Technology.
 * Copyright 2018 by Andrew Selivanov
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

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#include "ares.h"
#include "ares_inet_net_pton.h"
#include "ares_nowarn.h"
#include "ares_private.h"

static const struct ares_addrinfo empty_addrinfo;

struct ares_addrinfo *ares__malloc_addrinfo()
{
  struct ares_addrinfo *ai = ares_malloc(sizeof(struct ares_addrinfo));
  if (!ai)
    return NULL;

  *ai = empty_addrinfo;
  return ai;
}

/* Allocate new addrinfo and append to current or allocate new head_ai. */
struct ares_addrinfo *ares__append_addrinfo(struct ares_addrinfo *ai,
                                            struct ares_addrinfo **head_ai)
{
  if (ai)
    {
      ai->ai_next = ares__malloc_addrinfo();
      return ai->ai_next;
    }
  else
    {
      ai = ares__malloc_addrinfo();
      *head_ai = ai;
      return ai;
    }
}

int ares__get_addrinfo(FILE *fp,
                       const char *name,
                       unsigned short port,
                       const struct ares_addrinfo *hints,
                       struct ares_addrinfo **result)
{
  char *line = NULL, *p, *q;
  char *txtaddr, *txthost, *txtalias;
  int status;
  size_t linesize;
  ares_sockaddr addr;
  struct ares_addrinfo *ai = NULL, *head_ai = NULL;
  int match_with_alias, match_with_canonical;
  int got_address;

  /* Validate family */
  switch (hints->ai_family) {
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      break;
    default:
      return ARES_EBADFAMILY;
  }

  while ((status = ares__read_line(fp, &line, &linesize)) == ARES_SUCCESS)
    {
      match_with_alias = 0;
      match_with_canonical = 0;
      got_address = 0;

      /* Trim line comment. */
      p = line;
      while (*p && (*p != '#'))
        p++;
      *p = '\0';

      /* Trim trailing whitespace. */
      q = p - 1;
      while ((q >= line) && ISSPACE(*q))
        q--;
      *++q = '\0';

      /* Skip leading whitespace. */
      p = line;
      while (*p && ISSPACE(*p))
        p++;
      if (!*p)
        /* Ignore line if empty. */
        continue;

      /* Pointer to start of IPv4 or IPv6 address part. */
      txtaddr = p;

      /* Advance past address part. */
      while (*p && !ISSPACE(*p))
        p++;
      if (!*p)
        /* Ignore line if reached end of line. */
        continue;

      /* Null terminate address part. */
      *p = '\0';

      /* Advance to host name */
      p++;
      while (*p && ISSPACE(*p))
        p++;
      if (!*p)
        /* Ignore line if reached end of line. */
        continue;  /* LCOV_EXCL_LINE: trailing whitespace already stripped */

      /* Pointer to start of host name. */
      txthost = p;

      /* Advance past host name. */
      while (*p && !ISSPACE(*p))
        p++;

      /* Pointer to start of first alias. */
      txtalias = NULL;
      if (*p)
        {
          q = p + 1;
          while (*q && ISSPACE(*q))
            q++;
          if (*q)
            txtalias = q;
        }

      /* Null terminate host name. */
      *p = '\0';

      /* Find out if host name matches with one of the aliases. */
      while (txtalias)
        {
          p = txtalias;
          while (*p && !ISSPACE(*p))
            p++;
          q = p;
          while (*q && ISSPACE(*q))
            q++;
          *p = '\0';
          if (strcasecmp(txtalias, name) == 0)
            {
              match_with_alias = 1;
              break;
            }
          txtalias = *q ? q : NULL;
        }

      /* Find out if host name matches with canonical host name. */
      if (strcasecmp(txthost, name) == 0)
        {
          match_with_canonical = 1;
        }

      /* Try next line if host does not match. */
      if (!match_with_alias && !match_with_canonical)
        {
          continue;
        }

      /*
       * Convert address string to network address for the requested families.
       * Actual address family possible values are AF_INET and AF_INET6 only.
       */
      if ((hints->ai_family == AF_INET) || (hints->ai_family == AF_UNSPEC))
        {
          memset(&addr, 0, sizeof(addr));
          addr.sa4.sin_port = htons(port);
          addr.sa4.sin_addr.s_addr = inet_addr(txtaddr);
          if (addr.sa4.sin_addr.s_addr != INADDR_NONE)
            {
              ai = ares__append_addrinfo(ai, &head_ai);
              if(!ai)
                {
                  goto enomem;
                }

              ai->ai_family = addr.sa.sa_family = AF_INET;
              ai->ai_addrlen = sizeof(sizeof(addr.sa4));
              ai->ai_addr = ares_malloc(sizeof(addr.sa4));
              if (!ai->ai_addr)
                {
                  goto enomem;
                }
              memcpy(ai->ai_addr, &addr.sa4, sizeof(addr.sa4));
              got_address = 1;
            }
        }
      if ((hints->ai_family == AF_INET6) || (hints->ai_family == AF_UNSPEC))
        {
          memset(&addr, 0, sizeof(addr));
          addr.sa6.sin6_port = htons(port);
          if (ares_inet_pton(AF_INET6, txtaddr, &addr.sa6.sin6_addr) > 0)
            {
              ai = ares__append_addrinfo(ai, &head_ai);
              if (!ai)
                {
                  goto enomem;
                }

              ai->ai_family = addr.sa.sa_family = AF_INET6;
              ai->ai_addrlen = sizeof(sizeof(addr.sa6));
              ai->ai_addr = ares_malloc(sizeof(addr.sa6));
              if (!ai->ai_addr)
                {
                  goto enomem;
                }
              memcpy(ai->ai_addr, &addr.sa6, sizeof(addr.sa6));
              got_address = 1;
            }
        }
      if (!got_address)
        /* Ignore line if invalid address string for the requested family. */
        continue;

      /* Copy official host name into the first addrinfo. */
      if (hints->ai_flags & ARES_AI_CANONNAME)
        {
          head_ai->ai_canonname = ares_strdup(txthost);
          if (!head_ai->ai_canonname)
            {
              goto enomem;
            }
        }
    }

  /* Last read failed. */
  if (status == ARES_ENOMEM)
    {
      goto enomem;
    }

  /* Free line buffer. */
  ares_free(line);

  if (head_ai)
    {
      *result = head_ai;
      return ARES_SUCCESS;
    }
  else
    {
      return ARES_ENOTFOUND;
    }

enomem:
  ares_free(line);
  ares_freeaddrinfo(head_ai);
  return ARES_ENOMEM;
}
