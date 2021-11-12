
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
#include "ares_strdup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif

#include "ares_nameser.h"

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_nowarn.h"
#include "ares_private.h"

int ares_parse_ptr_reply(const unsigned char *abuf, int alen, const void *addr,
                         int addrlen, int family, struct hostent **host)
{
  struct hostent *hostent = NULL;
  int status, i;
  int alias_alloc = 2;
  cares_ptr_reply* ptr_out = NULL;

  /* Set *host to NULL for all failure cases. */
  *host = NULL;

  status = cares_parse_ptr_reply(abuf, alen, &ptr_out);

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    if (ptr_out)
      ares_free_data(ptr_out);
    return status;
  }

  /* We got our answer.  Allocate memory to build the host entry. */
  hostent = ares_malloc(sizeof(*hostent));
  if (hostent)
  {
    hostent->h_addr_list = ares_malloc(2 * sizeof(char *));
    if (hostent->h_addr_list)
    {
      if (addr && addrlen)
      {
        hostent->h_addr_list[0] = ares_malloc(addrlen);
        if (!hostent->h_addr_list[0])
        {
          status = ARES_ENOMEM;
          if (ptr_out)
            ares_free_data(ptr_out);
          ares_free(hostent->h_addr_list);
          ares_free(hostent);
          return status;
        }
      } else {
        hostent->h_addr_list[0] = NULL;
      }
      hostent->h_aliases = ares_malloc(alias_alloc * sizeof (char *));
      if (hostent->h_aliases)
      {
        /* Fill in the hostent and return successfully. */
        hostent->h_name = NULL;

        /* iterate through the linked list of cares_ptr_reply
          and build the h_aliases array.                      */
        i = 0;
        for (const cares_ptr_reply* ptr_curr=ptr_out; ptr_curr;
            ptr_curr = cares_ptr_reply_get_next(ptr_curr))
        {
          if (!cares_ptr_reply_get_next(ptr_curr))
          {
            hostent->h_name = ares_strdup(cares_ptr_reply_get_host(ptr_curr));
            if (!hostent->h_name)
            {
              status = ARES_ENOMEM;
              if (ptr_out)
                ares_free_data(ptr_out);

              for (int j = 0; j < i; ++j)
              {
                if (hostent->h_aliases[j])
                {
                  ares_free(hostent->h_aliases[j]);
                }
              }
              if (hostent->h_aliases)
                ares_free(hostent->h_aliases);
              if (hostent->h_addr_list[0])
                ares_free(hostent->h_addr_list[0]);
              ares_free(hostent->h_addr_list);
              ares_free(hostent);
              return status;
            }
          }

          if (alias_alloc > 2)
          {
            char** ptr;
            ptr = ares_realloc(hostent->h_aliases,
                               alias_alloc * sizeof(char *));
            if (!ptr)
            {
              status = ARES_ENOMEM;
              if (ptr_out)
                ares_free_data(ptr_out);

              for (int j = 0; j < i; ++j)
              {
                if (hostent->h_aliases[j])
                {
                  ares_free(hostent->h_aliases[j]);
                }
              }
              if (hostent->h_name)
                ares_free(hostent->h_name);
              ares_free(hostent->h_aliases);
              if (hostent->h_addr_list[0])
                ares_free(hostent->h_addr_list[0]);
              ares_free(hostent->h_addr_list);
              ares_free(hostent);
              return status;
            }
            hostent->h_aliases = ptr;
          }
          hostent->h_aliases[i] = ares_strdup(cares_ptr_reply_get_host(ptr_curr));
          if (!hostent->h_aliases[i]) {
            status = ARES_ENOMEM;
            if (ptr_out)
              ares_free_data(ptr_out);

            for (int j = 0; j < i; ++j)
            {
              if (hostent->h_aliases[j])
                ares_free(hostent->h_aliases[j]);
            }
            if (hostent->h_name)
              ares_free(hostent->h_name);
            ares_free(hostent->h_aliases);
            if (hostent->h_addr_list[0])
              ares_free(hostent->h_addr_list[0]);
            ares_free(hostent->h_addr_list);
            ares_free(hostent);
            return status;
          }
          i++;
          alias_alloc++;
        }
        hostent->h_aliases[i] = NULL;
        hostent->h_addrtype = aresx_sitoss(family);
        hostent->h_length = aresx_sitoss(addrlen);
        if (addr && addrlen)
          memcpy(hostent->h_addr_list[0], addr, addrlen);
        hostent->h_addr_list[1] = NULL;
        *host = hostent;
        if (ptr_out)
          ares_free_data(ptr_out);

        return ARES_SUCCESS;
      }
      if (hostent->h_addr_list[0])
        ares_free(hostent->h_addr_list[0]);
      ares_free(hostent->h_addr_list);
    }
    ares_free(hostent);
  }
  if (ptr_out)
    ares_free_data(ptr_out);

  return ARES_ENOMEM;
}
