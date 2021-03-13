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

/*
 * ares_parse_ns_reply created by Vlad Dinulescu <vlad.dinulescu@avira.com>
 *      on behalf of AVIRA Gmbh - http://www.avira.com
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

#include "ares_nameser.h"

#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

int ares_parse_ns_reply( const unsigned char* abuf, int alen,
                         struct hostent** host )
{
  struct hostent *hostent = NULL;
  char *hname = NULL;
  const unsigned char *aptr;
  int status, i;
  long len;
  int alias_alloc = 2;
  cares_ns_reply* ns_out = NULL;

  /* Set *host to NULL for all failure cases. */
  *host = NULL;

  status = cares_parse_ns_reply(abuf, alen, &ns_out);

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    if (ns_out)
      ares_free_data(ns_out);
    return status;
  }

  aptr = abuf + HFIXEDSZ;
  status = ares__expand_name_for_response(aptr, abuf, alen, &hname, &len);
  if (status != ARES_SUCCESS)
  {
    ares_free_data(ns_out);
    return status;
  }

  /* We got our answer.  Allocate memory to build the host entry. */
  hostent = ares_malloc(sizeof(*hostent));
  if (hostent)
  {
    hostent->h_addr_list = ares_malloc(sizeof(char *));
    if (hostent->h_addr_list)
    {
      hostent->h_aliases = ares_malloc(alias_alloc * sizeof (char *));
      if (hostent->h_aliases)
      {
        /* Fill in the hostent and return successfully. */
        hostent->h_name = hname;

        /* iterate through the linked list of cares_ns_reply
          and build the h_aliases array.                      */
        i = 0;
        for (cares_ns_reply* ns_curr=ns_out; ns_curr;
              ns_curr = cares_ns_reply_get_next(ns_curr))
        {
          if (alias_alloc > 2)
          {
            char** ptr;
            ptr = ares_realloc(hostent->h_aliases,
                               alias_alloc * sizeof(char *));
            if (!ptr)
            {
              status = ARES_ENOMEM;
              if (ns_out)
                ares_free_data(ns_out);

              for (int j = 0; j < i; ++j)
              {
                if (hostent->h_aliases[j])
                  ares_free(hostent->h_aliases[j]);
              }
              ares_free(hostent->h_name);
              ares_free(hostent->h_aliases);
              ares_free(hostent->h_addr_list);
              ares_free(hostent);
              return status;
            }
            hostent->h_aliases = ptr;
          }
          hostent->h_aliases[i] = ares_strdup(cares_ns_reply_get_host(ns_curr));
          if (!hostent->h_aliases[i]) {
            status = ARES_ENOMEM;
            if (ns_out)
              ares_free_data(ns_out);

            for (int j = 0; j < i; ++j)
            {
              if (hostent->h_aliases[j])
                ares_free(hostent->h_aliases[j]);
            }
            ares_free(hostent->h_name);
            ares_free(hostent->h_aliases);
            ares_free(hostent->h_addr_list);
            ares_free(hostent);
            return status;
          }
          i++;
          alias_alloc++;
        }
        hostent->h_aliases[i] = NULL;
        hostent->h_addrtype = AF_INET;
        hostent->h_length = sizeof( struct in_addr );
        hostent->h_addr_list[0] = NULL;
        *host = hostent;
        if (ns_out)
          ares_free_data(ns_out);

        return ARES_SUCCESS;
      }
      ares_free(hostent->h_addr_list);
    }
    ares_free(hostent);
  }
  ares_free(hname);
  if (ns_out)
    ares_free_data(ns_out);

  return ARES_ENOMEM;
}
