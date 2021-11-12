
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2009 by Jakub Hrozek <jhrozek@redhat.com>
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

#include "ares_nameser.h"

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_data.h"
#include "ares_private.h"

static int
ares__parse_txt_reply (const unsigned char *abuf, int alen,
                       int ex, void **txt_out)
{
    /* call cares_parse_txt_reply, iterate through the result and
   * create a linked list of struct ares_txt_reply to return */

  int status;
  const unsigned char* txt = NULL;
  struct ares_txt_ext *txt_head = NULL;
  struct ares_txt_ext *txt_curr = NULL;
  struct ares_txt_ext *txt_last = NULL;
  const cares_txt_reply *ctxt_curr = NULL;
  cares_txt_reply *ctxt_out = NULL;

  /* Set *txt_out to NULL for all failure cases. */
  *txt_out = NULL;

  status = cares_parse_txt_reply(abuf, alen, &ctxt_out);

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    if (ctxt_out)
      ares_free_data (ctxt_out);
    return status;
  }

  /* iterate through the cares_txt_reply list and
   * create a new ares_txt_reply */
  for (ctxt_curr = ctxt_out; ctxt_curr;
    ctxt_curr = cares_txt_reply_get_next(ctxt_curr))
  {
    txt_curr = ares_malloc_data(ex ? ARES_DATATYPE_TXT_EXT :
                                     ARES_DATATYPE_TXT_REPLY);
    if (!txt_curr)
    {
      status = ARES_ENOMEM;
      break;
    }
    if (txt_last)
    {
      txt_last->next = txt_curr;
    }
    else
    {
      txt_head = txt_curr;
    }
    txt_last = txt_curr;

    txt = cares_txt_reply_get_txt(ctxt_curr);
    txt_curr->txt = ares_malloc(cares_txt_reply_get_length(ctxt_curr) + 1);
    if (!txt_curr->txt)
    {
      status = ARES_ENOMEM;
      break;
    }
    memcpy(txt_curr->txt, txt, cares_txt_reply_get_length(ctxt_curr));
    /* Make sure we NULL-terminate */
    txt_curr->txt[cares_txt_reply_get_length(ctxt_curr)] = 0;

    txt_curr->length = cares_txt_reply_get_length(ctxt_curr);
    if (ex)
      txt_curr->record_start = cares_txt_reply_get_record_start(ctxt_curr);

  }

  if (ctxt_out)
  {
    ares_free_data (ctxt_out);
  }

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    if (txt_head)
      ares_free_data (txt_head);
    return status;
  }

  /* everything looks fine, return the data */
  *txt_out = txt_head;

  return ARES_SUCCESS;
}

int
ares_parse_txt_reply (const unsigned char *abuf, int alen,
                      struct ares_txt_reply **txt_out)
{
  return ares__parse_txt_reply(abuf, alen, 0, (void **) txt_out);
}


int
ares_parse_txt_reply_ext (const unsigned char *abuf, int alen,
                          struct ares_txt_ext **txt_out)
{
  return ares__parse_txt_reply(abuf, alen, 1, (void **) txt_out);
}
