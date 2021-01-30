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
#include "ares_private.h"
#include "string.h"

struct cares_srv_reply*
cares_srv_reply_get_next(const struct cares_srv_reply* srv_reply)
{
  return srv_reply->next;
}

char* cares_srv_reply_get_host(const struct cares_srv_reply* srv_reply)
{
  char *newhost = NULL;
  if ((newhost = malloc(strlen(srv_reply->host) + 1)) != NULL) {
    strcpy(newhost, srv_reply->host);
  }
  return newhost;
}

unsigned short
cares_srv_reply_get_priority(const struct cares_srv_reply* srv_reply)
{
  return srv_reply->priority;
}

unsigned short
cares_srv_reply_get_weight(const struct cares_srv_reply* srv_reply)
{
  return srv_reply->weight;
}

unsigned short
cares_srv_reply_get_port(const struct cares_srv_reply* srv_reply)
{
  return srv_reply->port;
}

int cares_srv_reply_get_ttl(const struct cares_srv_reply* srv_reply)
{
  return srv_reply->ttl;
}

void cares_srv_reply_set_next(struct cares_srv_reply* srv_reply,
                              struct cares_srv_reply* next)
{
  srv_reply->next = next;
}

void cares_srv_reply_set_host(struct cares_srv_reply* srv_reply, char* host)
{
  srv_reply->host = host;
}

void cares_srv_reply_set_priority(struct cares_srv_reply* srv_reply,
                               const unsigned short priority)
{
  srv_reply->priority = priority;
}

void cares_srv_reply_set_weight(struct cares_srv_reply* srv_reply,
                             const unsigned short weight)
{
  srv_reply->weight = weight;
}

void cares_srv_reply_set_port(struct cares_srv_reply* srv_reply,
                           const unsigned short port)
{
  srv_reply->port = port;
}

void cares_srv_reply_set_ttl(struct cares_srv_reply* srv_reply, const int ttl)
{
  srv_reply->ttl = ttl;
}
