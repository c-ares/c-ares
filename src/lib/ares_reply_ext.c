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

struct ares_srv_ext* ares_srv_ext_get_next(const struct ares_srv_ext* srv_reply)
{
  return srv_reply->next;
}

char* ares_srv_ext_get_host(const struct ares_srv_ext* srv_reply)
{
  return srv_reply->host;
}

unsigned short ares_srv_ext_get_priority(const struct ares_srv_ext* srv_reply)
{
  return srv_reply->priority;
}

unsigned short ares_srv_ext_get_weight(const struct ares_srv_ext* srv_reply)
{
  return srv_reply->weight;
}

unsigned short ares_srv_ext_get_port(const struct ares_srv_ext* srv_reply)
{
  return srv_reply->port;
}

int ares_srv_ext_get_ttl(const struct ares_srv_ext* srv_reply)
{
  return srv_reply->ttl;
}

void ares_srv_ext_set_next(struct ares_srv_ext* srv_reply,
                           struct ares_srv_ext* next)
{
  srv_reply->next = next;
}

void ares_srv_ext_set_host(struct ares_srv_ext* srv_reply, char* host)
{
  srv_reply->host = host;
}

void ares_srv_ext_set_priority(struct ares_srv_ext* srv_reply,
                               const unsigned short priority)
{
  srv_reply->priority = priority;
}

void ares_srv_ext_set_weight(struct ares_srv_ext* srv_reply,
                             const unsigned short weight)
{
  srv_reply->weight = weight;
}

void ares_srv_ext_set_port(struct ares_srv_ext* srv_reply,
                           const unsigned short port)
{
  srv_reply->port = port;
}

void ares_srv_ext_set_ttl(struct ares_srv_ext* srv_reply, const int ttl)
{
  srv_reply->ttl = ttl;
}
