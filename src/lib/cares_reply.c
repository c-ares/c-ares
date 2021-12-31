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


// const cares_srv_reply*
// cares_srv_reply_get_next(const cares_srv_reply* srv_reply)
// {
//   return srv_reply->next;
// }

const char* cares_srv_reply_get_host(const cares_srv_reply* srv_reply)
{
  return srv_reply->host;
}

unsigned short
cares_srv_reply_get_priority(const cares_srv_reply* srv_reply)
{
  return srv_reply->priority;
}

unsigned short
cares_srv_reply_get_weight(const cares_srv_reply* srv_reply)
{
  return srv_reply->weight;
}

unsigned short
cares_srv_reply_get_port(const cares_srv_reply* srv_reply)
{
  return srv_reply->port;
}

unsigned int cares_srv_reply_get_ttl(const cares_srv_reply* srv_reply)
{
  return srv_reply->ttl;
}

// void cares_srv_reply_set_next(cares_srv_reply* srv_reply,
//                               cares_srv_reply* next)
// {
//   srv_reply->next = next;
// }

void cares_srv_reply_set_host(cares_srv_reply* srv_reply, char* host)
{
  srv_reply->host = host;
}

void cares_srv_reply_set_priority(cares_srv_reply* srv_reply,
                               const unsigned short priority)
{
  srv_reply->priority = priority;
}

void cares_srv_reply_set_weight(cares_srv_reply* srv_reply,
                             const unsigned short weight)
{
  srv_reply->weight = weight;
}

void cares_srv_reply_set_port(cares_srv_reply* srv_reply,
                           const unsigned short port)
{
  srv_reply->port = port;
}

void cares_srv_reply_set_ttl(cares_srv_reply* srv_reply,
                             const unsigned int ttl)
{
  srv_reply->ttl = ttl;
}



const cares_caa_reply*
cares_caa_reply_get_next(const cares_caa_reply* caa_reply)
{
  return caa_reply->next;
}

int
cares_caa_reply_get_critical(const cares_caa_reply* caa_reply)
{
  return caa_reply->critical;
}

const unsigned char*
cares_caa_reply_get_property(const cares_caa_reply* caa_reply)
{
  return caa_reply->property;
}

size_t
cares_caa_reply_get_plength(const cares_caa_reply* caa_reply)
{
  return caa_reply->plength;
}

const unsigned char*
cares_caa_reply_get_value(const cares_caa_reply* caa_reply)
{
  return caa_reply->value;
}

size_t
cares_caa_reply_get_length(const cares_caa_reply* caa_reply)
{
  return caa_reply->length;
}

unsigned int cares_caa_reply_get_ttl(const cares_caa_reply* caa_reply)
{
  return caa_reply->ttl;
}

void cares_caa_reply_set_next(cares_caa_reply* caa_reply,
                              cares_caa_reply* next)
{
  caa_reply->next = next;
}

void cares_caa_reply_set_critical(cares_caa_reply* caa_reply,
                                  const int critical)
{
  caa_reply->critical = critical;
}

void cares_caa_reply_set_property(cares_caa_reply* caa_reply,
                                  unsigned char* property)
{
  caa_reply->property = property;
}

void cares_caa_reply_set_plength(cares_caa_reply* caa_reply,
                                 const size_t plength)
{
  caa_reply->plength = plength;
}

void cares_caa_reply_set_value(cares_caa_reply* caa_reply,
                               unsigned char* value)
{
  caa_reply->value = value;
}

void cares_caa_reply_set_length(cares_caa_reply* caa_reply,
                                const size_t length)
{
  caa_reply->length = length;
}

void cares_caa_reply_set_ttl(cares_caa_reply* caa_reply,
                             const unsigned int ttl)
{
  caa_reply->ttl = ttl;
}

const cares_ptr_reply*
cares_ptr_reply_get_next(const cares_ptr_reply* ptr_reply)
{
  return ptr_reply->next;
}

const char*
cares_ptr_reply_get_host(const cares_ptr_reply* ptr_reply)
{
  return ptr_reply->host;
}

unsigned int cares_ptr_reply_get_ttl(const cares_ptr_reply* ptr_reply)
{
  return ptr_reply->ttl;
}

void cares_ptr_reply_set_next(cares_ptr_reply* ptr_reply,
                               cares_ptr_reply* next)
{
  ptr_reply->next = next;
}

void cares_ptr_reply_set_host(cares_ptr_reply* ptr_reply, char* host)
{
  ptr_reply->host = host;
}

void cares_ptr_reply_set_ttl(cares_ptr_reply* ptr_reply,
                             const unsigned int ttl)
{
  ptr_reply->ttl = ttl;
}

const cares_ns_reply*
cares_ns_reply_get_next(const cares_ns_reply* ns_reply)
{
  return ns_reply->next;
}

const char*
cares_ns_reply_get_host(const cares_ns_reply* ns_reply)
{
  return ns_reply->host;
}

unsigned int cares_ns_reply_get_ttl(const cares_ns_reply* ns_reply)
{
  return ns_reply->ttl;
}

void cares_ns_reply_set_next(cares_ns_reply* ns_reply,
                               cares_ns_reply* next)
{
  ns_reply->next = next;
}

void cares_ns_reply_set_host(cares_ns_reply* ns_reply, char* host)
{
  ns_reply->host = host;
}

void cares_ns_reply_set_ttl(cares_ns_reply* ns_reply,
                            const unsigned int ttl)
{
  ns_reply->ttl = ttl;
}

const cares_mx_reply*
cares_mx_reply_get_next(const cares_mx_reply* mx_reply)
{
  return mx_reply->next;
}

const char*
cares_mx_reply_get_host(const cares_mx_reply* mx_reply)
{
  return mx_reply->host;
}

unsigned short
cares_mx_reply_get_priority(const cares_mx_reply* mx_reply)
{
  return mx_reply->priority;
}

unsigned int cares_mx_reply_get_ttl(const cares_mx_reply* mx_reply)
{
  return mx_reply->ttl;
}

void cares_mx_reply_set_next(cares_mx_reply* mx_reply,
                             cares_mx_reply* next)
{
  mx_reply->next = next;
}

void cares_mx_reply_set_host(cares_mx_reply* mx_reply, char *host)
{
  mx_reply->host = host;
}

void cares_mx_reply_set_priority(cares_mx_reply* mx_reply,
                                 const unsigned short priority)
{
  mx_reply->priority = priority;
}

void cares_mx_reply_set_ttl(cares_mx_reply* mx_reply,
                            const unsigned int ttl)
{
  mx_reply->ttl = ttl;
}

const cares_txt_reply*
cares_txt_reply_get_next(const cares_txt_reply* txt_reply)
{
  return txt_reply->next;
}

const unsigned char*
cares_txt_reply_get_txt(const cares_txt_reply* txt_reply)
{
  return txt_reply->txt;
}

size_t
cares_txt_reply_get_length(const cares_txt_reply* txt_reply)
{
  return txt_reply->length;
}

unsigned char
cares_txt_reply_get_record_start(const cares_txt_reply* txt_reply)
{
  return txt_reply->record_start;
}

unsigned int cares_txt_reply_get_ttl(const cares_txt_reply* txt_reply)
{
  return txt_reply->ttl;
}

void cares_txt_reply_set_next(cares_txt_reply* txt_reply,
                              cares_txt_reply* next)
{
  txt_reply->next = next;
}

void cares_txt_reply_set_txt(cares_txt_reply* txt_reply,
                             unsigned char* txt)
{
  txt_reply->txt = txt;
}

void cares_txt_reply_set_length(cares_txt_reply* txt_reply,
                                const size_t length)
{
  txt_reply->length = length;
}

void cares_txt_reply_set_record_start(cares_txt_reply* txt_reply,
                                      const unsigned char record_start)
{
  txt_reply->record_start = record_start;
}

void cares_txt_reply_set_ttl(cares_txt_reply* txt_reply,
                             const unsigned int ttl)
{
  txt_reply->ttl = ttl;
}

const cares_naptr_reply*
cares_naptr_reply_get_next(const cares_naptr_reply* naptr_reply)
{
  return naptr_reply->next;
}

const unsigned char*
cares_naptr_reply_get_flags(const cares_naptr_reply* naptr_reply)
{
  return naptr_reply->flags;
}

const unsigned char*
cares_naptr_reply_get_service(const cares_naptr_reply* naptr_reply)
{
  return naptr_reply->service;
}

const unsigned char*
cares_naptr_reply_get_regexp(const cares_naptr_reply* naptr_reply)
{
  return naptr_reply->regexp;
}

const char*
cares_naptr_reply_get_replacement(const cares_naptr_reply* naptr_reply)
{
  return naptr_reply->replacement;
}

unsigned short
cares_naptr_reply_get_order(const cares_naptr_reply* naptr_reply)
{
  return naptr_reply->order;
}

unsigned short
cares_naptr_reply_get_preference(const cares_naptr_reply* naptr_reply)
{
  return naptr_reply->preference;
}

unsigned int cares_naptr_reply_get_ttl(const cares_naptr_reply* naptr_reply)
{
  return naptr_reply->ttl;
}

void cares_naptr_reply_set_next(cares_naptr_reply* naptr_reply,
                                cares_naptr_reply* next)
{
  naptr_reply->next = next;
}

void cares_naptr_reply_set_flags(cares_naptr_reply* naptr_reply,
                                 unsigned char* flags)
{
  naptr_reply->flags = flags;
}

void cares_naptr_reply_set_service(cares_naptr_reply* naptr_reply,
                                   unsigned char* service)
{
  naptr_reply->service = service;
}

void cares_naptr_reply_set_regexp(cares_naptr_reply* naptr_reply,
                                  unsigned char* regexp)
{
  naptr_reply->regexp = regexp;
}

void cares_naptr_reply_set_replacement(cares_naptr_reply* naptr_reply,
                                       char* replacement)
{
  naptr_reply->replacement = replacement;
}

void cares_naptr_reply_set_order(cares_naptr_reply* naptr_reply,
                                 const unsigned short order)
{
  naptr_reply->order = order;
}

void cares_naptr_reply_set_preference(cares_naptr_reply* naptr_reply,
                                      const unsigned short preference)
{
  naptr_reply->preference = preference;
}

void cares_naptr_reply_set_ttl(cares_naptr_reply* naptr_reply,
                               const unsigned int ttl)
{
  naptr_reply->ttl = ttl;
}

const char*
cares_soa_reply_get_nsname(const cares_soa_reply* soa_reply)
{
  return soa_reply->nsname;
}

const char*
cares_soa_reply_get_hostmaster(const cares_soa_reply* soa_reply)
{
  return soa_reply->hostmaster;
}

unsigned int
cares_soa_reply_get_serial(const cares_soa_reply* soa_reply)
{
  return soa_reply->serial;
}

unsigned int
cares_soa_reply_get_refresh(const cares_soa_reply* soa_reply)
{
  return soa_reply->refresh;
}

unsigned int
cares_soa_reply_get_retry(const cares_soa_reply* soa_reply)
{
  return soa_reply->retry;
}

unsigned int
cares_soa_reply_get_expire(const cares_soa_reply* soa_reply)
{
  return soa_reply->expire;
}

unsigned int
cares_soa_reply_get_minttl(const cares_soa_reply* soa_reply)
{
  return soa_reply->minttl;
}

unsigned int cares_soa_reply_get_ttl(const cares_soa_reply* soa_reply)
{
  return soa_reply->ttl;
}

void cares_soa_reply_set_nsname(cares_soa_reply* soa_reply, char* nsname)
{
  soa_reply->nsname = nsname;
}

void cares_soa_reply_set_hostmaster(cares_soa_reply* soa_reply,
                                    char* hostmaster)
{
  soa_reply->hostmaster = hostmaster;
}

void cares_soa_reply_set_serial(cares_soa_reply* soa_reply,
                                const unsigned int serial)
{
  soa_reply->serial = serial;
}

void cares_soa_reply_set_refresh(cares_soa_reply* soa_reply,
                                 const unsigned int refresh)
{
  soa_reply->refresh = refresh;
}

void cares_soa_reply_set_retry(cares_soa_reply* soa_reply,
                               const unsigned int retry)
{
  soa_reply->retry = retry;
}

void cares_soa_reply_set_expire(cares_soa_reply* soa_reply,
                                const unsigned int expire)
{
  soa_reply->expire = expire;
}

void cares_soa_reply_set_minttl(cares_soa_reply* soa_reply,
                                const unsigned int minttl)
{
  soa_reply->minttl = minttl;
}

void cares_soa_reply_set_ttl(cares_soa_reply* soa_reply,
                             const unsigned int ttl)
{
  soa_reply->ttl = ttl;
}
