/* MIT License
 *
 * Copyright (c) 2024 The c-ares project and its contributors
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

#ifdef __APPLE__
#include "ares_setup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include "thirdparty/apple/dnsinfo.h"
#include "ares.h"
#include "ares_private.h"


typedef struct {
  void         *handle;
  const char   *(*dns_configuration_notify_key)(void);
  dns_config_t *(*dns_configuration_copy)(void);
  void          (*dns_configuration_free)(dns_config_t *config);
} dnsinfo_t;

static void dnsinfo_destroy(dnsinfo_t *dnsinfo)
{
  if (dnsinfo == NULL) {
    return;
  }

  if (dnsinfo->handle) {
    dlclose(dnsinfo->handle);
  }

  ares_free(dnsinfo);
}

static dnsinfo_t *dnsinfo_init(void)
{
  dnsinfo_t *dnsinfo = ares_malloc_zero(sizeof(*dnsinfo));

  dnsinfo->handle = dlopen("/usr/lib/libSystem.dylib", RTLD_LAZY | RTLD_NOLOAD);
  if (dnsinfo->handle == NULL) {
    goto fail;
  }

  dnsinfo->dns_configuration_notify_key = dlsym(dnsinfo->handle, "dns_configuration_notify_key");
  dnsinfo->dns_configuration_copy       = dlsym(dnsinfo->handle, "dns_configuration_copy");
  dnsinfo->dns_configuration_free       = dlsym(dnsinfo->handle, "dns_configuration_free");

  if (dnsinfo->dns_configuration_notify_key == NULL ||
      dnsinfo->dns_configuration_copy       == NULL ||
      dnsinfo->dns_configuration_free       == NULL) {
    goto fail;
  }

  return dnsinfo;

fail:
  dnsinfo_destroy(dnsinfo);
  return NULL;
}

static void print_resolver(dns_resolver_t *resolver)
{
  int i;

  printf("\t\tdomain: %s\n", resolver->domain);
  printf("\t\tport: %d\n", (int)resolver->port);
  printf("\t\tsearch (%d):\n", resolver->n_search);
  for (i=0; i<resolver->n_search; i++) {
    printf("\t\t\t%s\n", resolver->search[i]);
  }
  printf("\t\tsortaddr (%d):\n", resolver->n_sortaddr);
  for (i=0; i<resolver->n_sortaddr; i++) {
    char val[256];
    inet_ntop(AF_INET, &resolver->sortaddr[i]->address, val, sizeof(val));
    printf("\t\t%s/", val);
    inet_ntop(AF_INET, &resolver->sortaddr[i]->mask, val, sizeof(val));
    printf("%s\n", val);
  }
  printf("\t\toptions: %s\n", resolver->options);
  printf("\t\ttimeout: %u\n", resolver->timeout);
  printf("\t\tsearch order: 0x%02X\n", resolver->search_order);
  printf("\t\tif_index: %u\n", resolver->if_index);
  printf("\t\tflags: 0x%02X\n", resolver->flags);
  printf("\t\treach flags: 0x%02X\n", resolver->reach_flags); /* SCNetworkReachabilityFlags */
  printf("\t\tservice identifier: %u\n", resolver->service_identifier);
  printf("\t\tconfiguration identifier: %s\n", resolver->cid);
  printf("\t\tif_name: %s\n", resolver->if_name);

  printf("\t\tnameservers (%d):\n", resolver->n_nameserver);
  for (i = 0; i < resolver->n_nameserver; i++) {
    char val[256];
    if (resolver->nameserver[i]->sa_family == AF_INET) {
      struct sockaddr_in *addr_in = (struct sockaddr_in *)(void *)resolver->nameserver[i];
      memset(val, 0, sizeof(val));
      inet_ntop(AF_INET, &(addr_in->sin_addr), val, sizeof(val));
      printf("\t\t\t%s:%d\n", val, (int)ntohs(addr_in->sin_port));
    } else if (resolver->nameserver[i]->sa_family == AF_INET6) {
      struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)(void *)resolver->nameserver[i];
      memset(val, 0, sizeof(val));
      inet_ntop(AF_INET6, &(addr_in6->sin6_addr), val, sizeof(val));
      printf("\t\t\t[%s]:%d%%%d\n", val, (int)ntohs(addr_in6->sin6_port), addr_in6->sin6_scope_id);
    }
  }
}

static void print_resolvers(const char *name, dns_resolver_t **resolvers, int nresolvers)
{
  int i;

  printf("%s (%d):\n", name, nresolvers);
  for (i=0; i<nresolvers; i++) {
    printf("\tResolver[%d]:\n", i);
    print_resolver(resolvers[i]);
  }
}


int ares_sysconfig_read(void)
{
  dnsinfo_t      *dnsinfo = dnsinfo_init();
  dns_config_t   *sc_dns  = NULL;

  if (dnsinfo == NULL) {
    return 1;
  }

  sc_dns = dnsinfo->dns_configuration_copy();
  if (sc_dns == NULL) {
    return 1;
  }

  print_resolvers("Resolver", sc_dns->resolver, sc_dns->n_resolver);
  print_resolvers("Scoped Resolver", sc_dns->scoped_resolver, sc_dns->n_scoped_resolver);
  print_resolvers("Service Specific Resolver", sc_dns->service_specific_resolver, sc_dns->n_service_specific_resolver);

  dnsinfo->dns_configuration_free(sc_dns);
  dnsinfo_destroy(dnsinfo);
  return 0;

}

#endif
