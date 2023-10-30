/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2008 Daniel Stenberg
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

#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#include "ares.h"
#include "ares_data.h"
#include "ares_inet_net_pton.h"
#include "ares_private.h"

int ares_get_servers(ares_channel channel, struct ares_addr_node **servers)
{
  struct ares_addr_node *srvr_head = NULL;
  struct ares_addr_node *srvr_last = NULL;
  struct ares_addr_node *srvr_curr;
  ares_status_t          status = ARES_SUCCESS;
  ares__slist_node_t    *node;

  if (!channel) {
    return ARES_ENODATA;
  }

  for (node = ares__slist_node_first(channel->servers); node != NULL;
       node = ares__slist_node_next(node)) {
    struct server_state *server = ares__slist_node_val(node);

    /* Allocate storage for this server node appending it to the list */
    srvr_curr = ares_malloc_data(ARES_DATATYPE_ADDR_NODE);
    if (!srvr_curr) {
      status = ARES_ENOMEM;
      break;
    }
    if (srvr_last) {
      srvr_last->next = srvr_curr;
    } else {
      srvr_head = srvr_curr;
    }
    srvr_last = srvr_curr;

    /* Fill this server node data */
    srvr_curr->family = server->addr.family;
    if (srvr_curr->family == AF_INET) {
      memcpy(&srvr_curr->addrV4, &server->addr.addrV4,
             sizeof(srvr_curr->addrV4));
    } else {
      memcpy(&srvr_curr->addrV6, &server->addr.addrV6,
             sizeof(srvr_curr->addrV6));
    }
  }

  if (status != ARES_SUCCESS) {
    if (srvr_head) {
      ares_free_data(srvr_head);
      srvr_head = NULL;
    }
  }

  *servers = srvr_head;

  return (int)status;
}

int ares_get_servers_ports(ares_channel                 channel,
                           struct ares_addr_port_node **servers)
{
  struct ares_addr_port_node *srvr_head = NULL;
  struct ares_addr_port_node *srvr_last = NULL;
  struct ares_addr_port_node *srvr_curr;
  ares_status_t               status = ARES_SUCCESS;
  ares__slist_node_t         *slist;

  if (!channel) {
    return ARES_ENODATA;
  }

  for (node = ares__slist_node_first(channel->servers); node != NULL;
       node = ares__slist_node_next(node)) {
    struct server_state *server = ares__slist_node_val(node);

    /* Allocate storage for this server node appending it to the list */
    srvr_curr = ares_malloc_data(ARES_DATATYPE_ADDR_PORT_NODE);
    if (!srvr_curr) {
      status = ARES_ENOMEM;
      break;
    }
    if (srvr_last) {
      srvr_last->next = srvr_curr;
    } else {
      srvr_head = srvr_curr;
    }
    srvr_last = srvr_curr;

    /* Fill this server node data */
    srvr_curr->family = channel->servers[i].addr.family;
    srvr_curr->udp_port =
      ntohs((unsigned short)channel->servers[i].addr.udp_port);
    srvr_curr->tcp_port =
      ntohs((unsigned short)channel->servers[i].addr.tcp_port);
    if (srvr_curr->family == AF_INET) {
      memcpy(&srvr_curr->addrV4, &channel->servers[i].addr.addrV4,
             sizeof(srvr_curr->addrV4));
    } else {
      memcpy(&srvr_curr->addrV6, &channel->servers[i].addr.addrV6,
             sizeof(srvr_curr->addrV6));
    }
  }

  if (status != ARES_SUCCESS) {
    if (srvr_head) {
      ares_free_data(srvr_head);
      srvr_head = NULL;
    }
  }

  *servers = srvr_head;

  return (int)status;
}

int ares_set_servers(ares_channel channel, struct ares_addr_node *servers)
{
  struct ares_addr_node *srvr;
  size_t                 num_srvrs = 0;
  size_t                 i;

  if (ares_library_initialized() != ARES_SUCCESS) {
    return ARES_ENOTINITIALIZED; /* LCOV_EXCL_LINE: n/a on non-WinSock */
  }

  if (!channel) {
    return ARES_ENODATA;
  }

  if (ares__llist_len(channel->all_queries) != 0) {
    return ARES_ENOTIMP;
  }

  ares__destroy_servers_state(channel);

  for (srvr = servers; srvr; srvr = srvr->next) {
    num_srvrs++;
  }

  if (num_srvrs > 0) {
    /* Allocate storage for servers state */
    channel->servers = ares_malloc(num_srvrs * sizeof(*channel->servers));
    if (!channel->servers) {
      return ARES_ENOMEM;
    }
    memset(channel->servers, 0, num_srvrs * sizeof(*channel->servers));
    channel->nservers = num_srvrs;
    /* Fill servers state address data */
    for (i = 0, srvr = servers; srvr; i++, srvr = srvr->next) {
      channel->servers[i].addr.family   = srvr->family;
      channel->servers[i].addr.udp_port = 0;
      channel->servers[i].addr.tcp_port = 0;
      if (srvr->family == AF_INET) {
        memcpy(&channel->servers[i].addr.addrV4, &srvr->addrV4,
               sizeof(srvr->addrV4));
      } else {
        memcpy(&channel->servers[i].addr.addrV6, &srvr->addrV6,
               sizeof(srvr->addrV6));
      }
    }
    /* Initialize servers state remaining data */
    ares__init_servers_state(channel);
  }

  return ARES_SUCCESS;
}

int ares_set_servers_ports(ares_channel                channel,
                           struct ares_addr_port_node *servers)
{
  struct ares_addr_port_node *srvr;
  size_t                      num_srvrs = 0;
  size_t                      i;

  if (ares_library_initialized() != ARES_SUCCESS) {
    return ARES_ENOTINITIALIZED; /* LCOV_EXCL_LINE: n/a on non-WinSock */
  }

  if (!channel) {
    return ARES_ENODATA;
  }

  if (ares__llist_len(channel->all_queries) != 0) {
    return ARES_ENOTIMP;
  }

  ares__destroy_servers_state(channel);

  for (srvr = servers; srvr; srvr = srvr->next) {
    num_srvrs++;
  }

  if (num_srvrs > 0) {
    /* Allocate storage for servers state */
    channel->servers = ares_malloc(num_srvrs * sizeof(*channel->servers));
    if (!channel->servers) {
      return ARES_ENOMEM;
    }
    memset(channel->servers, 0, num_srvrs * sizeof(*channel->servers));
    channel->nservers = num_srvrs;
    /* Fill servers state address data */
    for (i = 0, srvr = servers; srvr; i++, srvr = srvr->next) {
      channel->servers[i].addr.family   = srvr->family;
      channel->servers[i].addr.udp_port = htons((unsigned short)srvr->udp_port);
      channel->servers[i].addr.tcp_port = htons((unsigned short)srvr->tcp_port);
      if (srvr->family == AF_INET) {
        memcpy(&channel->servers[i].addr.addrV4, &srvr->addrV4,
               sizeof(srvr->addrV4));
      } else {
        memcpy(&channel->servers[i].addr.addrV6, &srvr->addrV6,
               sizeof(srvr->addrV6));
      }
    }
    /* Initialize servers state remaining data */
    ares__init_servers_state(channel);
  }

  return ARES_SUCCESS;
}

/* Incomming string format: host[:port][,host[:port]]... */
/* IPv6 addresses with ports require square brackets [fe80::1%lo0]:53 */
static ares_status_t set_servers_csv(ares_channel channel, const char *_csv,
                                     int use_port)
{
  size_t                      i;
  char                       *csv = NULL;
  char                       *ptr;
  char                       *start_host;
  int                         cc      = 0;
  ares_status_t               status  = ARES_SUCCESS;
  struct ares_addr_port_node *servers = NULL;
  struct ares_addr_port_node *last    = NULL;

  if (ares_library_initialized() != ARES_SUCCESS) {
    return ARES_ENOTINITIALIZED; /* LCOV_EXCL_LINE: n/a on non-WinSock */
  }

  if (!channel) {
    return ARES_ENODATA;
  }

  i = ares_strlen(_csv);
  if (i == 0) {
    return ARES_SUCCESS; /* blank all servers */
  }

  csv = ares_malloc(i + 2);
  if (!csv) {
    return ARES_ENOMEM;
  }

  ares_strcpy(csv, _csv, i + 2);
  if (csv[i - 1] != ',') { /* make parsing easier by ensuring ending ',' */
    csv[i]     = ',';
    csv[i + 1] = 0;
  }

  start_host = csv;
  for (ptr = csv; *ptr; ptr++) {
    if (*ptr == ':') {
      /* count colons to determine if we have an IPv6 number or IPv4 with
         port */
      cc++;
    } else if (*ptr == '[') {
      /* move start_host if an open square bracket is found wrapping an IPv6
         address */
      start_host = ptr + 1;
    } else if (*ptr == ',') {
      char                       *pp   = ptr - 1;
      char                       *p    = ptr;
      int                         port = 0;
      struct in_addr              in4;
      struct ares_in6_addr        in6;
      struct ares_addr_port_node *s = NULL;

      *ptr = 0; /* null terminate host:port string */
      /* Got an entry..see if the port was specified. */
      if (cc > 0) {
        while (pp > start_host) {
          /* a single close square bracket followed by a colon, ']:' indicates
             an IPv6 address with port */
          if ((*pp == ']') && (*p == ':')) {
            break; /* found port */
          }
          /* a single colon, ':' indicates an IPv4 address with port */
          if ((*pp == ':') && (cc == 1)) {
            break; /* found port */
          }
          if (!(ISDIGIT(*pp) || (*pp == ':'))) {
            /* Found end of digits before we found :, so wasn't a port */
            /* must allow ':' for IPv6 case of ']:' indicates we found a port */
            pp = p = ptr;
            break;
          }
          pp--;
          p--;
        }
        if ((pp != start_host) && ((pp + 1) < ptr)) {
          /* Found it. Parse over the port number */
          /* when an IPv6 address is wrapped with square brackets the port
             starts at pp + 2 */
          if (*pp == ']') {
            p++; /* move p before ':' */
          }
          /* p will point to the start of the port */
          port = (int)strtol(p, NULL, 10);
          *pp  = 0; /* null terminate host */
        }
      }
      /* resolve host, try ipv4 first, rslt is in network byte order */
      if (!ares_inet_pton(AF_INET, start_host, &in4)) {
        /* Ok, try IPv6 then */
        if (!ares_inet_pton(AF_INET6, start_host, &in6)) {
          status = ARES_EBADSTR;
          goto out;
        }
        /* was ipv6, add new server */
        s = ares_malloc(sizeof(*s));
        if (!s) {
          status = ARES_ENOMEM;
          goto out;
        }
        s->family = AF_INET6;
        memcpy(&s->addr, &in6, sizeof(struct ares_in6_addr));
      } else {
        /* was ipv4, add new server */
        s = ares_malloc(sizeof(*s));
        if (!s) {
          status = ARES_ENOMEM;
          goto out;
        }
        s->family = AF_INET;
        memcpy(&s->addr, &in4, sizeof(struct in_addr));
      }
      if (s) {
        s->udp_port = use_port ? port : 0;
        s->tcp_port = s->udp_port;
        s->next     = NULL;
        if (last) {
          last->next = s;
          /* need to move last to maintain the linked list */
          last = last->next;
        } else {
          servers = s;
          last    = s;
        }
      }

      /* Set up for next one */
      start_host = ptr + 1;
      cc         = 0;
    }
  }

  status = (ares_status_t)ares_set_servers_ports(channel, servers);

out:
  if (csv) {
    ares_free(csv);
  }
  while (servers) {
    struct ares_addr_port_node *s = servers;
    servers                       = servers->next;
    ares_free(s);
  }

  return status;
}

int ares_set_servers_csv(ares_channel channel, const char *_csv)
{
  return (int)set_servers_csv(channel, _csv, FALSE);
}

int ares_set_servers_ports_csv(ares_channel channel, const char *_csv)
{
  return (int)set_servers_csv(channel, _csv, TRUE);
}

/* Save options from initialized channel */
int ares_save_options(ares_channel channel, struct ares_options *options,
                      int *optmask)
{
  size_t i;
  size_t j;
  size_t ipv4_nservers = 0;

  /* Zero everything out */
  memset(options, 0, sizeof(struct ares_options));

  if (!ARES_CONFIG_CHECK(channel)) {
    return ARES_ENODATA;
  }

  /* Traditionally the optmask wasn't saved in the channel struct so it was
     recreated here. ROTATE is the first option that has no struct field of
     its own in the public config struct */
  (*optmask)  = (ARES_OPT_FLAGS | ARES_OPT_TRIES | ARES_OPT_NDOTS |
                ARES_OPT_UDP_PORT | ARES_OPT_TCP_PORT | ARES_OPT_SOCK_STATE_CB |
                ARES_OPT_SERVERS | ARES_OPT_DOMAINS | ARES_OPT_LOOKUPS |
                ARES_OPT_SORTLIST | ARES_OPT_TIMEOUTMS);
  (*optmask) |= (channel->rotate ? ARES_OPT_ROTATE : ARES_OPT_NOROTATE);

  if (channel->resolvconf_path) {
    (*optmask) |= ARES_OPT_RESOLVCONF;
  }

  if (channel->hosts_path) {
    (*optmask) |= ARES_OPT_HOSTS_FILE;
  }

  /* Copy easy stuff */
  options->flags = (int)channel->flags;

  /* We return full millisecond resolution but that's only because we don't
     set the ARES_OPT_TIMEOUT anymore, only the new ARES_OPT_TIMEOUTMS */
  options->timeout            = (int)channel->timeout;
  options->tries              = (int)channel->tries;
  options->ndots              = (int)channel->ndots;
  options->udp_port           = ntohs(channel->udp_port);
  options->tcp_port           = ntohs(channel->tcp_port);
  options->sock_state_cb      = channel->sock_state_cb;
  options->sock_state_cb_data = channel->sock_state_cb_data;

  /* Copy IPv4 servers that use the default port */
  if (channel->nservers) {
    for (i = 0; i < channel->nservers; i++) {
      if ((channel->servers[i].addr.family == AF_INET) &&
          (channel->servers[i].addr.udp_port == 0) &&
          (channel->servers[i].addr.tcp_port == 0)) {
        ipv4_nservers++;
      }
    }
    if (ipv4_nservers) {
      options->servers = ares_malloc(ipv4_nservers * sizeof(struct in_addr));
      if (!options->servers) {
        return ARES_ENOMEM;
      }

      for (i = j = 0; i < channel->nservers; i++) {
        if ((channel->servers[i].addr.family == AF_INET) &&
            (channel->servers[i].addr.udp_port == 0) &&
            (channel->servers[i].addr.tcp_port == 0)) {
          memcpy(&options->servers[j++], &channel->servers[i].addr.addrV4,
                 sizeof(channel->servers[i].addr.addrV4));
        }
      }
    }
  }
  options->nservers = (int)ipv4_nservers;

  /* copy domains */
  if (channel->ndomains) {
    options->domains = ares_malloc(channel->ndomains * sizeof(char *));
    if (!options->domains) {
      return ARES_ENOMEM;
    }

    for (i = 0; i < channel->ndomains; i++) {
      options->domains[i] = ares_strdup(channel->domains[i]);
      if (!options->domains[i]) {
        options->ndomains = (int)i;
        return ARES_ENOMEM;
      }
    }
  }
  options->ndomains = (int)channel->ndomains;

  /* copy lookups */
  if (channel->lookups) {
    options->lookups = ares_strdup(channel->lookups);
    if (!options->lookups && channel->lookups) {
      return ARES_ENOMEM;
    }
  }

  /* copy sortlist */
  if (channel->nsort) {
    options->sortlist = ares_malloc(channel->nsort * sizeof(struct apattern));
    if (!options->sortlist) {
      return ARES_ENOMEM;
    }
    for (i = 0; i < channel->nsort; i++) {
      options->sortlist[i] = channel->sortlist[i];
    }
  }
  options->nsort = (int)channel->nsort;

  /* copy path for resolv.conf file */
  if (channel->resolvconf_path) {
    options->resolvconf_path = ares_strdup(channel->resolvconf_path);
    if (!options->resolvconf_path) {
      return ARES_ENOMEM;
    }
  }

  /* copy path for hosts file */
  if (channel->hosts_path) {
    options->hosts_path = ares_strdup(channel->hosts_path);
    if (!options->hosts_path) {
      return ARES_ENOMEM;
    }
  }

  if (channel->udp_max_queries > 0) {
    (*optmask)               |= ARES_OPT_UDP_MAX_QUERIES;
    options->udp_max_queries  = (int)channel->udp_max_queries;
  }

  return ARES_SUCCESS;
}

ares_status_t ares__init_by_options(ares_channel               channel,
                                    const struct ares_options *options,
                                    int                        optmask)
{
  size_t i;

  /* Easy stuff. */
  if (optmask & ARES_OPT_FLAGS) {
    channel->flags = (unsigned int)options->flags;
  }

  if (optmask & ARES_OPT_TIMEOUTMS) {
    channel->timeout = (unsigned int)options->timeout;
  } else if (optmask & ARES_OPT_TIMEOUT) {
    channel->timeout = (unsigned int)options->timeout * 1000;
  }

  if (optmask & ARES_OPT_TRIES) {
    channel->tries = (size_t)options->tries;
  }

  if (optmask & ARES_OPT_NDOTS) {
    channel->ndots = (size_t)options->ndots;
  }

  if (optmask & ARES_OPT_ROTATE) {
    channel->rotate = ARES_TRUE;
  }

  if (optmask & ARES_OPT_NOROTATE) {
    channel->rotate = ARES_FALSE;
  }

  if ((optmask & ARES_OPT_UDP_PORT) && channel->udp_port == 0) {
    channel->udp_port = htons(options->udp_port);
  }

  if ((optmask & ARES_OPT_TCP_PORT) && channel->tcp_port == 0) {
    channel->tcp_port = htons(options->tcp_port);
  }

  if ((optmask & ARES_OPT_SOCK_STATE_CB) && channel->sock_state_cb == NULL) {
    channel->sock_state_cb      = options->sock_state_cb;
    channel->sock_state_cb_data = options->sock_state_cb_data;
  }

  if (optmask & ARES_OPT_SOCK_SNDBUF && options->socket_send_buffer_size > 0) {
    channel->socket_send_buffer_size = options->socket_send_buffer_size;
  }

  if (optmask & ARES_OPT_SOCK_RCVBUF &&
      channel->socket_receive_buffer_size > 0) {
    channel->socket_receive_buffer_size = options->socket_receive_buffer_size;
  }

  if (optmask & ARES_OPT_EDNSPSZ) {
    channel->ednspsz = (size_t)options->ednspsz;
  }

  /* Copy the IPv4 servers, if given. */
  if (optmask & ARES_OPT_SERVERS) {
    /* Avoid zero size allocations at any cost */
    if (options->nservers > 0) {
      channel->servers =
        ares_malloc((size_t)options->nservers * sizeof(*channel->servers));
      if (!channel->servers) {
        return ARES_ENOMEM;
      }
      memset(channel->servers, 0,
             (size_t)options->nservers * sizeof(*channel->servers));
      for (i = 0; i < (size_t)options->nservers; i++) {
        channel->servers[i].addr.family   = AF_INET;
        channel->servers[i].addr.udp_port = 0;
        channel->servers[i].addr.tcp_port = 0;
        memcpy(&channel->servers[i].addr.addrV4, &options->servers[i],
               sizeof(channel->servers[i].addr.addrV4));
      }
    }
    channel->nservers = (size_t)options->nservers;
  }

  /* Copy the domains, if given.  Keep channel->ndomains consistent so
   * we can clean up in case of error.
   */
  if (optmask & ARES_OPT_DOMAINS) {
    /* Avoid zero size allocations at any cost */
    if (options->ndomains > 0) {
      channel->domains =
        ares_malloc((size_t)options->ndomains * sizeof(char *));
      if (!channel->domains) {
        return ARES_ENOMEM;
      }
      for (i = 0; i < (size_t)options->ndomains; i++) {
        channel->domains[i] = ares_strdup(options->domains[i]);
        if (!channel->domains[i]) {
          return ARES_ENOMEM;
        }
      }
    }
    channel->ndomains = (size_t)options->ndomains;
  }

  /* Set lookups, if given. */
  if ((optmask & ARES_OPT_LOOKUPS) && !channel->lookups) {
    channel->lookups = ares_strdup(options->lookups);
    if (!channel->lookups) {
      return ARES_ENOMEM;
    }
  }

  /* copy sortlist */
  if (optmask & ARES_OPT_SORTLIST && options->nsort > 0) {
    channel->nsort = (size_t)options->nsort;
    channel->sortlist =
      ares_malloc((size_t)options->nsort * sizeof(struct apattern));
    if (!channel->sortlist) {
      return ARES_ENOMEM;
    }
    for (i = 0; i < (size_t)options->nsort; i++) {
      channel->sortlist[i] = options->sortlist[i];
    }
  }

  /* Set path for resolv.conf file, if given. */
  if ((optmask & ARES_OPT_RESOLVCONF) && !channel->resolvconf_path) {
    channel->resolvconf_path = ares_strdup(options->resolvconf_path);
    if (!channel->resolvconf_path && options->resolvconf_path) {
      return ARES_ENOMEM;
    }
  }

  /* Set path for hosts file, if given. */
  if ((optmask & ARES_OPT_HOSTS_FILE) && !channel->hosts_path) {
    channel->hosts_path = ares_strdup(options->hosts_path);
    if (!channel->hosts_path && options->hosts_path) {
      return ARES_ENOMEM;
    }
  }

  if (optmask & ARES_OPT_UDP_MAX_QUERIES) {
    channel->udp_max_queries = (size_t)options->udp_max_queries;
  }

  channel->optmask = (unsigned int)optmask;

  return ARES_SUCCESS;
}
