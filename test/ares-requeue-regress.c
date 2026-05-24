/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
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

#include <ares.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct apattern {
  struct in_addr addr;
  struct in_addr mask;
};

static const uint8_t issue_1043_input[] = {
  0xff, 0xc2, 0xa7, 0x00, 0x80, 0x27, 0x27, 0x27, 0x27, 0x00, 0x00, 0x10,
  0x00, 0x40, 0x00, 0x00, 0x00, 0x34, 0x2b, 0x00, 0xa5, 0x85, 0x00, 0x27,
  0x18, 0x92, 0x18, 0x06, 0x89, 0xbc, 0xde, 0x00, 0x00, 0x00, 0x4a, 0x00,
  0x00, 0x40, 0x00, 0x00, 0x00, 0x34, 0x2b, 0x00, 0xa5, 0x85, 0x00, 0x00,
  0x02, 0xec, 0xff, 0x00, 0x40, 0x2b, 0x00, 0x00, 0x00, 0x01, 0xed, 0x00,
  0x30, 0x39, 0x32, 0x38, 0x34, 0xfa, 0x00, 0x00, 0xfa, 0x0e, 0xc0, 0xc0,
  0x01, 0x31, 0x31, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
  0x0a, 0xf3, 0x13, 0x0a, 0x0a, 0x0a, 0x0a, 0xd8, 0x0a, 0x43, 0x11, 0x0a,
  0x0a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x36, 0x33, 0x00,
  0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x01,
  0x01, 0x01, 0x41, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0xe4, 0xff, 0xff, 0x32, 0x00, 0x10,
  0x0f, 0xc0, 0xc0, 0x47, 0x38, 0xcd, 0x0a, 0x0a, 0x0a, 0x0a, 0xd8, 0x0a,
  0x0a, 0x11, 0x0a, 0x0a, 0x00, 0x39, 0x13, 0x30, 0x39, 0x32, 0x38, 0x34,
  0x36, 0x33, 0x00, 0x10, 0x0f, 0xc0, 0xc0, 0x01, 0x31, 0x31, 0x0a, 0x0a,
  0x0a, 0x0a, 0x0a, 0x0a, 0xff, 0xff, 0xff, 0x0a, 0x0a, 0x0a, 0xff, 0xff,
  0xff, 0x7f, 0x0a, 0x14, 0x0a, 0x0a, 0x0a, 0x0a, 0xd8, 0x0a, 0x43, 0x11,
  0x0a, 0x0a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x36, 0x33,
  0x00, 0x10, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x67,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0a,
  0x0a, 0x0a, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x41,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x80, 0x00, 0x00, 0x01, 0x01,
  0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x00, 0xa5,
  0x84, 0xed, 0x00, 0xff, 0xff, 0x00, 0x00, 0x40
};

static void dummy_host_callback(void *arg, int status, int timeouts,
                                const struct hostent *hostent)
{
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)hostent;
}

#define READ_BYTES(dst, nbytes)                                               \
  do {                                                                        \
    if (remain >= (nbytes)) {                                                 \
      memcpy((dst), ptr, (nbytes));                                           \
      ptr += (nbytes);                                                        \
      remain -= (nbytes);                                                     \
    }                                                                         \
  } while (0)

#define ALLOC_AND_COPY_STR(out_ptr, len_expr)                                 \
  do {                                                                        \
    size_t len = (len_expr);                                                  \
    if (remain >= len) {                                                      \
      (out_ptr) = (char *)malloc(len + 1);                                    \
      if ((out_ptr) != NULL) {                                                \
        memcpy((out_ptr), ptr, len);                                          \
        (out_ptr)[len] = '\0';                                                \
      }                                                                       \
      ptr += len;                                                             \
      remain -= len;                                                          \
    }                                                                         \
  } while (0)

static int run_issue_1043(const uint8_t *data, size_t size)
{
  const uint8_t              *ptr = data;
  size_t                      remain = size;
  ares_channel_t             *channel = NULL;
  int                         optmask = 0;
  struct ares_options         opts;

  memset(&opts, 0, sizeof(opts));

  READ_BYTES(&opts.flags, sizeof(int));
  READ_BYTES(&opts.timeout, sizeof(int));
  READ_BYTES(&opts.tries, sizeof(int));
  READ_BYTES(&opts.ndots, sizeof(int));
  READ_BYTES(&opts.udp_port, sizeof(unsigned short));
  READ_BYTES(&opts.tcp_port, sizeof(unsigned short));
  READ_BYTES(&opts.socket_send_buffer_size, sizeof(int));
  READ_BYTES(&opts.socket_receive_buffer_size, sizeof(int));

  READ_BYTES(&opts.nservers, sizeof(int));
  if (opts.nservers < 0) {
    opts.nservers = -opts.nservers;
  }
  opts.nservers %= 5;
  if (remain >= (size_t)opts.nservers * sizeof(struct in_addr)) {
    opts.servers =
      (struct in_addr *)malloc((size_t)opts.nservers * sizeof(struct in_addr));
    if (opts.servers != NULL) {
      memcpy(opts.servers, ptr,
             (size_t)opts.nservers * sizeof(struct in_addr));
    }
    ptr += (size_t)opts.nservers * sizeof(struct in_addr);
    remain -= (size_t)opts.nservers * sizeof(struct in_addr);
  }

  READ_BYTES(&opts.ndomains, sizeof(int));
  if (opts.ndomains < 0) {
    opts.ndomains = -opts.ndomains;
  }
  opts.ndomains %= 5;
  opts.domains = (char **)malloc((size_t)opts.ndomains * sizeof(char *));
  if (opts.domains != NULL) {
    int i;

    memset(opts.domains, 0, (size_t)opts.ndomains * sizeof(char *));
    for (i = 0; i < opts.ndomains; ++i) {
      size_t len;

      if (remain < 1) {
        break;
      }
      len = (size_t)(*ptr % 32);
      ptr++;
      remain--;
      if (remain < len) {
        len = remain;
      }
      if (len != 0) {
        opts.domains[i] = (char *)malloc(len + 1);
        if (opts.domains[i] != NULL) {
          memcpy(opts.domains[i], ptr, len);
          opts.domains[i][len] = '\0';
        }
        ptr += len;
        remain -= len;
      }
    }
  }

  if (remain >= 1) {
    size_t lookups_len = (size_t)(*ptr % 32);

    ptr++;
    remain--;
    if (remain >= lookups_len) {
      ALLOC_AND_COPY_STR(opts.lookups, lookups_len);
    }
  }

  READ_BYTES(&opts.nsort, sizeof(int));
  if (opts.nsort < 0) {
    opts.nsort = -opts.nsort;
  }
  opts.nsort %= 5;
  if (remain >= (size_t)opts.nsort * sizeof(struct apattern)) {
    opts.sortlist =
      (struct apattern *)malloc((size_t)opts.nsort * sizeof(struct apattern));
    if (opts.sortlist != NULL) {
      memcpy(opts.sortlist, ptr,
             (size_t)opts.nsort * sizeof(struct apattern));
    }
    ptr += (size_t)opts.nsort * sizeof(struct apattern);
    remain -= (size_t)opts.nsort * sizeof(struct apattern);
  }

  READ_BYTES(&opts.ednspsz, sizeof(int));

  if (remain >= 1) {
    size_t resolv_len = (size_t)(*ptr % 64);

    ptr++;
    remain--;
    if (remain >= resolv_len) {
      ALLOC_AND_COPY_STR(opts.resolvconf_path, resolv_len);
    }
  }

  if (remain >= 1) {
    size_t hosts_len = (size_t)(*ptr % 64);

    ptr++;
    remain--;
    if (remain >= hosts_len) {
      ALLOC_AND_COPY_STR(opts.hosts_path, hosts_len);
    }
  }

  READ_BYTES(&opts.udp_max_queries, sizeof(int));
  READ_BYTES(&opts.maxtimeout, sizeof(int));
  READ_BYTES(&opts.qcache_max_ttl, sizeof(unsigned int));
  READ_BYTES(&opts.evsys, sizeof(int));

  if (remain >= sizeof(struct ares_server_failover_options)) {
    memcpy(&opts.server_failover_opts, ptr,
           sizeof(struct ares_server_failover_options));
    ptr += sizeof(struct ares_server_failover_options);
    remain -= sizeof(struct ares_server_failover_options);
  }

  READ_BYTES(&optmask, sizeof(int));

  (void)ares_init_options(&channel, &opts, optmask);

  if (opts.resolvconf_path != NULL &&
      strcmp(opts.resolvconf_path, "./dummy_file") == 0 && remain > 0) {
    FILE *fp = fopen("./dummy_file", "wb");

    if (fp != NULL) {
      fwrite(ptr, 1, remain < 1024 ? remain : 1024, fp);
      fclose(fp);
    }
  }
  if (opts.hosts_path != NULL &&
      strcmp(opts.hosts_path, "./dummy_file") == 0 && remain > 0) {
    FILE *fp = fopen("./dummy_file", "wb");

    if (fp != NULL) {
      fwrite(ptr, 1, remain < 1024 ? remain : 1024, fp);
      fclose(fp);
    }
  }

  free(opts.servers);
  if (opts.domains != NULL) {
    int i;

    for (i = 0; i < opts.ndomains; ++i) {
      free(opts.domains[i]);
    }
    free(opts.domains);
  }
  free(opts.lookups);
  free(opts.sortlist);
  free(opts.resolvconf_path);
  free(opts.hosts_path);

  if (channel == NULL) {
#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    if (ares_init(&channel) != ARES_SUCCESS) {
      return 0;
    }
#if defined(__clang__)
#  pragma clang diagnostic pop
#elif defined(__GNUC__)
#  pragma GCC diagnostic pop
#endif
  }

  if (remain != 0) {
    size_t csv_len = remain / 4;

    if (csv_len > 0) {
      char *csv_str = (char *)malloc(csv_len + 1);

      if (csv_str != NULL) {
        memcpy(csv_str, ptr, csv_len);
        csv_str[csv_len] = '\0';
        ares_set_servers_csv(channel, csv_str);
        free(csv_str);
      }
      ptr += csv_len;
      remain -= csv_len;
    }
  }

  if (remain != 0) {
    size_t ports_csv_len = remain / 4;

    if (ports_csv_len > 0) {
      char *ports_csv_str = (char *)malloc(ports_csv_len + 1);

      if (ports_csv_str != NULL) {
        memcpy(ports_csv_str, ptr, ports_csv_len);
        ports_csv_str[ports_csv_len] = '\0';
        ares_set_servers_ports_csv(channel, ports_csv_str);
        free(ports_csv_str);
      }
      ptr += ports_csv_len;
      remain -= ports_csv_len;
    }
  }

  {
    uint8_t                     num_servers = 0;
    struct ares_addr_port_node *head = NULL;
    struct ares_addr_port_node *tail = NULL;

    if (remain >= 1) {
      num_servers = *ptr % 5;
      ptr++;
      remain--;
    }

    while (num_servers-- != 0) {
      struct ares_addr_port_node *node;

      node = (struct ares_addr_port_node *)malloc(sizeof(*node));
      if (node == NULL) {
        break;
      }
      memset(node, 0, sizeof(*node));

      if (remain < sizeof(int)) {
        free(node);
        break;
      }
      memcpy(&node->family, ptr, sizeof(int));
      ptr += sizeof(int);
      remain -= sizeof(int);

      if (node->family == AF_INET) {
        if (remain < sizeof(struct in_addr)) {
          free(node);
          break;
        }
        memcpy(&node->addr.addr4, ptr, sizeof(struct in_addr));
        ptr += sizeof(struct in_addr);
        remain -= sizeof(struct in_addr);
      } else if (node->family == AF_INET6) {
        if (remain < sizeof(struct ares_in6_addr)) {
          free(node);
          break;
        }
        memcpy(&node->addr.addr6, ptr, sizeof(struct ares_in6_addr));
        ptr += sizeof(struct ares_in6_addr);
        remain -= sizeof(struct ares_in6_addr);
      } else {
        free(node);
        continue;
      }

      if (remain < sizeof(int)) {
        free(node);
        break;
      }
      memcpy(&node->udp_port, ptr, sizeof(int));
      ptr += sizeof(int);
      remain -= sizeof(int);

      if (remain < sizeof(int)) {
        free(node);
        break;
      }
      memcpy(&node->tcp_port, ptr, sizeof(int));
      ptr += sizeof(int);
      remain -= sizeof(int);

      if (tail != NULL) {
        tail->next = node;
      } else {
        head = node;
      }
      tail = node;
    }

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    ares_set_servers_ports(channel, head);
#if defined(__clang__)
#  pragma clang diagnostic pop
#elif defined(__GNUC__)
#  pragma GCC diagnostic pop
#endif

    while (head != NULL) {
      struct ares_addr_port_node *next = head->next;

      free(head);
      head = next;
    }
  }

  if (remain >= sizeof(int)) {
    int   family = 0;
    void *addr = NULL;
    int   addrlen = 0;

    READ_BYTES(&family, sizeof(int));
    if (family == AF_INET && remain >= sizeof(struct in_addr)) {
      addrlen = (int)sizeof(struct in_addr);
      addr = malloc((size_t)addrlen);
      if (addr != NULL) {
        memcpy(addr, ptr, (size_t)addrlen);
      }
      ptr += (size_t)addrlen;
      remain -= (size_t)addrlen;
    } else if (family == AF_INET6 && remain >= sizeof(struct in6_addr)) {
      addrlen = (int)sizeof(struct in6_addr);
      addr = malloc((size_t)addrlen);
      if (addr != NULL) {
        memcpy(addr, ptr, (size_t)addrlen);
      }
      ptr += (size_t)addrlen;
      remain -= (size_t)addrlen;
    }

    if (addr != NULL) {
      ares_gethostbyaddr(channel, addr, addrlen, family, dummy_host_callback,
                         NULL);
      free(addr);
    }
  }

  {
    ares_channel_t *dup_channel = NULL;

    (void)ares_dup(&dup_channel, channel);
    if (dup_channel != NULL) {
      ares_destroy(dup_channel);
    }
  }

  ares_destroy(channel);
  return 0;
}

int main(void)
{
  return run_issue_1043(issue_1043_input, sizeof(issue_1043_input));
}
