/* MIT License
 *
 * Copyright (c) 2023 Brad House
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
#include "ares.h"
#include "ares_private.h"

#ifdef USE_WINSOCK
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#elif defined(HAVE_GETIFADDRS)
#  ifdef HAVE_SYS_TYPES_H
#    include <sys/types.h>
#  endif
#  ifdef HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#  endif
#  ifdef HAVE_NET_IF_H
#    include <net/if.h>
#  endif
#  ifdef HAVE_IFADDRS_H
#    include <ifaddrs.h>
#  endif
#  ifdef HAVE_SYS_IOCTL_H
#    include <sys/ioctl.h>
#  endif
#  ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#  endif
#endif

/*! Flags for interface ip addresses. */
typedef enum {
  ARES_IFACE_IP_V4        = 1 << 0, /*!< IPv4 address */
  ARES_IFACE_IP_V6        = 1 << 1, /*!< IPv6 address */
  ARES_IFACE_IP_LOOPBACK  = 1 << 2, /*!< Loopback adapter */
  ARES_IFACE_IP_OFFLINE   = 1 << 3, /*!< Adapter offline */
  ARES_IFACE_IP_LINKLOCAL = 1 << 4, /*!< Link-local ip address */
  /*! Default, enumerate all ips for online interfaces, including loopback */
  ARES_IFACE_IP_DEFAULT   = (ARES_IFACE_IP_V4|ARES_IFACE_IP_V6|
                             ARES_IFACE_IP_LOOPBACK|ARES_IFACE_IP_LINKLOCAL)
} ares__iface_ip_flags_t;

typedef struct {
  char                  *name;
  char                  *friendly_name;
  struct ares_addr       addr;
  unsigned char          netmask;
  int                    ll_scope;
  ares__iface_ip_flags_t flags;
} ares__iface_ip_t;

