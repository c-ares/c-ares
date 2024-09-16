/* MIT License
 *
 * Copyright (c) Massachusetts Institute of Technology
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
#include "ares_private.h"
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#  include <netinet/tcp.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef NETWARE
#  include <sys/filio.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <limits.h>

#if defined(__linux__) && defined(TCP_FASTOPEN_CONNECT)
#  define TFO_SUPPORTED      1
#  define TFO_SKIP_CONNECT   0
#  define TFO_USE_SENDTO     0
#  define TFO_USE_CONNECTX   0
#  define TFO_CLIENT_SOCKOPT TCP_FASTOPEN_CONNECT
#elif defined(__FreeBSD__) && defined(TCP_FASTOPEN)
#  define TFO_SUPPORTED      1
#  define TFO_SKIP_CONNECT   1
#  define TFO_USE_SENDTO     1
#  define TFO_USE_CONNECTX   0
#  define TFO_CLIENT_SOCKOPT TCP_FASTOPEN
#elif defined(__APPLE__) && defined(HAVE_CONNECTX)
#  define TFO_SUPPORTED    1
#  define TFO_SKIP_CONNECT 0
#  define TFO_USE_SENDTO   0
#  define TFO_USE_CONNECTX 1
#  undef TFO_CLIENT_SOCKOPT
#else
#  define TFO_SUPPORTED 0
#endif


/* Macro SOCKERRNO / SET_SOCKERRNO() returns / sets the *socket-related* errno
 * (or equivalent) on this platform to hide platform details to code using it.
 */
#ifdef USE_WINSOCK
#  define SOCKERRNO        ((int)WSAGetLastError())
#  define SET_SOCKERRNO(x) (WSASetLastError((int)(x)))
#else
#  define SOCKERRNO        (errno)
#  define SET_SOCKERRNO(x) (errno = (x))
#endif

/* Portable error number symbolic names defined to Winsock error codes. */
#ifdef USE_WINSOCK
#  undef EBADF           /* override definition in errno.h */
#  define EBADF WSAEBADF
#  undef EINTR           /* override definition in errno.h */
#  define EINTR WSAEINTR
#  undef EINVAL          /* override definition in errno.h */
#  define EINVAL WSAEINVAL
#  undef EWOULDBLOCK     /* override definition in errno.h */
#  define EWOULDBLOCK WSAEWOULDBLOCK
#  undef EINPROGRESS     /* override definition in errno.h */
#  define EINPROGRESS WSAEINPROGRESS
#  undef EALREADY        /* override definition in errno.h */
#  define EALREADY WSAEALREADY
#  undef ENOTSOCK        /* override definition in errno.h */
#  define ENOTSOCK WSAENOTSOCK
#  undef EDESTADDRREQ    /* override definition in errno.h */
#  define EDESTADDRREQ WSAEDESTADDRREQ
#  undef EMSGSIZE        /* override definition in errno.h */
#  define EMSGSIZE WSAEMSGSIZE
#  undef EPROTOTYPE      /* override definition in errno.h */
#  define EPROTOTYPE WSAEPROTOTYPE
#  undef ENOPROTOOPT     /* override definition in errno.h */
#  define ENOPROTOOPT WSAENOPROTOOPT
#  undef EPROTONOSUPPORT /* override definition in errno.h */
#  define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#  define ESOCKTNOSUPPORT WSAESOCKTNOSUPPORT
#  undef EOPNOTSUPP /* override definition in errno.h */
#  define EOPNOTSUPP   WSAEOPNOTSUPP
#  define EPFNOSUPPORT WSAEPFNOSUPPORT
#  undef EAFNOSUPPORT  /* override definition in errno.h */
#  define EAFNOSUPPORT WSAEAFNOSUPPORT
#  undef EADDRINUSE    /* override definition in errno.h */
#  define EADDRINUSE WSAEADDRINUSE
#  undef EADDRNOTAVAIL /* override definition in errno.h */
#  define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#  undef ENETDOWN      /* override definition in errno.h */
#  define ENETDOWN WSAENETDOWN
#  undef ENETUNREACH   /* override definition in errno.h */
#  define ENETUNREACH WSAENETUNREACH
#  undef ENETRESET     /* override definition in errno.h */
#  define ENETRESET WSAENETRESET
#  undef ECONNABORTED  /* override definition in errno.h */
#  define ECONNABORTED WSAECONNABORTED
#  undef ECONNRESET    /* override definition in errno.h */
#  define ECONNRESET WSAECONNRESET
#  undef ENOBUFS       /* override definition in errno.h */
#  define ENOBUFS WSAENOBUFS
#  undef EISCONN       /* override definition in errno.h */
#  define EISCONN WSAEISCONN
#  undef ENOTCONN      /* override definition in errno.h */
#  define ENOTCONN     WSAENOTCONN
#  define ESHUTDOWN    WSAESHUTDOWN
#  define ETOOMANYREFS WSAETOOMANYREFS
#  undef ETIMEDOUT     /* override definition in errno.h */
#  define ETIMEDOUT WSAETIMEDOUT
#  undef ECONNREFUSED  /* override definition in errno.h */
#  define ECONNREFUSED WSAECONNREFUSED
#  undef ELOOP         /* override definition in errno.h */
#  define ELOOP WSAELOOP
#  ifndef ENAMETOOLONG /* possible previous definition in errno.h */
#    define ENAMETOOLONG WSAENAMETOOLONG
#  endif
#  define EHOSTDOWN WSAEHOSTDOWN
#  undef EHOSTUNREACH /* override definition in errno.h */
#  define EHOSTUNREACH WSAEHOSTUNREACH
#  ifndef ENOTEMPTY   /* possible previous definition in errno.h */
#    define ENOTEMPTY WSAENOTEMPTY
#  endif
#  define EPROCLIM WSAEPROCLIM
#  define EUSERS   WSAEUSERS
#  define EDQUOT   WSAEDQUOT
#  define ESTALE   WSAESTALE
#  define EREMOTE  WSAEREMOTE
#endif


#ifndef HAVE_WRITEV
/* Structure for scatter/gather I/O. */
struct iovec {
  void  *iov_base; /* Pointer to data. */
  size_t iov_len;  /* Length of data.  */
};
#endif

ares_bool_t ares_socket_tfo_supported(const ares_channel_t *channel)
{
#if defined(TFO_SUPPORTED) && !TFO_SUPPORTED
  (void)channel;
  return ARES_FALSE;
#else
  if (channel->sock_funcs != NULL && channel->sock_funcs->asendv != NULL) {
    return ARES_FALSE;
  }

  return ARES_TRUE;
#endif
}

static ares_conn_err_t ares_socket_deref_error(int err)
{
  switch (err) {
#if defined(EWOULDBLOCK)
    case EWOULDBLOCK:
      return ARES_CONN_ERR_WOULDBLOCK;
#endif
#if defined(EAGAIN) && (!defined(EWOULDBLOCK) || EAGAIN != EWOULDBLOCK)
    case EAGAIN:
      return ARES_CONN_ERR_WOULDBLOCK;
#endif
    case EINPROGRESS:
      return ARES_CONN_ERR_WOULDBLOCK;
    case ENETDOWN:
      return ARES_CONN_ERR_NETDOWN;
    case ENETUNREACH:
      return ARES_CONN_ERR_NETUNREACH;
    case ECONNABORTED:
      return ARES_CONN_ERR_CONNABORTED;
    case ECONNRESET:
      return ARES_CONN_ERR_CONNRESET;
    case ECONNREFUSED:
      return ARES_CONN_ERR_CONNREFUSED;
    case ETIMEDOUT:
      return ARES_CONN_ERR_CONNTIMEDOUT;
    case EHOSTDOWN:
      return ARES_CONN_ERR_HOSTDOWN;
    case EHOSTUNREACH:
      return ARES_CONN_ERR_HOSTUNREACH;
    case EINTR:
      return ARES_CONN_ERR_INTERRUPT;
    case EAFNOSUPPORT:
      return ARES_CONN_ERR_AFNOSUPPORT;
    case EADDRNOTAVAIL:
      return ARES_CONN_ERR_BADADDR;
    default:
      break;
  }

  return ARES_CONN_ERR_FAILURE;
}

ares_bool_t ares_sockaddr_addr_eq(const struct sockaddr  *sa,
                                  const struct ares_addr *aa)
{
  const void *addr1;
  const void *addr2;

  if (sa->sa_family == aa->family) {
    switch (aa->family) {
      case AF_INET:
        addr1 = &aa->addr.addr4;
        addr2 = &(CARES_INADDR_CAST(const struct sockaddr_in *, sa))->sin_addr;
        if (memcmp(addr1, addr2, sizeof(aa->addr.addr4)) == 0) {
          return ARES_TRUE; /* match */
        }
        break;
      case AF_INET6:
        addr1 = &aa->addr.addr6;
        addr2 =
          &(CARES_INADDR_CAST(const struct sockaddr_in6 *, sa))->sin6_addr;
        if (memcmp(addr1, addr2, sizeof(aa->addr.addr6)) == 0) {
          return ARES_TRUE; /* match */
        }
        break;
      default:
        break; /* LCOV_EXCL_LINE */
    }
  }
  return ARES_FALSE; /* different */
}

ares_conn_err_t ares_socket_write(ares_channel_t *channel, ares_socket_t fd,
                                  const void *data, size_t len, size_t *written)
{
  int             flags = 0;
  ares_ssize_t    rv;
  ares_conn_err_t err = ARES_CONN_ERR_SUCCESS;

#ifdef HAVE_MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif

  if (channel->sock_funcs && channel->sock_funcs->asendv) {
    struct iovec vec;
    vec.iov_base = (void *)((size_t)data); /* Cast off const */
    vec.iov_len  = len;
    rv = channel->sock_funcs->asendv(fd, &vec, 1, channel->sock_func_cb_data);
    if (rv <= 0) {
      err = ares_socket_deref_error(SOCKERRNO);
    } else {
      *written = (size_t)rv;
    }
    return err;
  }

  rv = (ares_ssize_t)send((SEND_TYPE_ARG1)fd, (SEND_TYPE_ARG2)data,
                          (SEND_TYPE_ARG3)len, (SEND_TYPE_ARG4)flags);
  if (rv <= 0) {
    err = ares_socket_deref_error(SOCKERRNO);
  } else {
    *written = (size_t)rv;
  }
  return err;
}

ares_conn_err_t ares_socket_write_tfo(ares_channel_t *channel, ares_socket_t fd,
                                      const void *data, size_t len,
                                      size_t                *written,
                                      const struct sockaddr *sa,
                                      ares_socklen_t         salen)
{
  ares_conn_err_t err;

  if (!ares_socket_tfo_supported(channel)) {
    return ARES_CONN_ERR_NOTIMP;
  }

#if defined(TFO_USE_SENDTO) && TFO_USE_SENDTO
  {
    ares_ssize_t rv;
    int          flags = 0;

#  ifdef HAVE_MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#  endif

    err = ARES_CONN_ERR_SUCCESS;
    rv  = (ares_ssize_t)sendto((SEND_TYPE_ARG1)fd, (SEND_TYPE_ARG2)data,
                               (SEND_TYPE_ARG3)len, (SEND_TYPE_ARG4)flags, sa,
                               salen);
    if (rv <= 0) {
      err = ares_socket_deref_error(SOCKERRNO);
    } else {
      *written = (size_t)rv;
    }
  }
#else
  (void)sa;
  (void)salen;
  err = ares_socket_write(channel, fd, data, len, written);
#endif
  return err;
}

ares_conn_err_t ares_socket_recv(ares_channel_t *channel, ares_socket_t s,
                                 ares_bool_t is_tcp, void *data,
                                 size_t data_len, size_t *read_bytes)
{
  ares_ssize_t rv;

  *read_bytes = 0;

  if (channel->sock_funcs && channel->sock_funcs->arecvfrom) {
    rv = channel->sock_funcs->arecvfrom(s, data, data_len, 0, 0, 0,
                                        channel->sock_func_cb_data);
  } else {
    rv = (ares_ssize_t)recv((RECV_TYPE_ARG1)s, (RECV_TYPE_ARG2)data,
                            (RECV_TYPE_ARG3)data_len, (RECV_TYPE_ARG4)(0));
  }

  if (rv > 0) {
    *read_bytes = (size_t)rv;
    return ARES_CONN_ERR_SUCCESS;
  }

  if (rv == 0) {
    /* UDP allows 0-byte packets and is connectionless, so this is success */
    if (!is_tcp) {
      return ARES_CONN_ERR_SUCCESS;
    } else {
      return ARES_CONN_ERR_CONNCLOSED;
    }
  }

  /* If we're here, rv<0 */
  return ares_socket_deref_error(SOCKERRNO);
}

ares_conn_err_t ares_socket_recvfrom(ares_channel_t *channel, ares_socket_t s,
                                     ares_bool_t is_tcp, void *data,
                                     size_t data_len, int flags,
                                     struct sockaddr *from,
                                     ares_socklen_t  *from_len,
                                     size_t          *read_bytes)
{
  ares_ssize_t rv;

  if (channel->sock_funcs && channel->sock_funcs->arecvfrom) {
    rv = channel->sock_funcs->arecvfrom(s, data, data_len, flags, from,
                                        from_len, channel->sock_func_cb_data);
  } else {
#ifdef HAVE_RECVFROM
    rv = (ares_ssize_t)recvfrom(s, data, (RECVFROM_TYPE_ARG3)data_len, flags,
                                from, from_len);
#else
    return ares_socket_recv(channel, s, is_udp, data, data_len);
#endif
  }

  if (rv > 0) {
    *read_bytes = (size_t)rv;
    return ARES_CONN_ERR_SUCCESS;
  }

  if (rv == 0) {
    /* UDP allows 0-byte packets and is connectionless, so this is success */
    if (!is_tcp) {
      return ARES_CONN_ERR_SUCCESS;
    } else {
      return ARES_CONN_ERR_CONNCLOSED;
    }
  }

  /* If we're here, rv<0 */
  return ares_socket_deref_error(SOCKERRNO);
}

/*
 * setsocknonblock sets the given socket to either blocking or non-blocking
 * mode based on the 'nonblock' boolean argument. This function is highly
 * portable.
 */
static int setsocknonblock(ares_socket_t sockfd, /* operate on this */
                           int           nonblock /* TRUE or FALSE */)
{
#if defined(USE_BLOCKING_SOCKETS)

  return 0; /* returns success */

#elif defined(HAVE_FCNTL_O_NONBLOCK)

  /* most recent unix versions */
  int flags;
  flags = fcntl(sockfd, F_GETFL, 0);
  if (nonblock) {
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
  } else {
    return fcntl(sockfd, F_SETFL, flags & (~O_NONBLOCK)); /* LCOV_EXCL_LINE */
  }

#elif defined(HAVE_IOCTL_FIONBIO)

  /* older unix versions */
  int flags = nonblock ? 1 : 0;
  return ioctl(sockfd, FIONBIO, &flags);

#elif defined(HAVE_IOCTLSOCKET_FIONBIO)

#  ifdef WATT32
  char flags = nonblock ? 1 : 0;
#  else
  /* Windows */
  unsigned long flags = nonblock ? 1UL : 0UL;
#  endif
  return ioctlsocket(sockfd, (long)FIONBIO, &flags);

#elif defined(HAVE_IOCTLSOCKET_CAMEL_FIONBIO)

  /* Amiga */
  long flags = nonblock ? 1L : 0L;
  return IoctlSocket(sockfd, FIONBIO, flags);

#elif defined(HAVE_SETSOCKOPT_SO_NONBLOCK)

  /* BeOS */
  long b = nonblock ? 1L : 0L;
  return setsockopt(sockfd, SOL_SOCKET, SO_NONBLOCK, &b, sizeof(b));

#else
#  error "no non-blocking method was found/used/set"
#endif
}

#if defined(IPV6_V6ONLY) && defined(USE_WINSOCK)
/* It makes support for IPv4-mapped IPv6 addresses.
 * Linux kernel, NetBSD, FreeBSD and Darwin: default is off;
 * Windows Vista and later: default is on;
 * DragonFly BSD: acts like off, and dummy setting;
 * OpenBSD and earlier Windows: unsupported.
 * Linux: controlled by /proc/sys/net/ipv6/bindv6only.
 */
static void set_ipv6_v6only(ares_socket_t sockfd, int on)
{
  (void)setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on));
}
#else
#  define set_ipv6_v6only(s, v)
#endif

ares_conn_err_t ares_socket_enable_tfo(const ares_channel_t *channel,
                                       ares_socket_t         fd)
{
#if defined(TFO_CLIENT_SOCKOPT)
  int opt = 1;

  if (!ares_socket_tfo_supported(channel)) {
    return ARES_CONN_ERR_NOTIMP;
  }

  if (setsockopt(fd, IPPROTO_TCP, TFO_CLIENT_SOCKOPT, (void *)&opt,
                 sizeof(opt)) != 0) {
    return ARES_CONN_ERR_NOTIMP;
  }
#else
  if (!ares_socket_tfo_supported(channel)) {
    return ARES_CONN_ERR_NOTIMP;
  }

  (void)fd;
#endif
  return ARES_CONN_ERR_SUCCESS;
}

ares_status_t ares_socket_configure(ares_channel_t *channel, int family,
                                    ares_bool_t is_tcp, ares_socket_t fd)
{
  union {
    struct sockaddr     sa;
    struct sockaddr_in  sa4;
    struct sockaddr_in6 sa6;
  } local;

  ares_socklen_t bindlen = 0;

  /* do not set options for user-managed sockets */
  if (channel->sock_funcs && channel->sock_funcs->asocket) {
    return ARES_SUCCESS;
  }

  (void)setsocknonblock(fd, 1);

#if defined(FD_CLOEXEC) && !defined(MSDOS)
  /* Configure the socket fd as close-on-exec. */
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
    return ARES_ECONNREFUSED; /* LCOV_EXCL_LINE */
  }
#endif

  /* No need to emit SIGPIPE on socket errors */
#if defined(SO_NOSIGPIPE)
  {
    int opt = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&opt, sizeof(opt));
  }
#endif

  /* Set the socket's send and receive buffer sizes. */
  if (channel->socket_send_buffer_size > 0 &&
      setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                 (void *)&channel->socket_send_buffer_size,
                 sizeof(channel->socket_send_buffer_size)) != 0) {
    return ARES_ECONNREFUSED; /* LCOV_EXCL_LINE: UntestablePath */
  }

  if (channel->socket_receive_buffer_size > 0 &&
      setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                 (void *)&channel->socket_receive_buffer_size,
                 sizeof(channel->socket_receive_buffer_size)) != 0) {
    return ARES_ECONNREFUSED; /* LCOV_EXCL_LINE: UntestablePath */
  }

#ifdef SO_BINDTODEVICE
  if (ares_strlen(channel->local_dev_name)) {
    /* Only root can do this, and usually not fatal if it doesn't work, so
     * just continue on. */
    (void)setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, channel->local_dev_name,
                     sizeof(channel->local_dev_name));
  }
#endif

  if (family == AF_INET && channel->local_ip4) {
    memset(&local.sa4, 0, sizeof(local.sa4));
    local.sa4.sin_family      = AF_INET;
    local.sa4.sin_addr.s_addr = htonl(channel->local_ip4);
    bindlen                   = sizeof(local.sa4);
  } else if (family == AF_INET6 &&
             memcmp(channel->local_ip6, ares_in6addr_any._S6_un._S6_u8,
                    sizeof(channel->local_ip6)) != 0) {
    /* Only if not link-local and an ip other than "::" is specified */
    memset(&local.sa6, 0, sizeof(local.sa6));
    local.sa6.sin6_family = AF_INET6;
    memcpy(&local.sa6.sin6_addr, channel->local_ip6,
           sizeof(channel->local_ip6));
    bindlen = sizeof(local.sa6);
  }

  if (bindlen && bind(fd, &local.sa, bindlen) < 0) {
    return ARES_ECONNREFUSED;
  }

  if (family == AF_INET6) {
    set_ipv6_v6only(fd, 0);
  }

  if (is_tcp) {
    int opt = 1;

#ifdef TCP_NODELAY
    /*
     * Disable the Nagle algorithm (only relevant for TCP sockets, and thus not
     * in configure_socket). In general, in DNS lookups we're pretty much
     * interested in firing off a single request and then waiting for a reply,
     * so batching isn't very interesting.
     */
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&opt, sizeof(opt)) !=
        0) {
      return ARES_ECONNREFUSED;
    }
#endif
  }

  return ARES_SUCCESS;
}

ares_bool_t ares_sockaddr_to_ares_addr(struct ares_addr      *ares_addr,
                                       unsigned short        *port,
                                       const struct sockaddr *sockaddr)
{
  if (sockaddr->sa_family == AF_INET) {
    /* NOTE: memcpy sockaddr_in due to alignment issues found by UBSAN due to
     *       dnsinfo packing on MacOS */
    struct sockaddr_in sockaddr_in;
    memcpy(&sockaddr_in, sockaddr, sizeof(sockaddr_in));

    ares_addr->family = AF_INET;
    memcpy(&ares_addr->addr.addr4, &(sockaddr_in.sin_addr),
           sizeof(ares_addr->addr.addr4));

    if (port) {
      *port = ntohs(sockaddr_in.sin_port);
    }
    return ARES_TRUE;
  }

  if (sockaddr->sa_family == AF_INET6) {
    /* NOTE: memcpy sockaddr_in6 due to alignment issues found by UBSAN due to
     *       dnsinfo packing on MacOS */
    struct sockaddr_in6 sockaddr_in6;
    memcpy(&sockaddr_in6, sockaddr, sizeof(sockaddr_in6));

    ares_addr->family = AF_INET6;
    memcpy(&ares_addr->addr.addr6, &(sockaddr_in6.sin6_addr),
           sizeof(ares_addr->addr.addr6));
    if (port) {
      *port = ntohs(sockaddr_in6.sin6_port);
    }
    return ARES_TRUE;
  }

  return ARES_FALSE;
}

ares_conn_err_t ares_socket_open(ares_socket_t *sock, ares_channel_t *channel,
                                 int af, int type, int protocol)
{
  ares_socket_t s;

  *sock = ARES_SOCKET_BAD;

  if (channel->sock_funcs && channel->sock_funcs->asocket) {
    s = channel->sock_funcs->asocket(af, type, protocol,
                                     channel->sock_func_cb_data);
  } else {
    s = socket(af, type, protocol);
  }

  if (s == ARES_SOCKET_BAD) {
    return ares_socket_deref_error(SOCKERRNO);
  }

  *sock = s;

  return ARES_CONN_ERR_SUCCESS;
}

ares_conn_err_t ares_socket_connect(ares_channel_t *channel,
                                    ares_socket_t sockfd, ares_bool_t is_tfo,
                                    const struct sockaddr *addr,
                                    ares_socklen_t         addrlen)
{
  ares_conn_err_t err = ARES_CONN_ERR_SUCCESS;

#if defined(TFO_SKIP_CONNECT) && TFO_SKIP_CONNECT
  if (is_tfo) {
    return ARES_CONN_ERR_SUCCESS;
  }
#endif

  do {
    int rv;
    if (channel->sock_funcs && channel->sock_funcs->aconnect) {
      rv = channel->sock_funcs->aconnect(sockfd, addr, addrlen,
                                         channel->sock_func_cb_data);
    } else {
      if (is_tfo) {
#if defined(TFO_USE_CONNECTX) && TFO_USE_CONNECTX
        sa_endpoints_t endpoints;

        memset(&endpoints, 0, sizeof(endpoints));
        endpoints.sae_dstaddr    = addr;
        endpoints.sae_dstaddrlen = addrlen;

        rv = connectx(sockfd, &endpoints, SAE_ASSOCID_ANY,
                      CONNECT_DATA_IDEMPOTENT | CONNECT_RESUME_ON_READ_WRITE,
                      NULL, 0, NULL, NULL);
#else
        rv = connect(sockfd, addr, addrlen);
#endif
      } else {
        rv = connect(sockfd, addr, addrlen);
      }
    }

    if (rv < 0) {
      err = ares_socket_deref_error(SOCKERRNO);
    } else {
      err = ARES_CONN_ERR_SUCCESS;
    }
  } while (err == ARES_CONN_ERR_INTERRUPT);

  return err;
}

void ares_socket_close(ares_channel_t *channel, ares_socket_t s)
{
  if (s == ARES_SOCKET_BAD) {
    return;
  }

  if (channel->sock_funcs && channel->sock_funcs->aclose) {
    channel->sock_funcs->aclose(s, channel->sock_func_cb_data);
  } else {
    sclose(s);
  }
}

void ares_set_socket_callback(ares_channel_t           *channel,
                              ares_sock_create_callback cb, void *data)
{
  if (channel == NULL) {
    return;
  }
  channel->sock_create_cb      = cb;
  channel->sock_create_cb_data = data;
}

void ares_set_socket_configure_callback(ares_channel_t           *channel,
                                        ares_sock_config_callback cb,
                                        void                     *data)
{
  if (channel == NULL || channel->optmask & ARES_OPT_EVENT_THREAD) {
    return;
  }
  channel->sock_config_cb      = cb;
  channel->sock_config_cb_data = data;
}

void ares_set_socket_functions(ares_channel_t                     *channel,
                               const struct ares_socket_functions *funcs,
                               void                               *data)
{
  if (channel == NULL || channel->optmask & ARES_OPT_EVENT_THREAD) {
    return;
  }
  channel->sock_funcs        = funcs;
  channel->sock_func_cb_data = data;
}

void ares_set_pending_write_cb(ares_channel_t       *channel,
                               ares_pending_write_cb callback, void *user_data)
{
  if (channel == NULL || channel->optmask & ARES_OPT_EVENT_THREAD) {
    return;
  }
  channel->notify_pending_write_cb      = callback;
  channel->notify_pending_write_cb_data = user_data;
}
