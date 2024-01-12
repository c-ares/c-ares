/* MIT License
 *
 * Copyright (c) 2024 Brad House
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

struct ares_event_thread;
typedef struct ares_event_thread ares_event_thread_t;

struct ares_event_sys;
typedef struct ares_event_sys ares_event_sys_t;

typedef enum {
  ARES_EVENT_FLAG_NONE       = 0,
  ARES_EVENT_FLAG_READ       = 1 << 0,
  ARES_EVENT_FLAG_WRITE      = 1 << 1,
  ARES_EVENT_FLAG_OTHER      = 1 << 2
} ares_event_flags_t;

typedef void (*ares_event_cb_t)(ares_event_thread_t *e, ares_socket_t fd,
                                void *data, ares_event_flags_t flags);

typedef void (*ares_event_free_data_t)(void *data);

void ares_event_thread_destroy(ares_event_thread_t *e);
ares_event_thread_t *ares_event_thread_init(ares_channel_t *channel);

typedef struct {
  /*! Flags to monitor. OTHER is only allowed if the socket is ARES_SOCKET_BAD.
   */
  ares_event_flags_t      flags;
  /*! Callback to be called when event is triggered */
  ares_event_cb_t         cb;
  /*! Socket to monitor, allowed to be ARES_SOCKET_BAD if not monitoring a
   *  socket. */
  ares_socket_t           fd;
  /*! Data associated with event handle that will be passed to the callback.
   *  Optional, may be NULL. */
  /*! Data to be passed to callback. Optional, may be NULL. */
  void                   *data;
  /*! When cleaning up the registered event (either when removed or during
   *  shutdown), this function will be called to clean up the user-supplied
   *  data. Optional, May be NULL. */
  ares_event_free_data_t  free_data_cb;
} ares_event_t;

struct ares_event_thread {
  ares__thread_t       *thread;
  ares__thread_mutex_t *mutex;
  ares_channel_t       *channel;
  ares_bool_t           isup;
  ares__llist_t        *ev_updates;
  ares_event_sys_t     *ev_sys;
};


static ares_event_sys_t *ares_event_sys_init(void);
static void ares_event_sys_update(ares_event_sys_t *sys, ares__llist_t *ev_updates);
/* Returns number of events processed */
static size_t ares_event_sys_wait(ares_event_thread_t *e, unsigned long timeout_ms);
static void ares_event_sys_wake(ares_event_sys_t *sys);
static void ares_event_sys_destroy(ares_event_sys_t *sys);


static void ares_event_destroy_cb(void *arg)
{
  ares_event_t *event = arg;
  if (event == NULL)
    return;

  if (event->free_data_cb && event->data) {
    event->free_data_cb(event->data);
  }

  ares_free(event);
}

#if defined(_WIN32)

#else /* poll() */
#  include <poll.h>

struct ares_event_sys {
  ares__htable_asvp_t *fds; /*!< ares_event_t * members */
};

static void ares_event_sys_destroy(ares_event_sys_t *sys)
{
  if (sys == NULL)
    return;

  ares__htable_asvp_destroy(sys->fds);
  ares_free(sys);
}

static ares_event_sys_t *ares_event_sys_init(void)
{
  ares_event_sys_t *sys = ares_malloc_zero(sizeof(*sys));
  if (sys == NULL)
    return NULL;

  sys->fds = ares__htable_asvp_create(ares_event_destroy_cb);
  if (sys->fds == NULL) {
    ares_free(sys);
    return NULL;
  }

  return sys;
}

static void ares_event_sys_update(ares_event_sys_t *sys, ares__llist_t *ev_updates)
{
  ares__llist_node_t *node;

  if (sys == NULL || ev_updates == NULL)
    return;

  /* Iterate across all updates and apply to internal list, removing from update
   * list */
  while ((node = ares__llist_node_first(ev_updates)) != NULL) {
    ares_event_t *newev = ares__llist_node_val(node);
    ares_event_t *oldev = ares__htable_asvp_get_direct(sys->fds, newev->fd);

    /* Adding new */
    if (oldev == NULL) {
      ares__htable_asvp_insert(sys->fds, newev->fd, newev);
      continue;
    }

    /* Removal request */
    if (newev->flags == ARES_EVENT_FLAG_NONE) {
      ares__htable_asvp_remove(sys->fds, newev->fd);
      ares_free(newev);
      continue;
    }

    /* Modify request -- no changes allowed */
    oldev->flags = newev->flags;
    ares_free(newev);
  }
}

static size_t ares_event_sys_wait(ares_event_thread_t *e, unsigned long timeout_ms)
{
  size_t            num_fds = 0;
  ares_event_sys_t *sys     = e->ev_sys;
  ares_socket_t    *fdlist  = ares__htable_asvp_keys(sys->fds, &num_fds);
  struct pollfd    *pollfd  = NULL;
  int               rv;
  size_t            cnt     = 0;
  size_t            i;

  if (num_fds) {
    pollfd = ares_malloc_zero(sizeof(*pollfd) * num_fds);
    for (i=0; i<num_fds; i++) {
      ares_event_t *ev = ares__htable_asvp_get_direct(sys->fds, fdlist[i]);
      pollfd[i].fd     = ev->fd;
      if (ev->flags & ARES_EVENT_FLAG_READ)
        pollfd[i].events |= POLLIN;
      if (ev->flags & ARES_EVENT_FLAG_WRITE)
        pollfd[i].events |= POLLOUT;
    }
  }
  ares_free(fdlist);

  rv = poll(pollfd, (nfds_t)num_fds, (timeout_ms == 0)?-1:(int)timeout_ms);
  if (rv <= 0)
    goto done;

  for (i=0; i<num_fds; i++) {
    ares_event_t      *ev;
    ares_event_flags_t flags = 0;

    if (pollfd[i].revents == 0)
      continue;

    cnt++;

    ev = ares__htable_asvp_get_direct(sys->fds, pollfd[i].fd);
    if (ev == NULL || ev->cb == NULL)
      continue;

    if (pollfd[i].revents & (POLLERR|POLLHUP|POLLIN))
      flags |= ARES_EVENT_FLAG_READ;

    if (pollfd[i].revents & POLLOUT)
      flags |= ARES_EVENT_FLAG_WRITE;

    ev->cb(e, pollfd[i].fd, ev->data, flags);
  }

done:
  ares_free(pollfd);
  return cnt;
}

static void ares_event_sys_wake(ares_event_sys_t *sys)
{
  /* XXX: TODO */
}
#endif



/*! Queue an update for the event handle.
 *
 *  \param[in] e            pointer to event thread handle
 *  \param[in] flags        flags for the event handle.  Use ARES_EVENT_FLAG_NONE
 *                          if removing a socket from queue (not valid if socket
 *                          is ARES_SOCKET_BAD).  Non-socket events cannot be
 *                          removed, and must have ARES_EVENT_FLAG_OTHER set.
 *  \param[in] cb           Callback to call when event is triggered. Required.
 *                          Not allowed to be changed, ignored on modification.
 *  \param[in] fd           File descriptor/socket to monitor.  May be
 *                          ARES_SOCKET_BAD if not monitoring file descriptor.
 *  \param[in] data         Optional. Caller-supplied data to be passed to
 *                          callback. Only allowed on initial add, cannot be
 *                          modified later, ignored on modification.
 *  \param[in] free_data_cb Optional. Callback to clean up caller-supplied
 *                          data. Only allowed on initial add, cannot be
 *                          modified later, ignored on modification.
 *  \return ARES_SUCCESS on success
 */
static ares_status_t ares_event_update(ares_event_thread_t *e,
                                       ares_event_flags_t flags,
                                       ares_event_cb_t cb, ares_socket_t fd,
                                       void *data,
                                       ares_event_free_data_t free_data_cb)
{
  ares_event_t *event = NULL;

  if (e == NULL || cb == NULL) {
    return ARES_EFORMERR;
  }

  /* Validate flags */
  if (fd == ARES_SOCKET_BAD) {
    if (flags & (ARES_EVENT_FLAG_READ|ARES_EVENT_FLAG_WRITE))
      return ARES_EFORMERR;
    if (!(flags & ARES_EVENT_FLAG_OTHER))
      return ARES_EFORMERR;
  } else {
    if (flags & ARES_EVENT_FLAG_OTHER)
      return ARES_EFORMERR;
  }

  /* That's all the validation we can really do */
  event = ares_malloc_zero(sizeof(*event));
  if (event == NULL) {
    return ARES_ENOMEM;
  }

  event->flags        = flags;
  event->cb           = cb;
  event->fd           = fd;
  event->data         = data;
  event->free_data_cb = free_data_cb;

  if (ares__llist_insert_last(e->ev_updates, event) == NULL) {
    ares_free(event);
    return ARES_ENOMEM;
  }

  return ARES_SUCCESS;
}




static void ares_event_thread_process_fd(ares_event_thread_t *e,
                                         ares_socket_t fd, void *data,
                                         ares_event_flags_t flags)
{
  (void)data;
  ares_process_fd(e->channel, (flags & ARES_EVENT_FLAG_READ)?fd:ARES_SOCKET_BAD,
                  (flags & ARES_EVENT_FLAG_WRITE)?fd:ARES_SOCKET_BAD);
}


static void ares_event_thread_sockstate_cb(void *data, ares_socket_t socket_fd,
                                           int readable, int writable)
{
  ares_event_thread_t *e     = data;
  ares_event_flags_t   flags = ARES_EVENT_FLAG_NONE;

  if (readable) {
    flags |= ARES_EVENT_FLAG_READ;
  }

  if (writable) {
    flags |= ARES_EVENT_FLAG_WRITE;
  }

  /* Update channel fd */
  ares__thread_mutex_lock(e->mutex);

  ares_event_update(e, flags, ares_event_thread_process_fd, socket_fd,
                    NULL, NULL);

  /* Wake the event thread so it properly enqueues any updates */
  ares_event_sys_wake(e->ev_sys);

  ares__thread_mutex_unlock(e->mutex);
}


static void *ares_event_thread(void *arg)
{
  ares_event_thread_t *e = arg;

  ares__thread_mutex_lock(e->mutex);

  while (e->isup) {
    struct timeval  tv;
    struct timeval *tvout;
    unsigned long   timeout_ms = 0; /* 0 = unlimited */

    tvout = ares_timeout(e->channel, NULL, &tv);
    if (tvout != NULL) {
      timeout_ms = (unsigned long)(tvout->tv_sec * 1000) + (tvout->tv_usec / 1000) + 1;
    }

    ares_event_sys_update(e->ev_sys, e->ev_updates);

    /* Don't hold a mutex while waiting on events */
    ares__thread_mutex_unlock(e->mutex);
    if (ares_event_sys_wait(e, timeout_ms) == 0) {
      /* Each iteration should do timeout checking even if nothing was triggered */
      ares_process_fd(e->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    }

    ares__thread_mutex_lock(e->mutex);
  }

  ares__thread_mutex_unlock(e->mutex);
  return NULL;
}


void ares_event_thread_destroy(ares_event_thread_t *e)
{
  /* Wake thread and tell it to shutdown if it exists */
  ares__thread_mutex_lock(e->mutex);
  if (e->isup) {
    e->isup = ARES_FALSE;
    ares_event_sys_wake(e->ev_sys);
  }
  ares__thread_mutex_unlock(e->mutex);

  /* Wait for thread to shutdown */
  if (e->thread) {
    ares__thread_join(e->thread, NULL);
    e->thread = NULL;
  }

  ares__llist_destroy(e->ev_updates);
  e->ev_updates = NULL;

  if (e->ev_sys) {
    ares_event_sys_destroy(e->ev_sys);
    e->ev_sys = NULL;
  }

  ares__thread_mutex_destroy(e->mutex);
  e->mutex = NULL;

  ares_free(e);
}


ares_event_thread_t *ares_event_thread_init(ares_channel_t *channel)
{
  ares_event_thread_t *e = ares_malloc_zero(sizeof(*e));
  if (e == NULL) {
    return NULL;
  }

  e->mutex = ares__thread_mutex_create();
  if (e->mutex == NULL) {
    ares_event_thread_destroy(e);
    return NULL;
  }

  e->ev_updates = ares__llist_create(NULL);
  if (e->ev_updates == NULL) {
    ares_event_thread_destroy(e);
    return NULL;
  }

  e->channel = channel;
  e->isup    = ARES_TRUE;
  e->ev_sys  = ares_event_sys_init();
  if (e->ev_sys == NULL) {
    ares_event_thread_destroy(e);
    return NULL;
  }

  if (ares__thread_create(&e->thread, ares_event_thread, e) != ARES_SUCCESS) {
    ares_event_thread_destroy(e);
    return NULL;
  }

  channel->sock_state_cb      = ares_event_thread_sockstate_cb;
  channel->sock_state_cb_data = e;

  return e;
}
