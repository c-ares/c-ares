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
#ifdef HAVE_POLL_H
#  include <poll.h>
#endif
#ifdef HAVE_UNISTDD_H
#  include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif


struct ares_event_thread;
typedef struct ares_event_thread ares_event_thread_t;

struct ares_event;
typedef struct ares_event ares_event_t;

typedef enum {
  ARES_EVENT_FLAG_NONE       = 0,
  ARES_EVENT_FLAG_READ       = 1 << 0,
  ARES_EVENT_FLAG_WRITE      = 1 << 1,
  ARES_EVENT_FLAG_OTHER      = 1 << 2
} ares_event_flags_t;

typedef void (*ares_event_cb_t)(ares_event_thread_t *e, ares_socket_t fd,
                                void *data, ares_event_flags_t flags);

typedef void (*ares_event_free_data_t)(void *data);

typedef void (*ares_event_signal_cb_t)(const ares_event_t *event);

void ares_event_thread_destroy(ares_event_thread_t *e);
ares_event_thread_t *ares_event_thread_init(ares_channel_t *channel);


struct ares_event {
  /*! Registered event thread this event is bound to */
  ares_event_thread_t    *e;
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
  /*! Callback to call to trigger an event. */
  ares_event_signal_cb_t  signal_cb;
};


typedef struct {
  const char   *name;
  ares_bool_t (*init)(ares_event_thread_t *e);
  void        (*destroy)(ares_event_thread_t *e);
  void        (*event_add)(ares_event_thread_t *e, ares_event_t *event);
  void        (*event_del)(ares_event_thread_t *e, ares_event_t *event);
  void        (*event_mod)(ares_event_thread_t *e, ares_event_t *event,
                           ares_event_flags_t new_flags);
  size_t      (*wait)(ares_event_thread_t *e, unsigned long timeout_ms);
} ares_event_sys_t;


struct ares_event_thread {
  /*! Whether the event thread should be online or not.  Checked on every wake
   *  event before sleeping. */
  ares_bool_t             isup;
  /*! Handle to the thread for joining during shutdown */
  ares__thread_t         *thread;
  /*! Lock to protect the data contained within the event thread itself */
  ares__thread_mutex_t   *mutex;
  /*! Reference to the ares channel, for being able to call things like
   *  ares_timeout() and ares_process_fd(). */
  ares_channel_t         *channel;
  /*! Not-yet-processed event handle updates.  These will get enqueued by a
   *  thread other than the event thread itself. The event thread will then
   *  be woken then process these updates itself */
  ares__llist_t          *ev_updates;
  /*! Registered event handles. */
  ares__htable_asvp_t    *ev_handles;
  /*! Pointer to the event handle which is used to signal and wake the event
   *  thread itself.  This is needed to be able to do things like update the
   *  file descriptors being waited on and to wake the event subsystem during
   *  shutdown */
  ares_event_t           *ev_signal;
  /* Event subsystem callbacks */
  const ares_event_sys_t *ev_sys;
  /* Event subsystem private data */
  void                   *ev_sys_data;
};


static void ares_event_destroy_cb(void *arg)
{
  ares_event_t *event = arg;
  if (event == NULL)
    return;

  /* Unregister from the event thread if it was registered with one */
  if (event->e) {
    ares_event_thread_t *e = event->e;
    e->ev_sys->event_del(e, event);
    event->e = NULL;
  }

  if (event->free_data_cb && event->data) {
    event->free_data_cb(event->data);
  }

  ares_free(event);
}

/*! Queue an update for the event handle.  Will search by the fd passed if
 *  not ARES_SOCKET_BAD to find a match and perform an update or delete
 *  (depending on flags).  Otherwise will add.  Do not use the event handle
 *  returned if its not guaranteed to be an add operation.
 *
 *  \param[out] event        Event handle. Optional, can be NULL.  This handle
 *                           will be invalidate quickly if the result of the
 *                           operation is not an ADD.
 *  \param[in]  e            pointer to event thread handle
 *  \param[in]  flags        flags for the event handle.  Use ARES_EVENT_FLAG_NONE
 *                           if removing a socket from queue (not valid if socket
 *                           is ARES_SOCKET_BAD).  Non-socket events cannot be
 *                           removed, and must have ARES_EVENT_FLAG_OTHER set.
 *  \param[in]  cb           Callback to call when event is triggered. Required.
 *                           Not allowed to be changed, ignored on modification.
 *  \param[in]  fd           File descriptor/socket to monitor.  May be
 *                           ARES_SOCKET_BAD if not monitoring file descriptor.
 *  \param[in]  data         Optional. Caller-supplied data to be passed to
 *                           callback. Only allowed on initial add, cannot be
 *                           modified later, ignored on modification.
 *  \param[in]  free_data_cb Optional. Callback to clean up caller-supplied
 *                           data. Only allowed on initial add, cannot be
 *                           modified later, ignored on modification.
 *  \param[in]  signal_cb    Optional. Callback to call to trigger an event.
 *
 *  \return ARES_SUCCESS on success
 */
static ares_status_t ares_event_update(ares_event_t       **event,
                                       ares_event_thread_t *e,
                                       ares_event_flags_t  flags,
                                       ares_event_cb_t     cb,
                                       ares_socket_t       fd,
                                       void               *data,
                                       ares_event_free_data_t free_data_cb,
                                       ares_event_signal_cb_t signal_cb)
{
  ares_event_t *ev = NULL;

  if (e == NULL || cb == NULL) {
    return ARES_EFORMERR;
  }

  if (event != NULL)
    *event = NULL;

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
  ev = ares_malloc_zero(sizeof(*ev));
  if (ev == NULL) {
    return ARES_ENOMEM;
  }

  ev->flags        = flags;
  ev->cb           = cb;
  ev->fd           = fd;
  ev->data         = data;
  ev->free_data_cb = free_data_cb;
  ev->signal_cb    = signal_cb;

  if (ares__llist_insert_last(e->ev_updates, ev) == NULL) {
    ares_free(ev);
    return ARES_ENOMEM;
  }

  *event = ev;

  return ARES_SUCCESS;
}


static void ares_event_signal(const ares_event_t *event)
{
  if (event == NULL || event->signal_cb == NULL)
    return;
  event->signal_cb(event);
}


#ifdef HAVE_PIPE
typedef struct {
  int filedes[2];
} ares_pipeevent_t;

static void ares_pipeevent_destroy(ares_pipeevent_t *p)
{
  if (p->filedes[0] != -1)
    close(p->filedes[0]);
  if (p->filedes[1] != -1)
    close(p->filedes[1]);

  ares_free(p);
}

static void ares_pipeevent_destroy_cb(void *arg)
{
  ares_pipeevent_destroy(arg);
}

static ares_pipeevent_t *ares_pipeevent_init(void)
{
  ares_pipeevent_t *p = ares_malloc_zero(sizeof(*p));
  if (p == NULL)
    return NULL;

  p->filedes[0] = -1;
  p->filedes[1] = -1;

#  ifdef HAVE_PIPE2
  if (pipe2(p->filedes, O_NONBLOCK|O_CLOEXEC) != 0) {
    ares_pipeevent_destroy(p);
    return NULL;
  }
#  else
  if (pipe(p->filedes) != 0) {
    ares_pipeevent_destroy(p);
    return NULL;
  }

#    ifdef O_NONBLOCK
  {
    int val;
    val = fcntl(p->filedes[0], F_GETFL, 0);
    if (val >= 0) {
      val |= O_NONBLOCK;
    }
    fcntl(p->filedes[0], F_SETFL, val);

    val = fcntl(p->filedes[1], F_GETFL, 0);
    if (val >= 0) {
      val |= O_NONBLOCK;
    }
    fcntl(p->filedes[1], F_SETFL, val);
  }
#    endif

#    ifdef O_CLOEXEC
  fcntl(p->filedes[0], F_SETFD, O_CLOEXEC);
  fcntl(p->filedes[1], F_SETFD, O_CLOEXEC);
#    endif
#endif

#  ifdef F_SETNOSIGPIPE
  fcntl(p->filedes[0], F_SETNOSIGPIPE, 1);
  fcntl(p->filedes[1], F_SETNOSIGPIPE, 1);
#  endif

  return p;
}


static void ares_pipeevent_signal(const ares_event_t *e)
{
  ares_pipeevent_t *p;

  if (e == NULL || e->data == NULL)
    return;

  p = e->data;
  write(p->filedes[1], "1", 1);
}

static void ares_pipeevent_cb(ares_event_thread_t *e, ares_socket_t fd,
                              void *data, ares_event_flags_t flags)
{
  unsigned char     buf[32];
  ares_pipeevent_t *p = NULL;

  (void)e;
  (void)fd;
  (void)flags;

  if (data == NULL)
    return;

  p = data;

  while (read(p->filedes[0], buf, sizeof(buf)) == sizeof(buf)) {
    /* Do nothing */
  }

}


static ares_event_t *ares_pipeevent_create(ares_event_thread_t *e)
{
  ares_event_t     *event = NULL;
  ares_pipeevent_t *p     = NULL;
  ares_status_t     status;

  p = ares_pipeevent_init();
  if (p == NULL)
    return NULL;

  status = ares_event_update(&event, e, ARES_EVENT_FLAG_READ,
                             ares_pipeevent_cb,
                             p->filedes[0],
                             p,
                             ares_pipeevent_destroy_cb,
                             ares_pipeevent_signal);
  if (status != ARES_SUCCESS) {
    ares_pipeevent_destroy(p);
    return NULL;
  }

  return event;
}

#endif


#if defined(HAVE_POLL)

static ares_bool_t ares_evsys_poll_init(ares_event_thread_t *e)
{
  e->ev_signal = ares_pipeevent_create(e);
  if (e->ev_signal == NULL)
    return ARES_FALSE;
  return ARES_TRUE;
}

static void ares_evsys_poll_destroy(ares_event_thread_t *e)
{
  (void)e;
}

static void ares_evsys_poll_event_add(ares_event_thread_t *e, ares_event_t *event)
{
  (void)e;
  (void)event;
}

static void ares_evsys_poll_event_del(ares_event_thread_t *e, ares_event_t *event)
{
  (void)e;
  (void)event;
}

static void ares_evsys_poll_event_mod(ares_event_thread_t *e, ares_event_t *event, ares_event_flags_t new_flags)
{
  (void)e;
  (void)event;
  (void)new_flags;
}

static size_t ares_evsys_poll_wait(ares_event_thread_t *e, unsigned long timeout_ms)
{
  size_t            num_fds = 0;
  ares_socket_t    *fdlist  = ares__htable_asvp_keys(e->ev_handles, &num_fds);
  struct pollfd    *pollfd  = NULL;
  int               rv;
  size_t            cnt     = 0;
  size_t            i;

  if (num_fds) {
    pollfd = ares_malloc_zero(sizeof(*pollfd) * num_fds);
    for (i=0; i<num_fds; i++) {
      ares_event_t *ev = ares__htable_asvp_get_direct(e->ev_handles, fdlist[i]);
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

    ev = ares__htable_asvp_get_direct(e->ev_handles, pollfd[i].fd);
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


static const ares_event_sys_t ares_evsys_poll = {
  "poll",
  ares_evsys_poll_init,
  ares_evsys_poll_destroy,   /* NoOp */
  ares_evsys_poll_event_add, /* NoOp */
  ares_evsys_poll_event_del, /* NoOp */
  ares_evsys_poll_event_mod, /* NoOp */
  ares_evsys_poll_wait
};

#endif


static void ares_event_thread_wake(ares_event_thread_t *e)
{
  if (e == NULL)
    return;
  ares_event_signal(e->ev_signal);
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

  ares_event_update(NULL, e, flags, ares_event_thread_process_fd, socket_fd,
                    NULL, NULL, NULL);

  /* Wake the event thread so it properly enqueues any updates */
  ares_event_thread_wake(e);

  ares__thread_mutex_unlock(e->mutex);
}


static void ares_event_process_updates(ares_event_thread_t *e)
{
  ares__llist_node_t *node;

  /* Iterate across all updates and apply to internal list, removing from update
   * list */
  while ((node = ares__llist_node_first(e->ev_updates)) != NULL) {
    ares_event_t *newev = ares__llist_node_val(node);
    ares_event_t *oldev = ares__htable_asvp_get_direct(e->ev_handles, newev->fd);

    /* Adding new */
    if (oldev == NULL) {
      newev->e = e;
      e->ev_sys->event_add(e, newev);
      ares__htable_asvp_insert(e->ev_handles, newev->fd, newev);
      continue;
    }

    /* Removal request */
    if (newev->flags == ARES_EVENT_FLAG_NONE) {
      /* the callback for the removal will call e->ev_sys->event_del(e, event) */
      ares__htable_asvp_remove(e->ev_handles, newev->fd);
      ares_free(newev);
      continue;
    }

    /* Modify request -- only flags cn be changed */
    e->ev_sys->event_mod(e, oldev, newev->flags);
    oldev->flags = newev->flags;
    ares_free(newev);
  }
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

    ares_event_process_updates(e);

    /* Don't hold a mutex while waiting on events */
    ares__thread_mutex_unlock(e->mutex);
    if (e->ev_sys->wait(e, timeout_ms) == 0) {
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
    ares_event_thread_wake(e);
  }
  ares__thread_mutex_unlock(e->mutex);

  /* Wait for thread to shutdown */
  if (e->thread) {
    ares__thread_join(e->thread, NULL);
    e->thread = NULL;
  }

  ares__llist_destroy(e->ev_updates);
  e->ev_updates = NULL;

  ares__htable_asvp_destroy(e->ev_handles);
  e->ev_handles = NULL;

  if (e->ev_sys->destroy) {
    e->ev_sys->destroy(e);
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

  e->ev_handles = ares__htable_asvp_create(ares_event_destroy_cb);
  if (e->ev_handles == NULL) {
    ares_event_thread_destroy(e);
    return NULL;
  }

  e->channel = channel;
  e->isup    = ARES_TRUE;
  e->ev_sys  = &ares_evsys_poll;

  if (!e->ev_sys->init(e)) {
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
