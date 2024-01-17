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
#include "ares_event.h"

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


ares_status_t ares_event_update(ares_event_t       **event,
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
printf("%s(): fd %d, flags %X\n", __FUNCTION__, fd, flags);
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

  if (event != NULL) {
    *event = ev;
  }

  return ARES_SUCCESS;
}


static void ares_event_signal(const ares_event_t *event)
{
  if (event == NULL || event->signal_cb == NULL)
    return;
  event->signal_cb(event);
}


static void ares_event_thread_wake(ares_event_thread_t *e)
{
  if (e == NULL)
    return;
printf("%s()\n", __FUNCTION__);
  ares_event_signal(e->ev_signal);
}

static void ares_event_thread_process_fd(ares_event_thread_t *e,
                                         ares_socket_t fd, void *data,
                                         ares_event_flags_t flags)
{
  (void)data;
printf("%s(): fd %d\n", __FUNCTION__, fd);
  ares_process_fd(e->channel, (flags & ARES_EVENT_FLAG_READ)?fd:ARES_SOCKET_BAD,
                  (flags & ARES_EVENT_FLAG_WRITE)?fd:ARES_SOCKET_BAD);
}


static void ares_event_thread_sockstate_cb(void *data, ares_socket_t socket_fd,
                                           int readable, int writable)
{
  ares_event_thread_t *e     = data;
  ares_event_flags_t   flags = ARES_EVENT_FLAG_NONE;
printf("%s(): fd %d, readable: %d, writable: %d\n", __FUNCTION__, socket_fd, readable, writable);
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
    ares_event_t *newev = ares__llist_node_claim(node);
    ares_event_t *oldev = ares__htable_asvp_get_direct(e->ev_handles, newev->fd);

    /* Adding new */
    if (oldev == NULL) {
printf("%s(): added fd %d\n", __FUNCTION__, newev->fd);
      newev->e = e;
      e->ev_sys->event_add(e, newev);
      ares__htable_asvp_insert(e->ev_handles, newev->fd, newev);
      continue;
    }

    /* Removal request */
    if (newev->flags == ARES_EVENT_FLAG_NONE) {
      /* the callback for the removal will call e->ev_sys->event_del(e, event) */
printf("%s(): removed fd %d\n", __FUNCTION__, newev->fd);
      ares__htable_asvp_remove(e->ev_handles, newev->fd);
      ares_free(newev);
      continue;
    }

    /* Modify request -- only flags cn be changed */
printf("%s(): modified fd %d\n", __FUNCTION__, newev->fd);
    e->ev_sys->event_mod(e, oldev, newev->flags);
    oldev->flags = newev->flags;
    ares_free(newev);
  }
}

static void *ares_event_thread(void *arg)
{
  ares_event_thread_t *e = arg;
printf("%s(): enter\n", __FUNCTION__);
  ares__thread_mutex_lock(e->mutex);

  while (e->isup) {
    struct timeval  tv;
    struct timeval *tvout;
    unsigned long   timeout_ms = 0; /* 0 = unlimited */
    size_t          num_events;

    tvout = ares_timeout(e->channel, NULL, &tv);
    if (tvout != NULL) {
      timeout_ms = (unsigned long)(tvout->tv_sec * 1000) + (tvout->tv_usec / 1000) + 1;
    }

    ares_event_process_updates(e);

    /* Don't hold a mutex while waiting on events */
    ares__thread_mutex_unlock(e->mutex);
printf("%s(): wait %lums\n", __FUNCTION__, timeout_ms);
    num_events = e->ev_sys->wait(e, timeout_ms);
    if (num_events == 0) {
printf("%s(): timeout\n", __FUNCTION__);
      /* Each iteration should do timeout checking even if nothing was triggered */
      ares_process_fd(e->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    } else {
printf("%s(): %zu events\n", __FUNCTION__, num_events);
    }

    ares__thread_mutex_lock(e->mutex);
  }

  ares__thread_mutex_unlock(e->mutex);
printf("%s(): exit\n", __FUNCTION__);
  return NULL;
}


static void ares_event_thread_destroy_int(ares_event_thread_t *e)
{
printf("%s(): enter\n", __FUNCTION__);
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
printf("%s(): exit\n", __FUNCTION__);
}

void ares_event_thread_destroy(ares_channel_t *channel)
{
  ares_event_thread_t *e = channel->sock_state_cb_data;

  if (e == NULL)
    return;

  ares_event_thread_destroy_int(e);
}


ares_status_t ares_event_thread_init(ares_channel_t *channel)
{
  ares_event_thread_t *e;

printf("%s(): enter\n", __FUNCTION__);

  e = ares_malloc_zero(sizeof(*e));
  if (e == NULL) {
    return ARES_ENOMEM;
  }

  e->mutex = ares__thread_mutex_create();
  if (e->mutex == NULL) {
    ares_event_thread_destroy_int(e);
    return ARES_ENOMEM;
  }

  e->ev_updates = ares__llist_create(NULL);
  if (e->ev_updates == NULL) {
    ares_event_thread_destroy_int(e);
    return ARES_ENOMEM;
  }

  e->ev_handles = ares__htable_asvp_create(ares_event_destroy_cb);
  if (e->ev_handles == NULL) {
    ares_event_thread_destroy_int(e);
    return ARES_ENOMEM;
  }

  e->channel                  = channel;
  e->isup                     = ARES_TRUE;
#if defined(HAVE_KQUEUE)
  e->ev_sys                   = &ares_evsys_kqueue;
#elif defined(HAVE_POLL)
  e->ev_sys                   = &ares_evsys_poll;
#endif
  channel->sock_state_cb      = ares_event_thread_sockstate_cb;
  channel->sock_state_cb_data = e;

  if (!e->ev_sys->init(e)) {
    ares_event_thread_destroy_int(e);
    channel->sock_state_cb      = NULL;
    channel->sock_state_cb_data = NULL;
    return ARES_ESERVFAIL;
  }

  if (ares__thread_create(&e->thread, ares_event_thread, e) != ARES_SUCCESS) {
    ares_event_thread_destroy_int(e);
    channel->sock_state_cb      = NULL;
    channel->sock_state_cb_data = NULL;
    return ARES_ESERVFAIL;
  }


printf("%s(): success\n", __FUNCTION__);
  return ARES_SUCCESS;
}
