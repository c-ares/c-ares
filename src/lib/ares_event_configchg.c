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

static void ares_event_configchg_reload(ares_channel_t *channel)
{
  /* XXX: dispatch via thread so we don't block events */
  ares_reinit(channel);
}

#ifdef __LINUX__
#  include <sys/inotify.h>
struct ares_event_configchg {
  int           inotify_fd;
  ares_event_t *event;
};

void ares_event_configchg_destroy(ares_event_configchg_t *configchg, , ares_event_thread *e)
{
  if (configchg == NULL || configchg->inotify_fd == -1) {
    return;
  }
  ares_event_update(NULL, e, ARES_EVENT_FLAG_NONE, NULL, configchg->inotify_fd, NULL, NULL);
}

static void ares_event_configchg_free(void *data)
{
  ares_event_configchg_t *configchg = data;
  if (configchg == NULL)
    return;

  if (configchg->inotify_fd >= 0) {
    close(configchg->inotify_fd);
    configchg->inotify_fd = -1;
  }

  ares_free(configchg);
}

void ares_event_configchg_cb(ares_event_thread_t *e, ares_socket_t fd,
                             void *data, ares_event_flags_t flags)
{
  ares_event_configchg_t *configchg = data;
  /* Some systems cannot read integer variables if they are not
     properly aligned. On other systems, incorrect alignment may
     decrease performance. Hence, the buffer used for reading from
     the inotify file descriptor should have the same alignment as
     struct inotify_event. */
  char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
  const struct inotify_event *event;
  ssize_t len;
  ares_bool_t triggered = ARES_FALSE;

  while (1) {
    const char *ptr;

    len = read(fd, buf, sizeof(buf));
    if (len <= 0) {
      break;
    }

    /* Loop over all events in the buffer. */
    for (ptr = buf; ptr < buf + len;
         ptr += sizeof(struct inotify_event) + event->len) {

      event = (const struct inotify_event *)ptr;

      if (event->name == NULL)
        continue;

      if (strcasecmp(name, "resolv.conf") == 0 ||
          strcasecmp(name, "nsswitch.conf") == 0) {
        triggered = ARES_TRUE;
      }
    }
  }
  if (triggered) {
    ares_event_configchg_reload(e->channel);
  }
}


ares_status_t ares_event_configchg_init(ares_event_configchg_t **configchg, ares_event_thread *e)
{
  ares_status_t status = ARES_SUCCESS;

  *configchg = ares_malloc_zero(sizeof(**configchg));
  if (*configchg == NULL) {
    return ARES_ENOMEM;
  }

  *configchg->inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
  if (*configchg->inotify_fd == -1) {
    status = ARES_ESERVFAIL;
    goto done;
  }


  /* We need to monitor /etc/resolv.conf, /etc/nsswitch.conf */
  if (inotify_add_watch(*configchg->inotify_fd, "/etc", IN_CREATE|IN_MODIFY|IN_MOVED_TO|IN_ONLYDIR) == -1) {
    status = ARES_ESERVFAIL;
    goto done;
  }

  status = ares_event_update(&(*configchg)->event, e, ARES_EVENT_FLAG_READ,
                             cb, *configchg->inotify_fd,
                             ares_event_configchg_free, NULL);

done:
  if (status != ARES_SUCCESS) {
    ares_event_configchg_destroy(*configchg);
    *configchg = NULL;
  }
  return status;
}




#elif defined(_WIN32)

#elif defined(__APPLE__)

#else

#endif
