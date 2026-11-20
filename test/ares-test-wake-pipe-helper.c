#include "ares_private.h"
#include "event/ares_event.h"

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif
#include <errno.h>

int ares_test_wake_pipe(int failure);

#if defined(HAVE_PIPE) && defined(CARES_THREADS) && defined(O_NONBLOCK) && \
  defined(FD_CLOEXEC) && defined(O_APPEND)
#  undef pipe
#  undef fcntl
#  undef close

static int fds[2] = { -1, -1 };
static int closes[2];
static int calls;
static int fail_at = -1;
static int registrations;
static int invalid_close;

static int mock_pipe(int newfds[2])
{
  int flags;
  int i;

  if (pipe(newfds) < 0) {
    return -1;
  }
  for (i = 0; i < 2; i++) {
    flags = fcntl(newfds[i], F_GETFL);
    if (flags < 0) {
      close(newfds[0]);
      close(newfds[1]);
      return -1;
    }
    if (fcntl(newfds[i], F_SETFL, flags | O_APPEND) < 0) {
      close(newfds[0]);
      close(newfds[1]);
      return -1;
    }
  }
  fds[0] = newfds[0];
  fds[1] = newfds[1];
  return 0;
}

static int mock_fcntl(int fd, int cmd, long arg)
{
  int idx;

  if (cmd == F_GETFL || cmd == F_SETFL || cmd == F_SETFD) {
    idx = calls++;
    if (idx == fail_at) {
      errno = EIO;
      return -1;
    }
  }
  return fcntl(fd, cmd, arg);
}

static int mock_close(int fd)
{
  if (fd == fds[0]) {
    closes[0]++;
  } else if (fd == fds[1]) {
    closes[1]++;
  } else {
    invalid_close++;
  }
  return close(fd);
}

static ares_event_t event;

static ares_status_t mock_update(ares_event_t **out, ares_event_thread_t *e,
                                 ares_event_flags_t flags, ares_event_cb_t cb,
                                 ares_socket_t fd, void *data,
                                 ares_event_free_data_t freecb,
                                 ares_event_signal_cb_t signalcb)
{
  (void)e;
  (void)flags;
  (void)cb;
  (void)fd;
  (void)signalcb;
  event.data         = data;
  event.free_data_cb = freecb;
  *out               = &event;
  registrations++;
  return ARES_SUCCESS;
}

#  undef HAVE_PIPE2
#  define pipe                  mock_pipe
#  define fcntl                 mock_fcntl
#  define close                 mock_close
#  define ares_event_update     mock_update
#  define ares_pipeevent_create test_create
#  include "../src/lib/event/ares_event_wake_pipe.c"
#  undef pipe
#  undef fcntl
#  undef close
#  undef ares_event_update
#  undef ares_pipeevent_create

int ares_test_wake_pipe(int failure)
{
  ares_event_t *e;
  unsigned int  err = 0;
  int           i;
  int           flags;
  int           fdflags;

  if (failure < -1 || failure > 5) {
    return -1;
  }

  fds[0]             = -1;
  fds[1]             = -1;
  closes[0]          = 0;
  closes[1]          = 0;
  calls              = 0;
  fail_at            = failure;
  registrations      = 0;
  invalid_close      = 0;
  event.data         = NULL;
  event.free_data_cb = NULL;

  e = test_create(NULL);

  if (failure == -1) {
    if (e == NULL) {
      err |= 1u << 0;
    }
    if (registrations != 1) {
      err |= 1u << 2;
    }
    if (calls != 6) {
      err |= 1u << 3;
    }
    if (closes[0] != 0 || closes[1] != 0) {
      err |= 1u << 10;
    }
    if (e != NULL) {
      for (i = 0; i < 2; i++) {
        flags = fcntl(fds[i], F_GETFL);
        if (flags < 0 || (flags & O_NONBLOCK) == 0) {
          err |= 1u << (4 + i);
        }
        if (flags >= 0 && (flags & O_APPEND) == 0) {
          err |= 1u << (6 + i);
        }
        fdflags = fcntl(fds[i], F_GETFD);
        if (fdflags < 0 || (fdflags & FD_CLOEXEC) == 0) {
          err |= 1u << (8 + i);
        }
      }
    }
  } else {
    if (e != NULL) {
      err |= 1u << 1;
    }
    if (registrations != 0) {
      err |= 1u << 2;
    }
    if (calls != failure + 1) {
      err |= 1u << 3;
    }
    for (i = 0; i < 2; i++) {
      errno   = 0;
      fdflags = fcntl(fds[i], F_GETFD);
      if (fdflags != -1 || errno != EBADF) {
        err |= 1u << (13 + i);
      }
    }
  }

  if (e != NULL && e->free_data_cb != NULL) {
    e->free_data_cb(e->data);
  }

  for (i = 0; i < 2; i++) {
    if (closes[i] != 1) {
      err |= 1u << (11 + i);
    }
  }

  if (invalid_close != 0) {
    err |= 1u << 15;
  }
  return (int)err;
}
#else
int ares_test_wake_pipe(int failure)
{
  (void)failure;
  return -2;
}
#endif
