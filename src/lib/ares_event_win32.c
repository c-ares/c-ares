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

/* Uses an anonymous union */
#if defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wc11-extensions"
#endif

#include "ares_private.h"
#include "ares_event.h"
#include "ares_event_win32.h"
#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#if defined(USE_WINSOCK)

/* IMPLEMENTATION NOTES
 * ====================
 *
 * This implementation uses some undocumented functionality within Windows for
 * monitoring sockets. The Ancillary Function Driver (AFD) is the low level
 * implementation that Winsock2 sits on top of.  Winsock2 unfortunately does
 * not expose the equivalent of epoll() or kqueue(), but it is possible to
 * access AFD directly and use along with IOCP to simulate the functionality.
 * We want to use IOCP if possible as it gives us the ability to monitor more
 * than just sockets (WSAPoll is not an option), and perform arbitrary callbacks
 * which means we can hook in non-socket related events.
 *
 * The information for this implementation was gathered from "wepoll" and
 * "libuv" which both use slight variants on this, but this implementation
 * doesn't directly follow either methodology.
 *
 * Initialization:
 *   1. Dynamically load the NtDeviceIoControlFile internal symbol from
 *      ntdll.dll.  This function is used to submit the AFD POLL request.
 *   2. Create an IO Completion Port base handle via CreateIoCompletionPort()
 *      that all socket events will be delivered through.
 *   3. Create a callback to be used to be able to interrupt waiting for IOCP
 *      events, this may be called for allowing enqueuing of additional socket
 *      events or removing socket events. PostQueuedCompletionStatus() is the
 *      obvious choice.  We can use the same container format, the event
 *      delivered won't have an OVERLAPPED pointer so we can differentiate.
 *
 * Socket Add:
 *   1. Create/Allocate a container for holding metadata about a socket:
 *      - SOCKET base_socket;
 *      - SOCKET peer_socket;
 *      - OVERLAPPED overlapped; -- Used by AFD POLL
 *      - AFD_POLL_INFO afd_poll_info; -- Used by AFD POLL
 *   2. Call WSAIoctl(..., SIO_BASE_HANDLE, ...) to unwrap the SOCKET and get
 *      the "base socket" we can use for polling.  It appears this may fail so
 *      we should call WSAIoctl(..., SIO_BSP_HANDLE_POLL, ...) as a fallback.
 *   3. The SOCKET handle we have is most likely not capable of supporting
 *      OVERLAPPED, and we need to have a way to unbind a socket from IOCP
 *      (which is done via a simple closesocket()) so we need to duplicate the
 *      "base socket" using WSADuplicateSocketW() followed by
 *      WSASocketW(..., WSA_FLAG_OVERLAPPED) to create this "peer socket" for
 *      submitting AFD POLL requests.
 *   4. Bind to IOCP using CreateIoCompletionPort() referencing the "peer
 *      socket" and the base IOCP handle from "Initialization".  Use the
 *      "peer socket" as the "CompletionKey" which will be returned when an
 *      event occurs.
 *   5. Submit AFD POLL request (see "AFD POLL Request" section)
 *   6. Record a mapping between the "peer socket" and the socket container.
 *   NOTE: We use the "peer socket" as the completion key due to observation of
 *         events being delivered for sockets that have already been closed. If
 *         we used the container, we'd be referencing free'd memory if this
 *         occurs.
 *
 * Socket Delete:
 *   1. Call
 *      NtCancelIoFileEx((HANDLE)peer_socket, iosb, &temp_iosb);
 *      to cancel any pending operations.
 *   2. Call closesocket(peer_socket) to close the socket
 *   3. remove the mapping between the peer_socket and the container.
 *   4. free() the container
 *   NOTE: We have to use the container mapping due to stale events being
 *         delivered.
 *
 * Socket Modify:
 *   1. Submit AFD POLL request (see "AFD POLL Request" section), it will
 *      automatically cancel any prior poll request so there's no reason to
 *      call an explicit cancel.
 *
 * Event Wait:
 *   1. Call GetQueuedCompletionStatusEx() with the base IOCP handle, a
 *      stack allocated array of OVERLAPPED_ENTRY's, and an appropriate
 *      timeout.
 *   2. Iterate across returned events, if the lpOverlapped is NULL, then the
 *      the CompletionKey is a pointer to the container registered via
 *      PostQueuedCompletionStatus(), otherwise it is the "peer socket"
 *      registered with CreateIoCompletionPort() which needs to be dereferenced
 *      to the "socket container".
 *      NOTE: the dereference may fail if the connection was already cleaned up!
 *   4. If it is a "socket container" Submit AFD POLL Request
 *      (see "AFD POLL Request"). We must re-enable the request each time we
 *      receive a response, it is not persistent.
 *   5. Notify of any events received as indicated in the AFD_POLL_INFO
 *      Handles[0].Events (NOTE: check NumberOfHandles first, make sure it is
 *      > 0, otherwise we might not have events such as if our last request
 *      was cancelled).  Also need to check the IO_STATUS_BUFFER status member
 *      is STATUS_SUCCESS as otherwise it may simply advertise back to you the
 *      requested events.  This can happen during an automatic cancel such as
 *      when we are modifying the conditions we want to wait on.
 *
 * AFD Poll Request:
 *   1. Initialize the AFD_POLL_INFO structure:
 *      Exclusive         = TRUE; // Auto cancel duplicates for same socket
 *      NumberOfHandles   = 1;
 *      Timeout.QuadPart  = LLONG_MAX;
 *      Handles[0].Handle = (HANDLE)base_socket;
 *      Handles[0].Status = 0;
 *      Handles[0].Events = ... set as appropriate AFD_POLL_RECEIVE, etc;
 *   2. Zero out the OVERLAPPED and IO_STATUS_BLOCK structures
 *   3. Set the "Status" member of IO_STATUS_BLOCK to STATUS_PENDING
 *   4. Call
 *      NtDeviceIoControlFile((HANDLE)peer_socket, NULL, NULL, &overlapped,
 *                            &iosb, IOCTL_AFD_POLL
 *                            &afd_poll_info, sizeof(afd_poll_info),
 *                            &afd_poll_info, sizeof(afd_poll_info));
 *   NOTE: libuv used the memory starting at overlapped.Internal for the
 *         AFD_POLL_INFO pointer, no idea why.  Via testing we know its not
 *         needed.  That said the data in the OVERLAPPED structure seems
 *         meaningless so maybe they were just trying to align it to be
 *         meaningful.
 *
 *
 * References:
 *   - https://github.com/piscisaureus/wepoll/
 *   - https://github.com/libuv/libuv/
 */

#  include <stdarg.h>

#  define CARES_DEBUG 1

static void CARES_DEBUG_LOG(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
#  ifdef CARES_DEBUG
  vfprintf(stderr, fmt, ap);
  fflush(stderr);
#  endif
  va_end(ap);
}

typedef struct {
  /* Dynamically loaded symbols */
  NtDeviceIoControlFile_t NtDeviceIoControlFile;
  NtCancelIoFileEx_t      NtCancelIoFileEx;

  /* Implementation details */
  HANDLE                  iocp_handle;

  /* peer_socket -> ares_evsys_win32_eventdata_t * mapping for safe lookups
   * of events.  We can't just pass the data structure for event notifications
   * due to stale events being delivered thus causing use-after-free.
   * Also we can't use the existing socket mapping because if there is fast
   * recycling of ids, we may not detect that, but due to the way the
   * peer_socket is delayed being destroyed until the event thread can handle
   * it, the likelihood it will cycle too quickly is very small. */
  ares__htable_asvp_t    *peer_socket_handles;
} ares_evsys_win32_t;

typedef struct {
  /*! Pointer to parent event container */
  ares_event_t *event;
  /*! Socket passed in to monitor */
  SOCKET        socket;
  /*! Base socket derived from provided socket */
  SOCKET        base_socket;
  /*! New socket (duplicate base_socket handle) supporting OVERLAPPED operation
   */
  SOCKET        peer_socket;
  /*! Structure for submitting AFD POLL requests (Internals!) */
  AFD_POLL_INFO afd_poll_info;
  /*! Overlapped structure submitted with AFD POLL requests and returned with
   * IOCP results */
  OVERLAPPED    overlapped;
} ares_evsys_win32_eventdata_t;

static void ares_iocpevent_signal(const ares_event_t *event)
{
  ares_event_thread_t *e  = event->e;
  ares_evsys_win32_t  *ew = e->ev_sys_data;

  if (e == NULL) {
    return;
  }

  PostQueuedCompletionStatus(ew->iocp_handle, 0, (ULONG_PTR)event->data, NULL);
}

static void ares_iocpevent_cb(ares_event_thread_t *e, ares_socket_t fd,
                              void *data, ares_event_flags_t flags)
{
  (void)e;
  (void)data;
  (void)fd;
  (void)flags;
}

static ares_event_t *ares_iocpevent_create(ares_event_thread_t *e)
{
  ares_event_t *event = NULL;
  ares_status_t status;

  status =
    ares_event_update(&event, e, ARES_EVENT_FLAG_OTHER, ares_iocpevent_cb,
                      ARES_SOCKET_BAD, NULL, NULL, ares_iocpevent_signal);
  if (status != ARES_SUCCESS) {
    return NULL;
  }

  return event;
}

static void ares_evsys_win32_destroy(ares_event_thread_t *e)
{
  ares_evsys_win32_t *ew = NULL;

  if (e == NULL) {
    return;
  }

  CARES_DEBUG_LOG("** Win32 Event Destroy\n");

  ew = e->ev_sys_data;
  if (ew == NULL) {
    return;
  }

  if (ew->iocp_handle != NULL) {
    CloseHandle(ew->iocp_handle);
  }

  ares__htable_asvp_destroy(ew->peer_socket_handles);

  ares_free(ew);
  e->ev_sys_data = NULL;
}

static ares_bool_t ares_evsys_win32_init(ares_event_thread_t *e)
{
  ares_evsys_win32_t *ew = NULL;
  HMODULE             ntdll;

  CARES_DEBUG_LOG("** Win32 Event Init\n");

  ew = ares_malloc_zero(sizeof(*ew));
  if (ew == NULL) {
    return ARES_FALSE;
  }

  e->ev_sys_data = ew;

  /* All apps should have ntdll.dll already loaded, so just get a handle to
   * this */
  ntdll = GetModuleHandleA("ntdll.dll");
  if (ntdll == NULL) {
    goto fail;
  }

#  ifdef __GNUC__
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wpedantic"
/* Without the (void *) cast we get:
 *  warning: cast between incompatible function types from 'FARPROC' {aka 'long
 * long int (*)()'} to 'NTSTATUS (*)(...)'} [-Wcast-function-type] but with it
 * we get: warning: ISO C forbids conversion of function pointer to object
 * pointer type [-Wpedantic] look unsolvable short of killing the warning.
 */
#  endif


  /* Load Internal symbols not typically accessible */
  ew->NtDeviceIoControlFile = (NtDeviceIoControlFile_t)(void *)GetProcAddress(
    ntdll, "NtDeviceIoControlFile");
  ew->NtCancelIoFileEx =
    (NtCancelIoFileEx_t)(void *)GetProcAddress(ntdll, "NtCancelIoFileEx");

#  ifdef __GNUC__
#    pragma GCC diagnostic pop
#  endif

  if (ew->NtCancelIoFileEx == NULL || ew->NtDeviceIoControlFile == NULL) {
    goto fail;
  }

  ew->iocp_handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  if (ew->iocp_handle == NULL) {
    goto fail;
  }

  e->ev_signal = ares_iocpevent_create(e);
  if (e->ev_signal == NULL) {
    goto fail;
  }

  ew->peer_socket_handles = ares__htable_asvp_create(NULL);
  if (ew->peer_socket_handles == NULL) {
    goto fail;
  }

  return ARES_TRUE;

fail:
  ares_evsys_win32_destroy(e);
  return ARES_FALSE;
}

static ares_socket_t ares_evsys_win32_basesocket(ares_socket_t socket)
{
  while (1) {
    DWORD         bytes; /* Not used */
    ares_socket_t base_socket = ARES_SOCKET_BAD;
    int           rv;

    rv = WSAIoctl(socket, SIO_BASE_HANDLE, NULL, 0, &base_socket,
                  sizeof(base_socket), &bytes, NULL, NULL);
    if (rv != SOCKET_ERROR && base_socket != ARES_SOCKET_BAD) {
      socket = base_socket;
      break;
    }

    /* If we're here, an error occurred */
    if (GetLastError() == WSAENOTSOCK) {
      /* This is critical, exit */
      return ARES_SOCKET_BAD;
    }

    /* Work around known bug in Komodia based LSPs, use ARES_BSP_HANDLE_POLL
     * to retrieve the underlying socket to then loop and get the base socket:
     *  https://docs.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls
     *  https://www.komodia.com/newwiki/index.php?title=Komodia%27s_Redirector_bug_fixes#Version_2.2.2.6
     */
    base_socket = ARES_SOCKET_BAD;
    rv          = WSAIoctl(socket, SIO_BSP_HANDLE_POLL, NULL, 0, &base_socket,
                           sizeof(base_socket), &bytes, NULL, NULL);

    if (rv != SOCKET_ERROR && base_socket != ARES_SOCKET_BAD &&
        base_socket != socket) {
      socket = base_socket;
      continue; /* loop! */
    }

    return ARES_SOCKET_BAD;
  }

  return socket;
}

static ares_bool_t ares_evsys_win32_afd_enqueue(ares_event_t      *event,
                                                ares_event_flags_t flags)
{
  ares_event_thread_t          *e  = event->e;
  ares_evsys_win32_t           *ew = e->ev_sys_data;
  ares_evsys_win32_eventdata_t *ed = event->data;
  NTSTATUS                      status;
  IO_STATUS_BLOCK              *iosb_ptr;

  if (e == NULL || ed == NULL || ew == NULL) {
    return ARES_FALSE;
  }

  /* Enqueue AFD Poll */
  ed->afd_poll_info.Exclusive         = TRUE;
  ed->afd_poll_info.NumberOfHandles   = 1;
  ed->afd_poll_info.Timeout.QuadPart  = LLONG_MAX;
  ed->afd_poll_info.Handles[0].Handle = (HANDLE)ed->base_socket;
  ed->afd_poll_info.Handles[0].Status = 0;
  ed->afd_poll_info.Handles[0].Events = AFD_POLL_LOCAL_CLOSE;

  if (flags & ARES_EVENT_FLAG_READ) {
    ed->afd_poll_info.Handles[0].Events |=
      (AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT | AFD_POLL_ACCEPT |
       AFD_POLL_ABORT);
  }
  if (flags & ARES_EVENT_FLAG_WRITE) {
    ed->afd_poll_info.Handles[0].Events |=
      (AFD_POLL_SEND | AFD_POLL_CONNECT_FAIL);
  }
  if (flags == 0) {
    ed->afd_poll_info.Handles[0].Events |= AFD_POLL_DISCONNECT;
  }

  memset(&ed->overlapped, 0, sizeof(ed->overlapped));
  /* Mapping the IO_STATUS_BLOCK pointer to the first member in the
   * OVERLAPPED structure is something that libuv does. This sort of
   * tracks since the Status member for the IO_STATUS_BLOCK is the
   * first member and the "Internal" member for OVERLAPPED has a meaning
   * of status.  The OVERLAPPED structure appears to be otherwise unused when
   * testing using independent structures. I'm not actually sure if using this
   * provides any real benefits other than memory efficiency but maybe there
   * is some internal edge case they know about. */
  iosb_ptr         = (IO_STATUS_BLOCK *)&ed->overlapped.Internal;
  iosb_ptr->Status = STATUS_PENDING;

  status = ew->NtDeviceIoControlFile(
    (HANDLE)ed->peer_socket, NULL, NULL, &ed->overlapped, iosb_ptr,
    IOCTL_AFD_POLL, &ed->afd_poll_info, sizeof(ed->afd_poll_info),
    &ed->afd_poll_info, sizeof(ed->afd_poll_info));
  if (status != STATUS_SUCCESS && status != STATUS_PENDING) {
    return ARES_FALSE;
  }
  CARES_DEBUG_LOG("++ afd_enqueue ed=%p flags=%X\n", (void *)ed,
                  (unsigned int)flags);
  return ARES_TRUE;
}

static ares_bool_t ares_evsys_win32_afd_cancel(ares_evsys_win32_eventdata_t *ed)
{
  IO_STATUS_BLOCK    *iosb_ptr;
  IO_STATUS_BLOCK     cancel_iosb;
  ares_evsys_win32_t *ew;
  NTSTATUS            status;

  ew = ed->event->e->ev_sys_data;

  /* See discussion in ares_evsys_win32_afd_enqueue() */
  iosb_ptr = (IO_STATUS_BLOCK *)&ed->overlapped.Internal;

  /* Not pending, nothing to do. Most likely that means there is a pending
   * event that hasn't yet been delivered otherwise it would be re-armed
   * already */
  if (iosb_ptr->Status != STATUS_PENDING) {
CARES_DEBUG_LOG("** cancel not needed for ed=%p\n", (void *)ed);
    return ARES_FALSE;
  }

  status =
    ew->NtCancelIoFileEx((HANDLE)ed->peer_socket, iosb_ptr, &cancel_iosb);

CARES_DEBUG_LOG("** Enqueued cancel for ed=%p, status = %lX\n", (void *)ed, status);

  /* NtCancelIoFileEx() may return STATUS_NOT_FOUND if the operation completed
   * just before calling NtCancelIoFileEx(), but we have not yet received the
   * notifiction (but it should be queued for the next IOCP event).  */
  if (status == STATUS_SUCCESS || status == STATUS_NOT_FOUND) {
    return ARES_TRUE;
  }

  return ARES_FALSE;
}

static void ares_evsys_win32_eventdata_destroy(ares_evsys_win32_t           *ew,
                                               ares_evsys_win32_eventdata_t *ed)
{
  if (ew == NULL || ed == NULL) {
    return;
  }
  CARES_DEBUG_LOG("-- deleting ed=%p (%s)\n", (void *)ed,
    (ed->peer_socket == ARES_SOCKET_BAD)?"data":"socket");
  /* These type of handles are deferred destroy. Update tracking. */
  if (ed->peer_socket != ARES_SOCKET_BAD) {
    ares__htable_asvp_remove(ew->peer_socket_handles, ed->peer_socket);
    closesocket(ed->peer_socket);
  }

  ares_free(ed);
}

static ares_bool_t ares_evsys_win32_event_add(ares_event_t *event)
{
  ares_event_thread_t          *e  = event->e;
  ares_evsys_win32_t           *ew = e->ev_sys_data;
  ares_evsys_win32_eventdata_t *ed;
  WSAPROTOCOL_INFOW             protocol_info;
  ares_bool_t                   rc = ARES_FALSE;

  ed              = ares_malloc_zero(sizeof(*ed));
  ed->event       = event;
  ed->socket      = event->fd;
  ed->base_socket = ARES_SOCKET_BAD;
  ed->peer_socket = ARES_SOCKET_BAD;
  event->data     = ed;

  CARES_DEBUG_LOG("++ add ed=%p (%s) flags=%X\n", (void *)ed,
                  (ed->socket == ARES_SOCKET_BAD) ? "data" : "socket",
                  (unsigned int)event->flags);

  /* Likely a signal event, not something we will directly handle.  We create
   * the ares_evsys_win32_eventdata_t as the placeholder to use as the
   * IOCP Completion Key */
  if (ed->socket == ARES_SOCKET_BAD) {
    rc = ARES_TRUE;
    goto done;
  }

  ed->base_socket = ares_evsys_win32_basesocket(ed->socket);
  if (ed->base_socket == ARES_SOCKET_BAD) {
    goto done;
  }

  /* Create a peer socket that supports OVERLAPPED so we can use IOCP on the
   * socket handle */
  if (WSADuplicateSocketW(ed->base_socket, GetCurrentProcessId(),
                          &protocol_info) != 0) {
    goto done;
  }

  ed->peer_socket =
    WSASocketW(protocol_info.iAddressFamily, protocol_info.iSocketType,
               protocol_info.iProtocol, &protocol_info, 0, WSA_FLAG_OVERLAPPED);
  if (ed->peer_socket == ARES_SOCKET_BAD) {
    goto done;
  }

  SetHandleInformation((HANDLE)ed->peer_socket, HANDLE_FLAG_INHERIT, 0);

/*
  SetFileCompletionNotificationModes((HANDLE)ed->peer_socket,
                                     FILE_SKIP_SET_EVENT_ON_HANDLE);
*/

  if (CreateIoCompletionPort((HANDLE)ed->peer_socket, ew->iocp_handle,
                             (ULONG_PTR)ed->peer_socket, 0) == NULL) {
    goto done;
  }


  if (!ares__htable_asvp_insert(ew->peer_socket_handles, ed->peer_socket, ed)) {
    goto done;
  }

  if (!ares_evsys_win32_afd_enqueue(event, event->flags)) {
    goto done;
  }

  rc = ARES_TRUE;

done:
  if (!rc) {
    ares_evsys_win32_eventdata_destroy(ew, ed);
    event->data = NULL;
  }
  return rc;
}

static void ares_evsys_win32_event_del(ares_event_t *event)
{
  ares_evsys_win32_eventdata_t *ed = event->data;

  CARES_DEBUG_LOG("-- DELETE called on ed=%p\n", ed);

  /*
   * Cancel pending AFD Poll operation.  Not sure this is absolutely necessary.
   */
  if (ed && ed->peer_socket != ARES_SOCKET_BAD) {
    ares_evsys_win32_afd_cancel(ed);
  }

  ares_evsys_win32_eventdata_destroy(event->e->ev_sys_data, ed);

  event->data = NULL;
}

static void ares_evsys_win32_event_mod(ares_event_t      *event,
                                       ares_event_flags_t new_flags)
{
  ares_evsys_win32_eventdata_t *ed = event->data;

  /* Not for us */
  if (event->fd == ARES_SOCKET_BAD || ed == NULL) {
    return;
  }

  CARES_DEBUG_LOG("** mod ed=%p new_flags=%X\n", (void *)ed,
                  (unsigned int)new_flags);

  /* All we need to do is cancel the pending operation.  When the event gets
   * delivered for the cancellation, it will automatically re-enqueue a new
   * event */
  ares_evsys_win32_afd_cancel(ed);
}

static size_t ares_evsys_win32_wait(ares_event_thread_t *e,
                                    unsigned long        timeout_ms)
{
  ares_evsys_win32_t *ew = e->ev_sys_data;
  OVERLAPPED_ENTRY    entries[16];
  ULONG               maxentries = sizeof(entries) / sizeof(*entries);
  ULONG               nentries;
  BOOL                status;
  size_t              i;
  size_t              cnt  = 0;
  DWORD               tout = (timeout_ms == 0) ? INFINITE : (DWORD)timeout_ms;

  CARES_DEBUG_LOG("** Wait Enter\n");
  /* Process in a loop for as long as it fills the entire entries buffer, and
   * on subsequent attempts, ensure the timeout is 0 */
  do {
    nentries = maxentries;
    status   = GetQueuedCompletionStatusEx(ew->iocp_handle, entries, nentries,
                                           &nentries, tout, FALSE);

    /* Next loop around, we want to return instantly if there are no events to
     * be processed */
    tout = 0;

    if (!status) {
      break;
    }

    CARES_DEBUG_LOG("\t** GetQueuedCompletionStatusEx returned %zu entries\n",
                    (size_t)nentries);
    for (i = 0; i < (size_t)nentries; i++) {
      ares_event_flags_t            flags = 0;
      ares_evsys_win32_eventdata_t *ed    = NULL;
      ares_event_t                 *event = NULL;

      /* We have to dereference the data structure from peer_socket because we
       * have seen events delivered for closed connections.  We determine socket
       * vs non-socket (triggered via PostQueuedCompletionStatus) by the
       * existence of entries[i].lpOverlapped. */
      if (entries[i].lpOverlapped != NULL) {
        ed = ares__htable_asvp_get_direct(
          ew->peer_socket_handles, (ares_socket_t)entries[i].lpCompletionKey);

        /* If memory address for overlapped structure doesn't match expected,
         * that means the peer socket id was reused and this event is for the
         * old peer socket using the same id.  Discard */
        if (&ed->overlapped != entries[i].lpOverlapped) {
          ed = NULL;
        }
      } else {
        /* non-socket */
        ed = (ares_evsys_win32_eventdata_t *)entries[i].lpCompletionKey;
      }

      /* Must be a deleted handle, lets skip */
      if (ed == NULL) {
        CARES_DEBUG_LOG("\t\t** i=%zu, skip deleted handle\n", i);
        continue;
      }
      event = ed->event;

      CARES_DEBUG_LOG("\t\t** i=%zu, ed=%p, overlapped=%p (%s)\n", i,
                      (void *)ed, (void *)entries[i].lpOverlapped,
                      (ed->socket == ARES_SOCKET_BAD) ? "data" : "socket");
      if (ed->socket == ARES_SOCKET_BAD) {
        /* Some sort of signal event */
        flags = ARES_EVENT_FLAG_OTHER;
      } else {
        IO_STATUS_BLOCK *iosb_ptr = (IO_STATUS_BLOCK *)&ed->overlapped.Internal;

        /* Process events */
        if (iosb_ptr->Status == STATUS_SUCCESS &&
            ed->afd_poll_info.NumberOfHandles > 0) {
          if (ed->afd_poll_info.Handles[0].Events &
              (AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT | AFD_POLL_ACCEPT |
               AFD_POLL_ABORT)) {
            flags |= ARES_EVENT_FLAG_READ;
          }
          if (ed->afd_poll_info.Handles[0].Events &
              (AFD_POLL_SEND | AFD_POLL_CONNECT_FAIL)) {
            flags |= ARES_EVENT_FLAG_WRITE;
          }
          if (ed->afd_poll_info.Handles[0].Events & AFD_POLL_LOCAL_CLOSE) {
            CARES_DEBUG_LOG("\n\n*-*-*-*-*-\nLOCAL CLOSE on ed=%p\n*-*-*-*-*-\n\n", ed);
          }
          /* Mask flags against current desired flags.  We could have an event
           * queued that is outdated. */
          flags &= event->flags;
        }
        CARES_DEBUG_LOG("\t\t** ed=%p, iosb status=%lX, flags=%X\n",
                        (void *)ed, (void *)event,
                        (unsigned long)iosb_ptr->Status, (unsigned int)flags);


        /* Re-enqueue so we can get more events on the socket, we either
         * received a real event, or a cancellation notice.  Both cases we
         * re-queue. */
        ares_evsys_win32_afd_enqueue(event, event->flags);
      }

      if (flags != 0) {
        cnt++;
        event->cb(e, event->fd, event->data, flags);
      }
    }
  } while (nentries == maxentries);

  CARES_DEBUG_LOG("** Wait Exit\n");

  return cnt;
}

const ares_event_sys_t ares_evsys_win32 = { "win32",
                                            ares_evsys_win32_init,
                                            ares_evsys_win32_destroy,
                                            ares_evsys_win32_event_add,
                                            ares_evsys_win32_event_del,
                                            ares_evsys_win32_event_mod,
                                            ares_evsys_win32_wait };
#endif

#if defined(__clang__)
#  pragma GCC diagnostic pop
#endif
