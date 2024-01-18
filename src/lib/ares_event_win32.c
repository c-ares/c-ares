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

/* NOTE: This is heavily influenced by:
 *       https://github.com/piscisaureus/wepoll/
 */

#include "ares_setup.h"
#include "ares.h"
#include "ares_private.h"
#include "ares_event.h"
#ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#  include <ws2tcpip.h>
#endif
#ifdef HAVE_WINDOWS_H
#  include <windows.h>
#endif

#ifdef _WIN32

typedef struct {
  /* Dynamically loaded symbols */
  HMODULE ntdll;
  NTSTATUS (NTAPI *NtCancelIoFileEx)(HANDLE FileHandle,
                                     PIO_STATUS_BLOCK IoRequestToCancel,
                                     PIO_STATUS_BLOCK IoStatusBlock);
  NTSTATUS (NTAPI *NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes,
                                 PIO_STATUS_BLOCK IoStatusBlock,
                                 PLARGE_INTEGER AllocationSize,
                                 ULONG FileAttributes, ULONG ShareAccess,
                                 ULONG CreateDisposition, ULONG CreateOptions,
                                 PVOID EaBuffer,
                                 ULONG EaLength);
  NTSTATUS (NTAPI *NtCreateKeyedEvent)(PHANDLE KeyedEventHandle,
                                       ACCESS_MASK DesiredAccess,
                                       POBJECT_ATTRIBUTES ObjectAttributes,
                                       ULONG Flags);
  NTSTATUS (NTAPI *NtDeviceIoControlFile)(HANDLE FileHandle, HANDLE Event,
                                          PIO_APC_ROUTINE ApcRoutine,
                                          PVOID ApcContext,
                                          PIO_STATUS_BLOCK IoStatusBlock,
                                          ULONG IoControlCode,
                                          PVOID InputBuffer,
                                          ULONG InputBufferLength,
                                          PVOID OutputBuffer,
                                          ULONG OutputBufferLength);
  NTSTATUS (NTAPI *NtReleaseKeyedEvent)(HANDLE KeyedEventHandle, PVOID KeyValue,
                                        BOOLEAN Alertable,
                                        PLARGE_INTEGER Timeout);
  NTSTATUS (NTAPI *NtWaitForKeyedEvent)(HANDLE KeyedEventHandle, PVOID KeyValue,
                                        BOOLEAN Alertable,
                                        PLARGE_INTEGER Timeout);
  ULONG (WINAPI *RtlNtStatusToDosError)(NTSTATUS Status);

} ares_evsys_win32_t;

static void ares_evsys_win32_destroy(ares_event_thread_t *e)
{
  ares_evsys_win32_t *ew = NULL;

  if (e == NULL) {
    return;
  }

  ew = e->ev_sys_data;
  if (ew == NULL) {
    return;
  }

  if (ew->ntdll != NULL) {
    FreeLibrary(ew->ntdll);
    ew->ntdll = NULL;
  }

  ares_free(ew);
  e->ev_sys_data = NULL;
}

static ares_bool_t ares_evsys_win32_init(ares_event_thread_t *e)
{
  ares_evsys_win32_t *ew = NULL;

  ew = ares_malloc_zero(sizeof(*ew));
  if (ew == NULL) {
    return ARES_FALSE;
  }

  e->ev_sys_data = ew;

  /* Load Internal symbols not typically accessible */
  ew->ntdll = LoadLibraryA("ntdll.dll");
  if (ew->ntdll == NULL) {
    goto fail;
  }

  ew->NtCancelIoFileEx      = GetProcAddress(ew->ntdll, "NtCancelIoFileEx");
  ew->NtCreateFile          = GetProcAddress(ew->ntdll, "NtCreateFile");
  ew->NtCreateKeyedEvent    = GetProcAddress(ew->ntdll, "NtCreateKeyedEvent");
  ew->NtDeviceIoControlFile = GetProcAddress(ew->ntdll, "NtDeviceIoControlFile");
  ew->NtReleaseKeyedEvent   = GetProcAddress(ew->ntdll, "NtReleaseKeyedEvent");
  ew->NtWaitForKeyedEvent   = GetProcAddress(ew->ntdll, "NtWaitForKeyedEvent");
  ew->RtlNtStatusToDosError = GetProcAddress(ew->ntdll, "RtlNtStatusToDosError");
  if (ew->NtCancelIoFileEx      == NULL || ew->NtCreateFile          == NULL ||
      ew->NtCreateKeyedEvent    == NULL || ew->NtDeviceIoControlFile == NULL ||
      ew->NtReleaseKeyedEvent   == NULL || ew->NtWaitForKeyedEvent   == NULL ||
      ew->RtlNtStatusToDosError == NULL) {
    goto fail;
  }

  return ARES_TRUE;

fail:
  ares_evsys_win32_destroy(e);
  return ARES_FALSE;
}

static void ares_evsys_win32_event_add(ares_event_thread_t *e,
                                       ares_event_t        *event)
{
  ares_evsys_win32_t *ew = e->ev_sys_data;

}

static void ares_evsys_epoll_event_del(ares_event_thread_t *e,
                                       ares_event_t        *event)
{
  ares_evsys_win32_t *ew = e->ev_sys_data;

}

static void ares_evsys_epoll_event_mod(ares_event_thread_t *e,
                                       ares_event_t        *event,
                                       ares_event_flags_t   new_flags)
{
  ares_evsys_win32_t *ew = e->ev_sys_data;

}

static size_t ares_evsys_win32_wait(ares_event_thread_t *e,
                                    unsigned long        timeout_ms)
{
  ares_evsys_win32_t *ew      = e->ev_sys_data;

}

const ares_event_sys_t ares_evsys_win32 = { "win32",
                                            ares_evsys_win32_init,
                                            ares_evsys_win32_destroy,
                                            ares_evsys_win32_event_add,
                                            ares_evsys_win32_event_del,
                                            ares_evsys_win32_event_mod,
                                            ares_evsys_win32_wait };
#endif
