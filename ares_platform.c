

/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "ares_setup.h"
#include "ares_platform.h"

#if defined(WIN32) && !defined(MSDOS)

#define V_PLATFORM_WIN32s         0
#define V_PLATFORM_WIN32_WINDOWS  1
#define V_PLATFORM_WIN32_NT       2
#define V_PLATFORM_WIN32_CE       3

win_platform ares__getplatform(void)
{
  OSVERSIONINFOEX OsvEx;

  memset(&OsvEx, 0, sizeof(OsvEx));
  OsvEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
  if (!GetVersionEx((void *)&OsvEx))
    {
      memset(&OsvEx, 0, sizeof(OsvEx));
      OsvEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
      if (!GetVersionEx((void *)&OsvEx))
        return WIN_UNKNOWN;
    }

  switch(OsvEx.dwPlatformId)
    {
      case V_PLATFORM_WIN32s:
        return WIN_3X;

      case V_PLATFORM_WIN32_WINDOWS:
        return WIN_9X;

      case V_PLATFORM_WIN32_NT:
        return WIN_NT;

      case V_PLATFORM_WIN32_CE:
        return WIN_CE;

      default:
        return WIN_UNKNOWN;
    }
}

#endif
