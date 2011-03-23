#include "ares_setup.h"

#include "ares_private.h"

/* only do the following on windows
 */
#if (defined(WIN32) || defined(WATT32)) && !defined(MSDOS)

#ifdef __WATCOMC__
/*
 * Watcom needs a DllMain() in order to initialise the clib startup code.
 */
BOOL
WINAPI DllMain (HINSTANCE hnd, DWORD reason, LPVOID reserved)
{
  (void) hnd;
  (void) reason;
  (void) reserved;
  return (TRUE);
}
#endif

#define V_PLATFORM_WIN32s         0
#define V_PLATFORM_WIN32_WINDOWS  1
#define V_PLATFORM_WIN32_NT       2
#define V_PLATFORM_WIN32_CE       3

win_platform getplatform(void)
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

#endif /* WIN32 builds only */
