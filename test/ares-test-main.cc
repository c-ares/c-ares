#include <signal.h>
#include <stdlib.h>

#include "ares-test.h"

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  for (int ii = 1; ii < argc; ii++) {
    if (strcmp(argv[ii], "-v") == 0) {
      ares::test::verbose = true;
    } else if ((strcmp(argv[ii], "-p") == 0) && (ii + 1 < argc)) {
      ii++;
      ares::test::mock_port = atoi(argv[ii]);
    }
  }

#ifdef WIN32
  WORD wVersionRequested = MAKEWORD(2, 2);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#else
  signal(SIGPIPE, SIG_IGN);
#endif

  int rc = RUN_ALL_TESTS();

#ifdef WIN32
  WSACleanup();
#endif

  return rc;
}
