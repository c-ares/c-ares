#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <iostream>

#include "ares-test.h"

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  for (int ii = 1; ii < argc; ii++) {
    if (strcmp(argv[ii], "-v") == 0) {
      ares::test::verbose = true;
    }
  }

  int rc = RUN_ALL_TESTS();
  return rc;
}
