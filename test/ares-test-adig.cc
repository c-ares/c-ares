/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * SPDX-License-Identifier: MIT
 */

#include "ares-test.h"

#include <gtest/internal/gtest-port.h>

extern "C" int ares_test_adig_main(int argc, char **argv);

namespace ares {
namespace test {

#if GTEST_HAS_STREAM_REDIRECTION
TEST(AdigTest, RcfilePrecedence)
{
  const std::string root = TempNam(nullptr, "ares");
  TransientDir      rootdir(root);
  std::string       configdir = root;

#  if defined(WIN32)
  configdir += "/c-ares";
  TransientDir appdir(configdir);
  EnvValue     appdata("APPDATA", root.c_str());
#  elif defined(__APPLE__)
  const std::string library = root + "/Library";
  const std::string support = library + "/Application Support";
  configdir                 = support + "/c-ares";
  TransientDir librarydir(library);
  TransientDir supportdir(support);
  TransientDir appdir(configdir);
  EnvValue     home("HOME", root.c_str());
#  else
  EnvValue xdg_config_home("XDG_CONFIG_HOME", root.c_str());
#  endif

  TransientFile rcfile(configdir + "/adigrc", "+nocmd\n");
  char          prog[]      = "adig";
  char          query[]     = "-q";
  char          badname[]   = "bad..name";
  char          cmd[]       = "+cmd";
  char          skip[]      = "-r";
  char         *defaults[]  = { prog, query, badname, nullptr };
  char         *override[]  = { prog, cmd, query, badname, nullptr };
  char         *skipped[]   = { prog, skip, query, badname, nullptr };
  char         *late_skip[] = { prog, query, badname, skip, nullptr };

  testing::internal::CaptureStdout();
  testing::internal::CaptureStderr();
  EXPECT_EQ(2, ares_test_adig_main(3, defaults));
  std::string output = testing::internal::GetCapturedStdout();
  std::string error  = testing::internal::GetCapturedStderr();
  EXPECT_EQ(std::string::npos, output.find("; <<>> c-ares DiG"));
  EXPECT_NE(std::string::npos, error.find("Misformatted domain name"));

  testing::internal::CaptureStdout();
  testing::internal::CaptureStderr();
  EXPECT_EQ(2, ares_test_adig_main(4, override));
  output = testing::internal::GetCapturedStdout();
  error  = testing::internal::GetCapturedStderr();
  EXPECT_NE(std::string::npos, output.find("; <<>> c-ares DiG"));
  EXPECT_NE(std::string::npos, error.find("Misformatted domain name"));

  testing::internal::CaptureStdout();
  testing::internal::CaptureStderr();
  EXPECT_EQ(2, ares_test_adig_main(4, skipped));
  output = testing::internal::GetCapturedStdout();
  error  = testing::internal::GetCapturedStderr();
  EXPECT_NE(std::string::npos, output.find("; <<>> c-ares DiG"));
  EXPECT_NE(std::string::npos, error.find("Misformatted domain name"));

  testing::internal::CaptureStdout();
  testing::internal::CaptureStderr();
  EXPECT_EQ(2, ares_test_adig_main(4, late_skip));
  output = testing::internal::GetCapturedStdout();
  error  = testing::internal::GetCapturedStderr();
  EXPECT_NE(std::string::npos, output.find("; <<>> c-ares DiG"));
  EXPECT_NE(std::string::npos, error.find("Misformatted domain name"));
}
#endif

} /* namespace test */
} /* namespace ares */
