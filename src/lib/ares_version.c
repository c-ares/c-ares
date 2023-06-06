/***********************
 * Copyright (C) the Massachusetts Institute of Technology.
 * Copyright (C) Daniel Stenberg
 *
 * SPDX-License-Identifier: MIT
 */
#include "ares_setup.h"
#include "ares.h"

const char *ares_version(int *version)
{
  if(version)
    *version = ARES_VERSION;

  return ARES_VERSION_STR;
}
