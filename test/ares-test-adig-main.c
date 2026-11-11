/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * SPDX-License-Identifier: MIT
 */

/* Exercise the tool's actual command-line entry point in arestest without
 * requiring a subprocess or a separate executable path. */
int ares_test_adig_main(int argc, char **argv);
#define main ares_test_adig_main
#include "../src/tools/adig.c"
