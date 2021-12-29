/* Copyright (C) 2021 by Kyle Evans
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "ares_private.h"
#include "ares_data.h"

typedef enum {
  CARES_CONTAINER_SRV_REPLY_CONTAINER,
  CARES_CONTAINER_LAST          /* not used */
} cares_datatype;


struct cares_data_container {
  cares_datatype type;  /* Actual data type identifier. */
  unsigned int  mark;  /* Private ares_data signature. */
  union {
    struct cares_srv_reply_container    srv_container;
  } container;
};

void *ares_malloc_container(cares_datatype type);