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

#include <stddef.h>
#include "ares_setup.h"
#include "ares.h"
#include "ares_private.h"
#include "cares_free_container.h"
#include "ares_data.h"
#include "stdio.h"

void cares_free_container(void *containerptr)
{
    if (containerptr == NULL) {
        return;
    }
    printf("containerptr: %p\n", (void *)containerptr);

    struct cares_container *ptr;
    unsigned int count;

    ptr = (void *)((char *)containerptr - offsetof(struct cares_container, container));

    printf("ptr: %p\n", (void *)ptr);

    if (ptr->mark != ARES_DATATYPE_MARK)
      return;

    printf("after mark in free container\n");

    switch (ptr->type)
    {
      case CARES_CONTAINER_SRV_REPLY_CONTAINER:
        printf("inside switch 1\n");
        count = ptr->container.srv_container.count;
        break;
    
      default:
        return;
    }

    printf("before for loop in free container; count: %u\n", count);
    for (unsigned int i = 0; i < count; ++i)
    {
        printf("outside switch 2\n");
        switch (ptr->type)
        {
          case CARES_CONTAINER_SRV_REPLY_CONTAINER:
            printf("inside switch 2\n");
            if (ptr->container.srv_container.replies[i])
            {
              printf("before free data; replies[i]: %p\n", (void *)ptr->container.srv_container.replies[i]);
              ares_free_data(ptr->container.srv_container.replies[i]);
              printf("after free data\n");
            }

            if (i == count - 1)
            {
              printf("before free replies\n");
              ares_free(ptr->container.srv_container.replies);
              printf("after free replies\n");
              break;
            }
        
          default:
            return;
        }
    }

    printf("before free ptr\n");
    ares_free(ptr);
    printf("after free ptr\n");
}

void *cares_malloc_container(cares_container_type type)
{
  struct cares_container *ptr;

  ptr = ares_malloc(sizeof(struct cares_container));
  if (!ptr)
    return NULL;

  switch (type)
    {
      case CARES_CONTAINER_SRV_REPLY_CONTAINER:
        ptr->container.srv_container.replies = NULL;
        ptr->container.srv_container.curr = 0;
        ptr->container.srv_container.count = 0;
        break;

      default:
        ares_free(ptr);
        return NULL;
    }

  ptr->mark = ARES_DATATYPE_MARK;
  ptr->type = type;

  return &ptr->container;
}
