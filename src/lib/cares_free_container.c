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

void cares_free_container(void *containerptr)
{
    if (containerptr == NULL) {
        return;
    }

    struct cares_container *ptr;
    unsigned int count = 0;

    ptr = (void *)((char *)containerptr - offsetof(struct cares_container, container));

    if (ptr->mark != ARES_DATATYPE_MARK)
      return;

    switch (ptr->type)
    {
      case CARES_CONTAINER_SRV_REPLY_CONTAINER:
        count = ptr->container.srv_container.count;
        break;
    
      default:
        break;
    }

    for (unsigned int i = 0; i < count; ++i)
    {
        switch (ptr->type)
        {
          case CARES_CONTAINER_SRV_REPLY_CONTAINER:
            if (ptr->container.srv_container.replies[i])
            {
	      printf("before ares_free_data in free container; count: %u\n", count);
              ares_free_data(ptr->container.srv_container.replies[i]);
            }

            if (i == count - 1)
            {
	      printf("before free replies in free container\n");
              ares_free(ptr->container.srv_container.replies);
            }
            break;
        
          default:
            break;
        }
    }

    ares_free(ptr);
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
