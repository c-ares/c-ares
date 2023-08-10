/* Copyright (C) 2023 by Brad House
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
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __ARES__HTABLE_STVP_H
#define __ARES__HTABLE_STVP_H

/* Hashtable with size_t key and void pointer value */

struct ares__htable_stvp;
typedef struct ares__htable_stvp ares__htable_stvp_t;
typedef void (*ares__htable_stvp_val_free_t)(void *val);

void ares__htable_stvp_destroy(ares__htable_stvp_t *htable);

ares__htable_stvp_t *ares__htable_stvp_create(
    ares__htable_stvp_val_free_t val_free);

unsigned int ares__htable_stvp_insert(ares__htable_stvp_t *htable, size_t key,
                                      void *val);

unsigned int ares__htable_stvp_get(ares__htable_stvp_t *htable, size_t key,
                                   void **val);

void *ares__htable_stvp_get_direct(ares__htable_stvp_t *htable, size_t key);

unsigned int ares__htable_stvp_remove(ares__htable_stvp_t *htable, size_t key);

#endif /* __ARES__HTABLE_STVP_H */
