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
#ifndef __ARES__HTABLE_H
#define __ARES__HTABLE_H

struct ares__htable_t;
typedef struct ares__htable ares__htable_t;
typedef unsigned int (*ares__htable_hashfunc_t)(const void *bucket,
                                                unsigned int seed);
typedef void (*ares__htable_bucket_free_t)(void *bucket);
typedef const void *(*ares__htable_bucket_key_t)(const void *bucket);
typedef unsigned int (*ares__htable_key_eq_t)(const void *key1,
                                              const void *key2);


void ares__htable_destroy(ares__htable_t *htable);
ares__htable_t *ares__htable_create(ares__htable_hashfunc_t    hash_func,
                                    ares__htable_bucket_key_t  bucket_key,
                                    ares__htable_bucket_free_t bucket_free,
                                    ares__htable_key_eq_t      key_eq);
unsigned int ares__htable_insert(ares__htable_t *htable, void *bucket);
void *ares__htable_get(ares__htable_t *htable, const void *key);
unsigned int ares__htable_remove(ares__htable_t *htable, const void *key);

unsigned int ares__htable_hash_FNV1a(const void *key, size_t key_len,
                                     unsigned int seed);
unsigned int ares__htable_hash_FNV1a_casecmp(const void *key, size_t key_len,
                                             unsigned int);

#endif /* __ARES__HTABLE_H */
