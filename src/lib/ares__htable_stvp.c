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
#include "ares_setup.h"
#include "ares.h"
#include "ares_private.h"
#include "ares__htable.h"
#include "ares__htable_stvp.h"


struct ares__htable_stvp {
  ares__htable_stvp_val_free_t free_val;
  ares__htable_t              *hash;
};


typedef struct {
  size_t               key;
  void                *val;
  ares__htable_stvp_t *parent;
} ares__htable_stvp_bucket_t;


void ares__htable_stvp_destroy(ares__htable_stvp_t *htable)
{
  if (htable == NULL)
    return;

  ares__htable_destroy(htable->hash);
  ares_free(htable);
}


static unsigned int hash_func(const void *bucket, unsigned int seed)
{
  const ares__htable_stvp_bucket_t *arg = bucket;
  return ares__htable_hash_FNV1a(&arg->key, sizeof(arg->key), seed);
}


static const void *bucket_key(const void *bucket)
{
  const ares__htable_stvp_bucket_t *arg = bucket;
  return &arg->key;
}


static void bucket_free(void *bucket)
{
  ares__htable_stvp_bucket_t *arg = bucket;

  if (arg->parent->free_val)
    arg->parent->free_val(arg->val);

  ares_free(arg);
}


static unsigned int key_eq(const void *key1, const void *key2)
{
  const size_t *k1 = key1;
  const size_t *k2 = key2;

  if (*k1 == *k2)
    return 1;

  return 0;
}


ares__htable_stvp_t *ares__htable_stvp_create(
    ares__htable_stvp_val_free_t val_free)
{
  ares__htable_stvp_t *htable = ares_malloc(sizeof(*htable));
  if (htable == NULL)
    goto fail;

  htable->hash = ares__htable_create(hash_func,
                                     bucket_key,
                                     bucket_free,
                                     key_eq);
  if (htable->hash == NULL)
    goto fail;

  htable->free_val = val_free;

  return htable;

fail:
  if (htable) {
    ares__htable_destroy(htable->hash);
    ares_free(htable);
  }
  return NULL;
}


unsigned int ares__htable_stvp_insert(ares__htable_stvp_t *htable, size_t key,
                                      void *val)
{
  ares__htable_stvp_bucket_t *bucket = NULL;

  if (htable == NULL)
    goto fail;

  bucket = ares_malloc(sizeof(*bucket));
  if (bucket == NULL)
    goto fail;

  bucket->parent = htable;
  bucket->key    = key;
  bucket->val    = val;

  if (!ares__htable_insert(htable->hash, bucket))
    goto fail;

  return 1;

fail:
  if (bucket) {
    ares_free(bucket);
  }
  return 0;
}


unsigned int ares__htable_stvp_get(ares__htable_stvp_t *htable, size_t key,
                                   void **val)
{
  ares__htable_stvp_bucket_t *bucket = NULL;

  if (val)
    *val = NULL;

  if (htable == NULL)
    return 0;

  bucket = ares__htable_get(htable->hash, &key);
  if (bucket == NULL)
    return 0;

  if (val)
    *val = bucket->val;
  return 1;
}


void *ares__htable_stvp_get_direct(ares__htable_stvp_t *htable, size_t key)
{
  void *val = NULL;
  ares__htable_stvp_get(htable, key, &val);
  return val;
}


unsigned int ares__htable_stvp_remove(ares__htable_stvp_t *htable, size_t key)
{
  if (htable == NULL)
    return 0;

  return ares__htable_remove(htable->hash, &key);
}


size_t ares__htable_stvp_num_keys(ares__htable_stvp_t *htable)
{
  if (htable == NULL)
    return 0;
  return ares__htable_num_keys(htable->hash);
}
