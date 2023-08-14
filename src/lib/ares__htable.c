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
#include "ares__llist.h"
#include "ares__htable.h"

#define ARES__HTABLE_MAX_BUCKETS (1U<<24)
#define ARES__HTABLE_MIN_BUCKETS (1U<<4)
#define ARES__HTABLE_EXPAND_PERCENT 75

struct ares__htable {
  ares__htable_hashfunc_t    hash;
  ares__htable_bucket_key_t  bucket_key;
  ares__htable_bucket_free_t bucket_free;
  ares__htable_key_eq_t      key_eq;
  unsigned int               seed;
  unsigned int               size;
  size_t                     num_keys;
  /* NOTE: if we converted buckets into ares__slist_t we could guarantee on
   *       hash collisions we would have O(log n) worst case insert and search
   *       performance.  (We'd also need to make key_eq into a key_cmp to
   *       support sort).  That said, risk with a random hash seed is near zero,
   *       and ares__slist_t is heavier weight so I think using ares__llist_t is
   *       is an overall win. */
  ares__llist_t            **buckets;
};


static unsigned int ares__htable_generate_seed(ares__htable_t *htable)
{
  unsigned int seed = 0;

  /* Mix stack address, heap address, and time to generate a random seed, it
   * doesn't have to be super secure, just quick.  Likelihood of a hash
   * collision attack is very low with a small amount of effort */
  seed |= (unsigned int)((size_t)htable & 0xFFFFFFFF);
  seed |= (unsigned int)((size_t)&seed & 0xFFFFFFFF);
  seed |= (unsigned int)time(NULL) & 0xFFFFFFFF;
  return seed;
}

static void ares__htable_buckets_destroy(ares__llist_t **buckets,
                                         unsigned int size,
                                         unsigned char destroy_vals)
{
  unsigned int i;

  if (buckets == NULL)
    return;

  for (i=0; i<size; i++) {
    if (buckets[i] == NULL)
      continue;

    if (!destroy_vals)
      ares__llist_replace_destructor(buckets[i], NULL);

    ares__llist_destroy(buckets[i]);
  }

  ares_free(buckets);
}


void ares__htable_destroy(ares__htable_t *htable)
{
  if (htable == NULL)
    return;
  ares__htable_buckets_destroy(htable->buckets, htable->size, 1);
  ares_free(htable);
}


ares__htable_t *ares__htable_create(ares__htable_hashfunc_t    hash_func,
                                    ares__htable_bucket_key_t  bucket_key,
                                    ares__htable_bucket_free_t bucket_free,
                                    ares__htable_key_eq_t      key_eq)
{
  ares__htable_t *htable = NULL;

  if (hash_func == NULL || bucket_key == NULL || bucket_free == NULL ||
      key_eq == NULL) {
    goto fail;
  }

  htable = ares_malloc(sizeof(*htable));
  if (htable == NULL)
    goto fail;

  memset(htable, 0, sizeof(*htable));

  htable->hash        = hash_func;
  htable->bucket_key  = bucket_key;
  htable->bucket_free = bucket_free;
  htable->key_eq      = key_eq;
  htable->seed        = ares__htable_generate_seed(htable);
  htable->size        = ARES__HTABLE_MIN_BUCKETS;
  htable->buckets     = ares_malloc(sizeof(*htable->buckets) * htable->size);

  if (htable->buckets == NULL)
    goto fail;

  memset(htable->buckets, 0, sizeof(*htable->buckets) * htable->size);

  return htable;

fail:
  ares__htable_destroy(htable);
  return NULL;
}


/*! Grabs the Hashtable index from the key and length.  The h index is
 *  the hash of the function reduced to the size of the bucket list.
 *  We are doing "hash & (size - 1)" since we are guaranteeing a power of
 *  2 for size. This is equivalent to "hash % size", but should be more
 * efficient */
#define HASH_IDX(h, key) h->hash(key, h->seed) & (h->size - 1)

static ares__llist_node_t *ares__htable_find(ares__htable_t *htable,
                                             unsigned int idx,
                                             const void *key)
{
  ares__llist_node_t *node = NULL;

  for (node = ares__llist_node_first(htable->buckets[idx]);
       node != NULL;
       node = ares__llist_node_next(node)) {

    if (htable->key_eq(key, htable->bucket_key(ares__llist_node_val(node))))
      break;
  }

  return node;
}


static unsigned int ares__htable_expand(ares__htable_t *htable)
{
  ares__llist_t **buckets  = NULL;
  unsigned int    old_size = htable->size;
  size_t          i;

  /* Not a failure, just won't expand */
  if (old_size == ARES__HTABLE_MAX_BUCKETS)
    return 1;

  htable->size <<= 1;

  /* We must do this in 2 passes as we want it to be non-destructive in case
   * there is a memory allocation failure.  So we will actually use more 
   * memory doing it this way, but at least we might be able to gracefully
   * recover */
  buckets = ares_malloc(sizeof(*buckets) * htable->size);
  if (buckets == NULL)
    goto fail;

  memset(buckets, 0, sizeof(*buckets) * htable->size);

  for (i=0; i<old_size; i++) {
    ares__llist_node_t *node;
    for (node = ares__llist_node_first(htable->buckets[i]);
         node != NULL;
         node = ares__llist_node_next(node)) {

      void  *val = ares__llist_node_val(node);
      size_t idx = HASH_IDX(htable, htable->bucket_key(val));

      if (buckets[idx] == NULL) {
        buckets[idx] = ares__llist_create(htable->bucket_free);
        if (buckets[idx] == NULL)
          goto fail;
      }

      if (ares__llist_insert_first(buckets[idx], val) == NULL) {
        goto fail;
      }

    }
  }

  /* Swap out buckets */
  ares__htable_buckets_destroy(htable->buckets, old_size, 0);
  htable->buckets = buckets;
  return 1;

fail:
  ares__htable_buckets_destroy(buckets, htable->size, 0);
  htable->size = old_size;

  return 0;
}


unsigned int ares__htable_insert(ares__htable_t *htable, void *bucket)
{
  unsigned int        idx  = 0;
  ares__llist_node_t *node = NULL;
  const void         *key  = NULL;

  if (htable == NULL || bucket == NULL)
    return 0;


  key  = htable->bucket_key(bucket);
  idx  = HASH_IDX(htable, key);

  /* See if we have a matching bucket already, if so, replace it */
  node = ares__htable_find(htable, idx, key);
  if (node != NULL) {
    ares__llist_node_replace(node, bucket);
    return 1;
  }

  /* Check to see if we should rehash because likelihood of collisions has
   * increased beyond our threshold */
  if (htable->num_keys+1 > (htable->size * ARES__HTABLE_EXPAND_PERCENT) / 100) {
    if (!ares__htable_expand(htable)) {
      return 0;
    }
    /* If we expanded, need to calculate a new index */
    idx = HASH_IDX(htable, key);
  }

  /* We lazily allocate the linked list */
  if (htable->buckets[idx] == NULL) {
    htable->buckets[idx] = ares__llist_create(htable->bucket_free);
    if (htable->buckets[idx] == NULL)
      return 0;
  }
  
  node = ares__llist_insert_first(htable->buckets[idx], bucket);
  if (node == NULL)
    return 0;

  htable->num_keys++;

  return 1;
}

  
void *ares__htable_get(ares__htable_t *htable, const void *key)
{
  unsigned int idx;

  if (htable == NULL || key == NULL)
    return NULL;

  idx = HASH_IDX(htable, key);

  return ares__llist_node_val(ares__htable_find(htable, idx, key));
}


unsigned int ares__htable_remove(ares__htable_t *htable, const void *key)
{
  ares__llist_node_t *node;
  unsigned int        idx;

  if (htable == NULL || key == NULL)
    return 0;

  idx  = HASH_IDX(htable, key);
  node = ares__htable_find(htable, idx, key);
  if (node == NULL)
    return 0;

  htable->num_keys--;
  ares__llist_node_destroy(node);
  return 1;
}

size_t ares__htable_num_keys(ares__htable_t *htable)
{
  if (htable == NULL)
    return 0;
  return htable->num_keys;
}

unsigned int ares__htable_hash_FNV1a(const void *key, size_t key_len,
                                     unsigned int seed)
{
  const unsigned char *data = key;
  /* recommended seed is 2166136261U, but we don't want collisions */
  unsigned int         hv   = seed; 
  size_t               i;

  for (i = 0; i < key_len; i++) {
    hv ^= (unsigned int)data[i];
    /* hv *= 0x01000193 */
    hv += (hv<<1) + (hv<<4) + (hv<<7) + (hv<<8) + (hv<<24);
  }

  return hv;
}

/* Case insensitive version, meant for strings */
unsigned int ares__htable_hash_FNV1a_casecmp(const void *key, size_t key_len,
                                             unsigned int seed)
{
  const unsigned char *data = key;
  unsigned int         hv   = seed;
  size_t               i;

  for (i = 0; i < key_len; i++) {
    hv ^= (unsigned int)tolower((char)data[i]);
    /* hv *=  16777619 */
    hv += (hv<<1) + (hv<<4) + (hv<<7) + (hv<<8) + (hv<<24);
  }

  return hv;
}
