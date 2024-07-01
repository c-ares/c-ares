/* MIT License
 *
 * Copyright (c) 2024 Brad House
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ares_private.h"
#include "ares_dns_private.h"


struct  ares__dns_multistring {
  /*! whether or not cached concatenated string is valid */
  ares_bool_t    cache_invalidated;
  /*!<combined/concatenated string cache */
  unsigned char *cache_str;
  /*! length of combined/concatenated string */
  size_t         cache_str_len;
  /*! List of ares__buf_t pointers for string */
  ares__llist_t *strs;
};


static void ares___dns_multistring_list_destroy(void *arg)
{
  if (arg == NULL) {
    return;
  }
  ares__buf_destroy(arg);
}

ares__dns_multistring_t *ares__dns_multistring_create(void)
{
  ares__dns_multistring_t *strs = ares_malloc_zero(sizeof(*strs));
  if (strs == NULL) {
    return NULL;
  }

  strs->strs = ares__llist_create(ares___dns_multistring_list_destroy);
  if (strs->strs == NULL) {
    ares_free(strs);
    return NULL;
  }

  return strs;
}

void ares__dns_multistring_destroy(ares__dns_multistring_t *strs)
{
  if (strs == NULL) {
    return;
  }
  ares__llist_destroy(strs->strs);
  ares_free(strs->cache_str);
  ares_free(strs);
}

ares_status_t ares__dns_multistring_append(ares__dns_multistring_t *strs,
                                           size_t idx,
                                           const unsigned char *str, size_t len)
{
  ares__llist_node_t *node;
  ares__buf_t        *buf;

  if (strs == NULL || str == NULL || len == 0) {
    return ARES_EFORMERR;
  }

  strs->cache_invalidated = ARES_TRUE;

  node = ares__llist_node_idx(strs->strs, idx);
  if (node == NULL) {
    return ARES_EFORMERR;
  }

  buf = ares__llist_node_val(node);
  return ares__buf_append(buf, str, len);
}

ares_status_t ares__dns_multistring_del(ares__dns_multistring_t *strs,
                                        size_t idx)
{
  ares__llist_node_t *node;

  if (strs == NULL) {
    return ARES_EFORMERR;
  }

  strs->cache_invalidated = ARES_TRUE;

  node = ares__llist_node_idx(strs->strs, idx);
  if (node == NULL) {
    return ARES_EFORMERR;
  }

  ares__llist_node_destroy(node);
  return ARES_SUCCESS;
}

ares_status_t ares__dns_multistring_add(ares__dns_multistring_t *strs,
                                        const unsigned char *str, size_t len)
{
  ares__buf_t  *buf;
  ares_status_t status;

  if (strs == NULL) {
    return ARES_EFORMERR;
  }

  strs->cache_invalidated = ARES_TRUE;

  /* NOTE: its ok to have an empty string added */
  if (str == NULL && len != 0) {
    return ARES_EFORMERR;
  }

  buf = ares__buf_create();
  if (buf == NULL) {
    return ARES_ENOMEM;
  }

  if (len) {
    status = ares__buf_append(buf, str, len);
    if (status != ARES_SUCCESS) {
      ares__buf_destroy(buf);
      return status;
    }
  }

  if (ares__llist_insert_last(strs->strs, buf) == NULL) {
    ares__buf_destroy(buf);
    return ARES_ENOMEM;
  }

  return ARES_SUCCESS;
}

ares__buf_t *ares__dns_multistring_get(ares__dns_multistring_t *strs,
                                       size_t idx)
{
  ares__llist_node_t *node;

  if (strs == NULL) {
    return NULL;
  }

  node = ares__llist_node_idx(strs->strs, idx);
  if (node == NULL) {
    return NULL;
  }

  return ares__llist_node_val(node);
}


const unsigned char *ares__dns_multistring_get_combined(
  ares__dns_multistring_t *strs, size_t *len)
{
  ares__buf_t        *buf = NULL;
  ares__llist_node_t *node;

  if (strs == NULL || len == NULL) {
    return NULL;
  }

  *len = 0;

  /* Return cache if possible */
  if (!strs->cache_invalidated) {
    *len = strs->cache_str_len;
    return strs->cache_str;
  }

  /* Clear cache */
  ares_free(strs->cache_str);
  strs->cache_str     = NULL;
  strs->cache_str_len = 0;

  buf = ares__buf_create();

  for (node = ares__llist_node_first(strs->strs); node != NULL;
       node = ares__llist_node_next(node)) {
    ares__buf_t *strbuf = ares__llist_node_val(node);
    size_t strlen;
    if (ares__buf_append(buf, ares__buf_peek(strbuf, &strlen), strlen)
        != ARES_SUCCESS) {
      ares__buf_destroy(buf);
      return NULL;
    }
  }

  strs->cache_str = (unsigned char *)ares__buf_finish_str(buf,
                                                          &strs->cache_str_len);
  if (strs->cache_str != NULL) {
    strs->cache_invalidated = ARES_FALSE;
  }
  *len = strs->cache_str_len;
  return strs->cache_str;
}
