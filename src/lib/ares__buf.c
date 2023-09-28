/* MIT License
 *
 * Copyright (c) 2023 Brad House
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
#include "ares_setup.h"
#include "ares.h"
#include "ares_private.h"
#include "ares__buf.h"
#include <limits.h>
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

struct ares__buf {
  const unsigned char *data;           /*!< pointer to start of data buffer */
  size_t               data_len;       /*!< total size of data in buffer */

  unsigned char       *alloc_buf;      /*!< Pointer to allocated data buffer,
                                        *   not used for const buffers */
  size_t               alloc_buf_len;  /*!< Size of allocated data buffer */

  size_t               offset;         /*!< Current working offset in buffer */
  size_t               tag_offset;     /*!< Tagged offset in buffer. Uses
                                        *   SIZE_MAX if not set. */
};

ares__buf_t *ares__buf_create(void)
{
  ares__buf_t *buf = ares_malloc(sizeof(*buf));
  if (buf == NULL)
    return NULL;

  memset(buf, 0, sizeof(*buf));
  buf->tag_offset = SIZE_MAX;
  return buf;
}


ares__buf_t *ares__buf_create_const(const unsigned char *data, size_t data_len)
{
  ares__buf_t *buf;

  if (data == NULL || data_len == 0)
    return NULL;

  buf = ares__buf_create();
  if (buf == NULL)
    return NULL;

  buf->data     = data;
  buf->data_len = data_len;

  return buf;
}


void ares__buf_destroy(ares__buf_t *buf)
{
  if (buf == NULL)
    return;
  ares_free(buf->alloc_buf);
  ares_free(buf);
}


static int ares__buf_is_const(const ares__buf_t *buf)
{
  if (buf == NULL)
    return 0;

  if (buf->data != NULL && buf->alloc_buf == NULL)
    return 1;

  return 0;
}


static void ares__buf_reclaim(ares__buf_t *buf, size_t needed_size)
{
  size_t prefix_size;
  size_t remaining_size;
  size_t data_size;

  if (buf == NULL)
    return;

  if (ares__buf_is_const(buf))
    return;

  remaining_size = buf->alloc_buf_len - buf->data_len;

  /* No need to do an expensive move operation, we have enough to just append */
  if (remaining_size >= needed_size)
    return;

  if (buf->tag_offset != SIZE_MAX) {
    prefix_size = buf->tag_offset;
  } else {
    prefix_size = buf->offset;
  }

  if (prefix_size == 0)
    return;

  data_size = buf->data_len - prefix_size;

  memmove(buf->alloc_buf, buf->alloc_buf + prefix_size, data_size);
  buf->data     = buf->alloc_buf;
  buf->data_len = data_size;
  buf->offset  -= prefix_size;
  if (buf->tag_offset != SIZE_MAX)
    buf->tag_offset -= prefix_size;

  return;
}


static int ares__buf_ensure_space(ares__buf_t *buf, size_t needed_size)
{
  size_t         remaining_size;
  size_t         alloc_size;
  unsigned char *ptr;

  if (buf == NULL)
    return 0;

  if (ares__buf_is_const(buf))
    return 0;

  /* See if just moving consumed data frees up enough space */
  ares__buf_reclaim(buf, needed_size);

  remaining_size = buf->alloc_buf_len - buf->data_len;
  if (remaining_size >= needed_size)
    return 1;

  alloc_size = buf->alloc_buf_len;

  /* Not yet started */
  if (alloc_size == 0)
    alloc_size = 512;

  /* Increase allocation by powers of 2 */
  do {
    alloc_size <<= 1;
    remaining_size = alloc_size - buf->data_len;
  } while (remaining_size < needed_size);

  ptr = ares_realloc(buf->alloc_buf, alloc_size);
  if (ptr == NULL)
    return 0;

  buf->alloc_buf     = ptr;
  buf->alloc_buf_len = alloc_size;
  buf->data          = ptr;

  return 1;
}


int ares__buf_append(ares__buf_t *buf, const unsigned char *data,
                     size_t data_len)
{
  if (data == NULL || data_len == 0)
    return 0;

  if (!ares__buf_ensure_space(buf, data_len))
    return 0;

  memcpy(buf->alloc_buf + buf->data_len, data, data_len);
  buf->data_len += data_len;
  return 1;
}


unsigned char *ares__buf_append_start(ares__buf_t *buf, size_t *len)
{
  if (len == NULL || *len == 0)
    return 0;

  if (!ares__buf_ensure_space(buf, *len))
    return 0;

  *len = buf->alloc_buf_len - buf->data_len;
  return buf->alloc_buf + buf->data_len;
}


void ares__buf_append_finish(ares__buf_t *buf, size_t len)
{
  if (buf == NULL)
    return;

  buf->data_len += len;
}


void ares__buf_tag(ares__buf_t *buf)
{
  if (buf == NULL)
    return;

  buf->tag_offset = buf->offset;
}


int ares__buf_tag_rollback(ares__buf_t *buf)
{
  if (buf == NULL || buf->tag_offset == SIZE_MAX)
    return 0;

  buf->offset     = buf->tag_offset;
  buf->tag_offset = SIZE_MAX;
  return 1;
}


int ares__buf_tag_clear(ares__buf_t *buf)
{
  if (buf == NULL || buf->tag_offset == SIZE_MAX)
    return 0;

  buf->tag_offset = SIZE_MAX;
  return 1;
}


const unsigned char *ares__buf_tag_fetch(const ares__buf_t *buf, size_t *len)
{
  if (buf == NULL || buf->tag_offset == SIZE_MAX || len == NULL)
    return NULL;

  *len = buf->offset - buf->tag_offset;
  return buf->data + buf->tag_offset;
}


static const unsigned char *ares__buf_fetch(const ares__buf_t *buf, size_t *len)
{
  if (len != NULL)
    *len = 0;

  if (buf == NULL || len == NULL || buf->data == NULL)
    return NULL;

  *len = buf->data_len - buf->offset;
  return buf->data + buf->offset;
}


int ares__buf_consume(ares__buf_t *buf, size_t len)
{
  size_t remaining_len;

  ares__buf_fetch(buf, &remaining_len);

  if (remaining_len < len)
    return 0;

  buf->offset += len;
  return 1;
}


int ares__buf_fetch_be16(ares__buf_t *buf, unsigned short *u16)
{
  size_t               remaining_len;
  const unsigned char *ptr = ares__buf_fetch(buf, &remaining_len);

  if (buf == NULL || u16 == NULL || remaining_len < sizeof(*u16))
    return 0;

  *u16 = (unsigned short)((unsigned short)(ptr[0]) << 8 | (unsigned short)ptr[1]);

  return ares__buf_consume(buf, sizeof(*u16));
}


int ares__buf_fetch_bytes(ares__buf_t *buf, unsigned char *bytes,
                          size_t len)
{
  size_t               remaining_len;
  const unsigned char *ptr = ares__buf_fetch(buf, &remaining_len);

  if (buf == NULL || bytes == NULL || len == 0 || remaining_len < len)
    return 0;

  memcpy(bytes, ptr, len);
  return ares__buf_consume(buf, len);
}


size_t ares__buf_len(const ares__buf_t *buf)
{
  size_t len = 0;
  ares__buf_fetch(buf, &len);
  return len;
}


const unsigned char *ares__buf_peek(const ares__buf_t *buf, size_t *len)
{
  return ares__buf_fetch(buf, len);
}

#if 0
int ares__buf_fetch_dnsheader(ares__buf_t *buf, ares_dns_header_t *header);
#endif
