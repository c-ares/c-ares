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
#include "ares__parser.h"

struct ares__parser {
  const unsigned char *data;           /*!< pointer to start of data buffer */
  size_t               data_len;       /*!< total size of data in buffer */

  unsigned char       *alloc_buf;      /*!< Pointer to allocated data buffer,
                                        *   not used for const buffers */
  size_t               alloc_buf_len;  /*!< Size of allocated data buffer */

  size_t               offset;         /*!< Current working offset in buffer */
  size_t               tag_offset;     /*!< Tagged offset in buffer. Uses
                                        *   SIZE_MAX if not set. */
};

ares__parser_t *ares__parser_create(void)
{
  ares__parser_t *parser = ares_malloc(sizeof(*parser));
  if (parser == NULL)
    return NULL;

  memset(parser, 0, sizeof(*parser));
  parser->tag_offset = SIZE_MAX;
  return parser;
}


ares__parser_t *ares__parser_create_const(const unsigned char *buf,
                                          size_t buf_len)
{
  ares__parser_t *parser;

  if (buf == NULL || buf_len == 0)
    return NULL;

  parser = ares__parser_create();
  if (parser == NULL)
    return NULL;

  parser->data     = buf;
  parser->data_len = buf_len;

  return parser;
}


void ares__parser_destroy(ares__parser_t *parser)
{
  if (parser == NULL)
    return;
  ares_free(parser->alloc_buf);
  ares_free(parser);
}


static int ares__parser_is_const(const ares__parser_t *parser)
{
  if (parser == NULL)
    return 0;

  if (parser->data != NULL && parser->alloc_buf == NULL)
    return 1;

  return 0;
}


static void ares__parser_truncate(ares__parser_t *parser, size_t needed_size)
{
  size_t prefix_size;
  size_t remaining_size;
  size_t data_size;

  if (parser == NULL)
    return;

  if (ares__parser_is_const(parser))
    return;

  remaining_size = parser->alloc_buf_len - parser->data_len;

  /* No need to do an expensive move operation, we have enough to just append */
  if (remaining_size >= needed_size)
    return;

  if (parser->tag_offset != SIZE_MAX) {
    prefix_size = parser->tag_offset;
  } else {
    prefix_size = parser->offset;
  }

  if (prefix_size == 0)
    return;

  data_size = parser->data_len - prefix_size;

  memmove(parser->alloc_buf, parser->alloc_buf + prefix_size, data_size);
  parser->data     = parser->alloc_buf;
  parser->data_len = data_size;
  parser->offset  -= prefix_size;
  if (parser->tag_offset != SIZE_MAX)
    parser->tag_offset -= prefix_size;

  return;
}


static int ares__parser_ensure_space(ares__parser_t *parser, size_t needed_size)
{
  size_t         remaining_size;
  size_t         alloc_size;
  unsigned char *ptr;

  if (parser == NULL)
    return 0;

  if (ares__parser_is_const(parser))
    return 0;

  /* See if just moving consumed data frees up enough space */
  ares__parser_truncate(parser, needed_size);

  remaining_size = parser->alloc_buf_len - parser->data_len;
  if (remaining_size >= needed_size)
    return 1;

  alloc_size = parser->alloc_buf_len;

  /* Not yet started */
  if (alloc_size == 0)
    alloc_size = 512;

  /* Increase allocation by powers of 2 */
  do {
    alloc_size <<= 1;
    remaining_size = alloc_size - parser->data_len;
  } while (remaining_size < needed_size);

  ptr = ares_realloc(parser->alloc_buf, alloc_size);
  if (ptr == NULL)
    return 0;

  parser->alloc_buf     = ptr;
  parser->alloc_buf_len = alloc_size;
  parser->data          = ptr;

  return 1;
}


int ares__parser_append(ares__parser_t *parser, const unsigned char *buf,
                        size_t buf_len)
{
  if (buf == NULL || buf_len == 0)
    return 0;

  if (!ares__parser_ensure_space(parser, buf_len))
    return 0;

  memcpy(parser->alloc_buf + parser->data_len, buf, buf_len);
  parser->data_len += buf_len;
  return 1;
}


unsigned char *ares__parser_append_start(ares__parser_t *parser, size_t *len)
{
  if (len == NULL || *len == 0)
    return 0;

  if (!ares__parser_ensure_space(parser, *len))
    return 0;

  *len = parser->alloc_buf_len - parser->data_len;
  return parser->alloc_buf + parser->data_len;
}


void ares__parser_append_finish(ares__parser_t *parser, size_t len)
{
  if (parser == NULL)
    return;

  parser->data_len += len;
}


void ares__parser_tag(ares__parser_t *parser)
{
  if (parser == NULL)
    return;

  parser->tag_offset = parser->offset;
}


int ares__parser_tag_rollback(ares__parser_t *parser)
{
  if (parser == NULL || parser->tag_offset == SIZE_MAX)
    return 0;

  parser->offset     = parser->tag_offset;
  parser->tag_offset = SIZE_MAX;
  return 1;
}


int ares__parser_tag_clear(ares__parser_t *parser)
{
  if (parser == NULL || parser->tag_offset == SIZE_MAX)
    return 0;

  parser->tag_offset = SIZE_MAX;
  return 1;
}


const unsigned char *ares__parser_tag_fetch(const ares__parser_t *parser,
                                            size_t *len)
{
  if (parser == NULL || parser->tag_offset == SIZE_MAX || len == NULL)
    return NULL;

  *len = parser->offset - parser->tag_offset;
  return parser->data + parser->tag_offset;
}


static const unsigned char *ares__parser_fetch(const ares__parser_t *parser,
                                               size_t *len)
{
  if (len != NULL)
    *len = 0;

  if (parser == NULL || len == NULL)
    return NULL;

  *len = parser->data_len - parser->offset;
  return parser->data + parser->offset;
}


int ares__parser_consume(ares__parser_t *parser, size_t len)
{
  size_t               remaining_len;
  const unsigned char *ptr = ares__parser_fetch(parser, &remaining_len);

  if (remaining_len < len)
    return 0;

  parser->offset += len;
  return 1;
}


int ares__parser_fetch_be16(ares__parser_t *parser, unsigned short *u16)
{
  size_t               remaining_len;
  const unsigned char *ptr = ares__parser_fetch(parser, &remaining_len);

  if (parser == NULL || u16 == NULL || remaining_len < sizeof(*u16))
    return 0;

  *u16 = ptr[0] << 8 | ptr[1];

  return ares__parser_consume(parser, sizeof(*u16));
}


int ares__parser_fetch_bytes(ares__parser_t *parser, unsigned char *bytes,
                             size_t len)
{
  size_t               remaining_len;
  const unsigned char *ptr = ares__parser_fetch(parser, &remaining_len);

  if (parser == NULL || bytes == NULL || len == 0 || remaining_len < len)
    return 0;

  memcpy(bytes, ptr, len);
  return ares__parser_consume(parser, len);
}


size_t ares__parser_len(const ares__parser_t *parser)
{
  size_t len = 0;
  ares__parser_fetch(parser, &len);
  return len;
}


const unsigned char *ares__parser_peek(const ares__parser_t *parser,
                                       size_t *len)
{
  return ares__parser_fetch(parser, len);
}

#if 0
int ares__parser_fetch_dnsheader(ares__parser_t *parser, ares_dns_header_t *header);
#endif
