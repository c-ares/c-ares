/* MIT License
 *
 * Copyright (c) 2025 Brad House
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
#ifndef __ARES_IDNAMAP_H
#define __ARES_IDNAMAP_H

#include <stddef.h>

/*! UTS #46 IDNA mapping status.  Codepoints not present in the table are
 *  valid and used as-is (this includes deviation codepoints since we only
 *  perform nontransitional processing).  Numeric values must match the
 *  status values emitted by unicode-codegen.py. */
typedef enum {
  ARES_IDNA_STATUS_DISALLOWED = 1, /*!< Codepoint not permitted in a domain */
  ARES_IDNA_STATUS_IGNORED    = 2, /*!< Codepoint removed from the domain */
  ARES_IDNA_STATUS_MAPPED     = 3  /*!< Codepoint replaced by mapping data */
} ares_idnamap_status_t;

/*! Inclusive codepoint range and its mapping status.  Sorted ascending by
 *  code_min with no overlapping ranges, suitable for binary search.  For
 *  ARES_IDNA_STATUS_MAPPED, the replacement is the UTF-8 byte sequence
 *  ares_idnamap_data_pool[map_offset] through map_offset + map_len - 1;
 *  mappings are variable length (up to 18 codepoints in Unicode 17) so they
 *  are stored in the shared pool rather than inline. */
typedef struct {
  unsigned int  code_min;   /*!< First codepoint in range */
  unsigned int  code_max;   /*!< Last codepoint in range (inclusive) */
  unsigned char status;     /*!< ares_idnamap_status_t */
  unsigned char map_len;    /*!< Byte length of UTF-8 mapping in pool */
  unsigned int  map_offset; /*!< Offset of UTF-8 mapping in pool */
} ares_idnamap_data_t;

extern const size_t              ares_idnamap_data_len;
extern const ares_idnamap_data_t ares_idnamap_data[];
extern const unsigned char       ares_idnamap_data_pool[];
/*! Byte length of ares_idnamap_data_pool, for bounds validation of the
 *  map_offset/map_len pool references */
extern const size_t              ares_idnamap_data_pool_len;

#endif
