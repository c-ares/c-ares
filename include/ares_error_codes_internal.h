/* MIT License
 *
 * Copyright (c) Massachusetts Institute of Technology
 * Copyright (c) Daniel Stenberg
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

#ifndef ARES_ERROR_CODES_INTERNAL_H
#define ARES_ERROR_CODES_INTERNAL_H

/**
 * Internal error codes (not exposed in the public API).
 *
 * These error codes provide more granular error information for internal use.
 * They are always converted to public ares_status_t codes before being
 * returned to users or passed to callbacks to maintain backward compatibility.
 *
 * Internal error codes start at 1000 to avoid collision with public codes (0-26).
 */

typedef enum {
  /* Public errors (for reference, avoid using internally after mapping) */
  ARES_EINTERNAL_SUCCESS = 0,

  /* DNS message parsing errors (1000-1100) */
  ARES_EINTERNAL_INVALID_QUERY = 1001,
  ARES_EINTERNAL_INVALID_MSG = 1002,
  ARES_EINTERNAL_TRUNCATED = 1003,
  ARES_EINTERNAL_MALFORMED_RESPONSE = 1004,
  ARES_EINTERNAL_INVALID_NAME = 1005,
  ARES_EINTERNAL_INVALID_RDATA = 1006,

  /* Connection and communication errors (1100-1200) */
  ARES_EINTERNAL_CONNECTION_FAILED = 1101,
  ARES_EINTERNAL_SEND_FAILED = 1102,
  ARES_EINTERNAL_RECV_FAILED = 1103,

  /* Resource exhaustion (1200-1300) */
  ARES_EINTERNAL_OUT_OF_MEMORY = 1201,
  ARES_EINTERNAL_RESOURCE_EXHAUSTED = 1202,

  /* Validation and constraint errors (1300-1400) */
  ARES_EINTERNAL_INVALID_PARAMETER = 1301,
  ARES_EINTERNAL_INVALID_LENGTH = 1302,
  ARES_EINTERNAL_INVALID_ENCODING = 1303,

  /* State and lifecycle errors (1400-1500) */
  ARES_EINTERNAL_INVALID_STATE = 1401,
  ARES_EINTERNAL_CHANNEL_DESTROYED = 1402,

  /* Timeout and cancellation (1500-1600) */
  ARES_EINTERNAL_TIMEOUT = 1501,
  ARES_EINTERNAL_CANCELLED = 1502
} ares_ecode_internal_t;

#endif /* ARES_ERROR_CODES_INTERNAL_H */
