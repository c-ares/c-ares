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

#include "ares_setup.h"
#include "ares.h"
#include "ares_error_codes_internal.h"

/**
 * Maps internal error codes to public ares_status_t codes.
 *
 * Internal error codes provide granular error information, but the public API
 * must always return standardized codes to maintain backward compatibility with
 * existing applications that may depend on specific error codes.
 *
 * This function ensures a single point of conversion that can be audited and
 * updated consistently across the entire codebase.
 */
ares_status_t ares_map_internal_error(ares_ecode_internal_t internal_code)
{
  if (internal_code == ARES_EINTERNAL_SUCCESS) {
    return ARES_SUCCESS;
  }

  /* DNS message parsing errors */
  if (internal_code == ARES_EINTERNAL_INVALID_QUERY ||
      internal_code == ARES_EINTERNAL_INVALID_MSG ||
      internal_code == ARES_EINTERNAL_INVALID_NAME) {
    return ARES_EBADQUERY;
  }

  if (internal_code == ARES_EINTERNAL_TRUNCATED) {
    return ARES_EBADRESP;
  }

  if (internal_code == ARES_EINTERNAL_MALFORMED_RESPONSE ||
      internal_code == ARES_EINTERNAL_INVALID_RDATA) {
    return ARES_EBADRESP;
  }

  /* Connection and communication errors */
  if (internal_code == ARES_EINTERNAL_CONNECTION_FAILED ||
      internal_code == ARES_EINTERNAL_SEND_FAILED ||
      internal_code == ARES_EINTERNAL_RECV_FAILED) {
    return ARES_ECONNREFUSED;
  }

  /* Resource exhaustion */
  if (internal_code == ARES_EINTERNAL_OUT_OF_MEMORY ||
      internal_code == ARES_EINTERNAL_RESOURCE_EXHAUSTED) {
    return ARES_ENOMEM;
  }

  /* Validation and constraint errors */
  if (internal_code == ARES_EINTERNAL_INVALID_PARAMETER ||
      internal_code == ARES_EINTERNAL_INVALID_LENGTH ||
      internal_code == ARES_EINTERNAL_INVALID_ENCODING) {
    return ARES_EBADSTR;
  }

  /* State and lifecycle errors */
  if (internal_code == ARES_EINTERNAL_INVALID_STATE) {
    return ARES_ESERVFAIL;
  }

  if (internal_code == ARES_EINTERNAL_CHANNEL_DESTROYED) {
    return ARES_EDESTRUCTION;
  }

  /* Timeout and cancellation */
  if (internal_code == ARES_EINTERNAL_TIMEOUT) {
    return ARES_ETIMEOUT;
  }

  if (internal_code == ARES_EINTERNAL_CANCELLED) {
    return ARES_ECANCELLED;
  }

  /* Default fallback for unmapped codes (should not happen in production) */
  return ARES_ESERVFAIL;
}
