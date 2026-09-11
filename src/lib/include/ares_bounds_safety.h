/* MIT License
 *
 * Copyright (c) 2026 Jeff Bindel <jeff@incrediblybased.co>
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
/*
 * ares_bounds_safety.h - portability macros for optional -fbounds-safety
 *
 * When CARES_SUPPORT_FBOUNDS_SAFETY is defined (typically via
 * -DCARES_SUPPORT_FBOUNDS_SAFETY and a Clang toolchain that implements
 * -fbounds-safety), these macros expand to Clang bounds annotations.
 * Otherwise they expand to nothing so default builds are unchanged.
 *
 * Pattern matches libwebp / libpng / giflib / lz4 / zstd inert-macro
 * -fbounds-safety adoption: annotations are inert unless explicitly enabled.
 */
#ifndef __ARES__BOUNDS_SAFETY_H
#define __ARES__BOUNDS_SAFETY_H

#ifdef CARES_SUPPORT_FBOUNDS_SAFETY

#  include <ptrcheck.h>
/* Non-ABI-breaking sized-by annotations for byte buffers whose companion
 * field is a capacity / length in bytes (struct ares_buf alloc_buf /
 * alloc_buf_len and data / data_len). Use *_OR_NULL when the pointer may
 * be NULL while the companion size is zero.
 */
#  define ARES_SIZED_BY(n) __sized_by(n)
#  define ARES_SIZED_BY_OR_NULL(n) __sized_by_or_null(n)
#  define ARES_COUNTED_BY(n) __counted_by(n)
#  define ARES_COUNTED_BY_OR_NULL(n) __counted_by_or_null(n)

#else /* !CARES_SUPPORT_FBOUNDS_SAFETY */

#  define ARES_SIZED_BY(n)
#  define ARES_SIZED_BY_OR_NULL(n)
#  define ARES_COUNTED_BY(n)
#  define ARES_COUNTED_BY_OR_NULL(n)

#endif /* CARES_SUPPORT_FBOUNDS_SAFETY */

#endif /* __ARES__BOUNDS_SAFETY_H */
