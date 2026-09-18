/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
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

#ifndef __ARES_MEM_H
#define __ARES_MEM_H

/* Memory management functions */
CARES_EXTERN void *ares_malloc(size_t size);
CARES_EXTERN void *ares_realloc(void *ptr, size_t size);
CARES_EXTERN void ares_free(void *ptr);
CARES_EXTERN void *ares_malloc_zero(size_t size);
CARES_EXTERN void *ares_realloc_zero(void *ptr, size_t orig_size,
                                     size_t new_size);

/* Array allocation functions.
 *
 * Any allocation whose size is a count multiplied by an element size must use
 * one of these rather than open-coding the multiplication, so that a count
 * large enough to wrap size_t fails the allocation instead of silently
 * producing a short buffer that the caller then indexes past. */

/*! Allocate an array of elements, checking the size calculation for overflow.
 *  The returned memory is not initialized.
 *
 *  \param[in] num   Number of elements
 *  \param[in] size  Size of each element in bytes
 *  \return pointer to the allocated array, or NULL if num * size overflows
 *          size_t or the allocation fails.
 */
CARES_EXTERN void *ares_malloc_array(size_t num, size_t size);

/*! Allocate an array of elements, checking the size calculation for overflow.
 *  The returned memory is zero-filled.
 *
 *  \param[in] num   Number of elements
 *  \param[in] size  Size of each element in bytes
 *  \return pointer to the allocated array, or NULL if num * size overflows
 *          size_t or the allocation fails.
 */
CARES_EXTERN void *ares_malloc_zero_array(size_t num, size_t size);

/*! Resize an array of elements, checking the size calculation for overflow.
 *  Any newly added elements are not initialized.  On failure the original
 *  array is left untouched and still owned by the caller.
 *
 *  \param[in] ptr   Existing array, or NULL to allocate a new one
 *  \param[in] num   New number of elements
 *  \param[in] size  Size of each element in bytes
 *  \return pointer to the resized array, or NULL if num * size overflows
 *          size_t or the allocation fails.
 */
CARES_EXTERN void *ares_realloc_array(void *ptr, size_t num, size_t size);

/*! Resize an array of elements, checking the size calculations for overflow.
 *  Any newly added elements are zero-filled.  On failure the original array is
 *  left untouched and still owned by the caller.
 *
 *  \param[in] ptr       Existing array, or NULL to allocate a new one
 *  \param[in] orig_num  Current number of elements in ptr
 *  \param[in] new_num   New number of elements
 *  \param[in] size      Size of each element in bytes
 *  \return pointer to the resized array, or NULL if either orig_num * size or
 *          new_num * size overflows size_t or the allocation fails.
 */
CARES_EXTERN void *ares_realloc_zero_array(void *ptr, size_t orig_num,
                                           size_t new_num, size_t size);

#endif
