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
#ifndef __ARES__BUF_H
#define __ARES__BUF_H

/*! \addtogroup ares__buf Safe Data Builder and buffer
 *
 * This is a buffer building and parsing framework with a focus on security over
 * performance. All data to be read from the buffer will perform explicit length
 * validation and return a success/fail result.  There are also various helpers
 * for writing data to the buffer which dynamically grows.
 *
 * The helpers for this object are meant to be added as needed.  If you can't
 * find it, write it!
 *
 * @{
 */
struct ares__buf;

/*! Opaque data type for generic hash table implementation */
typedef struct ares__buf ares__buf_t;

/*! Create a new buffer object that dynamically allocates buffers for data.
 * 
 *  \return initialized buffer object or NULL if out of memory.
 */
ares__buf_t *ares__buf_create(void);

/*! Create a new buffer object that uses a user-provided data pointer.  The
 *  data provided will not be manipulated, and cannot be appended to.  This
 *  is strictly used for parsing.
 *
 *  \param[in] data     Data to provide to buffer, must not be NULL.
 *  \param[in] data_len Size of buffer provided, must be > 0
 *
 *  \return initialized buffer object or NULL if out of memory or misuse.
 */
ares__buf_t *ares__buf_create_const(const unsigned char *data, size_t data_len);

/*! Destroy an initialized buffer object.
 *
 *  \param[in] buf  Initialized buf object
 */
void ares__buf_destroy(ares__buf_t *buf);

/*! Append to a dynamic buffer object
 *
 *  \param[in] buf      Initialized buffer object
 *  \param[in] data     Data to copy to buffer object
 *  \param[in] data_len Length of data to copy to buffer object.
 *  \return 1 on success, 0 on failure (out of memory, const buffer, usage, etc)
 */
int ares__buf_append(ares__buf_t *buf, const unsigned char *data,
                     size_t data_len);


/*! Start a dynamic append operation that returns a buffer suitable for
 *  writing.  A desired minimum length is passed in, and the actual allocated
 *  buffer size is returned which may be greater than the requested size.
 *  No operation other than ares__buf_append_finish() is allowed on the
 *  buffer after this request.
 *
 *  \param[in]     buf     Initialized buffer object
 *  \param[in,out] len     Desired non-zero length passed in, actual buffer size
 *                         returned.
 *  \return Pointer to writable buffer or NULL on failure (usage, out of mem)
 */
unsigned char *ares__buf_append_start(ares__buf_t *buf, size_t *len);

/*! Finish a dynamic append operation.  Called after
 *  ares__buf_append_start() once desired data is written.
 *
 *  \param[in] buf    Initialized buffer object.
 *  \param[in] len    Length of data written.  May be zero to terminate
 *                    operation. Must not be greater than returned from
 *                    ares__buf_append_start().
 */
void ares__buf_append_finish(ares__buf_t *buf, size_t len);

/*! Tag a position to save in the buffer in case parsing needs to rollback,
 *  such as if insufficient data is available, but more data may be added in
 *  the future.  Only a single tag can be set per buffer object.  Setting a
 *  tag will override any pre-existing tag.
 *
 *  \param[in] buf Initialized buffer object
 */
void ares__buf_tag(ares__buf_t *buf);

/*! Rollback to a tagged position.  Will automatically clear the tag.
 *
 *  \param[in] buf Initialized buffer object
 *  \return 1 on success, 0 if no tag
 */
int ares__buf_tag_rollback(ares__buf_t *buf);

/*! Clear the tagged position without rolling back.  You should do this any
 *  time a tag is no longer needed as future append operations can reclaim
 *  buffer space.
 *
 *  \param[in] buf Initialized buffer object
 *  \return 1 on success, 0 if no tag
 */
int ares__buf_tag_clear(ares__buf_t *buf);

/*! Fetch the buffer and length of data starting from the tagged position up
 *  to the _current_ position.  It will not unset the tagged position.  The
 *  data may be invalidated by any future ares__buf_*() calls.
 *
 *  \param[in]  buf    Initialized buffer object
 *  \param[out] len    Length between tag and current offset in buffer
 *  \return NULL on failure (such as no tag), otherwise pointer to start of
 *          buffer
 */
const unsigned char *ares__buf_tag_fetch(const ares__buf_t *buf, size_t *len);

/*! Consume the given number of bytes without reading them.
 *
 *  \param[in] buf    Initialized buffer object
 *  \param[in] len    Length to consume
 *  \return 1 on success, 0 if insufficient buffer remaining
 */
int ares__buf_consume(ares__buf_t *buf, size_t len);

/*! Fetch a 16bit Big Endian number from the buffer.
 *
 *  \param[in]  buf     Initialized buffer object
 *  \param[out] u16     Buffer to hold 16bit integer
 *  \return 1 on success, 0 if insufficient buffer remaining
 */
int ares__buf_fetch_be16(ares__buf_t *buf, unsigned short *u16);

/*! Fetch the requested number of bytes into the provided buffer
 *
 *  \param[in]  buf     Initialized buffer object
 *  \param[out] bytes   Buffer to hold data
 *  \param[in]  len     Requested number of bytes (must be > 0)
 *  \return 1 on success, 0 if insufficient buffer remaining (or misuse)
 */
int ares__buf_fetch_bytes(ares__buf_t *buf, unsigned char *bytes,
                          size_t len);

/*! Size of unprocessed remaining data length
 *
 *  \param[in] buf Initialized buffer object
 *  \return length remaining
 */
size_t ares__buf_len(const ares__buf_t *buf);

/*! Retrieve a pointer to the currently unprocessed data.  Generally this isn't
 *  recommended to be used in practice.  The returned pointer may be invalidated
 *  by any future ares__buf_*() calls.
 *
 *  \param[in]  buf    Initialized buffer object
 *  \param[out] len    Length of available data
 *  \return Pointer to buffer of unprocessed data
 */
const unsigned char *ares__buf_peek(const ares__buf_t *buf,
                                       size_t *len);

#if 0
int ares__buf_fetch_dnsheader(ares__buf_t *buf, ares_dns_header_t *header);
#endif

/*! @} */

#endif /* __ARES__buffer_H */
