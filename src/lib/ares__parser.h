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
#ifndef __ARES__PARSER_H
#define __ARES__PARSER_H

/*! \addtogroup ares__parser Safe Data Parser
 *
 * This is a parsing framework with a focus on security over performance. All
 * data to be read from the parser will perform explicit length validation
 * and return a success/fail result.
 *
 * @{
 */
struct ares__parser;

/*! Opaque data type for generic hash table implementation */
typedef struct ares__parser ares__parser_t;

/*! Create a new parser object that dynamically allocates buffers for data.
 * 
 *  \return initialized parser object or NULL if out of memory.
 */
ares__parser_t *ares__parser_create(void);

/*! Create a new parser object that uses a user-provided data pointer.  The
 *  data provided will not be manipulated.
 *
 *  \param[in] buf     Buffer to provide to parser, must not be NULL.
 *  \param[in] buf_len Size of buffer provided, must be > 0
 *
 *  \return initialized parser object or NULL if out of memory or misuse.
 */
ares__parser_t *ares__parser_create_const(const unsigned char *buf,
                                          size_t buf_len);

/*! Destroy an initialized parser object.
 *
 *  \param[in] parser  Initialized parser object
 */
void ares__parser_destroy(ares__parser_t *parser);

/*! Append to a dynamic parser object
 *
 *  \param[in] parser  Initialized parser object
 *  \param[in] buf     Buffer to copy to parser object
 *  \param[in] buf_len Length of buffer to copy to parser object.
 *  \return 1 on success, 0 on failure (out of memory, const parser, usage, etc)
 */
int ares__parser_append(ares__parser_t *parser, const unsigned char *buf,
                        size_t buf_len);


/*! Start a dynamic append operation that returns a buffer suitable for
 *  writing.  A desired minimum length is passed in, and the actual allocated
 *  buffer size is returned which may be greater than the requested size.
 *  No operation other than ares__parser_append_finish() is allowed on the
 *  parser after this request.
 *
 *  \param[in]     parser  Initialized parser object
 *  \param[in,out] len     Desired non-zero length passed in, actual buffer size
 *                         returned.
 *  \return Pointer to writable buffer or NULL on failure (usage, out of mem)
 */
unsigned char *ares__parser_append_start(ares__parser_t *parser, size_t *len);

/*! Finish a dynamic append operation.  Called after
 *  ares__parser_append_start() once desired data is written.
 *
 *  \param[in] parser Initialized parser object.
 *  \param[in] len    Length of data written.  May be zero to terminate
 *                    operation. Must not be greater than returned from
 *                    ares__parser_append_start().
 */
void ares__parser_append_finish(ares__parser_t *parser, size_t len);

/*! Tag a position to save in the parser in case parsing needs to rollback,
 *  such as if insufficient data is available, but more data may be added in
 *  the future.  Only a single tag can be set per parser object.  Setting a
 *  tag will override any pre-existing tag.
 *
 *  \param[in] parser Initialized parser object
 */
void ares__parser_tag(ares__parser_t *parser);

/*! Rollback to a tagged position.  Will automatically clear the tag.
 *
 *  \param[in] parser Initialized parser object
 *  \return 1 on success, 0 if no tag
 */
int ares__parser_tag_rollback(ares__parser_t *parser);

/*! Clear the tagged position without rolling back.  You should do this any
 *  time a tag is no longer needed as future append operations can reclaim
 *  buffer space.
 *
 *  \param[in] parser Initialized parser object
 *  \return 1 on success, 0 if no tag
 */
int ares__parser_tag_clear(ares__parser_t *parser);

/*! Fetch the buffer and length of data starting from the tagged position up
 *  to the _current_ position.  It will not unset the tagged position.  The
 *  data may be invalidated by any future ares__parser_*() calls.
 *
 *  \param[in]  parser Initialized parser object
 *  \param[out] len    Length between tag and current offset in parser
 *  \return NULL on failure (such as no tag), otherwise pointer to start of
 *          buffer
 */
const unsigned char *ares__parser_tag_fetch(const ares__parser_t *parser, size_t *len);

/*! Consume the given number of bytes without reading them.
 *
 *  \param[in] parser Initialized parser object
 *  \param[in] len    Length to consume
 *  \return 1 on success, 0 if insufficient buffer remaining
 */
int ares__parser_consume(ares__parser_t *parser, size_t len);

/*! Fetch a 16bit Big Endian number from the parser.
 *
 *  \param[in]  parser  Initialized parser object
 *  \param[out] u16     Buffer to hold 16bit integer
 *  \return 1 on success, 0 if insufficient buffer remaining
 */
int ares__parser_fetch_be16(ares__parser_t *parser, unsigned short *u16);

/*! Fetch the requested number of bytes into the provided buffer
 *
 *  \param[in]  parser  Initialized parser object
 *  \param[out] bytes   Buffer to hold data
 *  \param[in]  len     Requested number of bytes (must be > 0)
 *  \return 1 on success, 0 if insufficient buffer remaining (or misuse)
 */
int ares__parser_fetch_bytes(ares__parser_t *parser, unsigned char *bytes,
                             size_t len);

/*! Size of unprocessed remaining data length
 *
 *  \param[in] parser Initialized parser object
 *  \return length remaining
 */
size_t ares__parser_len(const ares__parser_t *parser);

/*! Retrieve a pointer to the currently unprocessed data.  Generally this isn't
 *  recommended to be used in practice.  The returned pointer may be invalidated
 *  by any future ares__parser_*() calls.
 *
 *  \param[in]  parser Initialized parser object
 *  \param[out] len    Length of available data
 *  \return Pointer to buffer of unprocessed data
 */
const unsigned char *ares__parser_peek(const ares__parser_t *parser,
                                       size_t *len);

#if 0
int ares__parser_fetch_dnsheader(ares__parser_t *parser, ares_dns_header_t *header);
#endif

/*! @} */

#endif /* __ARES__PARSER_H */
