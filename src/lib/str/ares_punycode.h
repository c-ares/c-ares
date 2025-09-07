/* MIT License
 *
 * Copyright (c) Brad House
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
#ifndef __ARES_PUNYCODE_H
#define __ARES_PUNYCODE_H


/*! Punycode encode a domain as per RFC3492 from buf to buf.
 *
 *  This function will split the domain into each component then punycode encode
 *  it and rejoin the components.  If there are no UTF8 codepoints outside the
 *  ascii range this will return the same as the input, but it is, however, an
 *  expensive operation and users should scan the domain to see if conversion is
 *  really necessary before calling this function.
 *
 *  \param[in]     inbuf  Input domain name
 *  \param[in,out] outbuf Output punycode encoded domain
 *  \return ARES_SUCCESS on success, or otherwise an ares_status_t error.
 */
ares_status_t ares_punycode_encode_domain_buf(ares_buf_t *inbuf, ares_buf_t *outbuf);

/*! Punycode encode a domain as per RFC3492 from string to string.
 *
 *  This function will split the domain into each component then punycode encode
 *  it and rejoin the components.  If there are no UTF8 codepoints outside the
 *  ascii range this will return the same as the input, but it is, however, an
 *  expensive operation and users should scan the domain to see if conversion is
 *  really necessary before calling this function.
 *
 *  \param[in]  domain  Input domain name
 *  \param[out] out     Output punycode encoded domain
 *  \return ARES_SUCCESS on success, or otherwise an ares_status_t error.
 */
ares_status_t ares_punycode_encode_domain(const char *domain, char **out);

/*! Punycode decode a domain as per RFC3492 from buf to buf.
 *
 *  This function will split the domain into each component then punycode decode
 *  it and rejoin the components.  If the passed in domain doesn't have any
 *  sections starting with "xn--" this will return the same as the input, but
 *  it is, however, an expensive operation and users should scan the domain to
 *  see if conversion is really necessary before calling this function.
 *
 *  \param[in]     inbuf  Input domain name
 *  \param[in,out] outbuf Output punycode decoded domain
 *  \return ARES_SUCCESS on success, or otherwise an ares_status_t error.
 */
ares_status_t ares_punycode_decode_domain_buf(ares_buf_t *inbuf, ares_buf_t *outbuf);

/*! Punycode decode a domain as per RFC3492 from string to string.
 *
 *  This function will split the domain into each component then punycode decode
 *  it and rejoin the components.  If the passed in domain doesn't have any
 *  sections starting with "xn--" this will return the same as the input, but
 *  it is, however, an expensive operation and users should scan the domain to
 *  see if conversion is really necessary before calling this function.
 *
 *  \param[in]  domain  Input domain name
 *  \param[out] out     Output punycode decoded domain
 *  \return ARES_SUCCESS on success, or otherwise an ares_status_t error.
 */
ares_status_t ares_punycode_decode_domain(const char *domain, char **out);

#endif
