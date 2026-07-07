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
 *  \param[in,out] inbuf  Input domain name.  Consumed by this function.
 *  \param[in,out] outbuf Output punycode encoded domain.  On error may
 *                        contain a partially-encoded name.
 *  \return ARES_SUCCESS on success, ARES_EBADNAME if an encoded label
 *          exceeds the DNS label length limit or the delta arithmetic would
 *          overflow, or otherwise an ares_status_t error.
 */
CARES_EXTERN ares_status_t ares_punycode_encode_domain_buf(ares_buf_t *inbuf,
                                                           ares_buf_t *outbuf);

/*! Punycode encode a domain as per RFC3492 from string to string.  See
 *  ares_punycode_encode_domain_buf() for details.
 *
 *  \param[in]  domain  Input domain name
 *  \param[out] out     Output punycode encoded domain
 *  \return ARES_SUCCESS on success, or otherwise an ares_status_t error.
 */
CARES_EXTERN ares_status_t ares_punycode_encode_domain(const char *domain,
                                                       char      **out);

/*! Punycode decode a domain as per RFC3492 from buf to buf.
 *
 *  This function will split the domain into each component then punycode decode
 *  it and rejoin the components.  Labels not starting with the "xn--" ACE
 *  prefix (compared case-insensitively as per RFC 5890) contain no encoded
 *  data and are passed through as-is, so a domain with no encoded labels
 *  returns the same as the input.  It is, however, an expensive operation and
 *  users should scan the domain to see if conversion is really necessary
 *  before calling this function.
 *
 *  \param[in,out] inbuf  Input domain name.  Consumed by this function.
 *  \param[in,out] outbuf Output punycode decoded domain.  On error may
 *                        contain a partially-decoded name.
 *  \return ARES_SUCCESS on success, ARES_EBADNAME if an encoded label is
 *          not printable ASCII, exceeds the DNS label length limit, or is
 *          not valid punycode, or otherwise an ares_status_t error.
 */
CARES_EXTERN ares_status_t ares_punycode_decode_domain_buf(ares_buf_t *inbuf,
                                                           ares_buf_t *outbuf);

/*! Punycode decode a domain as per RFC3492 from string to string.  See
 *  ares_punycode_decode_domain_buf() for details.
 *
 *  \param[in]  domain  Input domain name
 *  \param[out] out     Output punycode decoded domain
 *  \return ARES_SUCCESS on success, or otherwise an ares_status_t error.
 */
CARES_EXTERN ares_status_t ares_punycode_decode_domain(const char *domain,
                                                       char      **out);

/*! IDNA encode a domain from buf to buf: apply the UTS #46 mapping step
 *  (nontransitional, casefolding, removing ignored codepoints, and rejecting
 *  disallowed codepoints), then punycode encode each label as per RFC3492.
 *
 *  This is the function to use for converting a user-visible unicode domain
 *  into the ASCII form used on the wire.  Known divergences from a full
 *  UTS #46 implementation:
 *   - NFC normalization of the mapped output is NOT performed; input that is
 *     not already in NFC form (rare in practice, e.g. decomposed sequences
 *     from macOS filenames) may produce a different label than a conforming
 *     implementation.
 *   - The CheckHyphens, CheckBidi and CheckJoiners (ContextJ) validation
 *     steps are not performed (e.g. ZWJ/ZWNJ are accepted context-free).
 *   - The non-normative IDNA2008 NV8/XV8 exclusions are treated as
 *     disallowed for unicode codepoints, which is stricter than web browsers:
 *     e.g. emoji domains that browsers resolve are rejected here.
 *
 *  \param[in,out] inbuf  Input domain name in UTF-8.  Consumed by this
 *                        function.
 *  \param[in,out] outbuf Output IDNA (punycode) encoded domain.  On error
 *                        may contain a partially-encoded name.
 *  \return ARES_SUCCESS on success, ARES_EBADNAME if the domain contains
 *          disallowed codepoints or an encoded label exceeds the DNS label
 *          length limit, or otherwise an ares_status_t error.
 */
CARES_EXTERN ares_status_t ares_idna_encode_domain_buf(ares_buf_t *inbuf,
                                                       ares_buf_t *outbuf);

/*! IDNA encode a domain from string to string.  See
 *  ares_idna_encode_domain_buf() for details.
 *
 *  \param[in]  domain  Input domain name in UTF-8
 *  \param[out] out     Output IDNA (punycode) encoded domain
 *  \return ARES_SUCCESS on success, or otherwise an ares_status_t error.
 */
CARES_EXTERN ares_status_t ares_idna_encode_domain(const char *domain,
                                                   char      **out);

#endif
