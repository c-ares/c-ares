/* MIT License
 *
 * Copyright (C) 2011 by Ben Noordhuis <info@bnoordhuis.nl>
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

/* This code was originally derived from the code by Ben Noordhuis, however it
 * has been heavily modified by Brad House in these ways:
 *  - Does not take UTF32 input, instead operate directly on UTF8 input
 *  - Use c-ares buffer objects for reading and writing for memory safety
 *  - Output xn-- prefix on any encoded strings
 *  - Split domain into its components to be able to operate on domains
 * directly.
 */

#include "ares_private.h"
#include "ares_str.h"
#include "ares_punycode.h"

/* punycode parameters, see http://tools.ietf.org/html/rfc3492#section-5 */
#define BASE         36
#define TMIN         1
#define TMAX         26
#define SKEW         38
#define DAMP         700
#define INITIAL_N    128
#define INITIAL_BIAS 72

static size_t adapt_bias(size_t delta, size_t n_points, ares_bool_t is_first)
{
  size_t k;

  delta /= is_first ? DAMP : 2;
  delta += delta / n_points;

  /* while delta > 455: delta /= 35 */
  for (k = 0; delta > ((BASE - TMIN) * TMAX) / 2; k += BASE) {
    delta /= (BASE - TMIN);
  }

  return k + (((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

static unsigned char encode_digit(int c)
{
  if (c > 25) {
    return ((unsigned char)c) + 22;  /* '0'..'9' */
  } else {
    return ((unsigned char)c) + 'a'; /* 'a'..'z' */
  }
}

/* Encode as a generalized variable-length integer. Returns number of bytes
 * written. */
static ares_status_t encode_var_int(const size_t bias, const size_t delta,
                                    ares_buf_t *buf)
{
  ares_status_t status;
  size_t        k;
  size_t        q;
  size_t        t;

  k = BASE;
  q = delta;

  while (1) {
    if (k <= bias) {
      t = TMIN;
    } else if (k >= bias + TMAX) {
      t = TMAX;
    } else {
      t = k - bias;
    }

    if (q < t) {
      break;
    }

    status =
      ares_buf_append_byte(buf, encode_digit((int)(t + (q - t) % (BASE - t))));
    if (status != ARES_SUCCESS) {
      return status;
    }

    q  = (q - t) / (BASE - t);
    k += BASE;
  }

  return ares_buf_append_byte(buf, encode_digit((int)q));
}

static ares_status_t punycode_encode(ares_buf_t *inbuf, ares_buf_t *buf)
{
  ares_status_t status = ARES_SUCCESS;
  size_t        b;
  size_t        h;
  size_t        delta;
  size_t        bias;
  size_t        m;
  size_t        n;
  size_t        utf8_cnt;
  size_t        initial_len;
  unsigned int  cp;

  /* Get the total number of characters */
  status = ares_buf_len_utf8(inbuf, &utf8_cnt);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* If count matches the number of bytes, it is all ASCII */
  if (utf8_cnt == ares_buf_len(inbuf)) {
    size_t               len;
    const unsigned char *ptr = ares_buf_peek(inbuf, &len);
    return ares_buf_append(buf, ptr, len);
  }

  /* Output prefix */
  status = ares_buf_append_str(buf, "xn--");
  if (status != ARES_SUCCESS) {
    return status;
  }

  initial_len = ares_buf_len(buf);

  /* Output all ASCII characters to output buffer in order */
  ares_buf_tag(inbuf);
  while (ares_buf_len(inbuf)) {
    status = ares_buf_fetch_codepoint(inbuf, &cp);
    if (status != ARES_SUCCESS) {
      return status;
    }

    if (cp < 128) {
      status = ares_buf_append_byte(buf, (unsigned char)cp);
      if (status != ARES_SUCCESS) {
        return status;
      }
    }
  }
  ares_buf_tag_rollback(inbuf);

  b = h = ares_buf_len(buf) - initial_len;

  /* If any data written, output '-' as a delimiter */
  if (b > 0) {
    status = ares_buf_append_byte(buf, '-');
    if (status != ARES_SUCCESS) {
      return status;
    }
  }

  n     = INITIAL_N;
  bias  = INITIAL_BIAS;
  delta = 0;

  for (; h < utf8_cnt; n++, delta++) {
    /* Find next smallest non-basic code point. */
    ares_buf_tag(inbuf);
    m = SIZE_MAX;
    while (ares_buf_len(inbuf)) {
      status = ares_buf_fetch_codepoint(inbuf, &cp);
      if (status != ARES_SUCCESS) {
        return status;
      }
      if (cp >= n && cp < m) {
        m = cp;
      }
    }
    ares_buf_tag_rollback(inbuf);

    delta += (m - n) * (h + 1);
    n      = m;

    ares_buf_tag(inbuf);
    while (ares_buf_len(inbuf)) {
      status = ares_buf_fetch_codepoint(inbuf, &cp);
      if (status != ARES_SUCCESS) {
        return status;
      }
      if (cp < n) {
        delta++;
      } else if (cp == n) {
        status = encode_var_int(bias, delta, buf);
        if (status != ARES_SUCCESS) {
          return status;
        }
        bias  = adapt_bias(delta, h + 1, h == b);
        delta = 0;
        h++;
      }
    }
    ares_buf_tag_rollback(inbuf);
  }

  return ARES_SUCCESS;
}

ares_status_t ares_punycode_encode_domain_buf(ares_buf_t *inbuf, ares_buf_t *outbuf)
{
  ares_status_t status = ARES_SUCCESS;
  ares_array_t *split  = NULL;
  size_t        i;

  if (inbuf == NULL || outbuf == NULL) {
    return ARES_EFORMERR;
  }

  /* Each section of a domain must be punycode encoded separately */
  status = ares_buf_split(inbuf, (const unsigned char *)".", 1,
                          ARES_BUF_SPLIT_NONE, 0, &split);
  if (status != ARES_SUCCESS) {
    goto fail;
  }

  for (i = 0; i < ares_array_len(split); i++) {
    ares_buf_t **sect = ares_array_at(split, i);
    if (i != 0) {
      status = ares_buf_append_byte(outbuf, '.');
      if (status != ARES_SUCCESS) {
        goto fail;
      }
    }
    status = punycode_encode(*sect, outbuf);
    if (status != ARES_SUCCESS) {
      goto fail;
    }
  }

fail:
  ares_array_destroy(split);
  return status;
}

ares_status_t ares_punycode_encode_domain(const char *domain, char **out)
{
  ares_buf_t   *inbuf  = NULL;
  ares_buf_t   *outbuf = NULL;
  ares_status_t status;

  inbuf =
    ares_buf_create_const((const unsigned char *)domain, ares_strlen(domain));
  if (inbuf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  outbuf = ares_buf_create();
  if (outbuf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  status = ares_punycode_encode_domain_buf(inbuf, outbuf);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  *out   = ares_buf_finish_str(outbuf, NULL);
  outbuf = NULL;

done:
  ares_buf_destroy(inbuf);
  ares_buf_destroy(outbuf);
  return status;
}

static unsigned int decode_digit(unsigned int v)
{
  if (ares_isdigit(v)) {
    return 26 + (v - '0');
  }
  if (ares_islower(v)) {
    return v - 'a';
  }
  if (ares_isupper(v)) {
    return v - 'A';
  }
  return BASE;
}

#define UINTMAX 0xFFFFFFFF

static ares_status_t punycode_decode(ares_buf_t *inbuf, ares_buf_t *outbuf)
{
  unsigned int  n;
  unsigned int  i;
  size_t        di;
  size_t        bias;
  unsigned int *utf32  = NULL;
  ares_status_t status = ARES_SUCCESS;
  size_t        num_ascii_chars;

  if (inbuf == NULL || outbuf == NULL) {
    return ARES_EFORMERR;
  }

  /* Make sure input is all ascii-printable or its an error */
  if (!ares_buf_isprint(inbuf)) {
    return ARES_EFORMERR;
  }

  /* If it doesn't start with "xn--" then its all ascii */
  if (!ares_buf_begins_with(inbuf, (const unsigned char *)"xn--", 4)) {
    size_t               len;
    const unsigned char *ptr = ares_buf_peek(inbuf, &len);
    return ares_buf_append(outbuf, ptr, len);
  }
  ares_buf_consume(inbuf, 4);

  /* Allocate a buffer to hold utf32 codepoints that is guaranteed to be big
   * enough so we don't have to track overflows */
  utf32 = ares_malloc_zero(sizeof(*utf32) * ares_buf_len(inbuf));
  if (utf32 == NULL) {
    return ARES_ENOMEM;
  }

  ares_buf_tag(inbuf);

  /* Search for the delimiter and copy */
  num_ascii_chars = ares_buf_consume_last_charset(inbuf,
      (const unsigned char *)"-", 1, ARES_TRUE);
  if (num_ascii_chars != SIZE_MAX) {
    size_t               data_len = 0;
    const unsigned char *data     = ares_buf_tag_fetch(inbuf, &data_len);
    size_t               j;

    for (j=0; j<num_ascii_chars; j++) {
      utf32[j] = data[j];
    }
    /* Consume '-' */
    ares_buf_consume(inbuf, 1);
    di = num_ascii_chars;
  } else {
    di = 0;
  }

  ares_buf_tag_clear(inbuf);

  i    = 0;
  n    = INITIAL_N;
  bias = INITIAL_BIAS;

  for ( ; ares_buf_len(inbuf) > 0; di++) {
    size_t org_i = i;
    size_t k;
    size_t w;

    for (w = 1, k = BASE; ; k += BASE) {
      unsigned char b;
      size_t        digit;
      size_t        t;

      status = ares_buf_fetch_bytes(inbuf, &b, 1);
      if (status != ARES_SUCCESS) {
        goto done;
      }

      digit = decode_digit(b);

      if (digit >= BASE) {
        status = ARES_EFORMERR;
        goto done;
      }

      if (digit > (UINTMAX - i) / w) {
        /* OVERFLOW */
        status = ARES_EFORMERR;
        goto done;
      }

      i += digit * w;

      if (k <= bias) {
        t = TMIN;
      } else if (k >= bias + TMAX) {
        t = TMAX;
      } else {
        t = k - bias;
      }

      if (digit < t) {
        break;
      }

      if (w > UINTMAX / (BASE - t)) {
        /* OVERFLOW */
        status = ARES_EFORMERR;
        goto done;
      }

      w *= BASE - t;
    }

    bias = adapt_bias(i - org_i, di + 1, org_i == 0);

    if (i / (di + 1) > UINTMAX - n) {
      /* OVERFLOW */
      status = ARES_EFORMERR;
      goto done;
    }

    n += i / (di + 1);
    i %= (di + 1);
    memmove(utf32 + i + 1, utf32 + i, (di - i) * sizeof(*utf32));
    utf32[i++] = n;
  }

  /* Convert to UTF8 */
  for (i=0; i<di; i++) {
    status = ares_buf_append_codepoint(outbuf, utf32[i]);
    if (status != ARES_SUCCESS) {
      goto done;
    }
  }

done:
  ares_free(utf32);
  return status;
}

ares_status_t ares_punycode_decode_domain_buf(ares_buf_t *inbuf, ares_buf_t *outbuf)
{
  ares_status_t status = ARES_SUCCESS;
  ares_array_t *split  = NULL;
  size_t        i;

  if (inbuf == NULL || outbuf == NULL) {
    return ARES_EFORMERR;
  }

  /* Each section of a domain must be punycode decoded separately */
  status = ares_buf_split(inbuf, (const unsigned char *)".", 1,
                          ARES_BUF_SPLIT_NONE, 0, &split);
  if (status != ARES_SUCCESS) {
    goto fail;
  }

  for (i = 0; i < ares_array_len(split); i++) {
    ares_buf_t **sect = ares_array_at(split, i);
    if (i != 0) {
      status = ares_buf_append_byte(outbuf, '.');
      if (status != ARES_SUCCESS) {
        goto fail;
      }
    }
    status = punycode_decode(*sect, outbuf);
    if (status != ARES_SUCCESS) {
      goto fail;
    }
  }

fail:
  ares_array_destroy(split);
  return status;
}


ares_status_t ares_punycode_decode_domain(const char *domain, char **out)
{
  ares_buf_t   *inbuf  = NULL;
  ares_buf_t   *outbuf = NULL;
  ares_status_t status;

  inbuf =
    ares_buf_create_const((const unsigned char *)domain, ares_strlen(domain));
  if (inbuf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  outbuf = ares_buf_create();
  if (outbuf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  status = ares_punycode_decode_domain_buf(inbuf, outbuf);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  *out   = ares_buf_finish_str(outbuf, NULL);
  outbuf = NULL;

done:
  ares_buf_destroy(inbuf);
  ares_buf_destroy(outbuf);
  return status;
}
