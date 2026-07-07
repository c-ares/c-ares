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
#include "ares_idnamap.h"

/* punycode parameters, see http://tools.ietf.org/html/rfc3492#section-5 */
#define BASE         36
#define TMIN         1
#define TMAX         26
#define SKEW         38
#define DAMP         700
#define INITIAL_N    128
#define INITIAL_BIAS 72

/* RFC 3492 requires detection of overflow in the delta arithmetic.  Deltas
 * are represented here as size_t but bounded to 32 bits as per the RFC's
 * recommendation for the minimum viable maxint. */
#define PUNY_MAXINT ((size_t)0xFFFFFFFF)

/* Maximum length of a single DNS label as per RFC 1035 */
#define MAX_DNS_LABEL_LEN 63

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

static unsigned char encode_digit(size_t c)
{
  if (c > 25) {
    return (unsigned char)(c + 22);  /* '0'..'9' */
  } else {
    return (unsigned char)(c + 'a'); /* 'a'..'z' */
  }
}

/* Encode as a generalized variable-length integer. */
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

    status = ares_buf_append_byte(buf, encode_digit(t + (q - t) % (BASE - t)));
    if (status != ARES_SUCCESS) {
      return status;
    }

    q  = (q - t) / (BASE - t);
    k += BASE;
  }

  return ares_buf_append_byte(buf, encode_digit(q));
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

    /* Overflow check as per RFC 3492 Section 6.3 */
    if (m - n > (PUNY_MAXINT - delta) / (h + 1)) {
      return ARES_EBADNAME;
    }

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
        if (delta > PUNY_MAXINT) {
          return ARES_EBADNAME;
        }
      } else if (cp == n) {
        status = encode_var_int(bias, delta, buf);
        if (status != ARES_SUCCESS) {
          return status;
        }
        bias  = adapt_bias(delta, h + 1, h == b ? ARES_TRUE : ARES_FALSE);
        delta = 0;
        h++;
      }
    }
    ares_buf_tag_rollback(inbuf);
  }

  return ARES_SUCCESS;
}

ares_status_t ares_punycode_encode_domain_buf(ares_buf_t *inbuf,
                                              ares_buf_t *outbuf)
{
  ares_status_t status = ARES_SUCCESS;
  ares_array_t *split  = NULL;
  size_t        i;

  if (inbuf == NULL || outbuf == NULL) {
    return ARES_EFORMERR;
  }

  /* Each section of a domain must be punycode encoded separately.  Blank
   * sections are preserved so a fully-qualified domain's trailing dot (and
   * any malformed empty label, for downstream validation to see) survives */
  status = ares_buf_split(inbuf, (const unsigned char *)".", 1,
                          ARES_BUF_SPLIT_ALLOW_BLANK, 0, &split);
  if (status != ARES_SUCCESS) {
    goto fail;
  }

  for (i = 0; i < ares_array_len(split); i++) {
    ares_buf_t **sect = ares_array_at(split, i);
    size_t       label_start;

    if (i != 0) {
      status = ares_buf_append_byte(outbuf, '.');
      if (status != ARES_SUCCESS) {
        goto fail;
      }
    }

    label_start = ares_buf_len(outbuf);

    status = punycode_encode(*sect, outbuf);
    if (status != ARES_SUCCESS) {
      goto fail;
    }

    /* An encoded label that exceeds the DNS label limit can never be used */
    if (ares_buf_len(outbuf) - label_start > MAX_DNS_LABEL_LEN) {
      status = ARES_EBADNAME;
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

  if (domain == NULL || out == NULL) {
    return ARES_EFORMERR;
  }

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

static size_t decode_digit(unsigned char v)
{
  if (ares_isdigit(v)) {
    return 26 + (v - '0');
  }
  if (ares_islower(v)) {
    return (size_t)(v - 'a');
  }
  if (ares_isupper(v)) {
    return (size_t)(v - 'A');
  }
  return BASE;
}

static ares_status_t punycode_decode(ares_buf_t *inbuf, ares_buf_t *outbuf)
{
  size_t        n;
  size_t        i;
  size_t        bias;
  ares_array_t *codepoints = NULL;
  ares_status_t status     = ARES_SUCCESS;
  size_t        num_ascii_chars;
  size_t        idx;

  if (inbuf == NULL || outbuf == NULL) {
    return ARES_EFORMERR;
  }

  /* Empty labels (e.g. the root from a fully-qualified domain's trailing
   * dot) pass through, same as the encode direction */
  if (ares_buf_len(inbuf) == 0) {
    return ARES_SUCCESS;
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

  codepoints = ares_array_create(sizeof(unsigned int), NULL);
  if (codepoints == NULL) {
    return ARES_ENOMEM;
  }

  ares_buf_tag(inbuf);

  /* Search for the delimiter and copy the basic codepoints preceding it */
  num_ascii_chars = ares_buf_consume_last_charset(
    inbuf, (const unsigned char *)"-", 1, ARES_TRUE);
  if (num_ascii_chars != SIZE_MAX) {
    size_t               data_len = 0;
    const unsigned char *data     = ares_buf_tag_fetch(inbuf, &data_len);
    size_t               j;

    for (j = 0; j < num_ascii_chars; j++) {
      unsigned int *cp = NULL;

      status = ares_array_insert_last((void **)&cp, codepoints);
      if (status != ARES_SUCCESS) {
        goto done;
      }
      *cp = data[j];
    }
    /* Consume '-' */
    ares_buf_consume(inbuf, 1);
  }

  ares_buf_tag_clear(inbuf);

  i    = 0;
  n    = INITIAL_N;
  bias = INITIAL_BIAS;

  while (ares_buf_len(inbuf) > 0) {
    size_t        org_i = i;
    size_t        cnt   = ares_array_len(codepoints);
    size_t        k;
    size_t        w;
    unsigned int *cp = NULL;

    for (w = 1, k = BASE;; k += BASE) {
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

      if (digit > (PUNY_MAXINT - i) / w) {
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

      if (w > PUNY_MAXINT / (BASE - t)) {
        /* OVERFLOW */
        status = ARES_EFORMERR;
        goto done;
      }

      w *= BASE - t;
    }

    bias = adapt_bias(i - org_i, cnt + 1, org_i == 0 ? ARES_TRUE : ARES_FALSE);

    if (i / (cnt + 1) > PUNY_MAXINT - n) {
      /* OVERFLOW */
      status = ARES_EFORMERR;
      goto done;
    }

    n += i / (cnt + 1);
    i %= (cnt + 1);

    status = ares_array_insert_at((void **)&cp, codepoints, i);
    if (status != ARES_SUCCESS) {
      goto done;
    }
    *cp = (unsigned int)n;
    i++;
  }

  /* Convert to UTF8.  ares_buf_append_codepoint() rejects decoded values
   * that aren't valid Unicode scalar values (surrogates, > U+10FFFF). */
  for (idx = 0; idx < ares_array_len(codepoints); idx++) {
    const unsigned int *cp = ares_array_at(codepoints, idx);

    status = ares_buf_append_codepoint(outbuf, *cp);
    if (status != ARES_SUCCESS) {
      goto done;
    }
  }

done:
  ares_array_destroy(codepoints);
  return status;
}

ares_status_t ares_punycode_decode_domain_buf(ares_buf_t *inbuf,
                                              ares_buf_t *outbuf)
{
  ares_status_t status = ARES_SUCCESS;
  ares_array_t *split  = NULL;
  size_t        i;

  if (inbuf == NULL || outbuf == NULL) {
    return ARES_EFORMERR;
  }

  /* Each section of a domain must be punycode decoded separately.  Blank
   * sections are preserved, matching the encode direction */
  status = ares_buf_split(inbuf, (const unsigned char *)".", 1,
                          ARES_BUF_SPLIT_ALLOW_BLANK, 0, &split);
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

  if (domain == NULL || out == NULL) {
    return ARES_EFORMERR;
  }

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

static int ares_idnamap_cmp(const void *key, const void *member)
{
  const unsigned int        *cp = key;
  const ares_idnamap_data_t *e  = member;

  if (*cp < e->code_min) {
    return -1;
  }
  if (*cp > e->code_max) {
    return 1;
  }
  return 0;
}

/*! Search the UTS #46 IDNA mapping table.  Returns NULL if the codepoint has
 *  no entry, meaning it is valid and used as-is. */
static const ares_idnamap_data_t *ares_idnamap_lookup(unsigned int cp)
{
  return bsearch(&cp, ares_idnamap_data, ares_idnamap_data_len,
                 sizeof(*ares_idnamap_data), ares_idnamap_cmp);
}

/*! Apply the UTS #46 mapping step to an entire domain.  This must occur
 *  before splitting into labels since some codepoints (e.g. U+3002
 *  IDEOGRAPHIC FULL STOP) map to '.' */
static ares_status_t ares_idna_map_buf(ares_buf_t *inbuf, ares_buf_t *outbuf)
{
  ares_status_t status = ARES_SUCCESS;

  while (ares_buf_len(inbuf) > 0) {
    unsigned int               cp;
    const ares_idnamap_data_t *entry;

    status = ares_buf_fetch_codepoint(inbuf, &cp);
    if (status != ARES_SUCCESS) {
      return status;
    }

    /* ASCII passes through directly (lowercased for canonical form) without
     * consulting the table.  The table marks some ASCII such as '_' as
     * disallowed via the non-normative NV8 IDNA2008 exclusions, but those
     * characters are in widespread DNS use (e.g. service labels like _ldap).
     * Hostname validity of ASCII is enforced when the query is written. */
    if (cp < 0x80) {
      status = ares_buf_append_byte(outbuf, ares_tolower((unsigned char)cp));
      if (status != ARES_SUCCESS) {
        return status;
      }
      continue;
    }

    entry = ares_idnamap_lookup(cp);
    if (entry == NULL) {
      /* Valid, used as-is */
      status = ares_buf_append_codepoint(outbuf, cp);
      if (status != ARES_SUCCESS) {
        return status;
      }
      continue;
    }

    switch (entry->status) {
      case ARES_IDNA_STATUS_DISALLOWED:
        return ARES_EBADNAME;
      case ARES_IDNA_STATUS_IGNORED:
        break;
      case ARES_IDNA_STATUS_MAPPED:
        status = ares_buf_append(
          outbuf, &ares_idnamap_data_pool[entry->map_offset], entry->map_len);
        if (status != ARES_SUCCESS) {
          return status;
        }
        break;
      default:
        /* Can't happen with a well-formed table */
        return ARES_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  }

  return status;
}

ares_status_t ares_idna_encode_domain_buf(ares_buf_t *inbuf, ares_buf_t *outbuf)
{
  ares_buf_t   *mapped = NULL;
  ares_status_t status;

  if (inbuf == NULL || outbuf == NULL) {
    return ARES_EFORMERR;
  }

  mapped = ares_buf_create();
  if (mapped == NULL) {
    return ARES_ENOMEM;
  }

  status = ares_idna_map_buf(inbuf, mapped);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_punycode_encode_domain_buf(mapped, outbuf);

done:
  ares_buf_destroy(mapped);
  return status;
}

ares_status_t ares_idna_encode_domain(const char *domain, char **out)
{
  ares_buf_t   *inbuf  = NULL;
  ares_buf_t   *outbuf = NULL;
  ares_status_t status;

  if (domain == NULL || out == NULL) {
    return ARES_EFORMERR;
  }

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

  status = ares_idna_encode_domain_buf(inbuf, outbuf);
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
