/* MIT License
 *
 * Copyright (c) 2023 Brad House
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
#include "ares_private.h"

typedef struct {
  char  *name;
  size_t name_len;
  size_t idx;
} ares_nameoffset_t;

static void ares__nameoffset_free(void *arg)
{
  ares_nameoffset_t *off = arg;
  if (off == NULL) {
    return;
  }
  ares_free(off->name);
  ares_free(off);
}

static ares_status_t ares__nameoffset_create(ares__llist_t **list,
                                             const char *name, size_t idx)
{
  ares_status_t      status;
  ares_nameoffset_t *off = NULL;

  if (list == NULL || name == NULL || ares_strlen(name) == 0 ||
      ares_strlen(name) > 255) {
    return ARES_EFORMERR;
  }

  if (*list == NULL) {
    *list = ares__llist_create(ares__nameoffset_free);
  }
  if (*list == NULL) {
    status = ARES_ENOMEM;
    goto fail;
  }

  off = ares_malloc_zero(sizeof(*off));
  if (off == NULL) {
    return ARES_ENOMEM;
  }

  off->name     = ares_strdup(name);
  off->name_len = ares_strlen(off->name);
  off->idx      = idx;

  if (ares__llist_insert_last(*list, off) == NULL) {
    status = ARES_ENOMEM;
    goto fail;
  }

  status = ARES_SUCCESS;

fail:
  ares__nameoffset_free(off);
  return status;
}

static const ares_nameoffset_t *ares__nameoffset_find(ares__llist_t *list,
                                                      const char    *name)
{
  size_t                   name_len = ares_strlen(name);
  ares__llist_node_t      *node;
  const ares_nameoffset_t *longest_match = NULL;

  if (list == NULL || name == NULL || name_len == 0) {
    return NULL;
  }

  for (node = ares__llist_node_first(list); node != NULL;
       node = ares__llist_node_next(node)) {
    const ares_nameoffset_t *val = ares__llist_node_val(node);
    size_t                   prefix_len;

    /* Can't be a match if the stored name is longer */
    if (val->name_len > name_len) {
      continue;
    }

    /* Can't be the longest match if our existing longest match is longer */
    if (longest_match != NULL && longest_match->name_len > val->name_len) {
      continue;
    }

    prefix_len = name_len - val->name_len;

    if (strcasecmp(val->name, name + prefix_len) != 0) {
      continue;
    }

    /* We need to make sure if `val->name` is "example.com" that name is
     * is separated by a label, e.g. "myexample.com" is not ok, however
     * "my.example.com" is, so we look for the preceding "." */
    if (prefix_len != 0 && name[prefix_len - 1] != '.') {
      continue;
    }

    longest_match = val;
  }

  return longest_match;
}

typedef struct {
  unsigned char label[63];
  size_t        len;
} ares_dns_label_t;

static ares_status_t ares_parse_dns_name_escape(const char *ptr, size_t ptr_len,
                                                ares_bool_t validate_hostname,
                                                unsigned char *out,
                                                size_t        *consumed_chars)
{
  /* Must have at least 1 more character */
  if (ptr_len < 2) {
    return ARES_EBADNAME;
  }

  /* If next character is a digit, must have 3 */
  if (isdigit(ptr[1])) {
    int  i;
    char num[4];

    if (ptr_len < 4) {
      return ARES_EBADNAME;
    }

    /* Must all be digits */
    if (!isdigit(ptr[2]) || !isdigit(ptr[3])) {
      return ARES_EBADNAME;
    }

    num[0] = ptr[1];
    num[1] = ptr[2];
    num[2] = ptr[3];
    num[3] = 0;
    i      = atoi(num);

    /* Out of range */
    if (i > 255) {
      return ARES_EBADNAME;
    }

    if (validate_hostname && !ares__is_hostnamech((unsigned char)i)) {
      return ARES_EBADNAME;
    }

    *out            = (unsigned char)i;
    *consumed_chars = 3;
    return ARES_SUCCESS;
  }

  /* We can just output the character */
  if (validate_hostname && !ares__is_hostnamech(ptr[1])) {
    return ARES_EBADNAME;
  }

  *out            = (unsigned char)ptr[1];
  *consumed_chars = 1;
  return ARES_SUCCESS;
}

static ares_status_t ares_split_dns_name(ares_dns_label_t **labels_out,
                                         size_t            *num_labels_out,
                                         ares_bool_t        validate_hostname,
                                         const char        *name)
{
  ares_status_t     status;
  ares_dns_label_t *labels = NULL;
  ares_dns_label_t *label;
  size_t            num_labels = 0;
  size_t            len;
  size_t            i;
  size_t            total_len = 0;

  if (name == NULL || labels_out == NULL || num_labels_out == NULL) {
    return ARES_EFORMERR;
  }

  len = ares_strlen(name);

  /* Start with 1 label */
  num_labels = 1;
  labels     = ares_malloc_zero(sizeof(*labels) * num_labels);
  if (labels == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  label = &labels[num_labels - 1];
  for (i = 0; i < len; i++) {
    size_t remaining_len = len - i;

    /* New label */
    if (name[i] == '.') {
      void *temp;

      temp = ares_realloc_zero(labels, sizeof(*labels) * num_labels,
                               sizeof(*labels) * (num_labels + 1));
      if (temp == NULL) {
        status = ARES_ENOMEM;
        goto done;
      }
      labels = temp;
      label  = &labels[num_labels++];
      continue;
    }

    /* Can't append any more bytes */
    if (label->len == sizeof(label->label)) {
      status = ARES_EBADNAME;
      goto done;
    }

    /* Escape */
    if (name[i] == '\\') {
      size_t consumed_chars = 0;
      status                = ares_parse_dns_name_escape(
        name + i, remaining_len, validate_hostname, &label->label[label->len++],
        &consumed_chars);
      if (status != ARES_SUCCESS) {
        goto done;
      }
      i += consumed_chars;
      continue;
    }

    /* Output direct character */
    if (validate_hostname && !ares__is_hostnamech(name[i])) {
      status = ARES_EBADNAME;
      goto done;
    }
    label->label[label->len++] = (unsigned char)name[i];
  }

  /* Remove trailing blank label */
  if (labels[num_labels - 1].len == 0) {
    num_labels--;
  }

  /* If someone passed in "." there could have been 2 blank labels, check for
   * that */
  if (num_labels == 1 && labels[0].len == 0) {
    num_labels--;
  }

  /* Scan to make sure there are no blank labels */
  for (i = 0; i < num_labels; i++) {
    if (labels[i].len == 0) {
      status = ARES_EBADNAME;
      goto done;
    }
    total_len += labels[i].len;
  }

  /* Can't exceed maximum (unescaped) length */
  if (num_labels && total_len + num_labels - 1 > 255) {
    status = ARES_EBADNAME;
    goto done;
  }

  *labels_out     = labels;
  *num_labels_out = num_labels;
  status          = ARES_SUCCESS;

done:
  if (status != ARES_SUCCESS) {
    ares_free(labels);
  }
  return status;
}

ares_status_t ares__dns_name_write(ares__buf_t *buf, ares__llist_t **list,
                                   ares_bool_t validate_hostname,
                                   const char *name)
{
  const ares_nameoffset_t *off = NULL;
  size_t                   name_len;
  size_t                   pos    = ares__buf_get_position(buf);
  ares_dns_label_t        *labels = NULL;
  char                     name_copy[512];
  size_t                   num_labels = 0;
  ares_status_t            status;

  if (buf == NULL || name == NULL) {
    return ARES_EFORMERR;
  }

  /* NOTE: due to possible escaping, name_copy buffer is > 256 to allow for
   *       this */
  name_len = ares_strcpy(name_copy, name, sizeof(name_copy));

  /* Find longest match */
  if (list != NULL) {
    off = ares__nameoffset_find(*list, name_copy);
    if (off != NULL && off->name_len != name_len) {
      /* truncate */
      name_len                -= (off->name_len + 1);
      name_copy[name_len - 1]  = 0;
    }
  }

  /* Output labels */
  if (off == NULL || off->name_len != name_len) {
    size_t i;

    status =
      ares_split_dns_name(&labels, &num_labels, validate_hostname, name_copy);
    if (status != ARES_SUCCESS) {
      goto done;
    }

    for (i = 0; i < num_labels; i++) {
      status =
        ares__buf_append_byte(buf, (unsigned char)(labels[i].len & 0xFF));
      if (status != ARES_SUCCESS) {
        goto done;
      }

      status = ares__buf_append(buf, labels[i].label, labels[i].len);
      if (status != ARES_SUCCESS) {
        goto done;
      }
    }

    /* If we are NOT jumping to another label, output terminator */
    if (off == NULL) {
      status = ares__buf_append_byte(buf, 0);
      if (status != ARES_SUCCESS) {
        goto done;
      }
    }
  }

  /* Output name compression offset jump */
  if (off != NULL) {
    unsigned short u16 =
      (unsigned short)0xC000 | (unsigned short)(off->idx & 0x3FFF);
    status = ares__buf_append_be16(buf, u16);
    if (status != ARES_SUCCESS) {
      goto done;
    }
  }

  /* Store pointer for future jumps as long as its not an exact match for
   * a prior entry */
  if (list != NULL && off != NULL && off->name_len != name_len &&
      name_len > 0) {
    status = ares__nameoffset_create(list, name /* not truncated copy! */, pos);
    if (status != ARES_SUCCESS) {
      goto done;
    }
  }

  status = ARES_SUCCESS;

done:
  ares_free(labels);
  return status;
}

/* Reserved characters for names that need to be escaped */
static ares_bool_t is_reservedch(int ch)
{
  switch (ch) {
    case '"':
    case '.':
    case ';':
    case '\\':
    case '(':
    case ')':
    case '@':
    case '$':
      return ARES_TRUE;
    default:
      break;
  }

  return ARES_FALSE;
}

static ares_status_t ares__fetch_dnsname_into_buf(ares__buf_t *buf,
                                                  ares__buf_t *dest, size_t len,
                                                  ares_bool_t is_hostname)
{
  size_t               remaining_len;
  const unsigned char *ptr = ares__buf_peek(buf, &remaining_len);
  ares_status_t        status;
  size_t               i;

  if (buf == NULL || len == 0 || remaining_len < len) {
    return ARES_EBADRESP;
  }

  for (i = 0; i < len; i++) {
    unsigned char c = ptr[i];

    /* Hostnames have a very specific allowed character set.  Anything outside
     * of that (non-printable and reserved included) are disallowed */
    if (is_hostname && !ares__is_hostnamech(c)) {
      status = ARES_EBADRESP;
      goto fail;
    }

    /* NOTE: dest may be NULL if the user is trying to skip the name. validation
     *       still occurs above. */
    if (dest == NULL) {
      continue;
    }

    /* Non-printable characters need to be output as \DDD */
    if (!ares__isprint(c)) {
      unsigned char escape[4];

      escape[0] = '\\';
      escape[1] = '0' + (c / 100);
      escape[2] = '0' + ((c % 100) / 10);
      escape[3] = '0' + (c % 10);

      status = ares__buf_append(dest, escape, sizeof(escape));
      if (status != ARES_SUCCESS) {
        goto fail;
      }

      continue;
    }

    /* Reserved characters need to be escaped, otherwise normal */
    if (is_reservedch(c)) {
      status = ares__buf_append_byte(dest, '\\');
      if (status != ARES_SUCCESS) {
        goto fail;
      }
    }

    status = ares__buf_append_byte(dest, c);
    if (status != ARES_SUCCESS) {
      return status;
    }
  }

  return ares__buf_consume(buf, len);

fail:
  return status;
}

ares_status_t ares__dns_name_parse(ares__buf_t *buf, char **name,
                                   ares_bool_t is_hostname)
{
  size_t        save_offset = 0;
  unsigned char c;
  ares_status_t status;
  ares__buf_t  *namebuf     = NULL;
  size_t        label_start = ares__buf_get_position(buf);

  if (buf == NULL) {
    return ARES_EFORMERR;
  }

  if (name != NULL) {
    namebuf = ares__buf_create();
    if (namebuf == NULL) {
      status = ARES_ENOMEM;
      goto fail;
    }
  }

  /* The compression scheme allows a domain name in a message to be
   * represented as either:
   *
   * - a sequence of labels ending in a zero octet
   * - a pointer
   * - a sequence of labels ending with a pointer
   */
  while (1) {
    /* Keep track of the minimum label starting position to prevent forward
     * jumping */
    if (label_start > ares__buf_get_position(buf)) {
      label_start = ares__buf_get_position(buf);
    }

    status = ares__buf_fetch_bytes(buf, &c, 1);
    if (status != ARES_SUCCESS) {
      goto fail;
    }

    /* Pointer/Redirect */
    if ((c & 0xc0) == 0xc0) {
      /* The pointer takes the form of a two octet sequence:
       *
       *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
       *   | 1  1|                OFFSET                   |
       *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
       *
       * The first two bits are ones.  This allows a pointer to be distinguished
       * from a label, since the label must begin with two zero bits because
       * labels are restricted to 63 octets or less.  (The 10 and 01
       * combinations are reserved for future use.)  The OFFSET field specifies
       * an offset from the start of the message (i.e., the first octet of the
       * ID field in the domain header).  A zero offset specifies the first byte
       * of the ID field, etc.
       */
      size_t offset = (size_t)((c & 0x3F) << 8);

      /* Fetch second byte of the redirect length */
      status = ares__buf_fetch_bytes(buf, &c, 1);
      if (status != ARES_SUCCESS) {
        goto fail;
      }

      offset |= ((size_t)c);

      /* According to RFC 1035 4.1.4:
       *    In this scheme, an entire domain name or a list of labels at
       *    the end of a domain name is replaced with a pointer to a prior
       *    occurance of the same name.
       * Note the word "prior", meaning it must go backwards.  This was
       * confirmed via the ISC BIND code that it also prevents forward
       * pointers.
       */
      if (offset >= label_start) {
        status = ARES_EBADNAME;
        goto fail;
      }

      /* First time we make a jump, save the current position */
      if (save_offset == 0) {
        save_offset = ares__buf_get_position(buf);
      }

      status = ares__buf_set_position(buf, offset);
      if (status != ARES_SUCCESS) {
        status = ARES_EBADNAME;
        goto fail;
      }

      continue;
    } else if ((c & 0xc0) != 0) {
      /* 10 and 01 are reserved */
      status = ARES_EBADNAME;
      goto fail;
    } else if (c == 0) {
      /* termination via zero octet*/
      break;
    }

    /* New label */

    /* Labels are separated by periods */
    if (ares__buf_len(namebuf) != 0 && name != NULL) {
      status = ares__buf_append_byte(namebuf, '.');
      if (status != ARES_SUCCESS) {
        goto fail;
      }
    }

    status = ares__fetch_dnsname_into_buf(buf, namebuf, c, is_hostname);
    if (status != ARES_SUCCESS) {
      goto fail;
    }
  }

  /* Restore offset read after first redirect/pointer as this is where the DNS
   * message continues */
  if (save_offset) {
    ares__buf_set_position(buf, save_offset);
  }

  if (name != NULL) {
    *name = ares__buf_finish_str(namebuf, NULL);
    if (*name == NULL) {
      status = ARES_ENOMEM;
      goto fail;
    }
  }

  return ARES_SUCCESS;

fail:
  /* We want badname response if we couldn't parse */
  if (status == ARES_EBADRESP) {
    status = ARES_EBADNAME;
  }

  ares__buf_destroy(namebuf);
  return status;
}
