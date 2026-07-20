/* MIT License
 *
 * Copyright (c) 2026 The c-ares project and its contributors
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

#include "ares_private.h"

/* EBCDIC to ASCII lookup table (CCSID 37).
 * Only the DNS/hostname charset (letters, digits, hyphen, dot, space, comma,
 * underscore) is guaranteed fully correct; other slots map identity or to a
 * safe fallback.
 * Key corrections vs a naive identity table:
 *   0x40 -> ' '   (space)
 *   0x4B -> '.'   (period)
 *   0x60 -> '-'   (hyphen)
 *   0x6B -> ','   (comma)   -- delimiter used by ares_strsplit
 *   0x6D -> '_'   (underscore)
 *   0x81-0x89 -> a-i
 *   0x91-0x99 -> j-r
 *   0xA2-0xA9 -> s-z
 *   0xC1-0xC9 -> A-I
 *   0xD1-0xD9 -> J-R
 *   0xE2-0xE9 -> S-Z
 *   0xF0-0xF9 -> 0-9
 */
const unsigned char ares__ebcdic_to_ascii_table[256] = {
  /* 0x00-0x0F */
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
  0x0D, 0x0E, 0x0F,
  /* 0x10-0x1F */
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
  0x1D, 0x1E, 0x1F,
  /* 0x20-0x2F */
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
  0x2D, 0x2E, 0x2F,
  /* 0x30-0x3F */
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
  0x3D, 0x3E, 0x3F,
  /* 0x40 = EBCDIC space -> ASCII space */
  ' ', 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, '.', 0x4C,
  0x4D, 0x4E, 0x4F,
  /* 0x50-0x5F */
  '&', 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, '$', 0x5C,
  0x5D, 0x5E, 0x5F,
  /* 0x60 = EBCDIC hyphen/minus -> ASCII hyphen */
  '-', 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, ',', '%',
  '_', 0x6E, 0x6F,
  /* 0x70-0x7F */
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, '#', 0x7C,
  0x7D, 0x7E, 0x7F,
  /* 0x80-0x8F - lowercase a-i */
  0x80, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 0x8A, 0x8B, 0x8C, 0x8D,
  0x8E, 0x8F,
  /* 0x90-0x9F - lowercase j-r */
  0x90, 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 0x9A, 0x9B, 0x9C, 0x9D,
  0x9E, 0x9F,
  /* 0xA0-0xAF - lowercase s-z */
  0xA0, 0xA1, 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 0xAA, 0xAB, 0xAC, 0xAD,
  0xAE, 0xAF,
  /* 0xB0-0xBF */
  0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
  0xBD, 0xBE, 0xBF,
  /* 0xC0-0xCF - uppercase A-I */
  0xC0, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 0xCA, 0xCB, 0xCC, 0xCD,
  0xCE, 0xCF,
  /* 0xD0-0xDF - uppercase J-R */
  0xD0, 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 0xDA, 0xDB, 0xDC, 0xDD,
  0xDE, 0xDF,
  /* 0xE0-0xEF - uppercase S-Z */
  0xE0, 0xE1, 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 0xEA, 0xEB, 0xEC, 0xED,
  0xEE, 0xEF,
  /* 0xF0-0xFF - digits 0-9 */
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 0xFA, 0xFB, 0xFC, 0xFD,
  0xFE, 0xFF
};

/* Convert an EBCDIC buffer (up to len bytes) into a NUL-terminated ASCII
 * string in out, which must be at least len+1 bytes.  Stops at the first
 * NUL; trailing EBCDIC blank (0x40) padding becomes ASCII spaces, which
 * ares_strsplit() then drops as empty tokens. */
void ares__ebcdic_to_ascii_str(const char *ebcdic, size_t len, char *out)
{
  size_t i;
  for (i = 0; i < len && ebcdic[i] != '\0'; i++) {
    out[i] = (char)ares__ebcdic_to_ascii_table[(unsigned char)ebcdic[i]];
  }
  out[i] = '\0';
}

#ifdef __PASE__

/* EBCDIC space character (CCSID 37: 0x40 = space) */
#  define EBCDIC_SPACE '\x40'

#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <as400_protos.h>
#  include <pthread.h>
#  include <unistd.h>

/* IBM i ILE API structures for QtocRtvTCPA */

typedef struct {
  int bytes_returned;
  int bytes_available;
  int ipv6_status;
  int additional_info_offset;
  int additional_info_length;
  int ipv4_status;
} tcpa1100_t;

/* Byte-exact overlay of IBM TCPA1400 (QtocRtvTCPA format TCPA1400).
 * domain_name[255] + reserved[1] = 256 bytes; this lands request_dnssec at
 * offset 612 (4-byte aligned) with zero compiler padding — do not reorder or
 * remove any field, including char reserved. */
typedef struct {
  int  dns_list_offset;
  int  dns_list_count;
  int  dns_list_entry_size;
  int  dns_protocol;
  int  retries;
  int  time_interval;
  int  search_order;
  int  initial_server;
  int  dns_listening_port;
  char hostname[64];
  char domain_name[255];
  char reserved; /* padding: do not remove — required for byte-exact layout */
  char search_list[256];
  int  request_dnssec;
} tcpa1400_t;

typedef struct {
  int  version;
  char ip_address_string[45];
  char reserved[3];
  char ip_address[16];
} dns_list_item_t;

/* Thread-safe cache for ILE procedure pointer with fork detection */
static ILEpointer      qtocrtvtcpa_ptr __attribute__((aligned(16)));
static int             qtocrtvtcpa_initialized = 0;
static pid_t           cached_pid              = 0;
static pthread_mutex_t ile_mutex               = PTHREAD_MUTEX_INITIALIZER;

/* Thread-safe initialization of ILE API with fork detection.
 * ILE pointers are invalidated in a child process after fork(), so we
 * cache the PID and re-initialize whenever it changes. */
static ares_bool_t load_ile_api(void)
{
  ares_bool_t        ok = ARES_TRUE;
  unsigned long long actmark;
  pid_t              current_pid = getpid();

  pthread_mutex_lock(&ile_mutex);

  /* Fast path: already initialized in this process */
  if (qtocrtvtcpa_initialized && cached_pid == current_pid) {
    pthread_mutex_unlock(&ile_mutex);
    return ARES_TRUE;
  }

  /* Load (or reload after fork) the ILE service program */
  actmark = _ILELOADX("QSYS/QTOCNETSTS", ILELOAD_LIBOBJ);
  if (actmark == (unsigned long long)-1) {
    ok = ARES_FALSE;
    goto cleanup;
  }

  if (_ILESYMX(&qtocrtvtcpa_ptr, actmark, "QtocRtvTCPA") < 0) {
    ok = ARES_FALSE;
    goto cleanup;
  }

  cached_pid              = current_pid;
  qtocrtvtcpa_initialized = 1;

cleanup:
  pthread_mutex_unlock(&ile_mutex);
  return ok;
}

/* Upper bound on dns_list_count for buffer sizing.  The IBM docs do not
 * document a hard cap; in practice dns_list_count is always well below this.
 * The loop trusts dns_list_count as authoritative and bounds-checks every
 * offset, so this only affects the initial allocation size. */
#  define ARES_PASE_MAX_DNS_SERVERS 10

ares_status_t ares_init_sysconfig_pase(const ares_channel_t *channel,
                                       ares_sysconfig_t     *sysconfig)
{
  /* --- All declarations at top of function (C89/C90 compliance) --- */
  ares_status_t status;
  int           buflen;
  char         *buffer = NULL;
  tcpa1100_t   *header;
  tcpa1400_t   *header2;
  int           i, rc;
  size_t        off;
  char          ip_str[INET6_ADDRSTRLEN + 10]; /* extra room for [ip]:port */

  struct {
    int  bytes_provided;
    int  bytes_available;
    char msgid[8];
    char data[256];
  } err_code;

  const arg_type_t signature[] = { ARG_MEMPTR, ARG_MEMPTR, ARG_MEMPTR,
                                   ARG_MEMPTR, ARG_END };

  struct {
    ILEarglist_base base;
    ILEpointer      buffer;
    ILEpointer      buflen;
    ILEpointer      format;
    ILEpointer      errcode;
  } arglist __attribute__((aligned(16)));

  /* Format name "TCPA1400" in EBCDIC */
  char format[9] = "\xe3\xc3\xd7\xc1\xf1\xf4\xf0\xf0";

  /* Load ILE API; fall back to file-based config if unavailable */
  if (!load_ile_api()) {
    return ares_init_sysconfig_files(channel, sysconfig, ARES_TRUE);
  }

  /* Allocate buffer for the API response.
   * The layout is: tcpa1100_t at offset 0, then tcpa1400_t at
   * additional_info_offset (API-reported, may be larger than sizeof(tcpa1100_t)
   * due to alignment or future header growth), then the DNS list entries.
   * +512 covers any gap between the end of tcpa1100_t and
   * additional_info_offset. The bounds checks below ensure we never read past
   * buflen regardless. */
  buflen = (int)(sizeof(tcpa1100_t) + sizeof(tcpa1400_t) +
                 sizeof(dns_list_item_t) * ARES_PASE_MAX_DNS_SERVERS + 512);

  buffer = ares_malloc_zero((size_t)buflen);
  if (buffer == NULL) {
    return ARES_ENOMEM;
  }

  memset(&err_code, 0, sizeof(err_code));
  err_code.bytes_provided = sizeof(err_code);

  /* Wire up argument pointers for the ILE call */
  arglist.buffer.s.addr  = (address64_t)(intptr_t)&buffer[0];
  arglist.buflen.s.addr  = (address64_t)(intptr_t)&buflen;
  arglist.format.s.addr  = (address64_t)(intptr_t)&format[0];
  arglist.errcode.s.addr = (address64_t)(intptr_t)&err_code;

  /* Call QtocRtvTCPA ILE API.
   * Note: qtocrtvtcpa_ptr is read outside ile_mutex here.  This is safe in
   * practice — the pointer is stable once initialized, and a child process
   * calling this function is single-threaded post-fork — but is formally an
   * unsynchronized read of the global. */
  rc = _ILECALL(&qtocrtvtcpa_ptr, &arglist.base, signature, RESULT_VOID);

  if (rc != ILECALL_NOERROR || err_code.bytes_available) {
    ares_free(buffer);
    return ares_init_sysconfig_files(channel, sysconfig, ARES_TRUE);
  }

  /* --- Validate outer header offset before use (B5) --- */
  header = (tcpa1100_t *)buffer;
  if (header->additional_info_offset < 0 ||
      (size_t)header->additional_info_offset + sizeof(tcpa1400_t) >
        (size_t)buflen) {
    ares_free(buffer);
    return ares_init_sysconfig_files(channel, sysconfig, ARES_TRUE);
  }
  header2 = (tcpa1400_t *)(buffer + header->additional_info_offset);

  /* --- Extract DNS servers (B5: validate offsets; B6: apply port) --- */
  if (header2->dns_list_entry_size < (int)sizeof(dns_list_item_t)) {
    ares_free(buffer);
    return ares_init_sysconfig_files(channel, sysconfig, ARES_TRUE);
  }

  for (i = 0; i < header2->dns_list_count; i++) {
    dns_list_item_t *item;
    char             ip[INET6_ADDRSTRLEN];
    int              af;

    off = (size_t)header2->dns_list_offset +
          (size_t)i * (size_t)header2->dns_list_entry_size;
    if (off + sizeof(dns_list_item_t) > (size_t)buflen) {
      break;
    }
    item = (dns_list_item_t *)(buffer + off);
    af   = (item->version == 1 ? AF_INET : AF_INET6);

    if (inet_ntop(af, item->ip_address, ip, sizeof(ip)) == NULL) {
      continue;
    }

    /* Apply non-standard port if configured (B6) */
    if (header2->dns_listening_port != 0 && header2->dns_listening_port != 53) {
      snprintf(ip_str, sizeof(ip_str), "[%s]:%d", ip,
               header2->dns_listening_port);
    } else {
      ares_strcpy(ip_str, ip, sizeof(ip_str));
    }

    status = ares_sconfig_append_fromstr(channel, &sysconfig->sconfig, ip_str,
                                         ARES_TRUE);
    if (status != ARES_SUCCESS) {
      ares_free(buffer);
      return status;
    }
  }

  /* --- Extract domain search list (B2: convert whole field, no truncation) ---
   * The field is EBCDIC, space-separated, blank-padded.  Convert the whole
   * buffer first; EBCDIC 0x40 becomes ASCII ' ', which ares_strsplit then
   * uses as a delimiter — correctly splitting all domains and dropping the
   * trailing blank padding as empty tokens. */
  {
    char search_ascii[sizeof(header2->search_list) + 1]; /* +1 for NUL (B2) */
    ares__ebcdic_to_ascii_str(header2->search_list,
                              sizeof(header2->search_list), search_ascii);
    sysconfig->domains =
      ares_strsplit(search_ascii, ", ", &sysconfig->ndomains);
    /* NULL with ndomains==0 means the field was empty, not an alloc error */
    if (sysconfig->domains == NULL && sysconfig->ndomains > 0) {
      ares_free(buffer);
      return ARES_ENOMEM;
    }
  }

  /* --- Fall back to domain_name if search list yielded no domains (B7) ---
   * CHGTCPDMN DMNNAME(...) sets a primary domain independently of the
   * search list; use it as a single-entry search domain when needed. */
  if (sysconfig->ndomains == 0 && header2->domain_name[0] != '\0' &&
      header2->domain_name[0] != EBCDIC_SPACE) {
    char domain_ascii[sizeof(header2->domain_name) + 1];
    ares__ebcdic_to_ascii_str(header2->domain_name,
                              sizeof(header2->domain_name), domain_ascii);
    sysconfig->domains = ares_strsplit(domain_ascii, " ", &sysconfig->ndomains);
    if (sysconfig->domains == NULL && sysconfig->ndomains > 0) {
      ares_free(buffer);
      return ARES_ENOMEM;
    }
  }

  /* --- Configure timeout (B11: cast to size_t before multiply) --- */
  if (header2->time_interval > 0) {
    sysconfig->timeout_ms = (size_t)header2->time_interval * 1000;
  }

  /* --- Configure tries (B3: IBM retries excludes first attempt) ---
   * retries=0 means 1 total attempt; retries=2 means 3 total.
   * Set unconditionally — the API always returns a valid value (0-99). */
  sysconfig->tries = (size_t)header2->retries + 1;

  /* Configure rotate (initial_server: 1=first always, 2=rotate) */
  if (header2->initial_server == 2) {
    sysconfig->rotate = ARES_TRUE;
  }

  /* Configure TCP usage (dns_protocol: 1=UDP, 2=TCP) */
  if (header2->dns_protocol == 2) {
    sysconfig->usevc = ARES_TRUE;
  }

  /* --- Configure lookup order (B9: explicit if/else if; NULL-check strdup) ---
   * search_order: 1=local files first ("fb"), 2=remote DNS first ("bf").
   * Leave unchanged for 0 or any unrecognised value. */
  if (header2->search_order == 1) {
    sysconfig->lookups = ares_strdup("fb"); /* files, bind */
    if (sysconfig->lookups == NULL) {
      ares_free(buffer);
      return ARES_ENOMEM;
    }
  } else if (header2->search_order == 2) {
    sysconfig->lookups = ares_strdup("bf"); /* bind, files */
    if (sysconfig->lookups == NULL) {
      ares_free(buffer);
      return ARES_ENOMEM;
    }
  }

  ares_free(buffer);

  /* If no DNS servers were found, fall back to file-based config.
   * Note: any resolver settings already written above (timeout_ms, tries,
   * rotate, usevc, lookups, domains) remain set and will blend with whatever
   * ares_init_sysconfig_files() reads; the files parser frees-before-set so
   * there is no leak.  This is intentional: API-configured settings take
   * precedence, and the file fills in any gaps. */
  if (ares_llist_len(sysconfig->sconfig) == 0) {
    return ares_init_sysconfig_files(channel, sysconfig, ARES_TRUE);
  }

  return ARES_SUCCESS;
}

#endif
