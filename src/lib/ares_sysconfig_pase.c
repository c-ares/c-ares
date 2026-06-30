#include "ares_private.h"

#ifdef __PASE__

#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <as400_protos.h>
#  include <pthread.h>
#  include <unistd.h>

/* EBCDIC space character constant */
#define EBCDIC_SPACE '\x40'

/* IBM i ILE API structures for QtocRtvTCPA */

typedef struct {
  int bytes_returned;
  int bytes_available;
  int ipv6_status;
  int additional_info_offset;
  int additional_info_length;
  int ipv4_status;
} tcpa1100_t;

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
  char reserved;
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

/* EBCDIC to ASCII lookup table (256 bytes) - much faster than if-statements */
static const unsigned char ebcdic_to_ascii_table[256] = {
  /* 0x00-0x0F */
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  /* 0x10-0x1F */
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
  /* 0x20-0x2F */
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
  /* 0x30-0x3F */
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
  /* 0x40 = EBCDIC space */
  ' ',  0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  0x48, 0x49, 0x4A, '.',  0x4C, 0x4D, 0x4E, 0x4F,
  /* 0x50-0x5F */
  '&',  0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
  0x58, 0x59, 0x5A, '$',  0x5C, 0x5D, 0x5E, 0x5F,
  /* 0x60 = EBCDIC minus/hyphen */
  '-',  0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
  0x68, 0x69, 0x6A, 0x6B, '%',  0x6D, 0x6E, 0x6F,
  /* 0x70-0x7F */
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x78, 0x79, 0x7A, '#',  0x7C, 0x7D, 0x7E, 0x7F,
  /* 0x80-0x8F - lowercase a-i */
  0x80, 'a',  'b',  'c',  'd',  'e',  'f',  'g',
  'h',  'i',  0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
  /* 0x90-0x9F - lowercase j-r */
  0x90, 'j',  'k',  'l',  'm',  'n',  'o',  'p',
  'q',  'r',  0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
  /* 0xA0-0xAF - lowercase s-z */
  0xA0, 0xA1, 's',  't',  'u',  'v',  'w',  'x',
  'y',  'z',  0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
  /* 0xB0-0xBF */
  0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
  0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
  /* 0xC0-0xCF - uppercase A-I */
  0xC0, 'A',  'B',  'C',  'D',  'E',  'F',  'G',
  'H',  'I',  0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
  /* 0xD0-0xDF - uppercase J-R */
  0xD0, 'J',  'K',  'L',  'M',  'N',  'O',  'P',
  'Q',  'R',  0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
  /* 0xE0-0xEF - uppercase S-Z */
  0xE0, 0xE1, 'S',  'T',  'U',  'V',  'W',  'X',
  'Y',  'Z',  0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
  /* 0xF0-0xFF - digits 0-9 */
  '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
  '8',  '9',  0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

/* Fast EBCDIC to ASCII conversion using lookup table */
static char ebcdic_to_ascii(unsigned char c)
{
  return (char)ebcdic_to_ascii_table[c];
}

/* Thread-safe initialization of ILE API with fork detection */
static ares_status_t load_ile_api(void)
{
  ares_status_t      status      = ARES_SUCCESS;
  unsigned long long actmark;
  pid_t              current_pid = getpid();

  pthread_mutex_lock(&ile_mutex);

  /* Re-initialize if we're in a different process (after fork) */
  if (qtocrtvtcpa_initialized && cached_pid == current_pid) {
    pthread_mutex_unlock(&ile_mutex);
    return ARES_SUCCESS;
  }

  /* Load or reload the ILE service program */
  actmark = _ILELOADX("QSYS/QTOCNETSTS", ILELOAD_LIBOBJ);
  if (actmark == (unsigned long long)-1) {
    status = ARES_ELOADIPHLPAPI;
    goto cleanup;
  }

  if (_ILESYMX(&qtocrtvtcpa_ptr, actmark, "QtocRtvTCPA") < 0) {
    status = ARES_ELOADIPHLPAPI;
    goto cleanup;
  }

  cached_pid              = current_pid;
  qtocrtvtcpa_initialized = 1;

cleanup:
  pthread_mutex_unlock(&ile_mutex);
  return status;
}

ares_status_t ares_init_sysconfig_pase(const ares_channel_t *channel,
                                       ares_sysconfig_t     *sysconfig)
{
  ares_status_t status;
  unsigned int  buflen;
  char         *buffer = NULL;
  tcpa1100_t   *header;
  tcpa1400_t   *header2;
  int           i, rc;

  /* Load ILE API if not already loaded */
  status = load_ile_api();
  if (status != ARES_SUCCESS) {
    /* Fall back to file-based configuration */
    return ares_init_sysconfig_files(channel, sysconfig, ARES_TRUE);
  }

  /* Allocate buffer for API call */
  buflen = sizeof(tcpa1100_t) + sizeof(tcpa1400_t) +
           sizeof(dns_list_item_t) * 10 + 512;

  buffer = ares_malloc(buflen);
  if (buffer == NULL) {
    return ARES_ENOMEM;
  }

  memset(buffer, 0, buflen);

  /* Prepare error code structure */
  struct {
    int  bytes_provided;
    int  bytes_available;
    char msgid[8];
    char data[256];
  } err_code;
  memset(&err_code, 0, sizeof(err_code));
  err_code.bytes_provided = sizeof(err_code);

  /* Prepare argument list for ILE call */
  const arg_type_t signature[] = { ARG_MEMPTR, ARG_MEMPTR, ARG_MEMPTR,
                                    ARG_MEMPTR, ARG_END };

  struct {
    ILEarglist_base base;
    ILEpointer      buffer;
    ILEpointer      buflen;
    ILEpointer      format;
    ILEpointer      errcode;
  } arglist __attribute__((aligned(16)));

  /* Format name in EBCDIC: "TCPA1400" */
  char format[9] = "\xe3\xc3\xd7\xc1\xf1\xf4\xf0\xf0";

  arglist.buffer.s.addr  = (address64_t)(intptr_t)&buffer[0];
  arglist.buflen.s.addr  = (address64_t)(intptr_t)&buflen;
  arglist.format.s.addr  = (address64_t)(intptr_t)&format[0];
  arglist.errcode.s.addr = (address64_t)(intptr_t)&err_code;

  /* Call QtocRtvTCPA ILE API */
  rc = _ILECALL(&qtocrtvtcpa_ptr, &arglist.base, signature, RESULT_VOID);

  if (rc != ILECALL_NOERROR || err_code.bytes_available) {
    ares_free(buffer);
    /* Fall back to file-based configuration */
    return ares_init_sysconfig_files(channel, sysconfig, ARES_TRUE);
  }

  /* Parse the returned data */
  header  = (tcpa1100_t *)buffer;
  header2 = (tcpa1400_t *)(buffer + header->additional_info_offset);

  /* Extract DNS servers */
  for (i = 0; i < header2->dns_list_count && i < 10; i++) {
    dns_list_item_t *item =
      (dns_list_item_t *)(buffer + header2->dns_list_offset +
                          (i * header2->dns_list_entry_size));

    char ip[INET6_ADDRSTRLEN];
    int  af = (item->version == 1 ? AF_INET : AF_INET6);

    if (inet_ntop(af, item->ip_address, ip, sizeof(ip)) != NULL) {
      /* Skip empty or invalid entries that the API returns when slots are unused.
       * The QtocRtvTCPA API returns 0.0.0.0 or :: for unused DNS server slots
       * rather than reducing dns_list_count, so we filter them here. */
      if (strlen(ip) > 0 && strcmp(ip, "0.0.0.0") != 0 &&
          strcmp(ip, "::") != 0) {
        status = ares_sconfig_append_fromstr(channel, &sysconfig->sconfig, ip,
                                             ARES_TRUE);
        if (status != ARES_SUCCESS) {
          ares_free(buffer);
          return status;
        }
      }
    }
  }

  /* Extract domain search list (convert from EBCDIC) */
  if (header2->search_list[0] != '\0' && header2->search_list[0] != EBCDIC_SPACE) {
    char search_ascii[256];
    int  j;
    for (j = 0; j < sizeof(header2->search_list) && header2->search_list[j] != '\0' &&
                header2->search_list[j] != EBCDIC_SPACE;
         j++) {
      search_ascii[j] = ebcdic_to_ascii((unsigned char)header2->search_list[j]);
    }
    search_ascii[j] = '\0';

    if (j > 0) {
      sysconfig->domains = ares_strsplit(search_ascii, ", ", &sysconfig->ndomains);
      if (sysconfig->domains == NULL) {
        ares_free(buffer);
        return ARES_ENOMEM;
      }
    }
  }

  /* Configure timeout (time_interval is in seconds) */
  if (header2->time_interval > 0) {
    sysconfig->timeout_ms = header2->time_interval * 1000;
  }

  /* Configure retries (attempts) */
  if (header2->retries > 0) {
    sysconfig->tries = header2->retries;
  }

  /* Configure rotate (initial_server: 1=first always, 2=rotate) */
  if (header2->initial_server == 2) {
    sysconfig->rotate = ARES_TRUE;
  }

  /* Configure TCP usage (dns_protocol: 1=UDP, 2=TCP) */
  if (header2->dns_protocol == 2) {
    sysconfig->usevc = ARES_TRUE;
  }

  /* Configure lookup order (search_order: 1=local first, 2=remote first)
   * This maps to the "lookup" option in resolv.conf */
  if (header2->search_order == 1) {
    sysconfig->lookups = ares_strdup("fb");  /* files, bind */
  } else {
    sysconfig->lookups = ares_strdup("bf");  /* bind, files */
  }

  ares_free(buffer);

  /* If no DNS servers were found, fall back to file-based config */
  if (ares_llist_len(sysconfig->sconfig) == 0) {
    return ares_init_sysconfig_files(channel, sysconfig, ARES_TRUE);
  }

  return ARES_SUCCESS;
}

#endif
