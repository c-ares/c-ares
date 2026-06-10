#include "ares_private.h"

#ifdef __PASE__

#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <as400_protos.h>
#  include <pthread.h>

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

/* Thread-safe cache for ILE procedure pointer */
static ILEpointer      qtocrtvtcpa_ptr __attribute__((aligned(16)));
static int             qtocrtvtcpa_initialized = 0;
static pthread_mutex_t ile_mutex               = PTHREAD_MUTEX_INITIALIZER;

/* EBCDIC to ASCII conversion for common characters */
static char ebcdic_to_ascii(unsigned char c)
{
  /* Lowercase letters */
  if (c >= 0x81 && c <= 0x89) {
    return 'a' + (c - 0x81);
  }
  if (c >= 0x91 && c <= 0x99) {
    return 'j' + (c - 0x91);
  }
  if (c >= 0xA2 && c <= 0xA9) {
    return 's' + (c - 0xA2);
  }

  /* Uppercase letters */
  if (c >= 0xC1 && c <= 0xC9) {
    return 'A' + (c - 0xC1);
  }
  if (c >= 0xD1 && c <= 0xD9) {
    return 'J' + (c - 0xD1);
  }
  if (c >= 0xE2 && c <= 0xE9) {
    return 'S' + (c - 0xE2);
  }

  /* Numbers */
  if (c >= 0xF0 && c <= 0xF9) {
    return '0' + (c - 0xF0);
  }

  /* Special characters */
  if (c == 0x4B) {
    return '.';
  }
  if (c == 0x60) {
    return '-';
  }
  if (c == 0x40) {
    return ' ';
  }

  return c; /* Keep as-is for unmapped characters */
}

/* Thread-safe initialization of ILE API */
static ares_status_t load_ile_api(void)
{
  ares_status_t      status = ARES_SUCCESS;
  unsigned long long actmark;

  pthread_mutex_lock(&ile_mutex);

  if (qtocrtvtcpa_initialized) {
    pthread_mutex_unlock(&ile_mutex);
    return ARES_SUCCESS;
  }

  actmark = _ILELOADX("QSYS/QTOCNETSTS", ILELOAD_LIBOBJ);
  if (actmark == (unsigned long long)-1) {
    status = ARES_ELOADIPHLPAPI;
    goto cleanup;
  }

  if (_ILESYMX(&qtocrtvtcpa_ptr, actmark, "QtocRtvTCPA") < 0) {
    status = ARES_ELOADIPHLPAPI;
    goto cleanup;
  }

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
      /* Skip empty or invalid entries */
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
  if (header2->search_list[0] != '\0' && header2->search_list[0] != ' ') {
    char search_ascii[256];
    int  j;
    for (j = 0; j < 256 && header2->search_list[j] != '\0' &&
                header2->search_list[j] != ' ';
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

  ares_free(buffer);

  /* If no DNS servers were found, fall back to file-based config */
  if (ares_llist_len(sysconfig->sconfig) == 0) {
    return ares_init_sysconfig_files(channel, sysconfig, ARES_TRUE);
  }

  return ARES_SUCCESS;
}

#endif
