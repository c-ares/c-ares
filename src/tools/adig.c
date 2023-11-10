/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) The c-ares project and its contributors
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

#include "ares.h"
#include "ares_getopt.h"
#include "ares_dns.h"
#include "ares_nameser.h"
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/select.h>
#include <errno.h>
#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

/* ---- IMPLEMENT THESE IN c-ares */

static const char *ares_dns_opt_get_name_opt(unsigned short opt)
{
  return NULL;
}

static const char *ares_dns_opt_get_name_svcb(unsigned short opt)
{
  ares_svcb_param_t param = (ares_svcb_param_t)opt;
  switch (param) {
    case ARES_SVCB_PARAM_NO_DEFAULT_ALPN:
      return "no-default-alpn";
    case ARES_SVCB_PARAM_ECH:
      return "ech";
    case ARES_SVCB_PARAM_MANDATORY:
      return "mandatory";
    case ARES_SVCB_PARAM_ALPN:
      return "alpn";
    case ARES_SVCB_PARAM_PORT:
      return "port";
    case ARES_SVCB_PARAM_IPV4HINT:
      return "ipv4hint";
    case ARES_SVCB_PARAM_IPV6HINT:
      return "ipv6hint";
  }
  return NULL;
}

static const char *ares_dns_opt_get_name(ares_dns_rr_key_t key, unsigned short opt)
{
 switch (key) {
    case ARES_RR_OPT_OPTIONS:
      return ares_dns_opt_get_name_opt(opt);
    case ARES_RR_SVCB_PARAMS:
    case ARES_RR_HTTPS_PARAMS:
      return ares_dns_opt_get_name_svcb(opt);
    default:
      break;
  }
  return NULL;
}


static ares_dns_datatype_t ares_dns_opt_get_type_opt(unsigned short opt)
{
  return ARES_DATATYPE_BIN;
}

static ares_dns_datatype_t ares_dns_opt_get_type_svcb(unsigned short opt)
{
  ares_svcb_param_t param = (ares_svcb_param_t)opt;
  switch (param) {
    case ARES_SVCB_PARAM_NO_DEFAULT_ALPN:
    case ARES_SVCB_PARAM_ECH:
    case ARES_SVCB_PARAM_MANDATORY:
      return ARES_DATATYPE_BIN;
    case ARES_SVCB_PARAM_ALPN:
      return ARES_DATATYPE_STR;
    case ARES_SVCB_PARAM_PORT:
      return ARES_DATATYPE_U16;
    case ARES_SVCB_PARAM_IPV4HINT:
      return ARES_DATATYPE_INADDR;
    case ARES_SVCB_PARAM_IPV6HINT:
      return ARES_DATATYPE_INADDR6;
  }
  return ARES_DATATYPE_BIN;
}

static ares_dns_datatype_t ares_dns_opt_get_type(ares_dns_rr_key_t key, unsigned short opt)
{
  switch (key) {
    case ARES_RR_OPT_OPTIONS:
      return ares_dns_opt_get_type_opt(opt);
    case ARES_RR_SVCB_PARAMS:
    case ARES_RR_HTTPS_PARAMS:
      return ares_dns_opt_get_type_svcb(opt);
    default:
      break;
  }
  return ARES_DATATYPE_BIN;
}
static const char *ares_dns_rcode_tostr(ares_dns_rcode_t rcode)
{
  (void)rcode;
  return "RCODE";
}

/* ----- */

typedef struct {
  struct ares_options options;
  int                 optmask;
  ares_dns_class_t    qclass;
  ares_dns_rec_type_t qtype;
  unsigned int        use_ptr_helper;
  int                 args_processed;
  char               *servers;
  char                error[256];
} adig_config_t;

typedef struct {
  const char *name;
  int         value;
} nv_t;

static const nv_t configflags[] = {
  { "usevc",     ARES_FLAG_USEVC     },
  { "primary",   ARES_FLAG_PRIMARY   },
  { "igntc",     ARES_FLAG_IGNTC     },
  { "norecurse", ARES_FLAG_NORECURSE },
  { "stayopen",  ARES_FLAG_STAYOPEN  },
  { "noaliases", ARES_FLAG_NOALIASES }
};
static const size_t nconfigflags = sizeof(configflags) / sizeof(*configflags);

static int lookup_flag(const nv_t *nv, size_t num_nv, const char *name)
{
  size_t i;

  if (name == NULL)
    return 0;

  for (i=0; i<num_nv; i++) {
    if (strcasecmp(nv[i].name, name) == 0)
      return nv[i].value;
  }

  return 0;
}

static void print_help(void)
{
  printf("adig version %s\n\n", ares_version(NULL));
  printf(
    "usage: adig [-h] [-d] [-f flag] [[-s server] ...] [-T|U port] [-c class] "
    "[-t type] [-x|-xx] name ...\n\n"
    "  h : Display this help and exit.\n"
    "  d : Print some extra debugging output.\n\n"
    "  f flag   : Add a behavior control flag. Possible values are\n"
    "              igntc - ignore to query in TCP to get truncated UDP "
    "answer,\n"
    "              noaliases - don't honor the HOSTALIASES environment "
    "variable,\n"
    "              norecurse - don't query upstream servers recursively,\n"
    "              primary - use the first server,\n"
    "              stayopen - don't close the communication sockets, and\n"
    "              usevc - use TCP only.\n"
    "  s server : Connect to the specified DNS server, instead of the system's "
    "default one(s).\n"
    "              Servers are tried in round-robin, if the previous one "
    "failed.\n"
    "  T port   : Connect to the specified TCP port of DNS server.\n"
    "  U port   : Connect to the specified UDP port of DNS server.\n"
    "  c class  : Set the query class. Possible values for class are ANY, "
    "CHAOS, HS and IN (default)\n"
    "  t type   : Query records of the specified type.\n"
    "              Possible values for type are A (default), AAAA, ANY, CNAME,\n"
    "              HINFO, MX, NAPTR, NS, PTR, SOA, SRV, TXT, TLSA, URI, CAA,\n"
    "              SVCB, HTTPS\n\n"
    " -x  : For a '-t PTR a.b.c.d' lookup, query for 'd.c.b.a.in-addr.arpa.'\n"
  );
}


static ares_bool_t read_cmdline(int argc, char **argv, adig_config_t *config)
{
  int c;
  int f;

  while ((c = ares_getopt(argc, argv, "dh?f:s:c:t:T:U:x")) != -1) {
    switch (c) {
      case 'd':
#ifdef WATT32
        dbug_init();
#endif
        break;

      case 'h':
      case '?':
        print_help();
        exit(0);
        break;

      case 'f':
        f = lookup_flag(configflags, nconfigflags, optarg);
        if (f == 0) {
          snprintf(config->error, sizeof(config->error), "flag %s unknown",
            optarg);
        }

        config->options.flags |= f;
        config->optmask       |= ARES_OPT_FLAGS;
        break;

      case 's':
        if (optarg == NULL) {
          snprintf(config->error, sizeof(config->error), "%s", "missing servers");
          return ARES_FALSE;
        }
        config->servers = strdup(optarg);
        break;

      case 'c':
        if (!ares_dns_class_fromstr(&config->qclass, optarg)) {
          snprintf(config->error, sizeof(config->error), "unrecognied class %s", optarg);
          return ARES_FALSE;
        }
        break;

      case 't':
        if (!ares_dns_rec_type_fromstr(&config->qtype, optarg)) {
          snprintf(config->error, sizeof(config->error), "unrecognied type %s", optarg);
          return ARES_FALSE;
        }
        break;

      case 'T':
        /* Set the TCP port number. */
        if (!isdigit(*optarg)) {
          snprintf(config->error, sizeof(config->error), "invalid port number");
          return ARES_FALSE;
        }
        config->options.tcp_port  = (unsigned short)strtol(optarg, NULL, 0);
        config->options.flags    |= ARES_FLAG_USEVC;
        config->optmask          |= ARES_OPT_TCP_PORT;
        break;

      case 'U':
        /* Set the UDP port number. */
        if (!isdigit(*optarg)) {
          snprintf(config->error, sizeof(config->error), "invalid port number");
          return ARES_FALSE;
        }
        config->options.udp_port  = (unsigned short)strtol(optarg, NULL, 0);
        config->optmask          |= ARES_OPT_UDP_PORT;
        break;

      case 'x':
        config->use_ptr_helper++;
        break;
    }
  }

  config->args_processed = optind;

  argc -= optind;
  argv += optind;
  if (argc == 0) {
    snprintf(config->error, sizeof(config->error), "missing query name");
    return ARES_FALSE;
  }

  return ARES_TRUE;
}

static void print_flags(ares_dns_flags_t flags)
{
  if (flags & ARES_FLAG_QR)
    printf(" qr");
  if (flags & ARES_FLAG_AA)
    printf(" aa");
  if (flags & ARES_FLAG_TC)
    printf(" tc");
  if (flags & ARES_FLAG_RD)
    printf(" rd");
  if (flags & ARES_FLAG_RA)
    printf(" ra");
  if (flags & ARES_FLAG_AD)
    printf(" ad");
  if (flags & ARES_FLAG_CD)
    printf(" cd");
}

static void print_header(const ares_dns_record_t *dnsrec)
{
  printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n",
    ares_dns_opcode_tostr(ares_dns_record_get_opcode(dnsrec)),
    ares_dns_rcode_tostr(ares_dns_record_get_rcode(dnsrec)),
    ares_dns_record_get_id(dnsrec));
  printf(";; flags:");
  print_flags(ares_dns_record_get_flags(dnsrec));
  printf("; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n\n",
    (unsigned int)ares_dns_record_query_cnt(dnsrec),
    (unsigned int)ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER),
    (unsigned int)ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY),
    (unsigned int)ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL));
}

static void print_question(const ares_dns_record_t *dnsrec)
{
  size_t i;
  printf(";; QUESTION SECTION:\n");
  for (i=0; i<ares_dns_record_query_cnt(dnsrec); i++) {
    const char *name;
    ares_dns_rec_type_t qtype;
    ares_dns_class_t qclass;
    size_t           len;
    ares_dns_record_query_get(dnsrec, i, &name, &qtype, &qclass);
    len = strlen(name);
    printf(";%s.\t", name);
    if (len+1 < 24)
      printf("\t");
    if (len+1 < 16)
      printf("\t");
    printf("%s\t%s\n", ares_dns_class_tostr(qclass),
      ares_dns_rec_type_tostr(qtype));
  }
  printf("\n");
}


static void print_opt_addr(const unsigned char *val, size_t val_len)
{
  size_t i;
  if (val_len % 4 != 0) {
    printf("INVALID!");
    return;
  }
  for (i=0; i<val_len; i+=4) {
    char buf[256] = "";
    ares_inet_ntop(AF_INET, val + i, buf, sizeof(buf));
    if (i != 0)
      printf(",");
    printf("%s", buf);
  }
}

static void print_opt_addr6(const unsigned char *val, size_t val_len)
{
  size_t i;
  if (val_len % 16 != 0) {
    printf("INVALID!");
    return;
  }
  for (i=0; i<val_len; i+=16) {
    char buf[256] = "";

    ares_inet_ntop(AF_INET6, val + i, buf, sizeof(buf));
    if (i != 0)
      printf(",");
    printf("%s", buf);
  }
}

static void print_opt_u8(const unsigned char *val, size_t val_len)
{

}

static void print_opt_u16(const unsigned char *val, size_t val_len)
{

}

static void print_opt_u32(const unsigned char *val, size_t val_len)
{

}

static void print_opt_str(const unsigned char *val, size_t val_len)
{
  printf("\"%s\"", (const char *)val);
}

static void print_opt_bin(const unsigned char *val, size_t val_len)
{
  size_t               i;

  for (i=0; i<val_len; i++) {
    printf("%02x", (unsigned int)val[i]);
  }

}

static void print_opt_binp(const unsigned char *val, size_t val_len)
{
  /* XXX: handle escaping */
  printf("\"%s\"", (const char *)val);
}

static void print_opts(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
  size_t i;

  for (i=0; i<ares_dns_rr_get_opt_cnt(rr, key); i++) {
    size_t               val_len = 0;
    const unsigned char *val     = NULL;
    unsigned short       opt;
    const char          *name;

    if (i != 0)
      printf(" ");

    opt  = ares_dns_rr_get_opt(rr, key, i, &val, &val_len);
    name = ares_dns_opt_get_name(key, opt);
    if (name == NULL) {
      printf("key%u", (unsigned int)opt);
    } else {
      printf("%s", name);
    }
    if (val_len == 0)
      return;

    printf("=");

    switch (ares_dns_opt_get_type(key, opt)) {
      case ARES_DATATYPE_INADDR:
        print_opt_addr(val, val_len);
        break;
      case ARES_DATATYPE_INADDR6:
        print_opt_addr6(val, val_len);
        break;
      case ARES_DATATYPE_U8:
        print_opt_u8(val, val_len);
        break;
      case ARES_DATATYPE_U16:
        print_opt_u16(val, val_len);
        break;
      case ARES_DATATYPE_U32:
        print_opt_u32(val, val_len);
        break;
      case ARES_DATATYPE_NAME:
      case ARES_DATATYPE_STR:
        print_opt_str(val, val_len);
        break;
      case ARES_DATATYPE_BIN:
      case ARES_DATATYPE_OPT:
        print_opt_bin(val, val_len);
        break;
      case ARES_DATATYPE_BINP:
        print_opt_binp(val, val_len);
        break;
    }
  }
}

static void print_addr(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
  const struct in_addr *addr     = ares_dns_rr_get_addr(rr, key);
  char                  buf[256] = "";

  ares_inet_ntop(AF_INET, addr, buf, sizeof(buf));
  printf("%s", buf);
}

static void print_addr6(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
  const struct ares_in6_addr *addr     = ares_dns_rr_get_addr6(rr, key);
  char                        buf[256] = "";

  ares_inet_ntop(AF_INET6, addr, buf, sizeof(buf));
  printf("%s", buf);
}

static void print_u8(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
  unsigned char u8 = ares_dns_rr_get_u8(rr, key);
  printf("%u", (unsigned int)u8);
}

static void print_u16(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
  unsigned short u16 = ares_dns_rr_get_u16(rr, key);
  printf("%u", (unsigned int)u16);
}

static void print_u32(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
  unsigned int u32 = ares_dns_rr_get_u32(rr, key);
  printf("%u", u32);
}

static void print_name(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
  const char *str = ares_dns_rr_get_str(rr, key);
  printf("%s.", str);
}

static void print_str(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
  const char *str = ares_dns_rr_get_str(rr, key);
  printf("\"%s\"", str);
}

static void print_bin(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
  size_t               len  = 0;
  const unsigned char *binp = ares_dns_rr_get_bin(rr, key, &len);
  print_opt_bin(binp, len);
}

static void print_binp(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
  size_t               len;
  const unsigned char *binp = ares_dns_rr_get_bin(rr, key, &len);

  print_opt_binp(binp, len);
}


static void print_rr(const ares_dns_rr_t *rr)
{
  const char              *name     = ares_dns_rr_get_name(rr);
  size_t                   len      = strlen(name);
  size_t                   keys_cnt = 0;
  ares_dns_rec_type_t      rtype    = ares_dns_rr_get_type(rr);
  const ares_dns_rr_key_t *keys     = ares_dns_rr_get_keys(rtype, &keys_cnt);
  size_t                   i;

  printf("%s.\t", name);
  if (len < 24)
    printf("\t");

  printf("%u\t%s\t%s\t", ares_dns_rr_get_ttl(rr),
    ares_dns_class_tostr(ares_dns_rr_get_class(rr)),
    ares_dns_rec_type_tostr(rtype));

  /* Output params here */
  for (i=0; i<keys_cnt; i++) {
    ares_dns_datatype_t datatype = ares_dns_rr_key_datatype(keys[i]);
    if (i != 0)
      printf(" ");

    switch (datatype) {
      case ARES_DATATYPE_INADDR:
        print_addr(rr, keys[i]);
        break;
      case ARES_DATATYPE_INADDR6:
        print_addr6(rr, keys[i]);
        break;
      case ARES_DATATYPE_U8:
        print_u8(rr, keys[i]);
        break;
      case ARES_DATATYPE_U16:
        print_u16(rr, keys[i]);
        break;
      case ARES_DATATYPE_U32:
        print_u32(rr, keys[i]);
        break;
      case ARES_DATATYPE_NAME:
        print_name(rr, keys[i]);
        break;
      case ARES_DATATYPE_STR:
        print_str(rr, keys[i]);
        break;
      case ARES_DATATYPE_BIN:
        print_bin(rr, keys[i]);
        break;
      case ARES_DATATYPE_BINP:
        print_binp(rr, keys[i]);
        break;
      case ARES_DATATYPE_OPT:
        print_opts(rr, keys[i]);
        break;
    }
  }

  printf("\n");
}

static ares_bool_t has_opt(ares_dns_record_t *dnsrec, ares_dns_section_t section)
{
  size_t i;
  for (i=0; i < ares_dns_record_rr_cnt(dnsrec, section); i++) {
    const ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, section, i);
    if (ares_dns_rr_get_type(rr) == ARES_REC_TYPE_OPT)
      return ARES_TRUE;
  }
  return ARES_FALSE;
}

static void print_section(ares_dns_record_t *dnsrec, ares_dns_section_t section)
{
  size_t i;

  if (ares_dns_record_rr_cnt(dnsrec, section) == 0 ||
      (ares_dns_record_rr_cnt(dnsrec, section) == 1 && has_opt(dnsrec, section))
     ) {
    return;
  }

  printf(";; %s SECTION:\n", ares_dns_section_tostr(section));
  for (i=0; i< ares_dns_record_rr_cnt(dnsrec, section); i++) {
    const ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, section, i);
    if (ares_dns_rr_get_type(rr) == ARES_REC_TYPE_OPT)
      continue;
    print_rr(rr);
  }
  printf("\n");
}

static void callback(void *arg, int status, int timeouts, unsigned char *abuf,
                     int alen)
{
  ares_dns_record_t *dnsrec = NULL;
  (void)arg;
  (void)timeouts;

  printf(";; Got answer:");
  if (status != ARES_SUCCESS) {
    printf(" %s", ares_strerror(status));
  }
  printf("\n");

  if (abuf == NULL || alen == 0)
    return;

  status = (int)ares_dns_parse(abuf, (size_t)alen, 0, &dnsrec);
  if (status != ARES_SUCCESS) {
    fprintf(stderr, ";; FAILED TO PARSE DNS PACKET: %s\n", ares_strerror(status));
    return;
  }

  print_header(dnsrec);
  print_question(dnsrec);
  print_section(dnsrec, ARES_SECTION_ANSWER);
  print_section(dnsrec, ARES_SECTION_ADDITIONAL);
  print_section(dnsrec, ARES_SECTION_AUTHORITY);

  printf(";; MSG SIZE  rcvd: %d\n\n", alen);
  ares_dns_record_destroy(dnsrec);
}


static ares_status_t enqueue_query(ares_channel_t *channel, const adig_config_t *config, const char *name)
{
  ares_dns_record_t *dnsrec  = NULL;
  ares_dns_rr_t     *rr      = NULL;
  ares_status_t      status;
  unsigned char     *buf     = NULL;
  size_t             buf_len = 0;
  unsigned short     flags   = 0;

  if (!(config->options.flags & ARES_FLAG_NORECURSE)) {
    flags |= ARES_FLAG_RD;
  }

  status = ares_dns_record_create(&dnsrec, 0, flags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  /* XXX: if PTR, convert address to inarpa */

  status = ares_dns_record_query_add(dnsrec, name, config->qtype, config->qclass);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "", ARES_REC_TYPE_OPT, ARES_CLASS_IN, 0);
  if (status != ARES_SUCCESS) {
    goto done;
  }
  ares_dns_rr_set_u16(rr, ARES_RR_OPT_UDP_SIZE, 1280);
  ares_dns_rr_set_u8(rr, ARES_RR_OPT_VERSION, 0);

  status = ares_dns_write(dnsrec, &buf, &buf_len);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  ares_send(channel, buf, (int)buf_len, callback, NULL);
  ares_free_string(buf);

done:
  ares_dns_record_destroy(dnsrec);
  return status;
}


int main(int argc, char **argv)
{
  ares_channel_t *channel = NULL;
  ares_status_t   status;
  adig_config_t   config;
  int             i;

#ifdef USE_WINSOCK
  WORD    wVersionRequested = MAKEWORD(USE_WINSOCK, USE_WINSOCK);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#endif

  status = (ares_status_t)ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    fprintf(stderr, "ares_library_init: %s\n", ares_strerror((int)status));
    return 1;
  }

  memset(&config, 0, sizeof(config));
  config.qclass = ARES_CLASS_IN;
  config.qtype  = ARES_REC_TYPE_A;
  if (!read_cmdline(argc, argv, &config)) {
    printf("%s\n", config.error);
    print_help();
    return 1;
  }

  status = (ares_status_t)ares_init_options(&channel, &config.options, config.optmask);
  if (status != ARES_SUCCESS) {
    fprintf(stderr, "ares_init_options: %s\n", ares_strerror((int)status));
    return 1;
  }

  if (config.servers) {
    status = (ares_status_t)ares_set_servers_ports_csv(channel, config.servers);
    if (status != ARES_SUCCESS) {
      fprintf(stderr, "ares_set_servers_ports_csv: %s\n", ares_strerror((int)status));
      return 1;
    }
  }

  /* Enqueue a query for each separate name */
  for (i = config.args_processed; i < argc; i++) {
    status = enqueue_query(channel, &config, argv[i]);
    if (status != ARES_SUCCESS) {
      fprintf(stderr, "Failed to create query for %s: %s\n", argv[i], ares_strerror((int)status));
      return 1;
    }
  }

  /* Debug */
  printf("; <<>> c-ares DiG %s <<>>", ares_version(NULL));
  for (i = config.args_processed; i < argc; i++) {
    printf(" %s", argv[i]);
  }
  printf("\n");


  while (1) {
    fd_set          read_fds;
    fd_set          write_fds;
    int             nfds;
    struct timeval  tv;
    struct timeval *tvp;
    int             count;

    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    memset(&tv, 0, sizeof(tv));

    nfds = ares_fds(channel, &read_fds, &write_fds);
    if (nfds == 0) {
      break;
    }
    tvp = ares_timeout(channel, NULL, &tv);
    if (tvp == NULL) {
      break;
    }
    count = select(nfds, &read_fds, &write_fds, NULL, tvp);
    if (count < 0) {
#ifdef USE_WINSOCK
      int err = WSAGetLastError();
#else
      int err = errno;
#endif
      if (err != EAGAIN && err != EINTR) {
        fprintf(stderr, "select fail: %d", err);
        return 1;
      }
    }
    ares_process(channel, &read_fds, &write_fds);
  }

  ares_destroy(channel);
  ares_library_cleanup();

#ifdef USE_WINSOCK
  WSACleanup();
#endif
  return 0;
}
