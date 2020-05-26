#ifndef ADIGHELP_H
#define ADIGHELP_H
#include <stdio.h>
#include "ares_version.h"

/* Information from the man page. Formatting taken from man -h */
void print_help_info_adig() {
    printf("adig, version %s \n\n", ARES_VERSION_STR);
    printf("usage: adig [-h] [-d] [-f flag] [-s server] [-c class] [-t type] [-T|U port] name ...\n\n"
    "  d : Print some extra debugging output.\n"
    "  f : Add a flag. Possible values for flag are igntc, noaliases, norecurse, primary, stayopen, usevc.\n"
    "  h : Display this help and exit.\n\n"
    "  T port   : Use specified TCP port to connect to DNS server.\n"
    "  U port   : Use specified UDP port to connect to DNS server.\n"
    "  c class  : Set the query class. Possible values for class are NY, CHAOS, HS, IN  (default).\n"
    "  s server : Connect to specified DNS server, instead of the system's default one(s).\n"
    "  t type   : Query records of specified type.  \n"
    "              Possible values for type are A  \n"
    "              (default), AAAA, AFSDB,  ANY,\n"
    "              AXFR, CNAME, GPOS, HINFO, ISDN,\n"
    "              KEY, LOC, MAILA, MAILB, MB, MD,\n"
    "              MF, MG, MINFO, MR, MX, NAPTR, NS,\n"
    "              NSAP, NSAP_PTR, NULL, PTR, PX, RP,\n"
    "              RT,  SIG,  SOA, SRV, TXT, WKS, X25\n\n");
    exit(0);
}

void print_help_info_acountry() {
    printf("acountry, version %s \n\n", ARES_VERSION_STR);
    printf("usage: acountry [-?hdv] {host|addr} ...\n\n"
    "  d : Print some extra debugging output.\n"
    "  h : Display this help and exit.\n"
    "  v : Be more verbose. Print extra information.\n\n");
    exit(0);
}

void print_help_info_ahost() {
    printf("ahost, version %s \n\n", ARES_VERSION_STR);
    printf("usage: ahost [-h] [-d] [-s {domain}] [-t {a|aaaa|u}] {host|addr} ...\n\n"
    "  d : Print some extra debugging output.\n"
    "  h : Display this help and exit.\n\n"
    "  s domain : Specify the domain to search instead of \n"
    "               using the default values from \n"
    "               /etc/resolv.conf. This option only has an \n"
    "               effect on platforms that use /etc/resolv.conf\n"
    "               for DNS configuration; it has no effect on other\n"
    "               platforms (such as Win32 or Android).\n"
    "  t type   : If type is \"a\", print the A record (default).\n"
    "               If type is \"aaaa\", print the AAAA record.  If\n"
    "               type is \"u\", look for either AAAA or A record\n"
    "               (in that order).\n\n");
    exit(0);
} 

#endif