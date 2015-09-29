#include "ares-test.h"
#include <vector>

// Entrypoint for Clang's libfuzzer
extern "C" void LLVMFuzzerTestOneInput(const unsigned char *data,
                                       unsigned long size) {
  // Feed the data into each of the ares_parse_*_reply functions.
  struct hostent *host = nullptr;
  struct ares_addrttl info[5];
  int count = 5;
  ares_parse_a_reply(data, size, &host, info, &count);
  if (host) ares_free_hostent(host);

  host = nullptr;
  struct ares_addr6ttl info6[5];
  count = 5;
  ares_parse_aaaa_reply(data, size, &host, info6, &count);
  if (host) ares_free_hostent(host);

  host = nullptr;
  ares::byte addrv4[4] = {0x10, 0x20, 0x30, 0x40};
  ares_parse_ptr_reply(data, size, addrv4, sizeof(addrv4), AF_INET, &host);
  if (host) ares_free_hostent(host);

  host = nullptr;
  ares_parse_ns_reply(data, size, &host);
  if (host) ares_free_hostent(host);

  struct ares_srv_reply* srv = nullptr;
  ares_parse_srv_reply(data, size, &srv);
  if (srv) ares_free_data(srv);

  struct ares_mx_reply* mx = nullptr;
  ares_parse_mx_reply(data, size, &mx);
  if (mx) ares_free_data(mx);

  struct ares_txt_reply* txt = nullptr;
  ares_parse_txt_reply(data, size, &txt);
  if (txt) ares_free_data(txt);

  struct ares_soa_reply* soa = nullptr;
  ares_parse_soa_reply(data, size, &soa);
  if (soa) ares_free_data(soa);
}
