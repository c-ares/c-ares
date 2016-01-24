// General driver to allow command-line fuzzer (i.e. afl) to
// fuzz the libfuzzer entrypoint.
#include <stdio.h>
#include <unistd.h>

#include <vector>

extern "C" void LLVMFuzzerTestOneInput(const unsigned char *data,
                                       unsigned long size);
int main() {
  std::vector<unsigned char> input;
  while (true) {
    unsigned char buffer[1024];
    int len = read(fileno(stdin), buffer, sizeof(buffer));
    if (len <= 0) break;
    input.insert(input.end(), buffer, buffer + len);
  }
  LLVMFuzzerTestOneInput(input.data(), input.size());
  return 0;
}
