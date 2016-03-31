// General driver to allow command-line fuzzer (i.e. afl) to
// fuzz the libfuzzer entrypoint.
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <iostream>

#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data,
                                      unsigned long size);

static void ProcessFile(int fd) {
  std::vector<unsigned char> input;
  while (true) {
    unsigned char buffer[1024];
    int len = read(fd, buffer, sizeof(buffer));
    if (len <= 0) break;
    input.insert(input.end(), buffer, buffer + len);
  }
  LLVMFuzzerTestOneInput(input.data(), input.size());
}

int main(int argc, char *argv[]) {
  if (argc == 1) {
    ProcessFile(fileno(stdin));
  } else {
    for (int ii = 1; ii < argc; ++ii) {
      int fd = open(argv[ii], O_RDONLY);
      if (fd < 0) {
        std::cerr << "Failed to open '" << argv[ii] << "'" << std::endl;
        continue;
      }
      ProcessFile(fd);
      close(fd);
    }
  }
  return 0;
}
