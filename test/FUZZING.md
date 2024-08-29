# Fuzzing Hints

1. Set compiler that supports fuzzing, this is an example on MacOS using
   a homebrew-installed clang/llvm:
```
export CC="/opt/homebrew/Cellar/llvm/18.1.8/bin/clang"
export CXX="/opt/homebrew/Cellar/llvm/18.1.8/bin/clang++"
```

2. Compile c-ares with both ASAN and fuzzing support.  We want an optimized
   debug build so we will use `RelWithDebInfo`:
```
export CFLAGS="-fsanitize=address,fuzzer-no-link"
export CXXFLAGS="-fsanitize=address,fuzzer-no-link"
export LDFLAGS="-fsanitize=address,fuzzer-no-link"
mkdir buildfuzz
cd buildfuzz
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -G Ninja ..
ninja
```

3. Build the fuzz test itself linked against our fuzzing-enabled build:
```
${CC} -W -Wall -fsanitize=address,fuzzer -I../include -I../src/lib/include -I. -o ares-test-fuzz ../test/ares-test-fuzz.c -L./lib -Wl,-rpath ./lib -lcares
```

4. Run the fuzzer, its better if you can provide seed input but it does pretty
   well on its own since it uses coverage data to determine how to proceed.
   You can play with other flags etc, like `-jobs=XX` for parallelism.  See
   https://llvm.org/docs/LibFuzzer.html
```
mkdir corpus
./ares-test-fuzz -max_len=65535 corpus
```
