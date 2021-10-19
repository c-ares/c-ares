Creating Combined gmock release
===============================
```
wget https://github.com/google/googletest/archive/refs/tags/release-1.11.0.tar.gz && \
tar -zxvpf release-1.11.0.tar.gz && \
python3 ./googletest-release-1.11.0/googlemock/scripts/fuse_gmock_files.py ./googletest-release-1.11.0/googlemock gmock-1.11.0 && \
rm -rf googletest-release-1.11.0 release-1.11.0.tar.gz
```

