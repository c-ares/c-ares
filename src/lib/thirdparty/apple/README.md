The `dnsinfo.h` header was extracted from Apple's OpenSource repository:
[https://opensource.apple.com/source/configd/configd-963.50.8/dnsinfo/dnsinfo.h](https://opensource.apple.com/source/configd/configd-963.50.8/dnsinfo/dnsinfo.h)

We did make one tweak to this file to put `(void)` as the parameter list for both `dns_configuration_notify_key()`
and `dns_configuration_copy()` to sidestep compiler warnings in this old header.

NOTE: For legacy MacOS compatibility, we needed to import 963.50.8.  We tried with the
latest (at this time) of 1109.140.1, and it caused issues with MacPorts still supporting
MacOS versions 10.8-10.11.  There's really not any reason to not support these if it doesn't
take much effort if MacPorts still is.

This is needed to call into `dns_configuration_copy()` and `dns_configuration_free()`.
