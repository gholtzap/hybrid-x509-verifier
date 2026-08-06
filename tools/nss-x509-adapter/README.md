# NSS X.509 adapter

This adapter runs the paper's NSS 3.98 package and current NSS 3.126 with
`certUsageSSLServer` validation at a supplied UTC minute. The 3.126 image builds Mozilla's
NSS 3.126 and NSPR 4.39 archive after it verifies Mozilla's published SHA-256 value. Both Ubuntu
base images use fixed digests.

```sh
tools/nss-x509-adapter/build.sh
```

The Rust adapter runs the image without network access, capabilities, or a writable root file
system. The temporary NSS database is in a size-limited temporary file system.
