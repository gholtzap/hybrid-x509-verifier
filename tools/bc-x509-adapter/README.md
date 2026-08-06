# Bouncy Castle X.509 adapter

The `tls-transcript` mode runs an in-memory TLS 1.3 client and server twice. The first handshake
uses the correct ECDSA transcript input. The second signs a one-bit-altered transcript input with
the same key and certificate. A third handshake offers only an incompatible CertificateVerify
signature algorithm. The mode passes only when the first handshake completes and both negative
controls are rejected.

This adapter runs Bouncy Castle Java 1.84 PKIX validation at an exact validation time. Version
1.84 is both the study version and the current release as of 2026-08-04.

Build the pinned container:

```sh
tools/bc-x509-adapter/build.sh
```

The Rust adapter runs the container without a network, capabilities, or a writable root file
system. It mounts only the required certificates and, for the TLS control, its test key as
read-only files.

`path-builder` accepts bounded certificate bundles in the root and intermediate inputs. It uses
the PKIX path builder and emits the SHA-256 identity and signature algorithm of every selected
certificate, including the trust anchor.
