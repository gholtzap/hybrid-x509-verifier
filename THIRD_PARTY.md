# Third-party data

`tests/fixtures/paper-v1.0.2` contains a subset of the synthetic corpus from the
`pqt-verifier-semantics-artifact` version 1.0.2 repository at commit
`b1c2ee5e87862c4103b482571945505f82a0d0d9`.

The corpus data is under CC0-1.0. Its license text and original digest manifest are included
with the fixtures. No private keys, real credentials, domains, or personal data are included.
# Published corpus generator

The files in `tools/corpus-generator/src` and its Maven build file come from version 1.0.2 of
the reproducibility package for arXiv:2607.20800, commit
`b1c2ee5e87862c4103b482571945505f82a0d0d9`. They use the Apache License 2.0.

The Bouncy Castle adapter downloads Bouncy Castle Java 1.84 during its container build. Bouncy
Castle uses its own permissive license. See <https://www.bouncycastle.org/licence.html>.
# Paper wolfSSL verification harness

`tools/wolfssl-x509-adapter/wolfssl_verify.c` is adapted from the Apache-2.0 reproducibility
artifact for arXiv:2607.20800, copyright 2026 Electronics and Telecommunications Research
Institute.

# Imported OCSP verification vectors

`tests/fixtures/ocsp-imported` contains a public certificate, its issuer certificate, and an
OCSP response from the `x509-verify` 0.4.8 test data. The source repository is
<https://github.com/bhesh/x509-verify/> and uses the Apache-2.0 or MIT license. The response is
stored as Base64 text. These imported vectors test parsing and signature verification. They are
not part of the synthetic product matrix.
