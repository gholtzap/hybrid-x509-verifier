# Certificate corpus generator

This is the published `gen.GenValid` generator from artifact version 1.0.2 for
arXiv:2607.20800. The source commit is
`b1c2ee5e87862c4103b482571945505f82a0d0d9`. The source is Apache-2.0.

Run the generator and verify each generated DER value:

```sh
tools/corpus-generator/generate.sh
```

The command uses a pinned Maven and Java container. It writes to
`target/generated-corpus` by default. You can give a different output directory as the first
argument.

The Bouncy Castle composite key generator does not give byte-identical output with the fixed
random source. The command therefore starts with the published composite fixed vectors. The
independent Rust verifier checks these vectors and all generated certificates and CRLs against
the published DER size and SHA-256 digest.

New atomic path controls do not use that key generator. They construct composite keys from
deterministic ML-DSA-44 and P-256 component keys and set the Bouncy Castle component random source
before each composite signature. The full atomic chain, keys, mutations, and CRLs are
byte-identical across two runs.

The pure path controls form a deterministic ML-DSA root, intermediate, and leaf chain. They
include one invalid signature at each position and current root and intermediate CRLs. All files
are byte-identical across two runs.

The cross-signed controls use one composite intermediate key under separate classical and atomic
trust anchors. They include both intermediate certificates, route bundles, broken-route bundles,
component mutations, and current CRLs. All files are byte-identical across two runs.

The generator also creates `catalyst-leaf-bad-alt.pem`. Its classical signature is valid, but
its alternative ML-DSA signature is invalid. The command runs the generator twice and confirms
that this control is byte-identical.

It also creates `composite-leaf-bad-mldsa.pem` from the fixed composite vector. The mutation
changes one byte in the 2,420-byte ML-DSA-44 component and leaves the ECDSA component and signed
certificate data unchanged.
