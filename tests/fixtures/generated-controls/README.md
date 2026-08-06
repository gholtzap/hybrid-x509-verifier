# Generated controls

These synthetic controls come from `tools/corpus-generator`. They contain no real credentials.
The generator uses fixed keys, times, serial values, and signing random sources.

- `catalyst-leaf-bad-alt.pem` has a valid classical signature and an invalid alternative
  ML-DSA signature.
- `catalyst-leaf-base-key.pem` is a test-only ECDSA private key for TLS proof-of-possession
  checks. It matches the classical key in both Catalyst leaf controls.
- The `catalyst-path-*` files form a deterministic Catalyst root, intermediate, and leaf chain;
  add one wrong alternative signer at a time; provide the leaf test keys; and provide current
  empty root and intermediate CRLs.
- `pure-leaf-key.pem` is the test-only ML-DSA-44 private key for the pure post-quantum TLS
  proof-of-possession control.
- The `pure-path-*` files form a deterministic ML-DSA root, intermediate, and leaf chain. Each
  position has an invalid-signature control. The root and intermediate have current empty CRLs.
- `composite-leaf-key.pem`, `related-certA-key.pem`, and `related-leafB-key.pem` are the matching
  test-only keys for protocol controls.
- The Chameleon controls contain the test-only base and delta keys, the original reconstructed
  delta certificate, a corrected path-valid base certificate with valid delta evidence, and a
  path-valid base certificate whose delta certificate has the wrong signer.
- The `chameleon-path-*` files form parallel ML-DSA base and ECDSA delta chains. Each position
  has an invalid base signature and a valid base that contains an invalid delta signature. Both
  chains have current empty CRLs.
- `composite-leaf-bad-mldsa.pem` has an invalid ML-DSA-44 component and unchanged ECDSA
  component and signed certificate data.
- The `atomic-path-*` files form a deterministic, fully atomic root, intermediate, and leaf
  chain. Each position has separate invalid ECDSA and ML-DSA controls. The root and intermediate
  also have deterministic composite-signed empty CRLs.
- The `cross-*` files form a deterministic cross-signed hierarchy. The same composite
  intermediate key has a classical cross-certificate and an atomic cross-certificate under
  separate trust anchors. Route bundles, signature mutations, and three current CRLs support
  controlled path-selection checks.
- `catalyst-crl.pem` is a current empty CRL from the Catalyst issuing CA.
- `root-crl.pem` is a current empty CRL from the common classical root.
- The seven `related-*-ocsp.der.b64` files cover good classical status, revoked classical
  status, good post-quantum status, revoked post-quantum status, unknown post-quantum
  status, stale post-quantum status, and an unavailable responder.
- The nonce response uses the fixed 16-byte nonce `ABEiM0RVZneImaq7zN3u/w==`.
- The malformed response is a truncated four-byte DER value.
- The delegated responses prove acceptance with the OCSP signing extended usage and rejection
  when that authorization is missing.
- `related-crl-future.pem` lists a revocation that takes effect after the fixed validation time.
- `related-leafB-wrong-signer.pem` has the expected issuer name and serial but the wrong signer.
- `related-leafB-unbound.pem` is current and path-valid but does not match certA's binding hash.
- The five `related-certA-*` controls cover missing, broken, unknown-algorithm, malformed, and
  critical RelatedCertificate evidence.
- The `related-path-*` files form paired classical and ML-DSA chains. Each classical certificate
  binds the paired post-quantum certificate at the same position. Each position has bad-binding
  and bad-signature controls. Both chains have current empty CRLs.

`tools/corpus-generator/generate.sh` generates each control twice and compares the two outputs.
