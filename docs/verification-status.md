# Verification status

## Publication status

Do not publish this repository as a Hybrid X.509 authentication verifier in its current form. The
main command evaluates trusted, caller-supplied evidence claims. It does not independently derive
most certificate, path, revocation, or TLS facts from the original inputs.

The local results below are fixture-specific observations for the named source tree, commands,
adapters, and versions. They are not general proofs of X.509, TLS, hybrid-draft, or library
behavior.

## Locally observed in the current repository

- The policy oracle cannot return hybrid acceptance under P2 unless all in-scope
  certificates use a hybrid scheme, all required classical and post-quantum checks pass, and the
  request declares a bound selected path with a trust anchor.
- The oracle requires the stack report to name the applied validation time. A known
  failure overrides unrelated indeterminate input. `not-applicable` cannot bypass presence,
  recognition, signature, path, validity, revocation, or decision-sensitive-for-fixture checks. Pure
  post-quantum acceptance cannot be labeled as classical authentication.
- P3 is disabled as an acceptance policy until an authenticated continuity record exists. A
  caller-supplied previous level is not enough to preserve, upgrade, or downgrade authentication.
- Inferred or unknown checks cannot establish hybrid authentication.
- Omitted in-scope certificate evidence is a policy failure.
- The imported paper root certificate has its published DER SHA-256 digest.
- The containerized published generator reproduces all 17 Bouncy Castle artifacts. An
  independent Rust check confirms each DER size and SHA-256 digest.
- The six named certificate designs receive OID-based fixture classification in the imported
  paper corpus.
- The RelatedCertificate digest value in the published fixture matches the paired certificate.
- A deterministic RelatedCertificate control is current, issuer-signed, and accepted as a direct
  path, but its DER does not match the classical certificate's embedded hash. The independent
  binding check rejects it. This isolates binding failure from path, expiry, and revocation.
- The published CRL has a valid issuer match, time range, and signature. It revokes the bound
  post-quantum certificate.
- The CRL checker verifies the target certificate signature, CRL signer authorization and
  signature, inner and outer signature algorithm agreement, strict DER completion, extension
  semantics, normalized serial values, strict nextUpdate handling, and revocation effective time.
  Deterministic controls show that a future revocation is not active, exact nextUpdate is stale,
  and a copied issuer name and serial cannot replace certificate signature proof. Advanced CRL
  semantics such as indirect, partitioned, and delta CRLs are unsupported.
- The independent OCSP checker recomputes CertID issuer hashes and the certificate serial,
  verifies the target issuer and response signature, checks responder identity and bounded
  freshness, and maps good, revoked, unknown, and unavailable states without promoting an
  indeterminate result. An imported signed-good response passes. A one-bit signature mutation,
  a stale validation time, and a responder error cannot supply valid revocation evidence.
- The corpus generator creates deterministic OCSP responses for good classical status, revoked
  classical status, good post-quantum status, revoked post-quantum status, unknown
  post-quantum status, stale post-quantum status, an unavailable responder, and malformed DER.
  It also creates a fixed
  nonce response, an authorized delegated response, and a response signed by a delegated
  certificate without the required OCSP signing extended usage. Two independent generator runs
  and the committed controls have exact byte equality. The independent checker produces each
  expected result at the fixed validation time. A missing or different requested nonce prevents
  valid revocation evidence. The checker also rejects trailing certificate DER, mismatched inner
  and outer certificate signature algorithms, duplicate OCSP extensions, and unsupported
  critical OCSP extensions. Delegated responders without `id-pkix-ocsp-nocheck` or separate
  responder-revocation evidence produce indeterminate status evidence.
- The isolated current OpenSSL 4.0.1 adapter accepts the classical certificate and rejects the
  post-quantum certificate when the CRL is applied directly. It also rejects the published
  expired post-quantum credential at the same validation time.
- OpenSSL rejects a controlled mutation that changes only the outer classical signature.
- The combined P2 analysis reports rejection, classical-only fallback, and lifecycle
  desynchronization.
- External process execution has a time limit and bounded output capture.
- A timeout terminates the adapter process group. A test shows that a descendant cannot remain
  active after the timeout.
- Each stack observation states whether it used X.509 path validation or Web PKI server
  validation and whether execution had container isolation or process-only limits. The current
  matrix does not hide either difference.
- All 345 authoritative matrix entries use the shared container boundary. It disables network
  and IPC access, uses a read-only root and read-only input mounts, removes all capabilities,
  prevents privilege gain, runs as user 65532, rejects unsafe mount delimiters, and sets CPU,
  memory, process, file, output, and time limits. User-supplied native diagnostic probes are
  labeled `process-only` and are not part of the authoritative matrix. The Related revocation
  analysis now uses the isolated current OpenSSL container.
- The repository-owned Go, Bouncy Castle, Python cryptography, and wolfSSL adapters emit typed
  adapter-scope observations. Go records its direct
  issuer-signature check, Web PKI path operation, algorithms, outcomes, and observed extensions.
  Bouncy Castle records PKIX path, alternative-signature, delta-signature, and TLS transcript
  operations. Python cryptography records its Web PKI verification call and parsed leaf
  extensions. wolfSSL records its direct certificate-manager load and path-verification calls.
  These observations do not show full library internal behavior unless the library source is
  directly instrumented. Other adapters remain black-box results and do not claim internal
  execution. The current
  matrix has 184 instrumented entries across these eight adapter profiles.
- The available matrix records 345 isolated raw results: seven valid cases, a deterministic
  corrupted outer-signature variant for each case, invalid Catalyst, atomic-composite, and
  Chameleon evidence signatures, the published Chameleon study fixture, and Related Certificate
  controls for missing evidence, broken binding, an unknown algorithm, malformed evidence, a
  critical hybrid extension, and revoked classical status. It runs these cases across OpenSSL 4.0.1,
  oqs-provider 0.11.0 with
  OpenSSL 3.5.7, Bouncy Castle 1.84 and 1.85, NSS 3.98 and 3.126, GnuTLS 3.8.13 and 3.7.3,
  Go 1.26.4 and 1.26.5, Python cryptography 49.0.0 and 50.0.0, plus wolfSSL 5.9.2 in default and
  dual-algorithm modes. Each result states whether its version is current, a study version,
  both, or supplied by the user.
- Bouncy Castle 1.84 is the study adapter and Bouncy Castle 1.85 is the current adapter as of
  2026-08-05. Both run in read-only containers without network access or capabilities.
- A deterministic Catalyst control has a valid classical signature and an invalid ML-DSA
  alternative signature. It is byte-identical across two generator runs.
- A deterministic Catalyst path-scope chain has Catalyst evidence at the trust anchor,
  intermediate, and leaf. Three controls use a wrong alternative signer at one position at a
  time. They are byte-identical across two generator runs. Bouncy Castle default PKIX validation
  accepts the valid chain and all three invalid-alternative-signature chains. Direct alternative
  signature checks accept each valid position and reject each matching invalid control.
- The path-scope analyzer independently checks validity and current empty CRLs at one common time.
  It records fixture sensitivity for leaf and intermediate signatures. Trust-anchor
  self-signature controls remain experimental data and are not selected PKIX path evidence.
- A deterministic atomic-composite control changes one byte in the ML-DSA-44 signature
  component. Its signed certificate data and ECDSA component are byte-identical to the valid
  certificate. Bouncy Castle accepts the valid certificate and rejects this control. Every
  other matrix stack reports the atomic-composite scheme as unsupported. A separate control
  changes only the ECDSA component, and Bouncy Castle also rejects it.
- The generator constructs composite keys from deterministic ML-DSA-44 and P-256 component keys.
  This avoids the Bouncy Castle composite key generator, which ignores an injected fixed random
  source. Two independent runs produce byte-identical atomic root, intermediate, leaf, private
  keys, component mutations, and composite-signed CRLs.
- Bouncy Castle accepts the fully atomic path. Direct signature checks accept each valid
  certificate and reject separate ECDSA and ML-DSA mutations at the leaf, intermediate, and root.
  Both component mutations change path acceptance at the leaf and intermediate. Both root
  mutations do not change path acceptance because the root is the trust anchor. Composite-signed
  empty CRLs pass at the common validation time. P2 accepts the end-entity and certification-path scopes because trust-anchor self-signatures are not selected path evidence.
- A deterministic pure ML-DSA hierarchy has post-quantum certificates at the root,
  intermediate, and leaf. The valid path, all direct signature checks, validity checks, and both
  CRLs pass. Invalid signatures change path acceptance at the leaf and intermediate. The trust
  anchor self-signature is not decision-sensitive-for-fixture. P2 rejects all scopes because a pure
  post-quantum path is not hybrid, and the report does not label it as classical fallback.
- A deterministic cross-signed hierarchy gives one composite-key intermediate a classical
  cross-certificate and an atomic-composite cross-certificate under separate trust anchors. The
  path builder records the SHA-256 identity of each selected certificate. With both valid routes,
  Bouncy Castle selects the atomic route. Removing either trust anchor forces the matching route.
  Breaking only the atomic cross-certificate selects the classical route, and breaking only the
  classical cross-certificate selects the atomic route. Direct signature mutations, path
  mutations, validity checks, and all three CRLs establish the evidence at one common time. P2
  accepts the selected atomic route through certification-path scope. It rejects and classifies the
  selected classical route as classical-only fallback at certification-path scope. Certification-path
  results do not use trust-anchor self-signature evidence.
- Bouncy Castle 1.84 default validation accepts both the valid and invalid-PQ Catalyst controls.
  It rejects the invalid classical control. Its direct alternative-signature operation accepts
  the valid PQ control and rejects the invalid PQ control.
- The published Chameleon base certificate does not provide a valid positive delta-signature
  control. Its base certificate has inherited server extensions that are absent from the
  originally signed delta certificate. Direct reconstruction therefore changes the delta
  certificate signed data, and Bouncy Castle rejects its signature. The deterministic corrected
  control signs the delta certificate with the inherited extensions present. A second control
  uses the wrong delta signer. Bouncy Castle default path validation accepts both base
  certificates. Its direct delta-signature operation accepts the corrected control and rejects
  the wrong-signer control and the published fixture. This shows that default acceptance does
  not establish Chameleon delta authentication.
- A deterministic Chameleon hierarchy has ML-DSA base and ECDSA delta certificates at the root,
  intermediate, and leaf. The direct delta verifier reconstructs the issuer delta certificate
  when the issuer is also Chameleon. Both complete paths, all direct signatures, all validity
  checks, and four CRLs pass. At every position, the base path accepts a valid base certificate
  that contains an invalid delta signature. P2 rejects every scope because the classical delta
  evidence is not decision-sensitive-for-fixture. A bad base signature changes path acceptance at the leaf and
  intermediate, but not at the trust anchor.
- The Catalyst P2 analysis reports `classical_only_fallback: true` and rejects hybrid
  authentication. Every CRL check passes at the common validation time.
- The same analysis evaluates the published mixed chain at all scopes. End-entity P2 rejects
  because the leaf alternative signature is not decision-sensitive-for-fixture. Certification-path P2 also records
  that the Catalyst intermediate has an alternative public key but no alternative issuer
  signature. All three scopes reject, and no missing check is promoted to success.
- An isolated OpenSSL 4.0.1 TLS 1.3 server and client complete hostname and path verification for
  both the valid Catalyst certificate and its independently checked invalid-PQ control. The same
  client rejects a certificate with an invalid classical outer signature. Both accepted cases use
  `ecdsa_secp256r1_sha256` certificate authentication. The negotiated `X25519MLKEM768` key-exchange
  group is recorded separately and is not promoted to hybrid certificate authentication. P2
  rejects the handshake as classical-only fallback. Certificate selection and classical proof of
  possession are behaviorally established. A separate Bouncy Castle TLS 1.3 control completes the
  unchanged handshake and rejects a valid ECDSA signature over a one-bit-altered transcript input.
  This behaviorally establishes transcript binding.
- OpenSSL 4.0.1 completes a TLS 1.3 server handshake with the pure ML-DSA-44 leaf and its
  deterministic test key. The structured report records `mldsa44` certificate authentication,
  hostname verification, certificate selection, and behaviorally established post-quantum proof
  of possession. The Bouncy Castle transcript control completes the unchanged ML-DSA handshake
  and rejects a valid ML-DSA signature over a one-bit-altered transcript input.
- A Bouncy Castle TLS 1.3 control validates the atomic-composite path and completes an ECDSA
  proof of possession with the deterministic leaf key. A control that changes only the ECDSA
  certificate-signature component is rejected. A second control that changes only the ML-DSA-44
  certificate-signature component is also rejected. Both certificate-signature components are
  therefore decision-sensitive-for-fixture for path acceptance. P2 remains indeterminate because no checked
  revocation status exists for the composite issuer.
- A Bouncy Castle TLS 1.3 control completes an ML-DSA-44 handshake with the corrected Chameleon
  base certificate. The same handshake accepts a base certificate with an invalid classical
  delta signature. Direct delta verification accepts the valid delta and rejects the invalid
  delta, while a separate ECDSA handshake shows possession of the delta private key. P2 rejects
  the base handshake because the classical delta evidence is not decision-sensitive-for-fixture. The report
  does not claim that the two separate handshakes are one hybrid proof.
- A Bouncy Castle TLS 1.3 control completes an RSA handshake with the published Related classical
  certificate. The same classical handshake accepts controls with broken and missing binding
  evidence. A separate ML-DSA-44 handshake shows that the bound post-quantum credential is usable,
  while the common-time CRL check shows that it is revoked. P2 rejects the classical handshake
  and reports classical-only fallback and lifecycle desynchronization.
- Deterministic parallel Related chains cover the leaf, intermediate, and trust anchor. At each
  position, the classical certificate contains a valid RFC 9763 hash of the paired ML-DSA
  certificate. Both complete chains, all direct signatures, all validity checks, and four CRLs
  pass at one time. A bad binding at any position remains acceptable through the classical path,
  while the independent binding checker rejects it. P2 rejects every scope because the paired
  post-quantum evidence does not affect the classical path decision. End-entity and certification-path results are classical-only fallback. Certification-path fallback does not use trust-anchor self-signature evidence.
- Each successful Bouncy Castle transcript control also runs a client that offers only an
  incompatible CertificateVerify signature algorithm. The atomic ECDSA, Chameleon ML-DSA and
  ECDSA, Related RSA and ML-DSA, Catalyst ECDSA, and pure ML-DSA credentials all reject this
  negative negotiation control. No result treats an incompatible classical signature as a
  post-quantum fallback, or the reverse.
- A direct Go issuer-signature check shows that Go 1.26.4 does not implement the corpus ML-DSA
  issuer-signature algorithm. This explains the paper's unsupported result even though Go path
  building reports only an unknown authority.
- Go 1.26.4 remains the pinned study adapter. Go 1.26.5 is the separate digest-pinned current
  adapter. Govulncheck reports no reachable vulnerability for current 1.26.5. It reports two
  fixed standard-library advisories in study 1.26.4, but neither affected symbol is reachable.
- The NSS 3.98 study adapter accepts Catalyst and Related through their classical paths. It
  reports the other four designs as unsupported. It runs without network access, capabilities,
  or a writable root file system.
- Current NSS 3.126 accepts both pure post-quantum designs, Catalyst, Chameleon, and Related. It
  reports atomic composite as unsupported. It uses `vfychain`, as does the study adapter. An
  earlier `certutil -V` adapter path accepted five corrupted leaf signatures after database
  import; the invalid-signature matrix found this adapter defect, and a build regression check
  prevents its return. The image verifies Mozilla's published source archive SHA-256 value before it
  builds NSS 3.126 and NSPR 4.39. Build packages are not fixed to a dated repository snapshot.
- The oqs-provider 0.11.0 adapter reproduces the paper's six valid-case results. Its version
  transcript shows that OpenSSL 3.5.7 and both the default and OQS providers are active. The
  image uses fixed source commits and a digest-pinned base. Build packages are not yet fixed to a
  dated repository snapshot.
- The GnuTLS 3.7.3 study adapter applies the requested UTC validation time with libfaketime. It
  reproduces the paper's unsupported ML-DSA issuer-signature result. The separate GnuTLS 3.8.13
  container rejects this certificate as an invalid signature.
- The current OpenSSL 4.0.1 image builds the checksum-pinned official source archive with
  digest-pinned build and runtime images. The current GnuTLS 3.8.13 image verifies the signed,
  checksum-pinned official source archive and uses a digest-pinned base and dated Debian package
  snapshot. Both run with the matrix container restrictions.
- wolfSSL 5.9.2 default mode accepts the paper Catalyst certificate through its classical path.
  Dual-algorithm mode rejects the same certificate with code -155. Both modes apply the common
  validation time and reproduce all six paper valid-case results.
- Python cryptography 49.0.0 reproduces the paper's six valid-case results. Current version
  50.0.0 also accepts the ML-DSA-signed chain. Both exact-version images use a digest-pinned
  Python base and hash-pinned Python packages. Both apply the common validation time and run in
  read-only containers without network access or capabilities.
- The paper comparison reports account for 65 rows from the published artifact: 54 common matrix
  rows match exactly, four wolfSSL fixed-vector rows match exactly, and seven lifecycle rows are
  covered by the Related OpenSSL and oracle reports. The both-good lifecycle row has an explicit
  semantic difference: the paper records stack acceptance for two valid separate credentials,
  while this product requires the post-quantum evidence to be decision-sensitive-for-fixture for P2 acceptance.
- A one-hour libFuzzer campaign completed 270,973,987 PEM parser executions, 298,856,673 oracle
  JSON executions, and 232,053,158 OCSP DER executions without a crash. A current-source
  30-second pass then completed 2,402,600 PEM executions, 2,384,611 oracle JSON executions, and
  2,153,800 OCSP DER executions without a crash.
- RustSec reports no advisory for the locked Rust graph. The pinned OSV Scanner 2.4.0 checks the
  Rust, Go, Maven, and Python manifests and reports no unhandled vulnerability. Its dated policy
  exception is limited to cryptography 49.0.0, the isolated exact study control; current 50.0.0
  is tested separately.
- The root `sbom-rust.cdx.json` and `sbom-all.cdx.json` files were regenerated after the
  `hybrid-x509-evidence/v8` rename. Both identify the current package as
  `hybrid-x509-evidence`.
- The Rust toolchain is fixed at 1.92.0. A digest-pinned, read-only Linux container runs the
  complete 31-test oracle suite from a copied clean source tree. The checked-in workflow defines
  the same locked oracle checks on Ubuntu and macOS and the complete adapter suite on Ubuntu.
- A separate digest-pinned Linux check builds the locked release binary twice in independent
  anonymous volumes and requires byte-identical SHA-256 digests. The current local digest is
  `ee83403dca3a30c93c5e070e11fd1a9e86946e81189cdaaf50ae58a5fe93a017`.
- A digest-pinned release Dockerfile runs as user 65532. Two no-cache arm64 builds produced
  byte-identical OCI archives after layer times were rewritten to the fixed source epoch. The
  local archive SHA-256 is
  `20f4e7641bb9ab4c74936fac11b3a9ec8acae59d8bd22898f1b47be9719e49e1`.

These statements are covered by runnable tests. They are local macOS arm64 results until the
same checks run in pinned clean-machine environments.

## Required work not locally provable

- Hosted multi-platform continuous integration has not run from this checkout. The source commit
  used for the local matrix and SBOM refresh is
  `4f4626bcb1e03c72a861905d412080340ed53c71`, with tree
  `a3e45e478c8167a89da09a95d519d2587bcd790b`, and origin
  `https://github.com/gholtzap/hybrid-x509-verifier.git`.
- `reports/local-arm64/available-matrix.json`, `reports/local-arm64/matrix-report.json`,
  `sbom-rust.cdx.json`, and `sbom-all.cdx.json` were regenerated from that clean source commit.
  Other checked-in `reports/local-arm64/*.json` files remain stale generated artifacts from the
  version-one contract and are excluded from current release evidence until regenerated.
- Independent review is not available from the local workspace. The local reports state unknowns
  where black-box adapter behavior cannot show internal execution.

The broad local matrix was rerun from the clean source commit above. Remaining publication work is
to regenerate the non-matrix local reports and to run the hosted multi-platform checks.
