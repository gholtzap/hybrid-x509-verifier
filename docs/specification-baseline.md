# Specification baseline

Checked on 2026-08-05.

| Source | Version or status | Use |
| --- | --- | --- |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) | Internet Standard profile | Classical path and revocation rules |
| [RFC 9763](https://www.rfc-editor.org/rfc/rfc9763.html) | June 2025 | RelatedCertificate structure and binding |
| [RFC 9794](https://www.rfc-editor.org/rfc/rfc9794.html) | June 2025 | Hybrid terminology |
| [RFC 9881](https://www.rfc-editor.org/info/rfc9881) | October 2025 | ML-DSA X.509 algorithm identifiers |
| [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | Final, 2024; 2026 errata note | ML-DSA |
| [Composite ML-DSA draft](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) | draft-ietf-lamps-pq-composite-sigs-19; RFC Editor queue | Atomic composite fixture classification |
| [Chameleon certificate draft](https://datatracker.ietf.org/doc/draft-bonnell-lamps-chameleon-certs/) | draft-bonnell-lamps-chameleon-certs-07; expired | Research reproduction only |
| [Verifier-semantics paper](https://arxiv.org/abs/2607.20800) | v1, 2026-07-23 | Threat model and published comparison |
| [Paper artifact](https://github.com/taesung901-ui/pqt-verifier-semantics-artifact) | v1.0.2, commit `b1c2ee5e87862c4103b482571945505f82a0d0d9` | Synthetic fixtures and result comparison |

The evaluator does not treat a draft as a stable production contract. Scheme-specific rules
must name the exact source revision in each transcript.

## Validation stack baseline

The release sources were checked on 2026-08-05.

| Stack | Current control | Study control | Official source |
| --- | --- | --- | --- |
| OpenSSL | 4.0.1 | 3.5.7 | [OpenSSL releases](https://github.com/openssl/openssl/releases) |
| oqs-provider | 0.11.0 | 0.11.0 | [oqs-provider releases](https://github.com/open-quantum-safe/oqs-provider/releases) |
| GnuTLS | 3.8.13 | 3.7.3 | [GnuTLS release files](https://www.gnupg.org/ftp/gcrypt/gnutls/) |
| NSS | 3.126 | 3.98 | [NSS release files](https://ftp.mozilla.org/pub/security/nss/releases/) |
| Go crypto/x509 | 1.26.5 | 1.26.4 | [Go releases](https://go.dev/dl/) |
| Python cryptography | 50.0.0 | 49.0.0 | [Python package index](https://pypi.org/project/cryptography/) |
| Bouncy Castle Java | 1.85 | 1.84 | [Maven Central metadata](https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-jdk18on/maven-metadata.xml) |
| wolfSSL | 5.9.2 | 5.9.2 | [wolfSSL releases](https://github.com/wolfSSL/wolfssl/releases) |

When the current and study versions are equal, one fixed build covers both tracks. The wolfSSL
build has separate default and dual-algorithm modes.
