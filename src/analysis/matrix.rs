use crate::{
    API_VERSION, AdapterReport, Scheme,
    adapters::{
        AdapterSupportError,
        bouncy_castle::{
            BouncyCastleConfig, BouncyCastleError, BouncyCastleMode, verify as verify_bouncy_castle,
        },
        gnutls::{
            GnuTlsContainerConfig, GnuTlsError, GnuTlsStudyConfig,
            verify_container as verify_gnutls_container, verify_study as verify_gnutls_study,
        },
        go_x509::{
            GoX509ContainerConfig, GoX509Error, GoX509Release, verify_container as verify_go,
        },
        nss::{NssConfig, NssError, NssRelease, verify as verify_nss},
        openssl::{
            OpenSslContainerConfig, OpenSslError, OpenSslStudyConfig,
            verify_container as verify_openssl_container, verify_study as verify_openssl_study,
        },
        oqs_provider::{OqsProviderConfig, OqsProviderError, verify as verify_oqs_provider},
        pyca::{
            PycaContainerConfig, PycaError, PycaRelease, verify_container as verify_pyca_container,
        },
        wolfssl::{WolfSslConfig, WolfSslError, WolfSslMode, verify as verify_wolfssl},
    },
    mutation::{MutationError, corrupt_outer_signature, encode_certificate_pem},
    pem::{PemError, PemKind, read_der},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct AvailableMatrixConfig {
    pub fixtures: PathBuf,
    pub controls: PathBuf,
    pub openssl_current_image: String,
    pub openssl_study_image: String,
    pub gnutls_current_image: String,
    pub gnutls_study_image: String,
    pub go_study_image: String,
    pub go_current_image: String,
    pub pyca_study_image: String,
    pub pyca_current_image: String,
    pub docker: PathBuf,
    pub bouncy_castle_study_image: String,
    pub bouncy_castle_current_image: String,
    pub nss_study_image: String,
    pub nss_current_image: String,
    pub oqs_provider_image: String,
    pub wolfssl_image: String,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatrixEntry {
    pub case_id: String,
    pub scheme: Scheme,
    pub variant: MatrixVariant,
    pub report: AdapterReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixVariant {
    Valid,
    InvalidCertificateSignature,
    InvalidPostQuantumSignature,
    MissingHybridEvidence,
    BrokenBinding,
    UnknownHybridAlgorithm,
    MalformedHybridEvidence,
    CriticalHybridExtension,
    PublishedStudyFixture,
    InvalidHybridEvidenceSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatrixReport {
    pub api_version: String,
    pub requested_validation_time: String,
    pub entries: Vec<MatrixEntry>,
}

#[derive(Debug, Error)]
pub enum MatrixError {
    #[error(transparent)]
    OpenSsl(#[from] OpenSslError),
    #[error(transparent)]
    GnuTls(#[from] GnuTlsError),
    #[error(transparent)]
    Go(#[from] GoX509Error),
    #[error(transparent)]
    Pyca(#[from] PycaError),
    #[error(transparent)]
    BouncyCastle(#[from] BouncyCastleError),
    #[error(transparent)]
    Nss(#[from] NssError),
    #[error(transparent)]
    OqsProvider(#[from] OqsProviderError),
    #[error(transparent)]
    WolfSsl(#[from] WolfSslError),
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Pem(#[from] PemError),
    #[error(transparent)]
    Mutation(#[from] MutationError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy)]
struct Case {
    id: &'static str,
    scheme: Scheme,
    leaf: &'static str,
    issuer: &'static str,
    dns: &'static str,
    extension_oid: Option<&'static str>,
}

const CASES: [Case; 7] = [
    Case {
        id: "pure-pq-key",
        scheme: Scheme::PurePostQuantum,
        leaf: "pure-leaf.pem",
        issuer: "ica.pem",
        dns: "pure.pqc-probe.test",
        extension_oid: None,
    },
    Case {
        id: "pure-pq-signature",
        scheme: Scheme::PurePostQuantum,
        leaf: "pure-mldsa-signed-leaf.pem",
        issuer: "pure-mldsa-ica.pem",
        dns: "mldsa-signed.pqc-probe.test",
        extension_oid: None,
    },
    Case {
        id: "atomic-composite",
        scheme: Scheme::AtomicComposite,
        leaf: "composite-leaf.pem",
        issuer: "composite-ica.pem",
        dns: "composite.pqc-probe.test",
        extension_oid: None,
    },
    Case {
        id: "catalyst",
        scheme: Scheme::Catalyst,
        leaf: "catalyst-leaf.pem",
        issuer: "catalyst-ica.pem",
        dns: "catalyst.pqc-probe.test",
        extension_oid: Some("2.5.29.74"),
    },
    Case {
        id: "chameleon",
        scheme: Scheme::Chameleon,
        leaf: "chameleon-base.pem",
        issuer: "ica.pem",
        dns: "chameleon.pqc-probe.test",
        extension_oid: Some("2.16.840.1.114027.80.6.1"),
    },
    Case {
        id: "related",
        scheme: Scheme::Related,
        leaf: "related-certA.pem",
        issuer: "ica.pem",
        dns: "related-a.pqc-probe.test",
        extension_oid: Some("1.3.6.1.5.5.7.1.36"),
    },
    Case {
        id: "classical",
        scheme: Scheme::Classical,
        leaf: "related-certA-missing.pem",
        issuer: "ica.pem",
        dns: "related-a.pqc-probe.test",
        extension_oid: None,
    },
];

pub fn run_available_matrix(config: &AvailableMatrixConfig) -> Result<MatrixReport, MatrixError> {
    let root = config.fixtures.join("root.pem");
    let mut entries = Vec::with_capacity((CASES.len() * 2 + 9) * 15);
    for case in CASES {
        let leaf = match case.id {
            "chameleon" => config.controls.join("chameleon-base-valid-delta.pem"),
            "classical" => config.controls.join(case.leaf),
            _ => config.fixtures.join(case.leaf),
        };
        let issuer = config.fixtures.join(case.issuer);
        run_case(
            config,
            &mut entries,
            case,
            MatrixVariant::Valid,
            &root,
            &issuer,
            &leaf,
        )?;

        let der = read_der(&leaf, PemKind::Certificate, 16 * 1024 * 1024)?;
        let mut invalid_leaf = tempfile::NamedTempFile::new()?;
        invalid_leaf
            .write_all(encode_certificate_pem(&corrupt_outer_signature(&der)?).as_bytes())?;
        run_case(
            config,
            &mut entries,
            case,
            MatrixVariant::InvalidCertificateSignature,
            &root,
            &issuer,
            invalid_leaf.path(),
        )?;
    }
    for (case, variant, leaf) in [
        (
            CASES[3],
            MatrixVariant::InvalidPostQuantumSignature,
            "catalyst-leaf-bad-alt.pem",
        ),
        (
            CASES[2],
            MatrixVariant::InvalidPostQuantumSignature,
            "composite-leaf-bad-mldsa.pem",
        ),
        (
            CASES[5],
            MatrixVariant::MissingHybridEvidence,
            "related-certA-missing.pem",
        ),
        (
            CASES[5],
            MatrixVariant::BrokenBinding,
            "related-certA-broken-binding.pem",
        ),
        (
            CASES[5],
            MatrixVariant::UnknownHybridAlgorithm,
            "related-certA-unknown-digest.pem",
        ),
        (
            CASES[5],
            MatrixVariant::MalformedHybridEvidence,
            "related-certA-malformed.pem",
        ),
        (
            CASES[5],
            MatrixVariant::CriticalHybridExtension,
            "related-certA-critical.pem",
        ),
    ] {
        let issuer = config.fixtures.join(case.issuer);
        run_case(
            config,
            &mut entries,
            case,
            variant,
            &root,
            &issuer,
            &config.controls.join(leaf),
        )?;
    }
    let chameleon = CASES[4];
    for (variant, leaf) in [
        (
            MatrixVariant::PublishedStudyFixture,
            config.fixtures.join("chameleon-base.pem"),
        ),
        (
            MatrixVariant::InvalidHybridEvidenceSignature,
            config.controls.join("chameleon-base-bad-delta.pem"),
        ),
    ] {
        run_case(
            config,
            &mut entries,
            chameleon,
            variant,
            &root,
            &config.fixtures.join(chameleon.issuer),
            &leaf,
        )?;
    }
    Ok(MatrixReport {
        api_version: API_VERSION.to_owned(),
        requested_validation_time: config.validation_time.clone(),
        entries,
    })
}

fn run_case(
    config: &AvailableMatrixConfig,
    entries: &mut Vec<MatrixEntry>,
    case: Case,
    variant: MatrixVariant,
    root: &Path,
    issuer: &Path,
    leaf: &Path,
) -> Result<(), MatrixError> {
    push(
        entries,
        case,
        variant,
        verify_openssl_study(&OpenSslStudyConfig {
            docker: config.docker.clone(),
            image: config.openssl_study_image.clone(),
            trust_store: root.to_owned(),
            intermediate: issuer.to_owned(),
            leaf: leaf.to_owned(),
            crl: None,
            validation_time: config.validation_time.clone(),
            timeout: config.timeout,
            max_output_bytes: config.max_output_bytes,
        })?
        .report()?,
    );
    push(
        entries,
        case,
        variant,
        verify_openssl_container(&OpenSslContainerConfig {
            docker: config.docker.clone(),
            image: config.openssl_current_image.clone(),
            trust_store: root.to_owned(),
            intermediate: issuer.to_owned(),
            leaf: leaf.to_owned(),
            crl: None,
            validation_time: config.validation_time.clone(),
            timeout: config.timeout,
            max_output_bytes: config.max_output_bytes,
        })?
        .report()?,
    );
    push(
        entries,
        case,
        variant,
        verify_oqs_provider(&OqsProviderConfig {
            docker: config.docker.clone(),
            image: config.oqs_provider_image.clone(),
            trust_store: root.to_owned(),
            intermediate: issuer.to_owned(),
            leaf: leaf.to_owned(),
            validation_time: config.validation_time.clone(),
            timeout: config.timeout,
            max_output_bytes: config.max_output_bytes,
        })?
        .report()?,
    );
    for (release, image) in [
        (NssRelease::Study98, &config.nss_study_image),
        (NssRelease::Current126, &config.nss_current_image),
    ] {
        push(
            entries,
            case,
            variant,
            verify_nss(&NssConfig {
                docker: config.docker.clone(),
                image: image.clone(),
                release,
                trust_store: root.to_owned(),
                intermediate: issuer.to_owned(),
                leaf: leaf.to_owned(),
                validation_time: config.validation_time.clone(),
                timeout: config.timeout,
                max_output_bytes: config.max_output_bytes,
            })?
            .report()?,
        );
    }
    for image in [
        &config.bouncy_castle_study_image,
        &config.bouncy_castle_current_image,
    ] {
        push(
            entries,
            case,
            variant,
            verify_bouncy_castle(&BouncyCastleConfig {
                docker: config.docker.clone(),
                image: image.clone(),
                trust_store: root.to_owned(),
                intermediate: issuer.to_owned(),
                leaf: leaf.to_owned(),
                validation_time: config.validation_time.clone(),
                timeout: config.timeout,
                max_output_bytes: config.max_output_bytes,
                mode: BouncyCastleMode::Path,
                private_key: None,
                crl: None,
            })?
            .report()?,
        );
    }
    for mode in [WolfSslMode::Default, WolfSslMode::DualAlgorithm] {
        push(
            entries,
            case,
            variant,
            verify_wolfssl(&WolfSslConfig {
                docker: config.docker.clone(),
                image: config.wolfssl_image.clone(),
                mode,
                scheme: case.id.to_owned(),
                trust_store: root.to_owned(),
                intermediate: Some(issuer.to_owned()),
                leaf: leaf.to_owned(),
                validation_time: config.validation_time.clone(),
                timeout: config.timeout,
                max_output_bytes: config.max_output_bytes,
            })?
            .report()?,
        );
    }
    push(
        entries,
        case,
        variant,
        verify_gnutls_container(&GnuTlsContainerConfig {
            docker: config.docker.clone(),
            image: config.gnutls_current_image.clone(),
            trust_store: root.to_owned(),
            intermediate: issuer.to_owned(),
            leaf: leaf.to_owned(),
            validation_time: config.validation_time.clone(),
            timeout: config.timeout,
            max_output_bytes: config.max_output_bytes,
        })?
        .report()?,
    );
    push(
        entries,
        case,
        variant,
        verify_gnutls_study(&GnuTlsStudyConfig {
            docker: config.docker.clone(),
            image: config.gnutls_study_image.clone(),
            trust_store: root.to_owned(),
            intermediate: issuer.to_owned(),
            leaf: leaf.to_owned(),
            validation_time: config.validation_time.clone(),
            timeout: config.timeout,
            max_output_bytes: config.max_output_bytes,
        })?
        .report()?,
    );
    for (release, image) in [
        (GoX509Release::Study1264, &config.go_study_image),
        (GoX509Release::Current1265, &config.go_current_image),
    ] {
        push(
            entries,
            case,
            variant,
            verify_go(&GoX509ContainerConfig {
                docker: config.docker.clone(),
                image: image.clone(),
                trust_store: root.to_owned(),
                intermediate: issuer.to_owned(),
                leaf: leaf.to_owned(),
                dns_name: case.dns.to_owned(),
                validation_time: config.validation_time.clone(),
                timeout: config.timeout,
                max_output_bytes: config.max_output_bytes,
                release,
            })?
            .report()?,
        );
    }
    for (release, image) in [
        (PycaRelease::Study49, &config.pyca_study_image),
        (PycaRelease::Current50, &config.pyca_current_image),
    ] {
        push(
            entries,
            case,
            variant,
            verify_pyca_container(&PycaContainerConfig {
                docker: config.docker.clone(),
                image: image.clone(),
                release,
                trust_store: root.to_owned(),
                intermediate: issuer.to_owned(),
                leaf: leaf.to_owned(),
                dns_name: case.dns.to_owned(),
                validation_time: config.validation_time.clone(),
                hybrid_extension_oid: case.extension_oid.map(str::to_owned),
                timeout: config.timeout,
                max_output_bytes: config.max_output_bytes,
            })?
            .report()?,
        );
    }
    Ok(())
}

fn push(entries: &mut Vec<MatrixEntry>, case: Case, variant: MatrixVariant, report: AdapterReport) {
    entries.push(MatrixEntry {
        case_id: case.id.to_owned(),
        scheme: case.scheme,
        variant,
        report,
    });
}

pub fn default_fixture_path() -> &'static Path {
    Path::new("tests/fixtures/paper-v1.0.2")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StackVerdict;
    #[test]
    fn available_matrix_records_every_case_and_adapter() {
        let report = run_available_matrix(&AvailableMatrixConfig {
            fixtures: Path::new(env!("CARGO_MANIFEST_DIR")).join(default_fixture_path()),
            controls: Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/generated-controls"),
            openssl_current_image: "hybrid-x509-openssl:4.0.1".to_owned(),
            openssl_study_image: "hybrid-x509-oqs-provider:0.11.0".to_owned(),
            gnutls_current_image: "hybrid-x509-gnutls:3.8.13".to_owned(),
            gnutls_study_image: "hybrid-x509-gnutls:3.7.3".to_owned(),
            go_study_image: "hybrid-x509-go:1.26.4".to_owned(),
            go_current_image: "hybrid-x509-go:1.26.5".to_owned(),
            pyca_study_image: "hybrid-x509-pyca:49.0.0".to_owned(),
            pyca_current_image: "hybrid-x509-pyca:50.0.0".to_owned(),
            docker: "docker".into(),
            bouncy_castle_study_image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            bouncy_castle_current_image: "hybrid-x509-bouncycastle:1.85".to_owned(),
            nss_study_image: "hybrid-x509-nss:3.98".to_owned(),
            nss_current_image: "hybrid-x509-nss:3.126".to_owned(),
            oqs_provider_image: "hybrid-x509-oqs-provider:0.11.0".to_owned(),
            wolfssl_image: "hybrid-x509-wolfssl:5.9.2".to_owned(),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(report.entries.len(), 345);
        assert_eq!(
            report
                .entries
                .iter()
                .filter(|entry| entry.variant == MatrixVariant::InvalidPostQuantumSignature)
                .count(),
            30
        );
        for variant in [
            MatrixVariant::MissingHybridEvidence,
            MatrixVariant::BrokenBinding,
            MatrixVariant::UnknownHybridAlgorithm,
            MatrixVariant::MalformedHybridEvidence,
            MatrixVariant::CriticalHybridExtension,
        ] {
            assert_eq!(
                report
                    .entries
                    .iter()
                    .filter(|entry| entry.variant == variant)
                    .count(),
                15
            );
        }
        for variant in [
            MatrixVariant::PublishedStudyFixture,
            MatrixVariant::InvalidHybridEvidenceSignature,
        ] {
            assert_eq!(
                report
                    .entries
                    .iter()
                    .filter(|entry| entry.variant == variant)
                    .count(),
                15
            );
        }
        let related: Vec<_> = report
            .entries
            .iter()
            .filter(|entry| entry.case_id == "related" && entry.variant == MatrixVariant::Valid)
            .collect();
        assert_eq!(related.len(), 15);
        assert!(
            related
                .iter()
                .all(|entry| entry.report.observation.verdict == StackVerdict::Accept)
        );
        let classical: Vec<_> = report
            .entries
            .iter()
            .filter(|entry| entry.case_id == "classical" && entry.variant == MatrixVariant::Valid)
            .collect();
        assert_eq!(classical.len(), 15);
        assert!(
            classical
                .iter()
                .all(|entry| entry.report.observation.verdict == StackVerdict::Accept)
        );
        assert_eq!(
            report
                .entries
                .iter()
                .find(|entry| {
                    entry.case_id == "pure-pq-signature"
                        && entry.variant == MatrixVariant::Valid
                        && entry.report.observation.adapter == "gnutls-study"
                })
                .unwrap()
                .report
                .observation
                .verdict,
            StackVerdict::Unsupported
        );
        let invalid_accepts: Vec<_> = report
            .entries
            .iter()
            .filter(|entry| {
                entry.variant == MatrixVariant::InvalidCertificateSignature
                    && entry.report.observation.verdict == StackVerdict::Accept
            })
            .map(|entry| (&entry.case_id, &entry.report.observation.adapter))
            .collect();
        assert!(invalid_accepts.is_empty(), "{invalid_accepts:?}");
        for (variant, verdict) in [
            (MatrixVariant::Valid, StackVerdict::Accept),
            (
                MatrixVariant::InvalidPostQuantumSignature,
                StackVerdict::Reject,
            ),
        ] {
            assert_eq!(
                report
                    .entries
                    .iter()
                    .find(|entry| {
                        entry.case_id == "atomic-composite"
                            && entry.variant == variant
                            && entry.report.observation.adapter == "bouncycastle-java-study"
                    })
                    .unwrap()
                    .report
                    .observation
                    .verdict,
                verdict
            );
        }
    }
}
