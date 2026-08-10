use crate::{
    API_VERSION, AdapterReport, AlgorithmSecurity, BindingDesign, CheckResult, CheckState,
    Confidence, ProcessRecord, StackVerdict, ValidationProfile,
    adapters::{
        AdapterSupportError,
        bouncy_castle::{
            BouncyCastleConfig, BouncyCastleError, BouncyCastleMode, verify as verify_bouncy_castle,
        },
        container::readable_tempfile,
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
    path::{Path, PathBuf},
    process::Command,
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
    pub publication: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatrixEntry {
    pub case_id: String,
    pub subject_public_key_scheme: AlgorithmSecurity,
    pub certificate_signature_scheme: AlgorithmSecurity,
    pub binding_design: BindingDesign,
    pub variant: MatrixVariant,
    pub operation: ValidationProfile,
    pub expected_support: MatrixSupport,
    pub expected_stack_verdict: StackVerdict,
    pub process_execution: MatrixProcessExecution,
    pub claim_id: String,
    pub specification: String,
    pub specification_revision: String,
    pub report: AdapterReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixSupport {
    Supported,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatrixProcessExecution {
    pub version: CheckResult,
    pub verification: CheckResult,
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
    pub provenance: MatrixProvenance,
    pub entries: Vec<MatrixEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatrixProvenance {
    pub source_commit: String,
    pub source_tree: String,
    pub source_clean: bool,
    pub platform: String,
    pub adapter_images: Vec<AdapterImageProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdapterImageProvenance {
    pub image: String,
    pub content_digest: String,
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
    #[error("publication mode requires a clean source tree")]
    DirtySourceTree,
    #[error("cannot collect matrix provenance: {0}")]
    Provenance(String),
}

#[derive(Debug, Clone, Copy)]
struct Case {
    id: &'static str,
    subject_public_key_scheme: AlgorithmSecurity,
    certificate_signature_scheme: AlgorithmSecurity,
    binding_design: BindingDesign,
    leaf: &'static str,
    issuer: &'static str,
    dns: &'static str,
    extension_oid: Option<&'static str>,
}

const CASES: [Case; 7] = [
    Case {
        id: "pure-pq-key",
        subject_public_key_scheme: AlgorithmSecurity::PostQuantum,
        certificate_signature_scheme: AlgorithmSecurity::Classical,
        binding_design: BindingDesign::None,
        leaf: "pure-leaf.pem",
        issuer: "ica.pem",
        dns: "pure.pqc-probe.test",
        extension_oid: None,
    },
    Case {
        id: "pure-pq-signature",
        subject_public_key_scheme: AlgorithmSecurity::Classical,
        certificate_signature_scheme: AlgorithmSecurity::PostQuantum,
        binding_design: BindingDesign::None,
        leaf: "pure-mldsa-signed-leaf.pem",
        issuer: "pure-mldsa-ica.pem",
        dns: "mldsa-signed.pqc-probe.test",
        extension_oid: None,
    },
    Case {
        id: "atomic-composite",
        subject_public_key_scheme: AlgorithmSecurity::Classical,
        certificate_signature_scheme: AlgorithmSecurity::Hybrid,
        binding_design: BindingDesign::AtomicComposite,
        leaf: "composite-leaf.pem",
        issuer: "composite-ica.pem",
        dns: "composite.pqc-probe.test",
        extension_oid: None,
    },
    Case {
        id: "catalyst",
        subject_public_key_scheme: AlgorithmSecurity::Classical,
        certificate_signature_scheme: AlgorithmSecurity::Classical,
        binding_design: BindingDesign::Catalyst,
        leaf: "catalyst-leaf.pem",
        issuer: "catalyst-ica.pem",
        dns: "catalyst.pqc-probe.test",
        extension_oid: Some("2.5.29.74"),
    },
    Case {
        id: "chameleon",
        subject_public_key_scheme: AlgorithmSecurity::Classical,
        certificate_signature_scheme: AlgorithmSecurity::Classical,
        binding_design: BindingDesign::Chameleon,
        leaf: "chameleon-base.pem",
        issuer: "ica.pem",
        dns: "chameleon.pqc-probe.test",
        extension_oid: Some("2.16.840.1.114027.80.6.1"),
    },
    Case {
        id: "related",
        subject_public_key_scheme: AlgorithmSecurity::Classical,
        certificate_signature_scheme: AlgorithmSecurity::Classical,
        binding_design: BindingDesign::RelatedCertificate,
        leaf: "related-certA.pem",
        issuer: "ica.pem",
        dns: "related-a.pqc-probe.test",
        extension_oid: Some("1.3.6.1.5.5.7.1.36"),
    },
    Case {
        id: "classical",
        subject_public_key_scheme: AlgorithmSecurity::Classical,
        certificate_signature_scheme: AlgorithmSecurity::Classical,
        binding_design: BindingDesign::None,
        leaf: "related-certA-missing.pem",
        issuer: "ica.pem",
        dns: "related-a.pqc-probe.test",
        extension_oid: None,
    },
];

pub fn run_available_matrix(config: &AvailableMatrixConfig) -> Result<MatrixReport, MatrixError> {
    let provenance = collect_provenance(config)?;
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
        let invalid_leaf =
            readable_tempfile(encode_certificate_pem(&corrupt_outer_signature(&der)?).as_bytes())?;
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
        provenance,
        entries,
    })
}

fn collect_provenance(config: &AvailableMatrixConfig) -> Result<MatrixProvenance, MatrixError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let git = |arguments: &[&str]| -> Result<String, MatrixError> {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(repository)
            .output()?;
        if !output.status.success() {
            return Err(MatrixError::Provenance(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    let source_commit = git(&["rev-parse", "HEAD"])?;
    let source_tree = git(&["rev-parse", "HEAD^{tree}"])?;
    let source_clean = git(&["status", "--porcelain"])?.is_empty();
    ensure_publication_source_clean(config.publication, source_clean)?;
    let mut images = vec![
        &config.openssl_current_image,
        &config.openssl_study_image,
        &config.gnutls_current_image,
        &config.gnutls_study_image,
        &config.go_study_image,
        &config.go_current_image,
        &config.pyca_study_image,
        &config.pyca_current_image,
        &config.bouncy_castle_study_image,
        &config.bouncy_castle_current_image,
        &config.nss_study_image,
        &config.nss_current_image,
        &config.oqs_provider_image,
        &config.wolfssl_image,
    ];
    images.sort_unstable();
    images.dedup();
    let adapter_images = images
        .into_iter()
        .map(|image| {
            let output = Command::new(&config.docker)
                .args(["image", "inspect", "--format", "{{.Id}}", image])
                .output()?;
            if !output.status.success() {
                return Err(MatrixError::Provenance(format!(
                    "cannot inspect image {image}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            Ok(AdapterImageProvenance {
                image: image.clone(),
                content_digest: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            })
        })
        .collect::<Result<Vec<_>, MatrixError>>()?;
    Ok(MatrixProvenance {
        source_commit,
        source_tree,
        source_clean,
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        adapter_images,
    })
}

fn ensure_publication_source_clean(
    publication: bool,
    source_clean: bool,
) -> Result<(), MatrixError> {
    if publication && !source_clean {
        Err(MatrixError::DirtySourceTree)
    } else {
        Ok(())
    }
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
    let operation = report.observation.validation_profile;
    let adapter = report.observation.adapter.clone();
    entries.push(MatrixEntry {
        case_id: case.id.to_owned(),
        subject_public_key_scheme: case.subject_public_key_scheme,
        certificate_signature_scheme: case.certificate_signature_scheme,
        binding_design: case.binding_design,
        variant,
        operation,
        expected_support: expected_support(case, variant, &adapter),
        expected_stack_verdict: expected_stack_verdict(case, variant, &adapter),
        process_execution: MatrixProcessExecution {
            version: process_record_check(&report.version, StackVerdict::Accept),
            verification: process_record_check(&report.verification, report.observation.verdict),
        },
        claim_id: format!(
            "fixture-matrix:{}:{variant:?}:{operation:?}:{adapter}",
            case.id
        ),
        specification: specification(case.binding_design).to_owned(),
        specification_revision: specification_revision(case.binding_design).to_owned(),
        report,
    });
}

fn process_record_check(record: &ProcessRecord, verdict: StackVerdict) -> CheckResult {
    let completed = record.status_code.is_some()
        && !record.timed_out
        && !record.stdout.truncated
        && !record.stderr.truncated;
    let has_semantic_result =
        record.status_code == Some(0) || verdict != StackVerdict::Indeterminate;
    CheckResult {
        state: if completed && has_semantic_result {
            CheckState::Pass
        } else {
            CheckState::Fail
        },
        confidence: Confidence::Observed,
    }
}

fn expected_support(case: Case, variant: MatrixVariant, adapter: &str) -> MatrixSupport {
    let unsupported = (case.id == "atomic-composite" && !adapter.starts_with("bouncycastle-java"))
        || (case.id == "pure-pq-key" && adapter == "mozilla-nss-study")
        || (case.id == "pure-pq-signature"
            && matches!(
                adapter,
                "mozilla-nss-study"
                    | "gnutls-study"
                    | "go-crypto-x509-study"
                    | "go-crypto-x509-current"
                    | "pyca-cryptography-study"
            ))
        || (case.id == "chameleon" && adapter == "mozilla-nss-study")
        || (case.id == "related"
            && variant == MatrixVariant::CriticalHybridExtension
            && matches!(
                adapter,
                "mozilla-nss-study"
                    | "mozilla-nss-current"
                    | "bouncycastle-java-study"
                    | "bouncycastle-java-current"
            ));
    if unsupported {
        MatrixSupport::Unsupported
    } else {
        MatrixSupport::Supported
    }
}

fn expected_stack_verdict(case: Case, variant: MatrixVariant, adapter: &str) -> StackVerdict {
    if expected_support(case, variant, adapter) == MatrixSupport::Unsupported {
        return StackVerdict::Unsupported;
    }
    if variant == MatrixVariant::Valid
        && ((case.id == "pure-pq-signature"
            && matches!(adapter, "mozilla-nss-current" | "gnutls-current"))
            || (case.id == "catalyst" && adapter == "wolfssl-mode2"))
    {
        return StackVerdict::Reject;
    }
    match variant {
        MatrixVariant::Valid | MatrixVariant::PublishedStudyFixture => StackVerdict::Accept,
        MatrixVariant::MissingHybridEvidence
        | MatrixVariant::BrokenBinding
        | MatrixVariant::UnknownHybridAlgorithm
        | MatrixVariant::MalformedHybridEvidence => StackVerdict::Accept,
        MatrixVariant::InvalidCertificateSignature | MatrixVariant::CriticalHybridExtension => {
            StackVerdict::Reject
        }
        MatrixVariant::InvalidPostQuantumSignature
            if case.binding_design == BindingDesign::Catalyst && adapter != "wolfssl-mode2" =>
        {
            StackVerdict::Accept
        }
        MatrixVariant::InvalidPostQuantumSignature => StackVerdict::Reject,
        MatrixVariant::InvalidHybridEvidenceSignature => StackVerdict::Accept,
    }
}

fn specification(binding_design: BindingDesign) -> &'static str {
    match binding_design {
        BindingDesign::RelatedCertificate => "RFC 9763",
        BindingDesign::AtomicComposite => "draft-ietf-lamps-pq-composite-sigs",
        BindingDesign::Catalyst => "local Catalyst fixture design",
        BindingDesign::Chameleon => "draft-bonnell-lamps-chameleon-certs",
        BindingDesign::None => "RFC 5280",
        BindingDesign::Unknown => "unknown",
    }
}

fn specification_revision(binding_design: BindingDesign) -> &'static str {
    match binding_design {
        BindingDesign::RelatedCertificate => "RFC 9763",
        BindingDesign::AtomicComposite => "draft-ietf-lamps-pq-composite-sigs-19",
        BindingDesign::Catalyst => "local experiment",
        BindingDesign::Chameleon => "draft-bonnell-lamps-chameleon-certs-07 expired",
        BindingDesign::None => "RFC 5280",
        BindingDesign::Unknown => "unknown",
    }
}

pub fn default_fixture_path() -> &'static Path {
    Path::new("tests/fixtures/paper-v1.0.2")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_variants_have_explicit_expected_verdicts() {
        for (case, variant, adapter, expected) in [
            (
                CASES[2],
                MatrixVariant::Valid,
                "bouncycastle-java-current",
                StackVerdict::Accept,
            ),
            (
                CASES[2],
                MatrixVariant::InvalidCertificateSignature,
                "bouncycastle-java-current",
                StackVerdict::Reject,
            ),
            (
                CASES[2],
                MatrixVariant::InvalidPostQuantumSignature,
                "bouncycastle-java-current",
                StackVerdict::Reject,
            ),
            (
                CASES[3],
                MatrixVariant::InvalidPostQuantumSignature,
                "bouncycastle-java-current",
                StackVerdict::Accept,
            ),
            (
                CASES[5],
                MatrixVariant::MissingHybridEvidence,
                "bouncycastle-java-current",
                StackVerdict::Accept,
            ),
            (
                CASES[5],
                MatrixVariant::BrokenBinding,
                "bouncycastle-java-current",
                StackVerdict::Accept,
            ),
            (
                CASES[5],
                MatrixVariant::CriticalHybridExtension,
                "openssl-current",
                StackVerdict::Reject,
            ),
        ] {
            assert_eq!(expected_stack_verdict(case, variant, adapter), expected);
        }
    }

    #[test]
    fn classical_valid_baseline_never_allows_unsupported() {
        for adapter in [
            "openssl-study",
            "openssl-current",
            "oqs-provider",
            "mozilla-nss-study",
            "mozilla-nss-current",
            "bouncycastle-java-study",
            "bouncycastle-java-current",
            "wolfssl-mode1",
            "wolfssl-mode2",
            "gnutls-current",
            "gnutls-study",
            "go-crypto-x509-study",
            "go-crypto-x509-current",
            "pyca-cryptography-study",
            "pyca-cryptography-current",
        ] {
            assert_eq!(
                expected_support(CASES[6], MatrixVariant::Valid, adapter),
                MatrixSupport::Supported
            );
            assert_eq!(
                expected_stack_verdict(CASES[6], MatrixVariant::Valid, adapter),
                StackVerdict::Accept
            );
        }
    }

    #[test]
    fn publication_mode_rejects_a_dirty_source_tree() {
        assert!(matches!(
            ensure_publication_source_clean(true, false),
            Err(MatrixError::DirtySourceTree)
        ));
        assert!(ensure_publication_source_clean(false, false).is_ok());
    }

    #[test]
    fn matrix_cases_record_their_standards_status() {
        assert_eq!(specification(BindingDesign::RelatedCertificate), "RFC 9763");
        assert_eq!(
            specification_revision(BindingDesign::Chameleon),
            "draft-bonnell-lamps-chameleon-certs-07 expired"
        );
        assert_eq!(
            specification_revision(BindingDesign::Catalyst),
            "local experiment"
        );
    }

    #[test]
    fn process_execution_is_separate_from_the_semantic_verdict() {
        let mut record = ProcessRecord {
            status_code: Some(2),
            timed_out: false,
            elapsed_milliseconds: 1,
            stdout: crate::EncodedStream {
                encoding: "base64".to_owned(),
                data: String::new(),
                sha256: String::new(),
                captured_bytes: 0,
                truncated: false,
            },
            stderr: crate::EncodedStream {
                encoding: "base64".to_owned(),
                data: String::new(),
                sha256: String::new(),
                captured_bytes: 0,
                truncated: false,
            },
        };
        assert_eq!(
            process_record_check(&record, StackVerdict::Reject).state,
            CheckState::Pass
        );

        assert_eq!(
            process_record_check(&record, StackVerdict::Indeterminate).state,
            CheckState::Fail
        );

        record.timed_out = true;
        assert_eq!(
            process_record_check(&record, StackVerdict::Reject).state,
            CheckState::Fail
        );
    }

    #[test]
    fn available_matrix_records_every_case_and_adapter() {
        let _guard = crate::adapter_test_lock();
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
            publication: false,
        })
        .unwrap();

        assert_eq!(report.entries.len(), 345);
        let unexpected_verdicts: Vec<_> = report
            .entries
            .iter()
            .filter(|entry| entry.expected_stack_verdict != entry.report.observation.verdict)
            .map(|entry| {
                (
                    entry.case_id.as_str(),
                    entry.variant,
                    entry.report.observation.adapter.as_str(),
                    entry.operation,
                    entry.report.observation.verdict,
                    entry.expected_support,
                    entry.expected_stack_verdict,
                )
            })
            .collect();
        assert!(unexpected_verdicts.is_empty(), "{unexpected_verdicts:?}");
        let process_failures: Vec<_> = report
            .entries
            .iter()
            .filter(|entry| {
                entry.process_execution.version.state != CheckState::Pass
                    || entry.process_execution.verification.state != CheckState::Pass
            })
            .map(|entry| {
                (
                    entry.case_id.as_str(),
                    entry.variant,
                    entry.report.observation.adapter.as_str(),
                    entry.operation,
                    entry.process_execution.version.state,
                    entry.report.version.status_code,
                    entry.report.version.timed_out,
                    entry.process_execution.verification.state,
                    entry.report.verification.status_code,
                    entry.report.verification.timed_out,
                )
            })
            .collect();
        assert!(process_failures.is_empty(), "{process_failures:?}");
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
        for (case_id, variant, adapter, verdict) in [
            (
                "related",
                MatrixVariant::Valid,
                "openssl-current",
                StackVerdict::Accept,
            ),
            (
                "related",
                MatrixVariant::InvalidCertificateSignature,
                "openssl-current",
                StackVerdict::Reject,
            ),
            (
                "related",
                MatrixVariant::BrokenBinding,
                "openssl-current",
                StackVerdict::Accept,
            ),
            (
                "related",
                MatrixVariant::MissingHybridEvidence,
                "openssl-current",
                StackVerdict::Accept,
            ),
            (
                "catalyst",
                MatrixVariant::InvalidPostQuantumSignature,
                "bouncycastle-java-study",
                StackVerdict::Accept,
            ),
        ] {
            assert_eq!(
                report
                    .entries
                    .iter()
                    .find(|entry| {
                        entry.case_id == case_id
                            && entry.variant == variant
                            && entry.report.observation.adapter == adapter
                    })
                    .unwrap()
                    .report
                    .observation
                    .verdict,
                verdict,
                "{case_id} {variant:?} {adapter}"
            );
        }
    }
}
