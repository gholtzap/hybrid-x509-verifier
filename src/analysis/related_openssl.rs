use crate::{
    API_VERSION, AdapterReport, AlgorithmSecurity, AuthenticationLevel, BindingDesign, CheckResult,
    CheckState, Confidence, Evidence, EvidenceKind, OracleError, PathPosition, PathScope, Policy,
    StackVerdict, VerificationRequest, VerificationResult,
    adapters::openssl::{OpenSslContainerConfig, OpenSslError, verify_container as verify_openssl},
    adapters::{AdapterSupportError, check_from_verdict},
    analysis::{
        LeafPathProperties, certificate_der_hash, end_entity_certification_path, issuer_edge_hash,
        related_conformance_check,
    },
    evaluate,
    mutation::{MutationError, corrupt_outer_signature, encode_certificate_pem},
    pem::{
        CrlStatusResult, PemError, PemKind, RelatedBindingResult, RelatedConformanceResult,
        check_crl_status, inspect_certificate, read_der, verify_related_binding,
        verify_related_certificate_conformance,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{io::Write, path::PathBuf, time::Duration};
use thiserror::Error;

const INPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RelatedOpenSslConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub issuer: PathBuf,
    pub classical_certificate: PathBuf,
    pub post_quantum_certificate: PathBuf,
    pub expired_post_quantum_certificate: PathBuf,
    pub invalid_binding_certificate: PathBuf,
    pub crl: PathBuf,
    pub validation_time: String,
    pub policy: Policy,
    pub previous_authentication: Option<AuthenticationLevel>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelatedOpenSslReport {
    pub api_version: String,
    pub conformance: RelatedConformanceResult,
    pub binding: RelatedBindingResult,
    pub invalid_binding: RelatedBindingResult,
    pub classical_crl_status: CrlStatusResult,
    pub post_quantum_crl_status: CrlStatusResult,
    pub classical_control: AdapterReport,
    pub classical_invalid_control: AdapterReport,
    pub post_quantum_validity_control: AdapterReport,
    pub post_quantum_expired_control: AdapterReport,
    pub post_quantum_invalid_binding_path_control: AdapterReport,
    pub post_quantum_revocation_control: AdapterReport,
    pub result: VerificationResult,
}

#[derive(Debug, Error)]
pub enum RelatedOpenSslError {
    #[error("the classical certificate is not an RFC 9763 Related certificate")]
    WrongScheme,
    #[error(transparent)]
    OpenSsl(#[from] OpenSslError),
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Pem(#[from] PemError),
    #[error(transparent)]
    Mutation(#[from] MutationError),
    #[error(transparent)]
    Oracle(#[from] OracleError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn analyze(config: &RelatedOpenSslConfig) -> Result<RelatedOpenSslReport, RelatedOpenSslError> {
    if inspect_certificate(&config.classical_certificate, INPUT_LIMIT)?.binding_design
        != BindingDesign::RelatedCertificate
    {
        return Err(RelatedOpenSslError::WrongScheme);
    }

    let conformance = verify_related_certificate_conformance(
        &config.classical_certificate,
        &config.post_quantum_certificate,
        INPUT_LIMIT,
    )?;
    let binding = conformance.rfc9763.binding.clone();
    let invalid_binding = verify_related_binding(
        &config.classical_certificate,
        &config.invalid_binding_certificate,
        INPUT_LIMIT,
    )?;
    let classical_crl_status = check_crl_status(
        &config.classical_certificate,
        &config.issuer,
        &config.crl,
        &config.validation_time,
        INPUT_LIMIT,
    )?;
    let post_quantum_crl_status = check_crl_status(
        &config.post_quantum_certificate,
        &config.issuer,
        &config.crl,
        &config.validation_time,
        INPUT_LIMIT,
    )?;

    let classical = verify_openssl(&openssl_config(
        config,
        config.classical_certificate.clone(),
        Some(config.crl.clone()),
    ))?;
    let classical_der = read_der(
        &config.classical_certificate,
        PemKind::Certificate,
        INPUT_LIMIT,
    )?;
    let invalid_der = corrupt_outer_signature(&classical_der)?;
    let mut invalid_file = tempfile::NamedTempFile::new()?;
    invalid_file.write_all(encode_certificate_pem(&invalid_der).as_bytes())?;
    let classical_invalid = verify_openssl(&openssl_config(
        config,
        invalid_file.path().to_owned(),
        Some(config.crl.clone()),
    ))?;
    let post_quantum_validity = verify_openssl(&openssl_config(
        config,
        config.post_quantum_certificate.clone(),
        None,
    ))?;
    let post_quantum_invalid_binding_path = verify_openssl(&openssl_config(
        config,
        config.invalid_binding_certificate.clone(),
        None,
    ))?;
    let post_quantum_expired = verify_openssl(&openssl_config(
        config,
        config.expired_post_quantum_certificate.clone(),
        None,
    ))?;
    let post_quantum_revocation = verify_openssl(&openssl_config(
        config,
        config.post_quantum_certificate.clone(),
        Some(config.crl.clone()),
    ))?;

    let classical_outcome = if classical.observation.verdict == StackVerdict::Accept
        && classical_invalid.observation.verdict == StackVerdict::Reject
    {
        CheckResult {
            state: CheckState::Pass,
            confidence: Confidence::BehaviorallyEstablished,
        }
    } else {
        CheckResult {
            state: CheckState::Indeterminate,
            confidence: Confidence::Unknown,
        }
    };
    let conformance_check = related_conformance_check(&conformance);
    let post_quantum_outcome = if classical.observation.verdict == StackVerdict::Accept
        && conformance_check.state == CheckState::Pass
        && invalid_binding.check.state == CheckState::Fail
        && post_quantum_invalid_binding_path.observation.verdict == StackVerdict::Accept
        && post_quantum_expired.observation.verdict == StackVerdict::Reject
        && post_quantum_crl_status.revocation.state == CheckState::Fail
    {
        CheckResult {
            state: CheckState::Fail,
            confidence: Confidence::BehaviorallyEstablished,
        }
    } else {
        CheckResult {
            state: CheckState::Indeterminate,
            confidence: Confidence::Unknown,
        }
    };
    let observed_pass = CheckResult::observed(CheckState::Pass);
    let classical_path_pass = check_from_verdict(classical.observation.verdict);
    let pq_path_pass = check_from_verdict(post_quantum_validity.observation.verdict);
    let certificate_der_sha256 = certificate_der_hash(&config.classical_certificate, INPUT_LIMIT)?;
    let issuer_edge_sha256 =
        issuer_edge_hash(&config.classical_certificate, &config.issuer, INPUT_LIMIT)?;
    let request = VerificationRequest {
        api_version: API_VERSION.to_owned(),
        policy: config.policy,
        path_scope: PathScope::EndEntity,
        validation_time: config.validation_time.clone(),
        previous_authentication: config.previous_authentication,
        stack: classical.observation.clone(),
        certificate_path: end_entity_certification_path(
            &config.classical_certificate,
            &config.issuer,
            &config.trust_store,
            LeafPathProperties {
                subject_public_key_scheme: AlgorithmSecurity::Classical,
                certificate_signature_scheme: AlgorithmSecurity::Classical,
                binding_design: BindingDesign::RelatedCertificate,
            },
            INPUT_LIMIT,
        )?,
        evidence: vec![
            Evidence {
                id: "classical-certificate-path".to_owned(),
                certificate_id: "end-entity".to_owned(),
                position: PathPosition::EndEntity,
                certificate_der_sha256: Some(certificate_der_sha256.clone()),
                issuer_edge_sha256: Some(issuer_edge_sha256.clone()),
                kind: EvidenceKind::Classical,
                present: observed_pass,
                recognized: observed_pass,
                signature: classical_path_pass,
                binding: CheckResult::observed(CheckState::NotApplicable),
                path: classical_path_pass,
                validity: classical_path_pass,
                revocation: classical_crl_status.revocation,
                decision_sensitive_for_fixture: classical_outcome,
            },
            Evidence {
                id: "related-post-quantum-certificate".to_owned(),
                certificate_id: "end-entity".to_owned(),
                position: PathPosition::EndEntity,
                certificate_der_sha256: Some(certificate_der_sha256.clone()),
                issuer_edge_sha256: Some(issuer_edge_sha256.clone()),
                kind: EvidenceKind::PostQuantum,
                present: observed_pass,
                recognized: observed_pass,
                signature: pq_path_pass,
                binding: conformance_check,
                path: pq_path_pass,
                validity: pq_path_pass,
                revocation: post_quantum_crl_status.revocation,
                decision_sensitive_for_fixture: post_quantum_outcome,
            },
        ],
    };

    Ok(RelatedOpenSslReport {
        api_version: API_VERSION.to_owned(),
        conformance,
        binding,
        invalid_binding,
        classical_crl_status,
        post_quantum_crl_status,
        classical_control: classical.report()?,
        classical_invalid_control: classical_invalid.report()?,
        post_quantum_validity_control: post_quantum_validity.report()?,
        post_quantum_expired_control: post_quantum_expired.report()?,
        post_quantum_invalid_binding_path_control: post_quantum_invalid_binding_path.report()?,
        post_quantum_revocation_control: post_quantum_revocation.report()?,
        result: evaluate(&request)?,
    })
}

fn openssl_config(
    config: &RelatedOpenSslConfig,
    leaf: PathBuf,
    crl: Option<PathBuf>,
) -> OpenSslContainerConfig {
    OpenSslContainerConfig {
        docker: config.docker.clone(),
        image: config.image.clone(),
        trust_store: config.trust_store.clone(),
        intermediate: config.issuer.clone(),
        leaf,
        crl,
        validation_time: config.validation_time.clone(),
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_the_published_related_revocation_desynchronization() {
        let _guard = crate::adapter_test_lock();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let controls =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/generated-controls");
        let report = analyze(&RelatedOpenSslConfig {
            docker: "docker".into(),
            image: "hybrid-x509-openssl:4.0.1".to_owned(),
            trust_store: fixtures.join("root.pem"),
            issuer: fixtures.join("ica.pem"),
            classical_certificate: fixtures.join("related-certA.pem"),
            post_quantum_certificate: fixtures.join("related-leafB.pem"),
            expired_post_quantum_certificate: fixtures.join("related-leafB-expired.pem"),
            invalid_binding_certificate: controls.join("related-leafB-unbound.pem"),
            crl: fixtures.join("related-crl.pem"),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            policy: Policy::P2RequiredHybrid,
            previous_authentication: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(report.binding.check.state, CheckState::Pass);
        assert_eq!(
            report.conformance.rfc9763.key_usage_subset.state,
            CheckState::Fail
        );
        assert_eq!(
            report
                .conformance
                .hybrid_application_policy
                .dns_identity_overlap
                .state,
            CheckState::Fail
        );
        assert_eq!(report.invalid_binding.check.state, CheckState::Fail);
        assert_eq!(
            report
                .post_quantum_invalid_binding_path_control
                .observation
                .verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report.classical_control.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report.post_quantum_revocation_control.observation.verdict,
            StackVerdict::Reject
        );
        assert_eq!(
            report.post_quantum_expired_control.observation.verdict,
            StackVerdict::Reject
        );
        assert_eq!(report.result.policy_verdict, crate::PolicyVerdict::Reject);
        assert!(report.result.classical_only_fallback);
        assert!(report.result.lifecycle_desynchronization);
    }
}
