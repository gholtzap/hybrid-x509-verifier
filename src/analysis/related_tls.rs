use crate::{
    API_VERSION, AlgorithmSecurity, BindingDesign, CheckResult, CheckState, Evidence, EvidenceKind,
    OracleError, PathPosition, PathScope, Policy, StackVerdict, VerificationRequest,
    VerificationResult,
    adapters::container::readable_tempfile,
    analysis::{
        LeafPathProperties, behavioral_check, certificate_der_hash, certificate_trust_anchor,
        end_entity_certification_path, issuer_edge_hash, related_conformance_check,
        tls::{
            TlsObservationError, TlsTranscriptConfig, TlsTranscriptEvidence, observe_transcript,
        },
    },
    evaluate,
    mutation::{MutationError, corrupt_outer_signature, encode_certificate_pem},
    pem::{
        CrlStatusResult, PemError, PemKind, RelatedBindingResult, RelatedConformanceResult,
        check_certificate_validity, check_crl_status, inspect_certificate, read_der,
        verify_related_binding, verify_related_certificate_conformance,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use thiserror::Error;

const INPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RelatedTlsConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub issuer: PathBuf,
    pub classical_certificate: PathBuf,
    pub invalid_binding_classical_certificate: PathBuf,
    pub missing_binding_classical_certificate: PathBuf,
    pub post_quantum_certificate: PathBuf,
    pub expired_post_quantum_certificate: PathBuf,
    pub classical_private_key: PathBuf,
    pub post_quantum_private_key: PathBuf,
    pub crl: PathBuf,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelatedTlsReport {
    pub api_version: String,
    pub separate_post_quantum_tls_context: String,
    pub conformance: RelatedConformanceResult,
    pub binding: RelatedBindingResult,
    pub invalid_binding: RelatedBindingResult,
    pub classical_crl_status: CrlStatusResult,
    pub post_quantum_crl_status: CrlStatusResult,
    pub classical_tls: TlsTranscriptEvidence,
    pub invalid_classical_signature_tls: TlsTranscriptEvidence,
    pub invalid_binding_classical_tls: TlsTranscriptEvidence,
    pub missing_binding_classical_tls: TlsTranscriptEvidence,
    pub separate_post_quantum_tls: TlsTranscriptEvidence,
    pub expired_post_quantum_tls: TlsTranscriptEvidence,
    pub result: VerificationResult,
}

#[derive(Debug, Error)]
pub enum RelatedTlsError {
    #[error("the classical certificate must use the Related scheme")]
    WrongScheme,
    #[error(transparent)]
    Tls(#[from] TlsObservationError),
    #[error(transparent)]
    Pem(#[from] PemError),
    #[error(transparent)]
    Mutation(#[from] MutationError),
    #[error(transparent)]
    Oracle(#[from] OracleError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn analyze(config: &RelatedTlsConfig) -> Result<RelatedTlsReport, RelatedTlsError> {
    if inspect_certificate(&config.classical_certificate, INPUT_LIMIT)?.binding_design
        != BindingDesign::RelatedCertificate
    {
        return Err(RelatedTlsError::WrongScheme);
    }

    let conformance = verify_related_certificate_conformance(
        &config.classical_certificate,
        &config.post_quantum_certificate,
        INPUT_LIMIT,
    )?;
    let binding = conformance.rfc9763.binding.clone();
    let invalid_binding = verify_related_binding(
        &config.invalid_binding_classical_certificate,
        &config.post_quantum_certificate,
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

    let classical_tls = run_tls(
        config,
        config.classical_certificate.clone(),
        config.classical_private_key.clone(),
    )?;
    let invalid_binding_classical_tls = run_tls(
        config,
        config.invalid_binding_classical_certificate.clone(),
        config.classical_private_key.clone(),
    )?;
    let missing_binding_classical_tls = run_tls(
        config,
        config.missing_binding_classical_certificate.clone(),
        config.classical_private_key.clone(),
    )?;
    let separate_post_quantum_tls = run_tls(
        config,
        config.post_quantum_certificate.clone(),
        config.post_quantum_private_key.clone(),
    )?;
    let expired_post_quantum_tls = run_tls(
        config,
        config.expired_post_quantum_certificate.clone(),
        config.post_quantum_private_key.clone(),
    )?;
    let classical_der = read_der(
        &config.classical_certificate,
        PemKind::Certificate,
        INPUT_LIMIT,
    )?;
    let invalid_classical_file = readable_tempfile(
        encode_certificate_pem(&corrupt_outer_signature(&classical_der)?).as_bytes(),
    )?;
    let invalid_classical_signature_tls = run_tls(
        config,
        invalid_classical_file.path().to_owned(),
        config.classical_private_key.clone(),
    )?;

    let classical_accepts = classical_tls.report.observation.verdict == StackVerdict::Accept;
    let classical_outcome = behavioral_check(
        classical_accepts
            && invalid_classical_signature_tls.report.observation.verdict == StackVerdict::Reject,
        CheckState::Pass,
    );
    let conformance_check = related_conformance_check(&conformance);
    let post_quantum_outcome = behavioral_check(
        classical_accepts
            && conformance_check.state == CheckState::Pass
            && invalid_binding.check.state == CheckState::Fail
            && invalid_binding_classical_tls.report.observation.verdict == StackVerdict::Accept
            && missing_binding_classical_tls.report.observation.verdict == StackVerdict::Accept
            && post_quantum_crl_status.revocation.state == CheckState::Fail
            && expired_post_quantum_tls.report.observation.verdict == StackVerdict::Reject,
        CheckState::Fail,
    );
    let classical_path = CheckResult::observed(if classical_accepts {
        CheckState::Pass
    } else {
        CheckState::Fail
    });
    let post_quantum_validity = check_certificate_validity(
        &config.post_quantum_certificate,
        &config.validation_time,
        INPUT_LIMIT,
    )?;
    let certificate_der_sha256 = certificate_der_hash(&config.classical_certificate, INPUT_LIMIT)?;
    let post_quantum_certificate_der_sha256 =
        certificate_der_hash(&config.post_quantum_certificate, INPUT_LIMIT)?;
    let issuer_edge_sha256 =
        issuer_edge_hash(&config.classical_certificate, &config.issuer, INPUT_LIMIT)?;
    let present = CheckResult::observed(CheckState::Pass);
    let not_applicable = CheckResult::observed(CheckState::NotApplicable);
    let request = VerificationRequest {
        api_version: API_VERSION.to_owned(),
        policy: Policy::P2RequiredHybrid,
        path_scope: PathScope::EndEntity,
        validation_time: config.validation_time.clone(),
        previous_authentication: None,
        revocation_policy: crate::RevocationPolicy::crl_hard_fail(),
        stack: classical_tls.report.observation.clone(),
        expected_trust_anchor: certificate_trust_anchor(&config.trust_store, INPUT_LIMIT)?,
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
        paired_authentications: vec![crate::PairedAuthentication {
            operation_id: "end-entity-related-authentication".to_owned(),
            classical_certificate_id: "end-entity".to_owned(),
            post_quantum_certificate_der_sha256: post_quantum_certificate_der_sha256.clone(),
            same_authentication_operation: CheckResult::observed(CheckState::Fail),
        }],
        evidence: vec![
            Evidence {
                id: "related-classical-certificate".to_owned(),
                certificate_id: "end-entity".to_owned(),
                position: PathPosition::EndEntity,
                certificate_der_sha256: Some(certificate_der_sha256.clone()),
                evidence_artifact_der_sha256: Some(certificate_der_sha256.clone()),
                issuer_edge_sha256: Some(issuer_edge_sha256.clone()),
                authentication_operation_id: Some("end-entity-related-authentication".to_owned()),
                kind: EvidenceKind::Classical,
                present,
                recognized: present,
                signature: classical_path,
                binding: CheckResult::observed(CheckState::NotApplicable),
                path: classical_path,
                validity: check_certificate_validity(
                    &config.classical_certificate,
                    &config.validation_time,
                    INPUT_LIMIT,
                )?,
                revocation: classical_crl_status.revocation,
                revocation_method: crate::RevocationMethod::Crl,
                applied_revocation_policy: crate::RevocationPolicy::crl_hard_fail(),
                decision_sensitive_for_fixture: classical_outcome,
            },
            Evidence {
                id: "related-post-quantum-certificate".to_owned(),
                certificate_id: "end-entity".to_owned(),
                position: PathPosition::EndEntity,
                certificate_der_sha256: Some(certificate_der_sha256.clone()),
                evidence_artifact_der_sha256: Some(post_quantum_certificate_der_sha256),
                issuer_edge_sha256: Some(issuer_edge_sha256.clone()),
                authentication_operation_id: Some("end-entity-related-authentication".to_owned()),
                kind: EvidenceKind::PostQuantum,
                present,
                recognized: present,
                signature: not_applicable,
                binding: conformance_check,
                path: not_applicable,
                validity: post_quantum_validity,
                revocation: post_quantum_crl_status.revocation,
                revocation_method: crate::RevocationMethod::Crl,
                applied_revocation_policy: crate::RevocationPolicy::crl_hard_fail(),
                decision_sensitive_for_fixture: post_quantum_outcome,
            },
        ],
    };

    Ok(RelatedTlsReport {
        api_version: API_VERSION.to_owned(),
        separate_post_quantum_tls_context:
            "separate TLS authentication; not selected evidence for the classical TLS result"
                .to_owned(),
        conformance,
        binding,
        invalid_binding,
        classical_crl_status,
        post_quantum_crl_status,
        classical_tls,
        invalid_classical_signature_tls,
        invalid_binding_classical_tls,
        missing_binding_classical_tls,
        separate_post_quantum_tls,
        expired_post_quantum_tls,
        result: evaluate(&request)?,
    })
}

fn run_tls(
    config: &RelatedTlsConfig,
    leaf: PathBuf,
    private_key: PathBuf,
) -> Result<TlsTranscriptEvidence, TlsObservationError> {
    observe_transcript(&TlsTranscriptConfig {
        docker: config.docker.clone(),
        image: config.image.clone(),
        trust_store: config.trust_store.clone(),
        intermediate: config.issuer.clone(),
        leaf,
        private_key,
        validation_time: config.validation_time.clone(),
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyVerdict;
    use std::path::Path;

    #[test]
    fn classical_related_tls_ignores_post_quantum_lifecycle_and_binding() {
        let _guard = crate::adapter_test_lock();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixtures = repository.join("tests/fixtures/paper-v1.0.2");
        let controls = repository.join("tests/fixtures/generated-controls");
        let report = analyze(&RelatedTlsConfig {
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            trust_store: fixtures.join("root.pem"),
            issuer: fixtures.join("ica.pem"),
            classical_certificate: fixtures.join("related-certA.pem"),
            invalid_binding_classical_certificate: controls
                .join("related-certA-broken-binding.pem"),
            missing_binding_classical_certificate: controls.join("related-certA-missing.pem"),
            post_quantum_certificate: fixtures.join("related-leafB.pem"),
            expired_post_quantum_certificate: fixtures.join("related-leafB-expired.pem"),
            classical_private_key: controls.join("related-certA-key.pem"),
            post_quantum_private_key: controls.join("related-leafB-key.pem"),
            crl: fixtures.join("related-crl.pem"),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

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
        assert_eq!(
            report.classical_tls.report.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report
                .invalid_classical_signature_tls
                .report
                .observation
                .verdict,
            StackVerdict::Reject
        );
        assert_eq!(
            report
                .invalid_binding_classical_tls
                .report
                .observation
                .verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report
                .missing_binding_classical_tls
                .report
                .observation
                .verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report.separate_post_quantum_tls.report.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report.expired_post_quantum_tls.report.observation.verdict,
            StackVerdict::Reject
        );
        assert_eq!(report.result.policy_verdict, PolicyVerdict::Reject);
        assert!(report.result.classical_only_fallback);
        assert!(report.result.lifecycle_desynchronization);
    }
}
