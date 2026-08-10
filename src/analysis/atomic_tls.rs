use crate::{
    API_VERSION, AlgorithmSecurity, BindingDesign, CheckResult, CheckState, Evidence, EvidenceKind,
    OracleError, PathPosition, PathScope, Policy, StackVerdict, VerificationRequest,
    VerificationResult,
    adapters::container::readable_tempfile,
    analysis::{
        LeafPathProperties, behavioral_check, certificate_der_hash, certificate_trust_anchor,
        end_entity_certification_path, issuer_edge_hash,
        tls::{
            TlsObservationError, TlsTranscriptConfig, TlsTranscriptEvidence, observe_transcript,
        },
    },
    evaluate,
    mutation::{MutationError, corrupt_outer_signature, encode_certificate_pem},
    pem::{PemError, PemKind, check_certificate_validity, inspect_certificate, read_der},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use thiserror::Error;

const INPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AtomicTlsConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub issuer: PathBuf,
    pub valid_certificate: PathBuf,
    pub invalid_post_quantum_certificate: PathBuf,
    pub private_key: PathBuf,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtomicTlsReport {
    pub api_version: String,
    pub valid_tls: TlsTranscriptEvidence,
    pub invalid_classical_tls: TlsTranscriptEvidence,
    pub invalid_post_quantum_tls: TlsTranscriptEvidence,
    pub result: VerificationResult,
}

#[derive(Debug, Error)]
pub enum AtomicTlsError {
    #[error("both control certificates must use the atomic composite scheme")]
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

pub fn analyze(config: &AtomicTlsConfig) -> Result<AtomicTlsReport, AtomicTlsError> {
    for certificate in [
        &config.valid_certificate,
        &config.invalid_post_quantum_certificate,
    ] {
        if inspect_certificate(certificate, INPUT_LIMIT)?.binding_design
            != BindingDesign::AtomicComposite
        {
            return Err(AtomicTlsError::WrongScheme);
        }
    }

    let valid_tls = run_tls(config, config.valid_certificate.clone())?;
    let invalid_post_quantum_tls =
        run_tls(config, config.invalid_post_quantum_certificate.clone())?;
    let valid_der = read_der(&config.valid_certificate, PemKind::Certificate, INPUT_LIMIT)?;
    let invalid_classical_file = readable_tempfile(
        encode_certificate_pem(&corrupt_outer_signature(&valid_der)?).as_bytes(),
    )?;
    let invalid_classical_tls = run_tls(config, invalid_classical_file.path().to_owned())?;

    let valid_accepts = valid_tls.report.observation.verdict == StackVerdict::Accept;
    let classical_outcome = behavioral_check(
        valid_accepts && invalid_classical_tls.report.observation.verdict == StackVerdict::Reject,
        CheckState::Pass,
    );
    let post_quantum_outcome = behavioral_check(
        valid_accepts
            && invalid_post_quantum_tls.report.observation.verdict == StackVerdict::Reject,
        CheckState::Pass,
    );
    let component_signature = CheckResult {
        state: CheckState::Indeterminate,
        confidence: crate::Confidence::Unknown,
    };
    let path = CheckResult::observed(if valid_accepts {
        CheckState::Pass
    } else {
        CheckState::Fail
    });
    let validity = check_certificate_validity(
        &config.valid_certificate,
        &config.validation_time,
        INPUT_LIMIT,
    )?;
    let certificate_der_sha256 = certificate_der_hash(&config.valid_certificate, INPUT_LIMIT)?;
    let issuer_edge_sha256 =
        issuer_edge_hash(&config.valid_certificate, &config.issuer, INPUT_LIMIT)?;
    let present = CheckResult::observed(CheckState::Pass);
    let revocation = CheckResult::observed(CheckState::NotChecked);
    let request = VerificationRequest {
        api_version: API_VERSION.to_owned(),
        policy: Policy::P2RequiredHybrid,
        path_scope: PathScope::EndEntity,
        validation_time: config.validation_time.clone(),
        previous_authentication: None,
        revocation_policy: crate::RevocationPolicy::crl_hard_fail(),
        stack: valid_tls.report.observation.clone(),
        expected_trust_anchor: certificate_trust_anchor(&config.trust_store, INPUT_LIMIT)?,
        certificate_path: end_entity_certification_path(
            &config.valid_certificate,
            &config.issuer,
            &config.trust_store,
            LeafPathProperties {
                subject_public_key_scheme: AlgorithmSecurity::Classical,
                certificate_signature_scheme: AlgorithmSecurity::Hybrid,
                binding_design: BindingDesign::AtomicComposite,
            },
            INPUT_LIMIT,
        )?,
        paired_authentications: Vec::new(),
        evidence: vec![
            Evidence {
                id: "composite-ecdsa-component".to_owned(),
                certificate_id: "end-entity".to_owned(),
                position: PathPosition::EndEntity,
                certificate_der_sha256: Some(certificate_der_sha256.clone()),
                evidence_artifact_der_sha256: Some(certificate_der_sha256.clone()),
                issuer_edge_sha256: Some(issuer_edge_sha256.clone()),
                authentication_operation_id: None,
                kind: EvidenceKind::Classical,
                present,
                recognized: present,
                signature: component_signature,
                binding: CheckResult::observed(CheckState::NotApplicable),
                path,
                validity,
                revocation,
                revocation_method: crate::RevocationMethod::None,
                applied_revocation_policy: crate::RevocationPolicy::crl_hard_fail(),
                decision_sensitive_for_fixture: classical_outcome,
            },
            Evidence {
                id: "composite-mldsa-component".to_owned(),
                certificate_id: "end-entity".to_owned(),
                position: PathPosition::EndEntity,
                certificate_der_sha256: Some(certificate_der_sha256.clone()),
                evidence_artifact_der_sha256: Some(certificate_der_sha256.clone()),
                issuer_edge_sha256: Some(issuer_edge_sha256.clone()),
                authentication_operation_id: None,
                kind: EvidenceKind::PostQuantum,
                present,
                recognized: present,
                signature: component_signature,
                binding: CheckResult::observed(CheckState::NotApplicable),
                path,
                validity,
                revocation,
                revocation_method: crate::RevocationMethod::None,
                applied_revocation_policy: crate::RevocationPolicy::crl_hard_fail(),
                decision_sensitive_for_fixture: post_quantum_outcome,
            },
        ],
    };

    Ok(AtomicTlsReport {
        api_version: API_VERSION.to_owned(),
        valid_tls,
        invalid_classical_tls,
        invalid_post_quantum_tls,
        result: evaluate(&request)?,
    })
}

fn run_tls(
    config: &AtomicTlsConfig,
    leaf: PathBuf,
) -> Result<TlsTranscriptEvidence, TlsObservationError> {
    observe_transcript(&TlsTranscriptConfig {
        docker: config.docker.clone(),
        image: config.image.clone(),
        trust_store: config.trust_store.clone(),
        intermediate: config.issuer.clone(),
        leaf,
        private_key: config.private_key.clone(),
        validation_time: config.validation_time.clone(),
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, PolicyVerdict};
    use std::path::Path;

    #[test]
    fn both_atomic_signature_components_change_tls_acceptance() {
        let _guard = crate::adapter_test_lock();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixtures = repository.join("tests/fixtures/paper-v1.0.2");
        let controls = repository.join("tests/fixtures/generated-controls");
        let report = analyze(&AtomicTlsConfig {
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            trust_store: fixtures.join("root.pem"),
            issuer: fixtures.join("composite-ica.pem"),
            valid_certificate: fixtures.join("composite-leaf.pem"),
            invalid_post_quantum_certificate: controls.join("composite-leaf-bad-mldsa.pem"),
            private_key: controls.join("composite-leaf-key.pem"),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(
            report.valid_tls.report.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report.invalid_classical_tls.report.observation.verdict,
            StackVerdict::Reject
        );
        assert_eq!(
            report.invalid_post_quantum_tls.report.observation.verdict,
            StackVerdict::Reject
        );
        assert!(
            report
                .result
                .evaluated_evidence
                .iter()
                .all(|evidence| evidence.signature.state == CheckState::Indeterminate)
        );
        assert_eq!(
            report.valid_tls.signature.as_deref(),
            Some("ecdsa_secp256r1_sha256")
        );
        assert_eq!(report.result.policy_verdict, PolicyVerdict::Indeterminate);
        assert!(report.result.failed_checks.iter().any(|failure| {
            failure.check == "revocation"
                && failure.state == CheckState::NotChecked
                && failure.confidence == Confidence::Observed
        }));
    }
}
