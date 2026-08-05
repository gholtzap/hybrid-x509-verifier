use crate::{
    API_VERSION, AdapterReport, CertificateNode, CheckResult, CheckState, Evidence, EvidenceKind,
    OracleError, PathPosition, PathScope, Policy, Scheme, StackVerdict, VerificationRequest,
    VerificationResult,
    adapters::{
        AdapterSupportError,
        bouncy_castle::{
            BouncyCastleConfig, BouncyCastleError, BouncyCastleMode, verify as verify_bouncy_castle,
        },
    },
    analysis::{
        behavioral_check,
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
use std::{io::Write, path::PathBuf, time::Duration};
use thiserror::Error;

const INPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ChameleonTlsConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub issuer: PathBuf,
    pub valid_base_certificate: PathBuf,
    pub invalid_delta_base_certificate: PathBuf,
    pub delta_certificate: PathBuf,
    pub base_private_key: PathBuf,
    pub delta_private_key: PathBuf,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChameleonTlsReport {
    pub api_version: String,
    pub valid_base_tls: TlsTranscriptEvidence,
    pub invalid_base_signature_tls: TlsTranscriptEvidence,
    pub invalid_delta_base_tls: TlsTranscriptEvidence,
    pub separate_delta_tls: TlsTranscriptEvidence,
    pub valid_delta_direct_control: AdapterReport,
    pub invalid_delta_direct_control: AdapterReport,
    pub result: VerificationResult,
}

#[derive(Debug, Error)]
pub enum ChameleonTlsError {
    #[error("both base controls must use the Chameleon scheme")]
    WrongScheme,
    #[error(transparent)]
    Tls(#[from] TlsObservationError),
    #[error(transparent)]
    BouncyCastle(#[from] BouncyCastleError),
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

pub fn analyze(config: &ChameleonTlsConfig) -> Result<ChameleonTlsReport, ChameleonTlsError> {
    for certificate in [
        &config.valid_base_certificate,
        &config.invalid_delta_base_certificate,
    ] {
        if inspect_certificate(certificate, INPUT_LIMIT)?.scheme != Scheme::Chameleon {
            return Err(ChameleonTlsError::WrongScheme);
        }
    }

    let valid_base_tls = run_tls(
        config,
        config.valid_base_certificate.clone(),
        config.base_private_key.clone(),
    )?;
    let invalid_delta_base_tls = run_tls(
        config,
        config.invalid_delta_base_certificate.clone(),
        config.base_private_key.clone(),
    )?;
    let separate_delta_tls = run_tls(
        config,
        config.delta_certificate.clone(),
        config.delta_private_key.clone(),
    )?;
    let base_der = read_der(
        &config.valid_base_certificate,
        PemKind::Certificate,
        INPUT_LIMIT,
    )?;
    let mut invalid_base_file = tempfile::NamedTempFile::new()?;
    invalid_base_file
        .write_all(encode_certificate_pem(&corrupt_outer_signature(&base_der)?).as_bytes())?;
    let invalid_base_signature_tls = run_tls(
        config,
        invalid_base_file.path().to_owned(),
        config.base_private_key.clone(),
    )?;
    let valid_delta = run_delta(config, config.valid_base_certificate.clone())?;
    let invalid_delta = run_delta(config, config.invalid_delta_base_certificate.clone())?;

    let valid_accepts = valid_base_tls.report.observation.verdict == StackVerdict::Accept;
    let post_quantum_outcome = behavioral_check(
        valid_accepts
            && invalid_base_signature_tls.report.observation.verdict == StackVerdict::Reject,
        CheckState::Pass,
    );
    let classical_outcome = behavioral_check(
        valid_accepts
            && invalid_delta_base_tls.report.observation.verdict == StackVerdict::Accept
            && valid_delta.observation.verdict == StackVerdict::Accept
            && invalid_delta.observation.verdict == StackVerdict::Reject,
        CheckState::Fail,
    );
    let path = CheckResult::observed(if valid_accepts {
        CheckState::Pass
    } else {
        CheckState::Fail
    });
    let base_validity = check_certificate_validity(
        &config.valid_base_certificate,
        &config.validation_time,
        INPUT_LIMIT,
    )?;
    let delta_validity = check_certificate_validity(
        &config.delta_certificate,
        &config.validation_time,
        INPUT_LIMIT,
    )?;
    let present = CheckResult::observed(CheckState::Pass);
    let revocation = CheckResult::observed(CheckState::NotChecked);
    let delta_signature = CheckResult::observed(match valid_delta.observation.verdict {
        StackVerdict::Accept => CheckState::Pass,
        StackVerdict::Reject => CheckState::Fail,
        StackVerdict::Indeterminate | StackVerdict::Unsupported => CheckState::Indeterminate,
    });
    let request = VerificationRequest {
        api_version: API_VERSION.to_owned(),
        policy: Policy::P2RequiredHybrid,
        path_scope: PathScope::EndEntity,
        validation_time: config.validation_time.clone(),
        previous_authentication: None,
        stack: valid_base_tls.report.observation.clone(),
        certificate_path: vec![CertificateNode {
            id: "end-entity".to_owned(),
            position: PathPosition::EndEntity,
            scheme: Scheme::Chameleon,
        }],
        evidence: vec![
            Evidence {
                id: "delta-classical-certificate".to_owned(),
                certificate_id: "end-entity".to_owned(),
                position: PathPosition::EndEntity,
                kind: EvidenceKind::Classical,
                present,
                recognized: present,
                signature: delta_signature,
                binding: delta_signature,
                path: CheckResult::observed(
                    if separate_delta_tls.report.observation.verdict == StackVerdict::Accept {
                        CheckState::Pass
                    } else {
                        CheckState::Fail
                    },
                ),
                validity: delta_validity,
                revocation,
                outcome_bearing: classical_outcome,
            },
            Evidence {
                id: "base-mldsa-certificate".to_owned(),
                certificate_id: "end-entity".to_owned(),
                position: PathPosition::EndEntity,
                kind: EvidenceKind::PostQuantum,
                present,
                recognized: present,
                signature: post_quantum_outcome,
                binding: CheckResult::observed(CheckState::NotApplicable),
                path,
                validity: base_validity,
                revocation,
                outcome_bearing: post_quantum_outcome,
            },
        ],
    };

    Ok(ChameleonTlsReport {
        api_version: API_VERSION.to_owned(),
        valid_base_tls,
        invalid_base_signature_tls,
        invalid_delta_base_tls,
        separate_delta_tls,
        valid_delta_direct_control: valid_delta.report()?,
        invalid_delta_direct_control: invalid_delta.report()?,
        result: evaluate(&request)?,
    })
}

fn run_tls(
    config: &ChameleonTlsConfig,
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

fn run_delta(
    config: &ChameleonTlsConfig,
    leaf: PathBuf,
) -> Result<crate::adapters::AdapterExecution, BouncyCastleError> {
    verify_bouncy_castle(&BouncyCastleConfig {
        docker: config.docker.clone(),
        image: config.image.clone(),
        trust_store: config.trust_store.clone(),
        intermediate: config.issuer.clone(),
        leaf,
        validation_time: config.validation_time.clone(),
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
        mode: BouncyCastleMode::DeltaSignature,
        private_key: None,
        crl: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyVerdict;
    use std::path::Path;

    #[test]
    fn base_tls_does_not_make_delta_evidence_outcome_bearing() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixtures = repository.join("tests/fixtures/paper-v1.0.2");
        let controls = repository.join("tests/fixtures/generated-controls");
        let report = analyze(&ChameleonTlsConfig {
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            trust_store: fixtures.join("root.pem"),
            issuer: fixtures.join("ica.pem"),
            valid_base_certificate: controls.join("chameleon-base-valid-delta.pem"),
            invalid_delta_base_certificate: controls.join("chameleon-base-bad-delta.pem"),
            delta_certificate: controls.join("chameleon-delta-valid.pem"),
            base_private_key: controls.join("chameleon-base-key.pem"),
            delta_private_key: controls.join("chameleon-delta-key.pem"),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(
            report.valid_base_tls.report.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report.invalid_base_signature_tls.report.observation.verdict,
            StackVerdict::Reject
        );
        assert_eq!(
            report.invalid_delta_base_tls.report.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report.separate_delta_tls.report.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(report.valid_base_tls.signature.as_deref(), Some("mldsa44"));
        assert_eq!(
            report.separate_delta_tls.signature.as_deref(),
            Some("ecdsa_secp256r1_sha256")
        );
        assert_eq!(report.result.policy_verdict, PolicyVerdict::Reject);
        assert!(!report.result.classical_only_fallback);
    }
}
