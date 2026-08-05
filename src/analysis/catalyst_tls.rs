use crate::{
    API_VERSION, AdapterReport, CertificateNode, CheckResult, CheckState, Confidence, Evidence,
    EvidenceKind, OracleError, PathPosition, PathScope, Policy, Scheme, StackVerdict,
    VerificationRequest, VerificationResult,
    adapters::{
        AdapterSupportError,
        bouncy_castle::{
            BouncyCastleConfig, BouncyCastleError, BouncyCastleMode, verify as verify_bouncy_castle,
        },
        check_from_verdict,
        openssl::OpenSslTlsConfig,
    },
    analysis::tls::{
        TlsHandshakeEvidence, TlsObservationError, TlsTranscriptConfig, TlsTranscriptEvidence,
        observe as observe_tls, observe_transcript,
    },
    evaluate,
    mutation::{MutationError, corrupt_outer_signature, encode_certificate_pem},
    pem::{CrlStatusResult, PemError, PemKind, check_crl_status, inspect_certificate, read_der},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{io::Write, path::PathBuf, time::Duration};
use thiserror::Error;

const INPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CatalystTlsConfig {
    pub docker: PathBuf,
    pub openssl_image: String,
    pub bouncy_castle_image: String,
    pub trust_store: PathBuf,
    pub issuer: PathBuf,
    pub valid_certificate: PathBuf,
    pub invalid_post_quantum_certificate: PathBuf,
    pub private_key: PathBuf,
    pub crl: PathBuf,
    pub hostname: String,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalystTlsReport {
    pub api_version: String,
    pub crl_status: CrlStatusResult,
    pub valid_tls: TlsHandshakeEvidence,
    pub invalid_classical_tls: TlsHandshakeEvidence,
    pub invalid_post_quantum_tls: TlsHandshakeEvidence,
    pub valid_post_quantum_direct_control: AdapterReport,
    pub invalid_post_quantum_direct_control: AdapterReport,
    pub transcript_binding_control: TlsTranscriptEvidence,
    pub result: VerificationResult,
}

#[derive(Debug, Error)]
pub enum CatalystTlsError {
    #[error("both control certificates must use the Catalyst scheme")]
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

pub fn analyze(config: &CatalystTlsConfig) -> Result<CatalystTlsReport, CatalystTlsError> {
    for path in [
        &config.valid_certificate,
        &config.invalid_post_quantum_certificate,
    ] {
        if inspect_certificate(path, INPUT_LIMIT)?.scheme != Scheme::Catalyst {
            return Err(CatalystTlsError::WrongScheme);
        }
    }

    let crl_status = check_crl_status(
        &config.valid_certificate,
        &config.issuer,
        &config.crl,
        &config.validation_time,
        INPUT_LIMIT,
    )?;
    let mut valid_tls = run_tls(config, config.valid_certificate.clone())?;
    let invalid_post_quantum_tls =
        run_tls(config, config.invalid_post_quantum_certificate.clone())?;

    let valid_der = read_der(&config.valid_certificate, PemKind::Certificate, INPUT_LIMIT)?;
    let mut invalid_classical_file = tempfile::NamedTempFile::new()?;
    invalid_classical_file
        .write_all(encode_certificate_pem(&corrupt_outer_signature(&valid_der)?).as_bytes())?;
    let invalid_classical_tls = run_tls(config, invalid_classical_file.path().to_owned())?;

    let valid_post_quantum = run_post_quantum(config, config.valid_certificate.clone())?;
    let invalid_post_quantum =
        run_post_quantum(config, config.invalid_post_quantum_certificate.clone())?;
    let transcript_binding = run_transcript_binding(config)?;
    valid_tls.transcript_binding = transcript_binding.binding;

    let classical_outcome = behavioral_check(
        valid_tls.report.observation.verdict == StackVerdict::Accept
            && invalid_classical_tls.report.observation.verdict == StackVerdict::Reject,
        CheckState::Pass,
    );
    let post_quantum_outcome = behavioral_check(
        valid_tls.report.observation.verdict == StackVerdict::Accept
            && invalid_post_quantum_tls.report.observation.verdict == StackVerdict::Accept
            && valid_post_quantum.observation.verdict == StackVerdict::Accept
            && invalid_post_quantum.observation.verdict == StackVerdict::Reject,
        CheckState::Fail,
    );
    let observed_pass = CheckResult::observed(CheckState::Pass);
    let classical_path = check_from_verdict(valid_tls.report.observation.verdict);
    let post_quantum_signature = check_from_verdict(valid_post_quantum.observation.verdict);
    let request = VerificationRequest {
        api_version: API_VERSION.to_owned(),
        policy: Policy::P2RequiredHybrid,
        path_scope: PathScope::EndEntity,
        validation_time: config.validation_time.clone(),
        previous_authentication: None,
        stack: valid_tls.report.observation.clone(),
        certificate_path: vec![CertificateNode {
            id: "end-entity".to_owned(),
            position: PathPosition::EndEntity,
            scheme: Scheme::Catalyst,
        }],
        evidence: vec![
            Evidence {
                id: "classical-base-signature".to_owned(),
                certificate_id: "end-entity".to_owned(),
                position: PathPosition::EndEntity,
                kind: EvidenceKind::Classical,
                present: observed_pass,
                recognized: observed_pass,
                signature: classical_path,
                binding: CheckResult::observed(CheckState::NotApplicable),
                path: classical_path,
                validity: classical_path,
                revocation: crl_status.revocation,
                outcome_bearing: classical_outcome,
            },
            Evidence {
                id: "catalyst-alternative-signature".to_owned(),
                certificate_id: "end-entity".to_owned(),
                position: PathPosition::EndEntity,
                kind: EvidenceKind::PostQuantum,
                present: observed_pass,
                recognized: observed_pass,
                signature: post_quantum_signature,
                binding: post_quantum_signature,
                path: classical_path,
                validity: classical_path,
                revocation: crl_status.revocation,
                outcome_bearing: post_quantum_outcome,
            },
        ],
    };

    Ok(CatalystTlsReport {
        api_version: API_VERSION.to_owned(),
        crl_status,
        valid_tls,
        invalid_classical_tls,
        invalid_post_quantum_tls,
        valid_post_quantum_direct_control: valid_post_quantum.report()?,
        invalid_post_quantum_direct_control: invalid_post_quantum.report()?,
        transcript_binding_control: transcript_binding,
        result: evaluate(&request)?,
    })
}

fn run_tls(
    config: &CatalystTlsConfig,
    leaf: PathBuf,
) -> Result<TlsHandshakeEvidence, CatalystTlsError> {
    Ok(observe_tls(&OpenSslTlsConfig {
        docker: config.docker.clone(),
        image: config.openssl_image.clone(),
        trust_store: config.trust_store.clone(),
        intermediate: config.issuer.clone(),
        leaf: leaf.clone(),
        private_key: config.private_key.clone(),
        hostname: config.hostname.clone(),
        validation_time: config.validation_time.clone(),
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    })?)
}

fn run_post_quantum(
    config: &CatalystTlsConfig,
    leaf: PathBuf,
) -> Result<crate::adapters::AdapterExecution, BouncyCastleError> {
    verify_bouncy_castle(&BouncyCastleConfig {
        docker: config.docker.clone(),
        image: config.bouncy_castle_image.clone(),
        trust_store: config.trust_store.clone(),
        intermediate: config.issuer.clone(),
        leaf,
        validation_time: config.validation_time.clone(),
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
        mode: BouncyCastleMode::AlternativeSignature,
        private_key: None,
        crl: None,
    })
}

fn run_transcript_binding(
    config: &CatalystTlsConfig,
) -> Result<TlsTranscriptEvidence, CatalystTlsError> {
    Ok(observe_transcript(&TlsTranscriptConfig {
        docker: config.docker.clone(),
        image: config.bouncy_castle_image.clone(),
        trust_store: config.trust_store.clone(),
        intermediate: config.issuer.clone(),
        leaf: config.valid_certificate.clone(),
        private_key: config.private_key.clone(),
        validation_time: config.validation_time.clone(),
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    })?)
}

fn behavioral_check(established: bool, state: CheckState) -> CheckResult {
    if established {
        CheckResult {
            state,
            confidence: Confidence::BehaviorallyEstablished,
        }
    } else {
        CheckResult {
            state: CheckState::Indeterminate,
            confidence: Confidence::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyVerdict;
    use std::path::Path;

    #[test]
    fn tls_rejects_hybrid_authentication_when_pq_does_not_change_the_handshake() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let published = repository.join("tests/fixtures/paper-v1.0.2");
        let controls = repository.join("tests/fixtures/generated-controls");
        let report = analyze(&CatalystTlsConfig {
            docker: "docker".into(),
            openssl_image: "hybrid-x509-openssl:4.0.1".to_owned(),
            bouncy_castle_image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            trust_store: published.join("root.pem"),
            issuer: published.join("catalyst-ica.pem"),
            valid_certificate: published.join("catalyst-leaf.pem"),
            invalid_post_quantum_certificate: controls.join("catalyst-leaf-bad-alt.pem"),
            private_key: controls.join("catalyst-leaf-base-key.pem"),
            crl: controls.join("catalyst-crl.pem"),
            hostname: "catalyst.pqc-probe.test".to_owned(),
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
            StackVerdict::Accept
        );
        assert_eq!(
            report.valid_tls.authentication_signature.as_deref(),
            Some("ecdsa_secp256r1_sha256")
        );
        assert_eq!(
            report.valid_tls.key_exchange_group.as_deref(),
            Some("X25519MLKEM768")
        );
        assert_eq!(
            report.transcript_binding_control.report.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report
                .transcript_binding_control
                .altered_transcript_rejected,
            CheckResult {
                state: CheckState::Pass,
                confidence: Confidence::BehaviorallyEstablished,
            }
        );
        assert_eq!(
            report.valid_tls.transcript_binding,
            CheckResult {
                state: CheckState::Pass,
                confidence: Confidence::BehaviorallyEstablished,
            }
        );
        assert_eq!(report.result.policy_verdict, PolicyVerdict::Reject);
        assert!(report.result.classical_only_fallback);
    }
}
