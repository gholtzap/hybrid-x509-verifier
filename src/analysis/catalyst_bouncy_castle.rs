use crate::{
    API_VERSION, AdapterReport, AlgorithmSecurity, AuthenticationLevel, BindingDesign,
    CertificateNode, CheckResult, CheckState, Evidence, EvidenceKind, OracleError, PathPosition,
    PathScope, Policy, StackVerdict, VerificationRequest, VerificationResult,
    adapters::{
        AdapterSupportError,
        bouncy_castle::{
            BouncyCastleConfig, BouncyCastleError, BouncyCastleMode, verify as verify_bouncy_castle,
        },
        check_from_verdict,
    },
    analysis::{
        ScopedVerificationResult, behavioral_check, certificate_der_hash, issuer_edge_hash,
    },
    evaluate,
    mutation::{MutationError, corrupt_outer_signature, encode_certificate_pem},
    pem::{
        CrlStatusResult, PemError, PemKind, check_certificate_validity, check_crl_status,
        inspect_certificate, read_der,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{io::Write, path::PathBuf, time::Duration};
use thiserror::Error;

const INPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CatalystBouncyCastleConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub issuer: PathBuf,
    pub valid_certificate: PathBuf,
    pub invalid_post_quantum_certificate: PathBuf,
    pub crl: PathBuf,
    pub root_crl: PathBuf,
    pub validation_time: String,
    pub policy: Policy,
    pub previous_authentication: Option<AuthenticationLevel>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalystBouncyCastleReport {
    pub api_version: String,
    pub crl_status: CrlStatusResult,
    pub intermediate_crl_status: CrlStatusResult,
    pub root_crl_status: CrlStatusResult,
    pub valid_default_control: AdapterReport,
    pub invalid_classical_default_control: AdapterReport,
    pub invalid_post_quantum_default_control: AdapterReport,
    pub valid_post_quantum_direct_control: AdapterReport,
    pub invalid_post_quantum_direct_control: AdapterReport,
    pub intermediate_invalid_classical_control: AdapterReport,
    pub root_invalid_classical_control: AdapterReport,
    pub result: VerificationResult,
    pub scopes: Vec<ScopedVerificationResult>,
}

#[derive(Debug, Error)]
pub enum CatalystBouncyCastleError {
    #[error("both control certificates must use the Catalyst scheme")]
    WrongScheme,
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

pub fn analyze(
    config: &CatalystBouncyCastleConfig,
) -> Result<CatalystBouncyCastleReport, CatalystBouncyCastleError> {
    for path in [
        &config.valid_certificate,
        &config.invalid_post_quantum_certificate,
    ] {
        if inspect_certificate(path, INPUT_LIMIT)?.binding_design != BindingDesign::Catalyst {
            return Err(CatalystBouncyCastleError::WrongScheme);
        }
    }

    let crl_status = check_crl_status(
        &config.valid_certificate,
        &config.issuer,
        &config.crl,
        &config.validation_time,
        INPUT_LIMIT,
    )?;
    let intermediate_crl_status = check_crl_status(
        &config.issuer,
        &config.trust_store,
        &config.root_crl,
        &config.validation_time,
        INPUT_LIMIT,
    )?;
    let root_crl_status = check_crl_status(
        &config.trust_store,
        &config.trust_store,
        &config.root_crl,
        &config.validation_time,
        INPUT_LIMIT,
    )?;
    let leaf_validity = check_certificate_validity(
        &config.valid_certificate,
        &config.validation_time,
        INPUT_LIMIT,
    )?;
    let intermediate_validity =
        check_certificate_validity(&config.issuer, &config.validation_time, INPUT_LIMIT)?;
    let root_validity =
        check_certificate_validity(&config.trust_store, &config.validation_time, INPUT_LIMIT)?;
    let valid_default = run(
        config,
        config.valid_certificate.clone(),
        BouncyCastleMode::Path,
    )?;
    let invalid_post_quantum_default = run(
        config,
        config.invalid_post_quantum_certificate.clone(),
        BouncyCastleMode::Path,
    )?;
    let valid_post_quantum = run(
        config,
        config.valid_certificate.clone(),
        BouncyCastleMode::AlternativeSignature,
    )?;
    let invalid_post_quantum = run(
        config,
        config.invalid_post_quantum_certificate.clone(),
        BouncyCastleMode::AlternativeSignature,
    )?;

    let valid_der = read_der(&config.valid_certificate, PemKind::Certificate, INPUT_LIMIT)?;
    let mut invalid_classical_file = tempfile::NamedTempFile::new()?;
    invalid_classical_file
        .write_all(encode_certificate_pem(&corrupt_outer_signature(&valid_der)?).as_bytes())?;
    let invalid_classical = run(
        config,
        invalid_classical_file.path().to_owned(),
        BouncyCastleMode::Path,
    )?;
    let intermediate_der = read_der(&config.issuer, PemKind::Certificate, INPUT_LIMIT)?;
    let mut invalid_intermediate_file = tempfile::NamedTempFile::new()?;
    invalid_intermediate_file.write_all(
        encode_certificate_pem(&corrupt_outer_signature(&intermediate_der)?).as_bytes(),
    )?;
    let invalid_intermediate = run_paths(
        config,
        config.trust_store.clone(),
        invalid_intermediate_file.path().to_owned(),
        config.valid_certificate.clone(),
        BouncyCastleMode::Path,
    )?;
    let root_der = read_der(&config.trust_store, PemKind::Certificate, INPUT_LIMIT)?;
    let mut invalid_root_file = tempfile::NamedTempFile::new()?;
    invalid_root_file
        .write_all(encode_certificate_pem(&corrupt_outer_signature(&root_der)?).as_bytes())?;
    let invalid_root = run_paths(
        config,
        invalid_root_file.path().to_owned(),
        config.issuer.clone(),
        config.valid_certificate.clone(),
        BouncyCastleMode::Path,
    )?;

    let classical_outcome = behavioral_check(
        valid_default.observation.verdict == StackVerdict::Accept
            && invalid_classical.observation.verdict == StackVerdict::Reject,
        CheckState::Pass,
    );
    let post_quantum_outcome = behavioral_check(
        valid_default.observation.verdict == StackVerdict::Accept
            && invalid_post_quantum_default.observation.verdict == StackVerdict::Accept
            && valid_post_quantum.observation.verdict == StackVerdict::Accept
            && invalid_post_quantum.observation.verdict == StackVerdict::Reject,
        CheckState::Fail,
    );
    let intermediate_classical_outcome = behavioral_check(
        valid_default.observation.verdict == StackVerdict::Accept
            && invalid_intermediate.observation.verdict == StackVerdict::Reject,
        CheckState::Pass,
    );
    let root_classical_outcome = behavioral_check(
        valid_default.observation.verdict == StackVerdict::Accept
            && invalid_root.observation.verdict == StackVerdict::Accept,
        CheckState::Fail,
    );
    let observed_pass = CheckResult::observed(CheckState::Pass);
    let classical_path = check_from_verdict(valid_default.observation.verdict);
    let post_quantum_signature = check_from_verdict(valid_post_quantum.observation.verdict);
    let leaf_hash = certificate_der_hash(&config.valid_certificate, INPUT_LIMIT)?;
    let leaf_edge_hash = issuer_edge_hash(&config.valid_certificate, &config.issuer, INPUT_LIMIT)?;
    let intermediate_hash = certificate_der_hash(&config.issuer, INPUT_LIMIT)?;
    let intermediate_edge_hash =
        issuer_edge_hash(&config.issuer, &config.trust_store, INPUT_LIMIT)?;
    let root_hash = certificate_der_hash(&config.trust_store, INPUT_LIMIT)?;
    let certificate_path = vec![
        CertificateNode {
            id: "end-entity".to_owned(),
            position: PathPosition::EndEntity,
            subject_public_key_scheme: AlgorithmSecurity::Classical,
            certificate_signature_scheme: AlgorithmSecurity::Classical,
            binding_design: BindingDesign::Catalyst,
            der_sha256: Some(leaf_hash.clone()),
            issuer_edge_sha256: Some(leaf_edge_hash.clone()),
        },
        CertificateNode {
            id: "intermediate".to_owned(),
            position: PathPosition::Intermediate,
            subject_public_key_scheme: AlgorithmSecurity::Classical,
            certificate_signature_scheme: AlgorithmSecurity::Classical,
            binding_design: BindingDesign::Catalyst,
            der_sha256: Some(intermediate_hash.clone()),
            issuer_edge_sha256: Some(intermediate_edge_hash.clone()),
        },
        CertificateNode {
            id: "root".to_owned(),
            position: PathPosition::TrustAnchor,
            subject_public_key_scheme: AlgorithmSecurity::Classical,
            certificate_signature_scheme: AlgorithmSecurity::Classical,
            binding_design: BindingDesign::None,
            der_sha256: Some(root_hash.clone()),
            issuer_edge_sha256: None,
        },
    ];
    let missing = CheckResult::observed(CheckState::Fail);
    let not_checked = CheckResult::observed(CheckState::NotChecked);
    let evidence = vec![
        Evidence {
            id: "classical-base-signature".to_owned(),
            certificate_id: "end-entity".to_owned(),
            position: PathPosition::EndEntity,
            certificate_der_sha256: Some(leaf_hash.clone()),
            issuer_edge_sha256: Some(leaf_edge_hash.clone()),
            kind: EvidenceKind::Classical,
            present: observed_pass,
            recognized: observed_pass,
            signature: classical_path,
            binding: CheckResult::observed(CheckState::NotApplicable),
            path: classical_path,
            validity: leaf_validity,
            revocation: crl_status.revocation,
            decision_sensitive_for_fixture: classical_outcome,
        },
        Evidence {
            id: "catalyst-alternative-signature".to_owned(),
            certificate_id: "end-entity".to_owned(),
            position: PathPosition::EndEntity,
            certificate_der_sha256: Some(leaf_hash.clone()),
            issuer_edge_sha256: Some(leaf_edge_hash.clone()),
            kind: EvidenceKind::PostQuantum,
            present: observed_pass,
            recognized: observed_pass,
            signature: post_quantum_signature,
            binding: post_quantum_signature,
            path: classical_path,
            validity: leaf_validity,
            revocation: crl_status.revocation,
            decision_sensitive_for_fixture: post_quantum_outcome,
        },
        Evidence {
            id: "intermediate-classical-signature".to_owned(),
            certificate_id: "intermediate".to_owned(),
            position: PathPosition::Intermediate,
            certificate_der_sha256: Some(intermediate_hash.clone()),
            issuer_edge_sha256: Some(intermediate_edge_hash.clone()),
            kind: EvidenceKind::Classical,
            present: observed_pass,
            recognized: observed_pass,
            signature: intermediate_crl_status.issuer,
            binding: CheckResult::observed(CheckState::NotApplicable),
            path: classical_path,
            validity: intermediate_validity,
            revocation: intermediate_crl_status.revocation,
            decision_sensitive_for_fixture: intermediate_classical_outcome,
        },
        Evidence {
            id: "intermediate-alternative-signature".to_owned(),
            certificate_id: "intermediate".to_owned(),
            position: PathPosition::Intermediate,
            certificate_der_sha256: Some(intermediate_hash.clone()),
            issuer_edge_sha256: Some(intermediate_edge_hash.clone()),
            kind: EvidenceKind::PostQuantum,
            present: missing,
            recognized: not_checked,
            signature: not_checked,
            binding: not_checked,
            path: not_checked,
            validity: intermediate_validity,
            revocation: intermediate_crl_status.revocation,
            decision_sensitive_for_fixture: not_checked,
        },
        Evidence {
            id: "root-classical-signature".to_owned(),
            certificate_id: "root".to_owned(),
            position: PathPosition::TrustAnchor,
            certificate_der_sha256: Some(root_hash.clone()),
            issuer_edge_sha256: None,
            kind: EvidenceKind::Classical,
            present: observed_pass,
            recognized: observed_pass,
            signature: root_crl_status.issuer,
            binding: CheckResult::observed(CheckState::NotApplicable),
            path: classical_path,
            validity: root_validity,
            revocation: root_crl_status.revocation,
            decision_sensitive_for_fixture: root_classical_outcome,
        },
    ];
    let scopes = [PathScope::EndEntity, PathScope::CertificationPath]
        .into_iter()
        .map(|scope| {
            Ok(ScopedVerificationResult {
                scope,
                result: evaluate(&VerificationRequest {
                    api_version: API_VERSION.to_owned(),
                    policy: config.policy,
                    path_scope: scope,
                    validation_time: config.validation_time.clone(),
                    previous_authentication: config.previous_authentication,
                    stack: valid_default.observation.clone(),
                    certificate_path: certificate_path.clone(),
                    evidence: evidence.clone(),
                })?,
            })
        })
        .collect::<Result<Vec<_>, OracleError>>()?;

    Ok(CatalystBouncyCastleReport {
        api_version: API_VERSION.to_owned(),
        crl_status,
        intermediate_crl_status,
        root_crl_status,
        valid_default_control: valid_default.report()?,
        invalid_classical_default_control: invalid_classical.report()?,
        invalid_post_quantum_default_control: invalid_post_quantum_default.report()?,
        valid_post_quantum_direct_control: valid_post_quantum.report()?,
        invalid_post_quantum_direct_control: invalid_post_quantum.report()?,
        intermediate_invalid_classical_control: invalid_intermediate.report()?,
        root_invalid_classical_control: invalid_root.report()?,
        result: scopes[0].result.clone(),
        scopes,
    })
}

fn run(
    config: &CatalystBouncyCastleConfig,
    leaf: PathBuf,
    mode: BouncyCastleMode,
) -> Result<crate::adapters::AdapterExecution, BouncyCastleError> {
    run_paths(
        config,
        config.trust_store.clone(),
        config.issuer.clone(),
        leaf,
        mode,
    )
}

fn run_paths(
    config: &CatalystBouncyCastleConfig,
    trust_store: PathBuf,
    intermediate: PathBuf,
    leaf: PathBuf,
    mode: BouncyCastleMode,
) -> Result<crate::adapters::AdapterExecution, BouncyCastleError> {
    verify_bouncy_castle(&BouncyCastleConfig {
        docker: config.docker.clone(),
        image: config.image.clone(),
        trust_store,
        intermediate,
        leaf,
        validation_time: config.validation_time.clone(),
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
        mode,
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
    fn detects_catalyst_classical_only_fallback() {
        let _guard = crate::adapter_test_lock();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let published = repository.join("tests/fixtures/paper-v1.0.2");
        let controls = repository.join("tests/fixtures/generated-controls");
        let report = analyze(&CatalystBouncyCastleConfig {
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            trust_store: published.join("root.pem"),
            issuer: published.join("catalyst-ica.pem"),
            valid_certificate: published.join("catalyst-leaf.pem"),
            invalid_post_quantum_certificate: controls.join("catalyst-leaf-bad-alt.pem"),
            crl: controls.join("catalyst-crl.pem"),
            root_crl: controls.join("root-crl.pem"),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            policy: Policy::P2RequiredHybrid,
            previous_authentication: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(
            report.valid_default_control.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report.invalid_classical_default_control.observation.verdict,
            StackVerdict::Reject
        );
        assert_eq!(
            report
                .invalid_post_quantum_default_control
                .observation
                .verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report
                .invalid_post_quantum_direct_control
                .observation
                .verdict,
            StackVerdict::Reject
        );
        assert_eq!(
            report
                .valid_post_quantum_direct_control
                .source_instrumentation
                .as_ref()
                .unwrap()
                .events[0]
                .operation,
            "check-alternative-signature"
        );
        assert_eq!(report.result.policy_verdict, PolicyVerdict::Reject);
        assert!(report.result.classical_only_fallback);
        assert_eq!(report.scopes.len(), 2);
        assert!(
            report
                .scopes
                .iter()
                .all(|scope| scope.result.policy_verdict == PolicyVerdict::Reject)
        );
        assert_eq!(
            report
                .scopes
                .iter()
                .find(|scope| scope.scope == PathScope::CertificationPath)
                .unwrap()
                .result
                .evaluated_evidence
                .iter()
                .find(|evidence| evidence.id == "intermediate-alternative-signature")
                .unwrap()
                .present
                .state,
            CheckState::Fail
        );
    }
}
