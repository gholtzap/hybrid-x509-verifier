use crate::{
    API_VERSION, AdapterReport, AlgorithmSecurity, AuthenticationLevel, BindingDesign,
    CertificateNode, CheckResult, CheckState, Evidence, EvidenceKind, OracleError, PathPosition,
    PathScope, Policy, StackVerdict, VerificationRequest,
    adapters::{
        AdapterExecution, AdapterSupportError,
        bouncy_castle::{
            BouncyCastleConfig, BouncyCastleError, BouncyCastleMode, verify as verify_bouncy_castle,
        },
        check_from_verdict,
    },
    analysis::{
        ScopedVerificationResult, behavioral_check, certificate_der_hash, certificate_trust_anchor,
        issuer_edge_hash,
    },
    evaluate,
    pem::{PemError, check_certificate_validity, inspect_certificate},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;

const INPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AtomicPathScopeConfig {
    pub docker: PathBuf,
    pub image: String,
    pub root: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub invalid_classical_root: PathBuf,
    pub invalid_post_quantum_root: PathBuf,
    pub invalid_classical_intermediate: PathBuf,
    pub invalid_post_quantum_intermediate: PathBuf,
    pub invalid_classical_leaf: PathBuf,
    pub invalid_post_quantum_leaf: PathBuf,
    pub root_crl: PathBuf,
    pub intermediate_crl: PathBuf,
    pub validation_time: String,
    pub policy: Policy,
    pub previous_authentication: Option<AuthenticationLevel>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtomicPathPositionReport {
    pub position: PathPosition,
    pub validity: CheckResult,
    pub crl_status: AdapterReport,
    pub valid_signature: AdapterReport,
    pub invalid_classical_signature: AdapterReport,
    pub invalid_post_quantum_signature: AdapterReport,
    pub invalid_classical_default_path: AdapterReport,
    pub invalid_post_quantum_default_path: AdapterReport,
    pub classical_decision_sensitive_for_fixture: CheckResult,
    pub post_quantum_decision_sensitive_for_fixture: CheckResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtomicPathScopeReport {
    pub api_version: String,
    pub valid_default_path: AdapterReport,
    pub positions: Vec<AtomicPathPositionReport>,
    pub scopes: Vec<ScopedVerificationResult>,
}

#[derive(Debug, Error)]
pub enum AtomicPathScopeError {
    #[error("all atomic path controls must use the atomic composite scheme")]
    WrongScheme,
    #[error(transparent)]
    BouncyCastle(#[from] BouncyCastleError),
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Pem(#[from] PemError),
    #[error(transparent)]
    Oracle(#[from] OracleError),
}

struct PositionAnalysis {
    position: PathPosition,
    certificate_der_sha256: String,
    issuer_edge_sha256: Option<String>,
    validity: CheckResult,
    crl: AdapterExecution,
    valid_signature: AdapterExecution,
    invalid_classical_signature: AdapterExecution,
    invalid_post_quantum_signature: AdapterExecution,
    invalid_classical_path: AdapterExecution,
    invalid_post_quantum_path: AdapterExecution,
    classical_outcome: CheckResult,
    post_quantum_outcome: CheckResult,
}

pub fn analyze(
    config: &AtomicPathScopeConfig,
) -> Result<AtomicPathScopeReport, AtomicPathScopeError> {
    for certificate in [
        &config.root,
        &config.intermediate,
        &config.leaf,
        &config.invalid_classical_root,
        &config.invalid_post_quantum_root,
        &config.invalid_classical_intermediate,
        &config.invalid_post_quantum_intermediate,
        &config.invalid_classical_leaf,
        &config.invalid_post_quantum_leaf,
    ] {
        if inspect_certificate(certificate, INPUT_LIMIT)?.binding_design
            != BindingDesign::AtomicComposite
        {
            return Err(AtomicPathScopeError::WrongScheme);
        }
    }

    let valid_path = run_path(config, &config.root, &config.intermediate, &config.leaf)?;
    let analyses = [
        analyze_position(
            config,
            PathPosition::EndEntity,
            valid_path.observation.verdict,
        )?,
        analyze_position(
            config,
            PathPosition::Intermediate,
            valid_path.observation.verdict,
        )?,
        analyze_position(
            config,
            PathPosition::TrustAnchor,
            valid_path.observation.verdict,
        )?,
    ];
    let certificate_path = analyses
        .iter()
        .filter(|analysis| analysis.position != PathPosition::TrustAnchor)
        .map(|analysis| CertificateNode {
            id: position_id(analysis.position).to_owned(),
            position: analysis.position,
            subject_public_key_scheme: AlgorithmSecurity::Classical,
            certificate_signature_scheme: AlgorithmSecurity::Hybrid,
            binding_design: BindingDesign::AtomicComposite,
            der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
        })
        .collect::<Vec<_>>();
    let evidence = analyses
        .iter()
        .filter(|analysis| analysis.position != PathPosition::TrustAnchor)
        .flat_map(|analysis| position_evidence(analysis, valid_path.observation.verdict))
        .collect::<Vec<_>>();
    let expected_trust_anchor = certificate_trust_anchor(&config.root, INPUT_LIMIT)?;
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
                    revocation_policy: crate::RevocationPolicy::crl_hard_fail(),
                    stack: valid_path.observation.clone(),
                    expected_trust_anchor: expected_trust_anchor.clone(),
                    certificate_path: certificate_path.clone(),
                    paired_authentications: Vec::new(),
                    evidence: evidence.clone(),
                })?,
            })
        })
        .collect::<Result<Vec<_>, OracleError>>()?;
    let positions = analyses
        .into_iter()
        .map(|analysis| {
            Ok(AtomicPathPositionReport {
                position: analysis.position,
                validity: analysis.validity,
                crl_status: analysis.crl.report()?,
                valid_signature: analysis.valid_signature.report()?,
                invalid_classical_signature: analysis.invalid_classical_signature.report()?,
                invalid_post_quantum_signature: analysis.invalid_post_quantum_signature.report()?,
                invalid_classical_default_path: analysis.invalid_classical_path.report()?,
                invalid_post_quantum_default_path: analysis.invalid_post_quantum_path.report()?,
                classical_decision_sensitive_for_fixture: analysis.classical_outcome,
                post_quantum_decision_sensitive_for_fixture: analysis.post_quantum_outcome,
            })
        })
        .collect::<Result<Vec<_>, AdapterSupportError>>()?;

    Ok(AtomicPathScopeReport {
        api_version: API_VERSION.to_owned(),
        valid_default_path: valid_path.report()?,
        positions,
        scopes,
    })
}

fn analyze_position(
    config: &AtomicPathScopeConfig,
    position: PathPosition,
    valid_verdict: StackVerdict,
) -> Result<PositionAnalysis, AtomicPathScopeError> {
    let (certificate, issuer, crl, invalid_classical, invalid_post_quantum) = match position {
        PathPosition::EndEntity => (
            &config.leaf,
            &config.intermediate,
            &config.intermediate_crl,
            &config.invalid_classical_leaf,
            &config.invalid_post_quantum_leaf,
        ),
        PathPosition::Intermediate => (
            &config.intermediate,
            &config.root,
            &config.root_crl,
            &config.invalid_classical_intermediate,
            &config.invalid_post_quantum_intermediate,
        ),
        PathPosition::TrustAnchor => (
            &config.root,
            &config.root,
            &config.root_crl,
            &config.invalid_classical_root,
            &config.invalid_post_quantum_root,
        ),
    };
    let valid_signature = run_direct(config, issuer, certificate)?;
    let invalid_classical_signature = run_direct(config, issuer, invalid_classical)?;
    let invalid_post_quantum_signature = run_direct(config, issuer, invalid_post_quantum)?;
    let invalid_classical_path = path_with_replacement(config, position, invalid_classical)?;
    let invalid_post_quantum_path = path_with_replacement(config, position, invalid_post_quantum)?;
    let direct_controls = valid_signature.observation.verdict == StackVerdict::Accept;

    Ok(PositionAnalysis {
        position,
        certificate_der_sha256: certificate_der_hash(certificate, INPUT_LIMIT)?,
        issuer_edge_sha256: (position != PathPosition::TrustAnchor)
            .then(|| issuer_edge_hash(certificate, issuer, INPUT_LIMIT))
            .transpose()?,
        validity: check_certificate_validity(certificate, &config.validation_time, INPUT_LIMIT)?,
        crl: run_crl(config, issuer, certificate, crl)?,
        valid_signature,
        classical_outcome: outcome_check(
            valid_verdict,
            invalid_classical_path.observation.verdict,
            direct_controls
                && invalid_classical_signature.observation.verdict == StackVerdict::Reject,
        ),
        post_quantum_outcome: outcome_check(
            valid_verdict,
            invalid_post_quantum_path.observation.verdict,
            direct_controls
                && invalid_post_quantum_signature.observation.verdict == StackVerdict::Reject,
        ),
        invalid_classical_signature,
        invalid_post_quantum_signature,
        invalid_classical_path,
        invalid_post_quantum_path,
    })
}

fn outcome_check(valid: StackVerdict, invalid: StackVerdict, established: bool) -> CheckResult {
    if valid != StackVerdict::Accept || !established {
        return behavioral_check(false, CheckState::Indeterminate);
    }
    match invalid {
        StackVerdict::Reject => behavioral_check(true, CheckState::Pass),
        StackVerdict::Accept => behavioral_check(true, CheckState::Fail),
        StackVerdict::Indeterminate | StackVerdict::Unsupported => {
            behavioral_check(false, CheckState::Indeterminate)
        }
    }
}

fn position_evidence(analysis: &PositionAnalysis, valid_path: StackVerdict) -> [Evidence; 2] {
    let id = position_id(analysis.position);
    let pass = CheckResult::observed(CheckState::Pass);
    let signature = check_from_verdict(analysis.valid_signature.observation.verdict);
    let path = check_from_verdict(valid_path);
    let revocation = check_from_verdict(analysis.crl.observation.verdict);
    [
        Evidence {
            id: format!("{id}-ecdsa-component"),
            certificate_id: id.to_owned(),
            position: analysis.position,
            certificate_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            evidence_artifact_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
            authentication_operation_id: None,
            kind: EvidenceKind::Classical,
            present: pass,
            recognized: pass,
            signature,
            binding: CheckResult::observed(CheckState::NotApplicable),
            path,
            validity: analysis.validity,
            revocation,
            revocation_method: crate::RevocationMethod::Crl,
            applied_revocation_policy: crate::RevocationPolicy::crl_hard_fail(),
            decision_sensitive_for_fixture: analysis.classical_outcome,
        },
        Evidence {
            id: format!("{id}-mldsa-component"),
            certificate_id: id.to_owned(),
            position: analysis.position,
            certificate_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            evidence_artifact_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
            authentication_operation_id: None,
            kind: EvidenceKind::PostQuantum,
            present: pass,
            recognized: pass,
            signature,
            binding: CheckResult::observed(CheckState::NotApplicable),
            path,
            validity: analysis.validity,
            revocation,
            revocation_method: crate::RevocationMethod::Crl,
            applied_revocation_policy: crate::RevocationPolicy::crl_hard_fail(),
            decision_sensitive_for_fixture: analysis.post_quantum_outcome,
        },
    ]
}

fn position_id(position: PathPosition) -> &'static str {
    match position {
        PathPosition::EndEntity => "leaf",
        PathPosition::Intermediate => "intermediate",
        PathPosition::TrustAnchor => "root",
    }
}

fn path_with_replacement(
    config: &AtomicPathScopeConfig,
    position: PathPosition,
    replacement: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run_path(
        config,
        if position == PathPosition::TrustAnchor {
            replacement
        } else {
            &config.root
        },
        if position == PathPosition::Intermediate {
            replacement
        } else {
            &config.intermediate
        },
        if position == PathPosition::EndEntity {
            replacement
        } else {
            &config.leaf
        },
    )
}

fn run_path(
    config: &AtomicPathScopeConfig,
    root: &Path,
    intermediate: &Path,
    leaf: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        root.to_owned(),
        intermediate.to_owned(),
        leaf.to_owned(),
        BouncyCastleMode::Path,
        None,
    )
}

fn run_direct(
    config: &AtomicPathScopeConfig,
    issuer: &Path,
    certificate: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        config.root.clone(),
        issuer.to_owned(),
        certificate.to_owned(),
        BouncyCastleMode::CertificateSignature,
        None,
    )
}

fn run_crl(
    config: &AtomicPathScopeConfig,
    issuer: &Path,
    certificate: &Path,
    crl: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        config.root.clone(),
        issuer.to_owned(),
        certificate.to_owned(),
        BouncyCastleMode::CrlStatus,
        Some(crl.to_owned()),
    )
}

fn run(
    config: &AtomicPathScopeConfig,
    root: PathBuf,
    intermediate: PathBuf,
    leaf: PathBuf,
    mode: BouncyCastleMode,
    crl: Option<PathBuf>,
) -> Result<AdapterExecution, BouncyCastleError> {
    verify_bouncy_castle(&BouncyCastleConfig {
        docker: config.docker.clone(),
        image: config.image.clone(),
        trust_store: root,
        intermediate,
        leaf,
        validation_time: config.validation_time.clone(),
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
        mode,
        private_key: None,
        crl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyVerdict;
    use std::path::Path;

    #[test]
    fn atomic_components_are_decisive_for_certification_path_not_trust_anchor() {
        let _guard = crate::adapter_test_lock();
        let controls =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/generated-controls");
        let report = analyze(&AtomicPathScopeConfig {
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            root: controls.join("atomic-path-root.pem"),
            intermediate: controls.join("atomic-path-ica.pem"),
            leaf: controls.join("atomic-path-leaf.pem"),
            invalid_classical_root: controls.join("atomic-path-root-bad-ecdsa.pem"),
            invalid_post_quantum_root: controls.join("atomic-path-root-bad-mldsa.pem"),
            invalid_classical_intermediate: controls.join("atomic-path-ica-bad-ecdsa.pem"),
            invalid_post_quantum_intermediate: controls.join("atomic-path-ica-bad-mldsa.pem"),
            invalid_classical_leaf: controls.join("atomic-path-leaf-bad-ecdsa.pem"),
            invalid_post_quantum_leaf: controls.join("atomic-path-leaf-bad-mldsa.pem"),
            root_crl: controls.join("atomic-path-root-crl.pem"),
            intermediate_crl: controls.join("atomic-path-ica-crl.pem"),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            policy: Policy::P2RequiredHybrid,
            previous_authentication: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(
            report.valid_default_path.observation.verdict,
            StackVerdict::Accept
        );
        assert!(report.positions[..2].iter().all(|position| {
            position.classical_decision_sensitive_for_fixture.state == CheckState::Pass
                && position.post_quantum_decision_sensitive_for_fixture.state == CheckState::Pass
        }));
        assert_eq!(
            report.positions[2]
                .classical_decision_sensitive_for_fixture
                .state,
            CheckState::Fail
        );
        assert_eq!(
            report.positions[2]
                .post_quantum_decision_sensitive_for_fixture
                .state,
            CheckState::Fail
        );
        assert_eq!(
            report.scopes[0].result.policy_verdict,
            PolicyVerdict::Indeterminate
        );
        assert_eq!(
            report.scopes[1].result.policy_verdict,
            PolicyVerdict::Indeterminate
        );
    }
}
