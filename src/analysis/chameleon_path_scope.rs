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
        ScopedVerificationResult, behavioral_check, certificate_der_hash, issuer_edge_hash,
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
pub struct ChameleonPathScopeConfig {
    pub docker: PathBuf,
    pub image: String,
    pub root_base: PathBuf,
    pub intermediate_base: PathBuf,
    pub leaf_base: PathBuf,
    pub root_delta: PathBuf,
    pub intermediate_delta: PathBuf,
    pub leaf_delta: PathBuf,
    pub invalid_delta_root_base: PathBuf,
    pub invalid_delta_intermediate_base: PathBuf,
    pub invalid_delta_leaf_base: PathBuf,
    pub invalid_base_root: PathBuf,
    pub invalid_base_intermediate: PathBuf,
    pub invalid_base_leaf: PathBuf,
    pub root_base_crl: PathBuf,
    pub intermediate_base_crl: PathBuf,
    pub root_delta_crl: PathBuf,
    pub intermediate_delta_crl: PathBuf,
    pub validation_time: String,
    pub policy: Policy,
    pub previous_authentication: Option<AuthenticationLevel>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChameleonPathPositionReport {
    pub position: PathPosition,
    pub base_validity: CheckResult,
    pub delta_validity: CheckResult,
    pub base_crl_status: AdapterReport,
    pub delta_crl_status: AdapterReport,
    pub base_signature: AdapterReport,
    pub invalid_base_signature: AdapterReport,
    pub delta_signature: AdapterReport,
    pub invalid_delta_signature: AdapterReport,
    pub invalid_base_default_path: AdapterReport,
    pub invalid_delta_default_path: AdapterReport,
    pub classical_decision_sensitive_for_fixture: CheckResult,
    pub post_quantum_decision_sensitive_for_fixture: CheckResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChameleonPathScopeReport {
    pub api_version: String,
    pub base_default_path: AdapterReport,
    pub delta_path_control: AdapterReport,
    pub positions: Vec<ChameleonPathPositionReport>,
    pub scopes: Vec<ScopedVerificationResult>,
}

#[derive(Debug, Error)]
pub enum ChameleonPathScopeError {
    #[error("all base controls must use Chameleon and all delta controls must be classical")]
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
    base_validity: CheckResult,
    delta_validity: CheckResult,
    base_crl: AdapterExecution,
    delta_crl: AdapterExecution,
    base_signature: AdapterExecution,
    invalid_base_signature: AdapterExecution,
    delta_signature: AdapterExecution,
    invalid_delta_signature: AdapterExecution,
    invalid_base_path: AdapterExecution,
    invalid_delta_path: AdapterExecution,
    classical_outcome: CheckResult,
    post_quantum_outcome: CheckResult,
}

pub fn analyze(
    config: &ChameleonPathScopeConfig,
) -> Result<ChameleonPathScopeReport, ChameleonPathScopeError> {
    for certificate in [
        &config.root_base,
        &config.intermediate_base,
        &config.leaf_base,
        &config.invalid_delta_root_base,
        &config.invalid_delta_intermediate_base,
        &config.invalid_delta_leaf_base,
        &config.invalid_base_root,
        &config.invalid_base_intermediate,
        &config.invalid_base_leaf,
    ] {
        if inspect_certificate(certificate, INPUT_LIMIT)?.binding_design != BindingDesign::Chameleon
        {
            return Err(ChameleonPathScopeError::WrongScheme);
        }
    }
    for certificate in [
        &config.root_delta,
        &config.intermediate_delta,
        &config.leaf_delta,
    ] {
        if inspect_certificate(certificate, INPUT_LIMIT)?.binding_design != BindingDesign::None {
            return Err(ChameleonPathScopeError::WrongScheme);
        }
    }

    let base_path = run_path(
        config,
        &config.root_base,
        &config.intermediate_base,
        &config.leaf_base,
    )?;
    let delta_path = run_path(
        config,
        &config.root_delta,
        &config.intermediate_delta,
        &config.leaf_delta,
    )?;
    let analyses = [
        analyze_position(
            config,
            PathPosition::EndEntity,
            base_path.observation.verdict,
        )?,
        analyze_position(
            config,
            PathPosition::Intermediate,
            base_path.observation.verdict,
        )?,
        analyze_position(
            config,
            PathPosition::TrustAnchor,
            base_path.observation.verdict,
        )?,
    ];
    let certificate_path = analyses
        .iter()
        .map(|analysis| CertificateNode {
            id: position_id(analysis.position).to_owned(),
            position: analysis.position,
            subject_public_key_scheme: AlgorithmSecurity::Classical,
            certificate_signature_scheme: AlgorithmSecurity::Classical,
            binding_design: BindingDesign::Chameleon,
            der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
        })
        .collect::<Vec<_>>();
    let evidence = analyses
        .iter()
        .flat_map(|analysis| {
            position_evidence(
                analysis,
                base_path.observation.verdict,
                delta_path.observation.verdict,
            )
        })
        .collect::<Vec<_>>();
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
                    stack: base_path.observation.clone(),
                    certificate_path: certificate_path.clone(),
                    evidence: evidence.clone(),
                })?,
            })
        })
        .collect::<Result<Vec<_>, OracleError>>()?;
    let positions = analyses
        .into_iter()
        .map(|analysis| {
            Ok(ChameleonPathPositionReport {
                position: analysis.position,
                base_validity: analysis.base_validity,
                delta_validity: analysis.delta_validity,
                base_crl_status: analysis.base_crl.report()?,
                delta_crl_status: analysis.delta_crl.report()?,
                base_signature: analysis.base_signature.report()?,
                invalid_base_signature: analysis.invalid_base_signature.report()?,
                delta_signature: analysis.delta_signature.report()?,
                invalid_delta_signature: analysis.invalid_delta_signature.report()?,
                invalid_base_default_path: analysis.invalid_base_path.report()?,
                invalid_delta_default_path: analysis.invalid_delta_path.report()?,
                classical_decision_sensitive_for_fixture: analysis.classical_outcome,
                post_quantum_decision_sensitive_for_fixture: analysis.post_quantum_outcome,
            })
        })
        .collect::<Result<Vec<_>, AdapterSupportError>>()?;

    Ok(ChameleonPathScopeReport {
        api_version: API_VERSION.to_owned(),
        base_default_path: base_path.report()?,
        delta_path_control: delta_path.report()?,
        positions,
        scopes,
    })
}

fn analyze_position(
    config: &ChameleonPathScopeConfig,
    position: PathPosition,
    valid_path: StackVerdict,
) -> Result<PositionAnalysis, ChameleonPathScopeError> {
    let inputs = position_inputs(config, position);
    let base_signature = run_direct(config, inputs.base_issuer, inputs.base)?;
    let invalid_base_signature = run_direct(config, inputs.base_issuer, inputs.invalid_base)?;
    let delta_signature = run_delta(config, inputs.base_issuer, inputs.base)?;
    let invalid_delta_signature = run_delta(config, inputs.base_issuer, inputs.invalid_delta_base)?;
    let invalid_base_path = base_path_with_replacement(config, position, inputs.invalid_base)?;
    let invalid_delta_path =
        base_path_with_replacement(config, position, inputs.invalid_delta_base)?;

    Ok(PositionAnalysis {
        position,
        certificate_der_sha256: certificate_der_hash(inputs.base, INPUT_LIMIT)?,
        issuer_edge_sha256: (position != PathPosition::TrustAnchor)
            .then(|| issuer_edge_hash(inputs.base, inputs.base_issuer, INPUT_LIMIT))
            .transpose()?,
        base_validity: check_certificate_validity(
            inputs.base,
            &config.validation_time,
            INPUT_LIMIT,
        )?,
        delta_validity: check_certificate_validity(
            inputs.delta,
            &config.validation_time,
            INPUT_LIMIT,
        )?,
        base_crl: run_crl(config, inputs.base_issuer, inputs.base, inputs.base_crl)?,
        delta_crl: run_crl(config, inputs.delta_issuer, inputs.delta, inputs.delta_crl)?,
        classical_outcome: outcome_check(
            valid_path,
            invalid_delta_path.observation.verdict,
            delta_signature.observation.verdict == StackVerdict::Accept
                && invalid_delta_signature.observation.verdict == StackVerdict::Reject,
        ),
        post_quantum_outcome: outcome_check(
            valid_path,
            invalid_base_path.observation.verdict,
            base_signature.observation.verdict == StackVerdict::Accept
                && invalid_base_signature.observation.verdict == StackVerdict::Reject,
        ),
        base_signature,
        invalid_base_signature,
        delta_signature,
        invalid_delta_signature,
        invalid_base_path,
        invalid_delta_path,
    })
}

struct PositionInputs<'a> {
    base: &'a Path,
    delta: &'a Path,
    invalid_delta_base: &'a Path,
    invalid_base: &'a Path,
    base_issuer: &'a Path,
    delta_issuer: &'a Path,
    base_crl: &'a Path,
    delta_crl: &'a Path,
}

fn position_inputs(
    config: &ChameleonPathScopeConfig,
    position: PathPosition,
) -> PositionInputs<'_> {
    match position {
        PathPosition::EndEntity => PositionInputs {
            base: &config.leaf_base,
            delta: &config.leaf_delta,
            invalid_delta_base: &config.invalid_delta_leaf_base,
            invalid_base: &config.invalid_base_leaf,
            base_issuer: &config.intermediate_base,
            delta_issuer: &config.intermediate_delta,
            base_crl: &config.intermediate_base_crl,
            delta_crl: &config.intermediate_delta_crl,
        },
        PathPosition::Intermediate => PositionInputs {
            base: &config.intermediate_base,
            delta: &config.intermediate_delta,
            invalid_delta_base: &config.invalid_delta_intermediate_base,
            invalid_base: &config.invalid_base_intermediate,
            base_issuer: &config.root_base,
            delta_issuer: &config.root_delta,
            base_crl: &config.root_base_crl,
            delta_crl: &config.root_delta_crl,
        },
        PathPosition::TrustAnchor => PositionInputs {
            base: &config.root_base,
            delta: &config.root_delta,
            invalid_delta_base: &config.invalid_delta_root_base,
            invalid_base: &config.invalid_base_root,
            base_issuer: &config.root_base,
            delta_issuer: &config.root_delta,
            base_crl: &config.root_base_crl,
            delta_crl: &config.root_delta_crl,
        },
    }
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

fn position_evidence(
    analysis: &PositionAnalysis,
    base_path: StackVerdict,
    delta_path: StackVerdict,
) -> [Evidence; 2] {
    let id = position_id(analysis.position);
    let pass = CheckResult::observed(CheckState::Pass);
    [
        Evidence {
            id: format!("{id}-delta-certificate"),
            certificate_id: id.to_owned(),
            position: analysis.position,
            certificate_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
            kind: EvidenceKind::Classical,
            present: pass,
            recognized: pass,
            signature: check_from_verdict(analysis.delta_signature.observation.verdict),
            binding: check_from_verdict(analysis.delta_signature.observation.verdict),
            path: check_from_verdict(delta_path),
            validity: analysis.delta_validity,
            revocation: check_from_verdict(analysis.delta_crl.observation.verdict),
            decision_sensitive_for_fixture: analysis.classical_outcome,
        },
        Evidence {
            id: format!("{id}-base-certificate"),
            certificate_id: id.to_owned(),
            position: analysis.position,
            certificate_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
            kind: EvidenceKind::PostQuantum,
            present: pass,
            recognized: pass,
            signature: check_from_verdict(analysis.base_signature.observation.verdict),
            binding: CheckResult::observed(CheckState::NotApplicable),
            path: check_from_verdict(base_path),
            validity: analysis.base_validity,
            revocation: check_from_verdict(analysis.base_crl.observation.verdict),
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

fn base_path_with_replacement(
    config: &ChameleonPathScopeConfig,
    position: PathPosition,
    replacement: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run_path(
        config,
        if position == PathPosition::TrustAnchor {
            replacement
        } else {
            &config.root_base
        },
        if position == PathPosition::Intermediate {
            replacement
        } else {
            &config.intermediate_base
        },
        if position == PathPosition::EndEntity {
            replacement
        } else {
            &config.leaf_base
        },
    )
}

fn run_path(
    config: &ChameleonPathScopeConfig,
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
    config: &ChameleonPathScopeConfig,
    issuer: &Path,
    certificate: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        issuer.to_owned(),
        issuer.to_owned(),
        certificate.to_owned(),
        BouncyCastleMode::CertificateSignature,
        None,
    )
}

fn run_delta(
    config: &ChameleonPathScopeConfig,
    issuer_base: &Path,
    base: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        issuer_base.to_owned(),
        issuer_base.to_owned(),
        base.to_owned(),
        BouncyCastleMode::DeltaSignature,
        None,
    )
}

fn run_crl(
    config: &ChameleonPathScopeConfig,
    issuer: &Path,
    certificate: &Path,
    crl: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        issuer.to_owned(),
        issuer.to_owned(),
        certificate.to_owned(),
        BouncyCastleMode::CrlStatus,
        Some(crl.to_owned()),
    )
}

fn run(
    config: &ChameleonPathScopeConfig,
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

    #[test]
    fn base_path_ignores_delta_evidence_at_every_position() {
        let _guard = crate::adapter_test_lock();
        let controls =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/generated-controls");
        let report = analyze(&ChameleonPathScopeConfig {
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            root_base: controls.join("chameleon-path-root-base.pem"),
            intermediate_base: controls.join("chameleon-path-ica-base.pem"),
            leaf_base: controls.join("chameleon-path-leaf-base.pem"),
            root_delta: controls.join("chameleon-path-root-delta.pem"),
            intermediate_delta: controls.join("chameleon-path-ica-delta.pem"),
            leaf_delta: controls.join("chameleon-path-leaf-delta.pem"),
            invalid_delta_root_base: controls.join("chameleon-path-root-base-bad-delta.pem"),
            invalid_delta_intermediate_base: controls.join("chameleon-path-ica-base-bad-delta.pem"),
            invalid_delta_leaf_base: controls.join("chameleon-path-leaf-base-bad-delta.pem"),
            invalid_base_root: controls.join("chameleon-path-root-base-bad-signature.pem"),
            invalid_base_intermediate: controls.join("chameleon-path-ica-base-bad-signature.pem"),
            invalid_base_leaf: controls.join("chameleon-path-leaf-base-bad-signature.pem"),
            root_base_crl: controls.join("chameleon-path-root-base-crl.pem"),
            intermediate_base_crl: controls.join("chameleon-path-ica-base-crl.pem"),
            root_delta_crl: controls.join("chameleon-path-root-delta-crl.pem"),
            intermediate_delta_crl: controls.join("chameleon-path-ica-delta-crl.pem"),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            policy: Policy::P2RequiredHybrid,
            previous_authentication: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(
            report.base_default_path.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report.delta_path_control.observation.verdict,
            StackVerdict::Accept
        );
        assert!(report.positions.iter().all(|position| {
            position.invalid_delta_signature.observation.verdict == StackVerdict::Reject
                && position.invalid_delta_default_path.observation.verdict == StackVerdict::Accept
                && position.classical_decision_sensitive_for_fixture.state == CheckState::Fail
        }));
        assert!(
            report
                .scopes
                .iter()
                .all(|scope| scope.result.policy_verdict == PolicyVerdict::Reject)
        );
    }
}
