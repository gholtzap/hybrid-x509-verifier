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
pub struct PurePathScopeConfig {
    pub docker: PathBuf,
    pub image: String,
    pub root: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub invalid_root: PathBuf,
    pub invalid_intermediate: PathBuf,
    pub invalid_leaf: PathBuf,
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
pub struct PurePathPositionReport {
    pub position: PathPosition,
    pub validity: CheckResult,
    pub crl_status: AdapterReport,
    pub signature: AdapterReport,
    pub invalid_signature: AdapterReport,
    pub invalid_default_path: AdapterReport,
    pub decision_sensitive_for_fixture: CheckResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PurePathScopeReport {
    pub api_version: String,
    pub valid_default_path: AdapterReport,
    pub positions: Vec<PurePathPositionReport>,
    pub scopes: Vec<ScopedVerificationResult>,
}

#[derive(Debug, Error)]
pub enum PurePathScopeError {
    #[error("all pure path controls must use the pure post-quantum scheme")]
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
    signature: AdapterExecution,
    invalid_signature: AdapterExecution,
    invalid_path: AdapterExecution,
    outcome: CheckResult,
}

pub fn analyze(config: &PurePathScopeConfig) -> Result<PurePathScopeReport, PurePathScopeError> {
    for certificate in [
        &config.root,
        &config.intermediate,
        &config.leaf,
        &config.invalid_root,
        &config.invalid_intermediate,
        &config.invalid_leaf,
    ] {
        if inspect_certificate(certificate, INPUT_LIMIT)?.certificate_signature_scheme
            != AlgorithmSecurity::PostQuantum
        {
            return Err(PurePathScopeError::WrongScheme);
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
        .map(|analysis| CertificateNode {
            id: position_id(analysis.position).to_owned(),
            position: analysis.position,
            subject_public_key_scheme: AlgorithmSecurity::PostQuantum,
            certificate_signature_scheme: AlgorithmSecurity::PostQuantum,
            binding_design: BindingDesign::None,
            der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
        })
        .collect::<Vec<_>>();
    let evidence = analyses
        .iter()
        .map(|analysis| position_evidence(analysis, valid_path.observation.verdict))
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
                    stack: valid_path.observation.clone(),
                    certificate_path: certificate_path.clone(),
                    evidence: evidence.clone(),
                })?,
            })
        })
        .collect::<Result<Vec<_>, OracleError>>()?;
    let positions = analyses
        .into_iter()
        .map(|analysis| {
            Ok(PurePathPositionReport {
                position: analysis.position,
                validity: analysis.validity,
                crl_status: analysis.crl.report()?,
                signature: analysis.signature.report()?,
                invalid_signature: analysis.invalid_signature.report()?,
                invalid_default_path: analysis.invalid_path.report()?,
                decision_sensitive_for_fixture: analysis.outcome,
            })
        })
        .collect::<Result<Vec<_>, AdapterSupportError>>()?;
    Ok(PurePathScopeReport {
        api_version: API_VERSION.to_owned(),
        valid_default_path: valid_path.report()?,
        positions,
        scopes,
    })
}

fn analyze_position(
    config: &PurePathScopeConfig,
    position: PathPosition,
    valid_path: StackVerdict,
) -> Result<PositionAnalysis, PurePathScopeError> {
    let (certificate, issuer, invalid, crl) = match position {
        PathPosition::EndEntity => (
            &config.leaf,
            &config.intermediate,
            &config.invalid_leaf,
            &config.intermediate_crl,
        ),
        PathPosition::Intermediate => (
            &config.intermediate,
            &config.root,
            &config.invalid_intermediate,
            &config.root_crl,
        ),
        PathPosition::TrustAnchor => (
            &config.root,
            &config.root,
            &config.invalid_root,
            &config.root_crl,
        ),
    };
    let signature = run_direct(config, issuer, certificate)?;
    let invalid_signature = run_direct(config, issuer, invalid)?;
    let invalid_path = path_with_replacement(config, position, invalid)?;
    let established = signature.observation.verdict == StackVerdict::Accept
        && invalid_signature.observation.verdict == StackVerdict::Reject;
    let outcome = if valid_path != StackVerdict::Accept || !established {
        behavioral_check(false, CheckState::Indeterminate)
    } else {
        match invalid_path.observation.verdict {
            StackVerdict::Reject => behavioral_check(true, CheckState::Pass),
            StackVerdict::Accept => behavioral_check(true, CheckState::Fail),
            StackVerdict::Indeterminate | StackVerdict::Unsupported => {
                behavioral_check(false, CheckState::Indeterminate)
            }
        }
    };
    Ok(PositionAnalysis {
        position,
        certificate_der_sha256: certificate_der_hash(certificate, INPUT_LIMIT)?,
        issuer_edge_sha256: (position != PathPosition::TrustAnchor)
            .then(|| issuer_edge_hash(certificate, issuer, INPUT_LIMIT))
            .transpose()?,
        validity: check_certificate_validity(certificate, &config.validation_time, INPUT_LIMIT)?,
        crl: run_crl(config, issuer, certificate, crl)?,
        signature,
        invalid_signature,
        invalid_path,
        outcome,
    })
}

fn position_evidence(analysis: &PositionAnalysis, valid_path: StackVerdict) -> Evidence {
    let id = position_id(analysis.position);
    let pass = CheckResult::observed(CheckState::Pass);
    Evidence {
        id: format!("{id}-mldsa-certificate"),
        certificate_id: id.to_owned(),
        position: analysis.position,
        certificate_der_sha256: Some(analysis.certificate_der_sha256.clone()),
        issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
        kind: EvidenceKind::PostQuantum,
        present: pass,
        recognized: pass,
        signature: check_from_verdict(analysis.signature.observation.verdict),
        binding: CheckResult::observed(CheckState::NotApplicable),
        path: check_from_verdict(valid_path),
        validity: analysis.validity,
        revocation: check_from_verdict(analysis.crl.observation.verdict),
        decision_sensitive_for_fixture: analysis.outcome,
    }
}

fn position_id(position: PathPosition) -> &'static str {
    match position {
        PathPosition::EndEntity => "leaf",
        PathPosition::Intermediate => "intermediate",
        PathPosition::TrustAnchor => "root",
    }
}

fn path_with_replacement(
    config: &PurePathScopeConfig,
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
    config: &PurePathScopeConfig,
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
    config: &PurePathScopeConfig,
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

fn run_crl(
    config: &PurePathScopeConfig,
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
    config: &PurePathScopeConfig,
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
    fn pure_pq_path_is_verified_without_being_labeled_hybrid() {
        let _guard = crate::adapter_test_lock();
        let controls =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/generated-controls");
        let report = analyze(&PurePathScopeConfig {
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            root: controls.join("pure-path-root.pem"),
            intermediate: controls.join("pure-path-ica.pem"),
            leaf: controls.join("pure-path-leaf.pem"),
            invalid_root: controls.join("pure-path-root-bad-signature.pem"),
            invalid_intermediate: controls.join("pure-path-ica-bad-signature.pem"),
            invalid_leaf: controls.join("pure-path-leaf-bad-signature.pem"),
            root_crl: controls.join("pure-path-root-crl.pem"),
            intermediate_crl: controls.join("pure-path-ica-crl.pem"),
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
        assert_eq!(
            report.positions[0].decision_sensitive_for_fixture.state,
            CheckState::Pass
        );
        assert_eq!(
            report.positions[1].decision_sensitive_for_fixture.state,
            CheckState::Pass
        );
        assert_eq!(
            report.positions[2].decision_sensitive_for_fixture.state,
            CheckState::Fail
        );
        assert!(
            report
                .scopes
                .iter()
                .all(|scope| scope.result.policy_verdict == PolicyVerdict::Reject)
        );
        assert!(
            report
                .scopes
                .iter()
                .all(|scope| !scope.result.classical_only_fallback)
        );
    }
}
