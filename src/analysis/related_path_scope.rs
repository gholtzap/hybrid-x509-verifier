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
        related_conformance_check,
    },
    evaluate,
    pem::{
        PemError, RelatedBindingResult, RelatedConformanceResult, check_certificate_validity,
        inspect_certificate, verify_related_binding, verify_related_certificate_conformance,
    },
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
pub struct RelatedPathScopeConfig {
    pub docker: PathBuf,
    pub image: String,
    pub classical_root: PathBuf,
    pub classical_intermediate: PathBuf,
    pub classical_leaf: PathBuf,
    pub post_quantum_root: PathBuf,
    pub post_quantum_intermediate: PathBuf,
    pub post_quantum_leaf: PathBuf,
    pub invalid_binding_root: PathBuf,
    pub invalid_binding_intermediate: PathBuf,
    pub invalid_binding_leaf: PathBuf,
    pub invalid_classical_root: PathBuf,
    pub invalid_classical_intermediate: PathBuf,
    pub invalid_classical_leaf: PathBuf,
    pub invalid_post_quantum_root: PathBuf,
    pub invalid_post_quantum_intermediate: PathBuf,
    pub invalid_post_quantum_leaf: PathBuf,
    pub classical_root_crl: PathBuf,
    pub classical_intermediate_crl: PathBuf,
    pub post_quantum_root_crl: PathBuf,
    pub post_quantum_intermediate_crl: PathBuf,
    pub validation_time: String,
    pub policy: Policy,
    pub previous_authentication: Option<AuthenticationLevel>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelatedPathPositionReport {
    pub position: PathPosition,
    pub conformance: RelatedConformanceResult,
    pub binding: RelatedBindingResult,
    pub invalid_binding: RelatedBindingResult,
    pub classical_validity: CheckResult,
    pub post_quantum_validity: CheckResult,
    pub classical_crl_status: AdapterReport,
    pub post_quantum_crl_status: AdapterReport,
    pub classical_signature: AdapterReport,
    pub invalid_classical_signature: AdapterReport,
    pub post_quantum_signature: AdapterReport,
    pub invalid_post_quantum_signature: AdapterReport,
    pub invalid_classical_default_path: AdapterReport,
    pub invalid_binding_default_path: AdapterReport,
    pub invalid_post_quantum_path: AdapterReport,
    pub classical_decision_sensitive_for_fixture: CheckResult,
    pub post_quantum_decision_sensitive_for_fixture: CheckResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelatedPathScopeReport {
    pub api_version: String,
    pub classical_default_path: AdapterReport,
    pub post_quantum_path_control: AdapterReport,
    pub positions: Vec<RelatedPathPositionReport>,
    pub scopes: Vec<ScopedVerificationResult>,
}

#[derive(Debug, Error)]
pub enum RelatedPathScopeError {
    #[error("the classical controls must use Related and the paired controls must use pure PQ")]
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
    conformance: RelatedConformanceResult,
    binding: RelatedBindingResult,
    invalid_binding: RelatedBindingResult,
    classical_validity: CheckResult,
    post_quantum_validity: CheckResult,
    classical_crl: AdapterExecution,
    post_quantum_crl: AdapterExecution,
    classical_signature: AdapterExecution,
    invalid_classical_signature: AdapterExecution,
    post_quantum_signature: AdapterExecution,
    invalid_post_quantum_signature: AdapterExecution,
    invalid_classical_path: AdapterExecution,
    invalid_binding_path: AdapterExecution,
    invalid_post_quantum_path: AdapterExecution,
    classical_outcome: CheckResult,
    post_quantum_outcome: CheckResult,
}

pub fn analyze(
    config: &RelatedPathScopeConfig,
) -> Result<RelatedPathScopeReport, RelatedPathScopeError> {
    for certificate in [
        &config.classical_root,
        &config.classical_intermediate,
        &config.classical_leaf,
        &config.invalid_binding_root,
        &config.invalid_binding_intermediate,
        &config.invalid_binding_leaf,
        &config.invalid_classical_root,
        &config.invalid_classical_intermediate,
        &config.invalid_classical_leaf,
    ] {
        if inspect_certificate(certificate, INPUT_LIMIT)?.binding_design
            != BindingDesign::RelatedCertificate
        {
            return Err(RelatedPathScopeError::WrongScheme);
        }
    }
    for certificate in [
        &config.post_quantum_root,
        &config.post_quantum_intermediate,
        &config.post_quantum_leaf,
        &config.invalid_post_quantum_root,
        &config.invalid_post_quantum_intermediate,
        &config.invalid_post_quantum_leaf,
    ] {
        if inspect_certificate(certificate, INPUT_LIMIT)?.subject_public_key_scheme
            != AlgorithmSecurity::PostQuantum
        {
            return Err(RelatedPathScopeError::WrongScheme);
        }
    }

    let classical_path = run_classical_path(
        config,
        &config.classical_root,
        &config.classical_intermediate,
        &config.classical_leaf,
    )?;
    let post_quantum_path = run_post_quantum_path(
        config,
        &config.post_quantum_root,
        &config.post_quantum_intermediate,
        &config.post_quantum_leaf,
    )?;
    let analyses = [
        analyze_position(
            config,
            PathPosition::EndEntity,
            classical_path.observation.verdict,
        )?,
        analyze_position(
            config,
            PathPosition::Intermediate,
            classical_path.observation.verdict,
        )?,
        analyze_position(
            config,
            PathPosition::TrustAnchor,
            classical_path.observation.verdict,
        )?,
    ];
    let certificate_path = analyses
        .iter()
        .map(|analysis| CertificateNode {
            id: position_id(analysis.position).to_owned(),
            position: analysis.position,
            subject_public_key_scheme: AlgorithmSecurity::Classical,
            certificate_signature_scheme: AlgorithmSecurity::Classical,
            binding_design: BindingDesign::RelatedCertificate,
            der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
        })
        .collect::<Vec<_>>();
    let evidence = analyses
        .iter()
        .flat_map(|analysis| {
            position_evidence(
                analysis,
                classical_path.observation.verdict,
                post_quantum_path.observation.verdict,
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
                    stack: classical_path.observation.clone(),
                    certificate_path: certificate_path.clone(),
                    evidence: evidence.clone(),
                })?,
            })
        })
        .collect::<Result<Vec<_>, OracleError>>()?;
    let positions = analyses
        .into_iter()
        .map(|analysis| {
            Ok(RelatedPathPositionReport {
                position: analysis.position,
                conformance: analysis.conformance,
                binding: analysis.binding,
                invalid_binding: analysis.invalid_binding,
                classical_validity: analysis.classical_validity,
                post_quantum_validity: analysis.post_quantum_validity,
                classical_crl_status: analysis.classical_crl.report()?,
                post_quantum_crl_status: analysis.post_quantum_crl.report()?,
                classical_signature: analysis.classical_signature.report()?,
                invalid_classical_signature: analysis.invalid_classical_signature.report()?,
                post_quantum_signature: analysis.post_quantum_signature.report()?,
                invalid_post_quantum_signature: analysis.invalid_post_quantum_signature.report()?,
                invalid_classical_default_path: analysis.invalid_classical_path.report()?,
                invalid_binding_default_path: analysis.invalid_binding_path.report()?,
                invalid_post_quantum_path: analysis.invalid_post_quantum_path.report()?,
                classical_decision_sensitive_for_fixture: analysis.classical_outcome,
                post_quantum_decision_sensitive_for_fixture: analysis.post_quantum_outcome,
            })
        })
        .collect::<Result<Vec<_>, AdapterSupportError>>()?;

    Ok(RelatedPathScopeReport {
        api_version: API_VERSION.to_owned(),
        classical_default_path: classical_path.report()?,
        post_quantum_path_control: post_quantum_path.report()?,
        positions,
        scopes,
    })
}

fn analyze_position(
    config: &RelatedPathScopeConfig,
    position: PathPosition,
    classical_valid: StackVerdict,
) -> Result<PositionAnalysis, RelatedPathScopeError> {
    let inputs = position_inputs(config, position);
    let conformance =
        verify_related_certificate_conformance(inputs.classical, inputs.post_quantum, INPUT_LIMIT)?;
    let binding = conformance.rfc9763.binding.clone();
    let invalid_binding =
        verify_related_binding(inputs.invalid_binding, inputs.post_quantum, INPUT_LIMIT)?;
    let classical_signature = run_direct(config, inputs.classical_issuer, inputs.classical)?;
    let invalid_classical_signature =
        run_direct(config, inputs.classical_issuer, inputs.invalid_classical)?;
    let post_quantum_signature =
        run_direct(config, inputs.post_quantum_issuer, inputs.post_quantum)?;
    let invalid_post_quantum_signature = run_direct(
        config,
        inputs.post_quantum_issuer,
        inputs.invalid_post_quantum,
    )?;
    let invalid_classical_path =
        classical_path_with_replacement(config, position, inputs.invalid_classical)?;
    let invalid_binding_path =
        classical_path_with_replacement(config, position, inputs.invalid_binding)?;
    let invalid_post_quantum_path =
        post_quantum_path_with_replacement(config, position, inputs.invalid_post_quantum)?;
    let classical_outcome = outcome_check(
        classical_valid,
        invalid_classical_path.observation.verdict,
        classical_signature.observation.verdict == StackVerdict::Accept
            && invalid_classical_signature.observation.verdict == StackVerdict::Reject,
    );
    let conformance_check = related_conformance_check(&conformance);
    let post_quantum_controls = conformance_check.state == CheckState::Pass
        && invalid_binding.check.state == CheckState::Fail
        && invalid_binding_path.observation.verdict == StackVerdict::Accept
        && post_quantum_signature.observation.verdict == StackVerdict::Accept
        && invalid_post_quantum_signature.observation.verdict == StackVerdict::Reject;

    Ok(PositionAnalysis {
        position,
        certificate_der_sha256: certificate_der_hash(inputs.classical, INPUT_LIMIT)?,
        issuer_edge_sha256: (position != PathPosition::TrustAnchor)
            .then(|| issuer_edge_hash(inputs.classical, inputs.classical_issuer, INPUT_LIMIT))
            .transpose()?,
        conformance,
        binding,
        invalid_binding,
        classical_validity: check_certificate_validity(
            inputs.classical,
            &config.validation_time,
            INPUT_LIMIT,
        )?,
        post_quantum_validity: check_certificate_validity(
            inputs.post_quantum,
            &config.validation_time,
            INPUT_LIMIT,
        )?,
        classical_crl: run_crl(
            config,
            inputs.classical_issuer,
            inputs.classical,
            inputs.classical_crl,
        )?,
        post_quantum_crl: run_crl(
            config,
            inputs.post_quantum_issuer,
            inputs.post_quantum,
            inputs.post_quantum_crl,
        )?,
        classical_signature,
        invalid_classical_signature,
        post_quantum_signature,
        invalid_post_quantum_signature,
        invalid_classical_path,
        invalid_binding_path,
        invalid_post_quantum_path,
        classical_outcome,
        post_quantum_outcome: behavioral_check(
            classical_valid == StackVerdict::Accept && post_quantum_controls,
            CheckState::Fail,
        ),
    })
}

struct PositionInputs<'a> {
    classical: &'a Path,
    post_quantum: &'a Path,
    invalid_binding: &'a Path,
    invalid_classical: &'a Path,
    invalid_post_quantum: &'a Path,
    classical_issuer: &'a Path,
    post_quantum_issuer: &'a Path,
    classical_crl: &'a Path,
    post_quantum_crl: &'a Path,
}

fn position_inputs(config: &RelatedPathScopeConfig, position: PathPosition) -> PositionInputs<'_> {
    match position {
        PathPosition::EndEntity => PositionInputs {
            classical: &config.classical_leaf,
            post_quantum: &config.post_quantum_leaf,
            invalid_binding: &config.invalid_binding_leaf,
            invalid_classical: &config.invalid_classical_leaf,
            invalid_post_quantum: &config.invalid_post_quantum_leaf,
            classical_issuer: &config.classical_intermediate,
            post_quantum_issuer: &config.post_quantum_intermediate,
            classical_crl: &config.classical_intermediate_crl,
            post_quantum_crl: &config.post_quantum_intermediate_crl,
        },
        PathPosition::Intermediate => PositionInputs {
            classical: &config.classical_intermediate,
            post_quantum: &config.post_quantum_intermediate,
            invalid_binding: &config.invalid_binding_intermediate,
            invalid_classical: &config.invalid_classical_intermediate,
            invalid_post_quantum: &config.invalid_post_quantum_intermediate,
            classical_issuer: &config.classical_root,
            post_quantum_issuer: &config.post_quantum_root,
            classical_crl: &config.classical_root_crl,
            post_quantum_crl: &config.post_quantum_root_crl,
        },
        PathPosition::TrustAnchor => PositionInputs {
            classical: &config.classical_root,
            post_quantum: &config.post_quantum_root,
            invalid_binding: &config.invalid_binding_root,
            invalid_classical: &config.invalid_classical_root,
            invalid_post_quantum: &config.invalid_post_quantum_root,
            classical_issuer: &config.classical_root,
            post_quantum_issuer: &config.post_quantum_root,
            classical_crl: &config.classical_root_crl,
            post_quantum_crl: &config.post_quantum_root_crl,
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
    classical_path: StackVerdict,
    post_quantum_path: StackVerdict,
) -> [Evidence; 2] {
    let id = position_id(analysis.position);
    let pass = CheckResult::observed(CheckState::Pass);
    [
        Evidence {
            id: format!("{id}-classical-certificate"),
            certificate_id: id.to_owned(),
            position: analysis.position,
            certificate_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
            kind: EvidenceKind::Classical,
            present: pass,
            recognized: pass,
            signature: check_from_verdict(analysis.classical_signature.observation.verdict),
            binding: CheckResult::observed(CheckState::NotApplicable),
            path: check_from_verdict(classical_path),
            validity: analysis.classical_validity,
            revocation: check_from_verdict(analysis.classical_crl.observation.verdict),
            decision_sensitive_for_fixture: analysis.classical_outcome,
        },
        Evidence {
            id: format!("{id}-post-quantum-certificate"),
            certificate_id: id.to_owned(),
            position: analysis.position,
            certificate_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
            kind: EvidenceKind::PostQuantum,
            present: pass,
            recognized: pass,
            signature: check_from_verdict(analysis.post_quantum_signature.observation.verdict),
            binding: related_conformance_check(&analysis.conformance),
            path: check_from_verdict(post_quantum_path),
            validity: analysis.post_quantum_validity,
            revocation: check_from_verdict(analysis.post_quantum_crl.observation.verdict),
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

fn classical_path_with_replacement(
    config: &RelatedPathScopeConfig,
    position: PathPosition,
    replacement: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run_classical_path(
        config,
        if position == PathPosition::TrustAnchor {
            replacement
        } else {
            &config.classical_root
        },
        if position == PathPosition::Intermediate {
            replacement
        } else {
            &config.classical_intermediate
        },
        if position == PathPosition::EndEntity {
            replacement
        } else {
            &config.classical_leaf
        },
    )
}

fn post_quantum_path_with_replacement(
    config: &RelatedPathScopeConfig,
    position: PathPosition,
    replacement: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run_post_quantum_path(
        config,
        if position == PathPosition::TrustAnchor {
            replacement
        } else {
            &config.post_quantum_root
        },
        if position == PathPosition::Intermediate {
            replacement
        } else {
            &config.post_quantum_intermediate
        },
        if position == PathPosition::EndEntity {
            replacement
        } else {
            &config.post_quantum_leaf
        },
    )
}

fn run_classical_path(
    config: &RelatedPathScopeConfig,
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

fn run_post_quantum_path(
    config: &RelatedPathScopeConfig,
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
    config: &RelatedPathScopeConfig,
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
    config: &RelatedPathScopeConfig,
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
    config: &RelatedPathScopeConfig,
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
    fn separate_related_paths_do_not_make_pq_evidence_decisive() {
        let _guard = crate::adapter_test_lock();
        let controls =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/generated-controls");
        let report = analyze(&RelatedPathScopeConfig {
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            classical_root: controls.join("related-path-root-a.pem"),
            classical_intermediate: controls.join("related-path-ica-a.pem"),
            classical_leaf: controls.join("related-path-leaf-a.pem"),
            post_quantum_root: controls.join("related-path-root-b.pem"),
            post_quantum_intermediate: controls.join("related-path-ica-b.pem"),
            post_quantum_leaf: controls.join("related-path-leaf-b.pem"),
            invalid_binding_root: controls.join("related-path-root-a-bad-binding.pem"),
            invalid_binding_intermediate: controls.join("related-path-ica-a-bad-binding.pem"),
            invalid_binding_leaf: controls.join("related-path-leaf-a-bad-binding.pem"),
            invalid_classical_root: controls.join("related-path-root-a-bad-signature.pem"),
            invalid_classical_intermediate: controls.join("related-path-ica-a-bad-signature.pem"),
            invalid_classical_leaf: controls.join("related-path-leaf-a-bad-signature.pem"),
            invalid_post_quantum_root: controls.join("related-path-root-b-bad-signature.pem"),
            invalid_post_quantum_intermediate: controls
                .join("related-path-ica-b-bad-signature.pem"),
            invalid_post_quantum_leaf: controls.join("related-path-leaf-b-bad-signature.pem"),
            classical_root_crl: controls.join("related-path-root-a-crl.pem"),
            classical_intermediate_crl: controls.join("related-path-ica-a-crl.pem"),
            post_quantum_root_crl: controls.join("related-path-root-b-crl.pem"),
            post_quantum_intermediate_crl: controls.join("related-path-ica-b-crl.pem"),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            policy: Policy::P2RequiredHybrid,
            previous_authentication: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(
            report.classical_default_path.observation.verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            report.post_quantum_path_control.observation.verdict,
            StackVerdict::Accept
        );
        assert!(report.positions.iter().all(|position| {
            position.binding.check.state == CheckState::Pass
                && position.invalid_binding.check.state == CheckState::Fail
                && related_conformance_check(&position.conformance).state == CheckState::Fail
                && position.post_quantum_decision_sensitive_for_fixture.state
                    == CheckState::Indeterminate
        }));
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
                .all(|scope| scope.result.classical_only_fallback)
        );
    }
}
