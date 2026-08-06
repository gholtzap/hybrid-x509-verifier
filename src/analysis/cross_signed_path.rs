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
        ScopedVerificationResult, atomic_path_scope,
        atomic_path_scope::{AtomicPathScopeConfig, AtomicPathScopeReport},
        behavioral_check, issuer_edge_hash,
    },
    evaluate,
    pem::{PemError, PemKind, check_certificate_validity, read_der},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;

const INPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CrossSignedPathConfig {
    pub controls: PathBuf,
    pub docker: PathBuf,
    pub image: String,
    pub validation_time: String,
    pub policy: Policy,
    pub previous_authentication: Option<AuthenticationLevel>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SelectedRoute {
    Classical,
    Atomic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectedPathReport {
    pub adapter: AdapterReport,
    pub selected_path_sha256: Vec<String>,
    pub route: SelectedRoute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CrossSignedPathReport {
    pub api_version: String,
    pub selected_path: SelectedPathReport,
    pub forced_classical_path: SelectedPathReport,
    pub forced_atomic_path: SelectedPathReport,
    pub classical_fallback_path: SelectedPathReport,
    pub atomic_fallback_path: SelectedPathReport,
    pub invalid_classical_intermediate_path: AdapterReport,
    pub invalid_classical_root_path: AdapterReport,
    pub invalid_classical_leaf_component_paths: Vec<AdapterReport>,
    pub classical_intermediate_signature: AdapterReport,
    pub invalid_classical_intermediate_signature: AdapterReport,
    pub classical_root_signature: AdapterReport,
    pub invalid_classical_root_signature: AdapterReport,
    pub classical_root_crl_status: AdapterReport,
    pub shared_ica_crl_status: AdapterReport,
    pub atomic_route: AtomicPathScopeReport,
    pub selected_scopes: Vec<ScopedVerificationResult>,
    pub classical_fallback_scopes: Vec<ScopedVerificationResult>,
}

#[derive(Debug, Error)]
pub enum CrossSignedPathError {
    #[error("the path-builder output is missing a supported three-certificate selected path")]
    InvalidSelectedPath,
    #[error("the selected path differs from its controlled route")]
    UnexpectedRoute,
    #[error(transparent)]
    BouncyCastle(#[from] BouncyCastleError),
    #[error(transparent)]
    Adapter(#[from] AdapterSupportError),
    #[error(transparent)]
    Atomic(#[from] atomic_path_scope::AtomicPathScopeError),
    #[error(transparent)]
    Pem(#[from] PemError),
    #[error(transparent)]
    Oracle(#[from] OracleError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct BuilderOutput {
    selected_path_sha256: Vec<String>,
}

struct RouteHashes {
    classical_ica: String,
    classical_root: String,
    atomic_ica: String,
    atomic_root: String,
}

pub fn analyze(
    config: &CrossSignedPathConfig,
) -> Result<CrossSignedPathReport, CrossSignedPathError> {
    let path = |name: &str| config.controls.join(name);
    let hashes = RouteHashes {
        classical_ica: certificate_hash(&path("cross-ica-classical.pem"))?,
        classical_root: certificate_hash(&path("cross-root-classical.pem"))?,
        atomic_ica: certificate_hash(&path("cross-ica-atomic.pem"))?,
        atomic_root: certificate_hash(&path("cross-root-atomic.pem"))?,
    };
    let leaf = path("cross-leaf.pem");
    let selected_execution = run_builder(
        config,
        &path("cross-roots.pem"),
        &path("cross-icas.pem"),
        &leaf,
    )?;
    let forced_classical_execution = run_builder(
        config,
        &path("cross-root-classical.pem"),
        &path("cross-icas.pem"),
        &leaf,
    )?;
    let forced_atomic_execution = run_builder(
        config,
        &path("cross-root-atomic.pem"),
        &path("cross-icas.pem"),
        &leaf,
    )?;
    let classical_fallback_execution = run_builder(
        config,
        &path("cross-roots.pem"),
        &path("cross-icas-classical-fallback.pem"),
        &leaf,
    )?;
    let atomic_fallback_execution = run_builder(
        config,
        &path("cross-roots.pem"),
        &path("cross-icas-atomic-fallback.pem"),
        &leaf,
    )?;

    let selected = selected_path(&selected_execution, &hashes)?;
    let forced_classical = selected_path(&forced_classical_execution, &hashes)?;
    let forced_atomic = selected_path(&forced_atomic_execution, &hashes)?;
    let classical_fallback = selected_path(&classical_fallback_execution, &hashes)?;
    let atomic_fallback = selected_path(&atomic_fallback_execution, &hashes)?;
    if forced_classical.route != SelectedRoute::Classical
        || forced_atomic.route != SelectedRoute::Atomic
        || classical_fallback.route != SelectedRoute::Classical
        || atomic_fallback.route != SelectedRoute::Atomic
    {
        return Err(CrossSignedPathError::UnexpectedRoute);
    }

    let invalid_classical_intermediate_path = run_builder(
        config,
        &path("cross-root-classical.pem"),
        &path("cross-ica-classical-bad-signature.pem"),
        &leaf,
    )?;
    let invalid_classical_root_path = run_builder(
        config,
        &path("cross-root-classical-bad-signature.pem"),
        &path("cross-ica-classical.pem"),
        &leaf,
    )?;
    let invalid_leaf_ecdsa_path = run_builder(
        config,
        &path("cross-root-classical.pem"),
        &path("cross-ica-classical.pem"),
        &path("cross-leaf-bad-ecdsa.pem"),
    )?;
    let invalid_leaf_mldsa_path = run_builder(
        config,
        &path("cross-root-classical.pem"),
        &path("cross-ica-classical.pem"),
        &path("cross-leaf-bad-mldsa.pem"),
    )?;
    let classical_intermediate_signature = run_direct(
        config,
        &path("cross-root-classical.pem"),
        &path("cross-ica-classical.pem"),
    )?;
    let invalid_classical_intermediate_signature = run_direct(
        config,
        &path("cross-root-classical.pem"),
        &path("cross-ica-classical-bad-signature.pem"),
    )?;
    let classical_root_signature = run_direct(
        config,
        &path("cross-root-classical.pem"),
        &path("cross-root-classical.pem"),
    )?;
    let invalid_classical_root_signature = run_direct(
        config,
        &path("cross-root-classical.pem"),
        &path("cross-root-classical-bad-signature.pem"),
    )?;
    let classical_root_crl = run_crl(
        config,
        &path("cross-root-classical.pem"),
        &path("cross-ica-classical.pem"),
        &path("cross-root-classical-crl.pem"),
    )?;
    let shared_ica_crl = run_crl(
        config,
        &path("cross-ica-classical.pem"),
        &leaf,
        &path("cross-ica-crl.pem"),
    )?;

    let atomic = atomic_path_scope::analyze(&AtomicPathScopeConfig {
        docker: config.docker.clone(),
        image: config.image.clone(),
        root: path("cross-root-atomic.pem"),
        intermediate: path("cross-ica-atomic.pem"),
        leaf: leaf.clone(),
        invalid_classical_root: path("cross-root-atomic-bad-ecdsa.pem"),
        invalid_post_quantum_root: path("cross-root-atomic-bad-mldsa.pem"),
        invalid_classical_intermediate: path("cross-ica-atomic-bad-ecdsa.pem"),
        invalid_post_quantum_intermediate: path("cross-ica-atomic-bad-mldsa.pem"),
        invalid_classical_leaf: path("cross-leaf-bad-ecdsa.pem"),
        invalid_post_quantum_leaf: path("cross-leaf-bad-mldsa.pem"),
        root_crl: path("cross-root-atomic-crl.pem"),
        intermediate_crl: path("cross-ica-crl.pem"),
        validation_time: config.validation_time.clone(),
        policy: config.policy,
        previous_authentication: config.previous_authentication,
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    })?;

    let atomic_scopes = evaluate_atomic_route(config, &selected_execution, &atomic)?;
    let fallback_scopes = evaluate_classical_route(
        config,
        &classical_fallback_execution,
        &atomic,
        &classical_intermediate_signature,
        &invalid_classical_intermediate_signature,
        &invalid_classical_intermediate_path,
        &classical_root_signature,
        &invalid_classical_root_signature,
        &invalid_classical_root_path,
        &classical_root_crl,
        &shared_ica_crl,
    )?;
    let selected_scopes = match selected.route {
        SelectedRoute::Atomic => atomic_scopes,
        SelectedRoute::Classical => fallback_scopes.clone(),
    };

    Ok(CrossSignedPathReport {
        api_version: API_VERSION.to_owned(),
        selected_path: selected.with_report(selected_execution.report()?),
        forced_classical_path: forced_classical.with_report(forced_classical_execution.report()?),
        forced_atomic_path: forced_atomic.with_report(forced_atomic_execution.report()?),
        classical_fallback_path: classical_fallback
            .with_report(classical_fallback_execution.report()?),
        atomic_fallback_path: atomic_fallback.with_report(atomic_fallback_execution.report()?),
        invalid_classical_intermediate_path: invalid_classical_intermediate_path.report()?,
        invalid_classical_root_path: invalid_classical_root_path.report()?,
        invalid_classical_leaf_component_paths: vec![
            invalid_leaf_ecdsa_path.report()?,
            invalid_leaf_mldsa_path.report()?,
        ],
        classical_intermediate_signature: classical_intermediate_signature.report()?,
        invalid_classical_intermediate_signature: invalid_classical_intermediate_signature
            .report()?,
        classical_root_signature: classical_root_signature.report()?,
        invalid_classical_root_signature: invalid_classical_root_signature.report()?,
        classical_root_crl_status: classical_root_crl.report()?,
        shared_ica_crl_status: shared_ica_crl.report()?,
        atomic_route: atomic,
        selected_scopes,
        classical_fallback_scopes: fallback_scopes,
    })
}

struct SelectedPath {
    selected_path_sha256: Vec<String>,
    route: SelectedRoute,
}

impl SelectedPath {
    fn with_report(self, adapter: AdapterReport) -> SelectedPathReport {
        SelectedPathReport {
            adapter,
            selected_path_sha256: self.selected_path_sha256,
            route: self.route,
        }
    }
}

fn selected_path(
    execution: &AdapterExecution,
    hashes: &RouteHashes,
) -> Result<SelectedPath, CrossSignedPathError> {
    if execution.observation.verdict != StackVerdict::Accept {
        return Err(CrossSignedPathError::InvalidSelectedPath);
    }
    let parsed: BuilderOutput =
        serde_json::from_slice(&execution.verification_output.stdout.bytes)?;
    if parsed.selected_path_sha256.len() != 3 {
        return Err(CrossSignedPathError::InvalidSelectedPath);
    }
    let route = match (
        &parsed.selected_path_sha256[1],
        &parsed.selected_path_sha256[2],
    ) {
        (ica, root) if ica == &hashes.classical_ica && root == &hashes.classical_root => {
            SelectedRoute::Classical
        }
        (ica, root) if ica == &hashes.atomic_ica && root == &hashes.atomic_root => {
            SelectedRoute::Atomic
        }
        _ => return Err(CrossSignedPathError::InvalidSelectedPath),
    };
    Ok(SelectedPath {
        selected_path_sha256: parsed.selected_path_sha256,
        route,
    })
}

fn evaluate_atomic_route(
    config: &CrossSignedPathConfig,
    builder: &AdapterExecution,
    atomic: &AtomicPathScopeReport,
) -> Result<Vec<ScopedVerificationResult>, OracleError> {
    let evidence = atomic.scopes[0].result.evaluated_evidence.clone();
    evaluate_scopes(
        config,
        builder,
        atomic.scopes[0].result.certificate_path.clone(),
        evidence,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_classical_route(
    config: &CrossSignedPathConfig,
    builder: &AdapterExecution,
    atomic: &AtomicPathScopeReport,
    intermediate_signature: &AdapterExecution,
    invalid_intermediate_signature: &AdapterExecution,
    invalid_intermediate_path: &AdapterExecution,
    root_signature: &AdapterExecution,
    invalid_root_signature: &AdapterExecution,
    invalid_root_path: &AdapterExecution,
    root_crl: &AdapterExecution,
    ica_crl: &AdapterExecution,
) -> Result<Vec<ScopedVerificationResult>, CrossSignedPathError> {
    let mut evidence = atomic.scopes[0]
        .result
        .evaluated_evidence
        .iter()
        .filter(|item| item.position == PathPosition::EndEntity)
        .cloned()
        .collect::<Vec<_>>();
    let path = |name: &str| config.controls.join(name);
    let leaf_hash = certificate_hash(&path("cross-leaf.pem"))?;
    let leaf_edge_hash = issuer_edge_hash(
        &path("cross-leaf.pem"),
        &path("cross-ica-classical.pem"),
        INPUT_LIMIT,
    )?;
    let intermediate_hash = certificate_hash(&path("cross-ica-classical.pem"))?;
    let intermediate_edge_hash = issuer_edge_hash(
        &path("cross-ica-classical.pem"),
        &path("cross-root-classical.pem"),
        INPUT_LIMIT,
    )?;
    let root_hash = certificate_hash(&path("cross-root-classical.pem"))?;
    for item in &mut evidence {
        item.path = check_from_verdict(builder.observation.verdict);
        item.revocation = check_from_verdict(ica_crl.observation.verdict);
        item.certificate_der_sha256 = Some(leaf_hash.clone());
        item.issuer_edge_sha256 = Some(leaf_edge_hash.clone());
    }
    let pass = CheckResult::observed(CheckState::Pass);
    let not_applicable = CheckResult::observed(CheckState::NotApplicable);
    let intermediate_outcome = outcome(
        builder.observation.verdict,
        invalid_intermediate_path.observation.verdict,
        intermediate_signature.observation.verdict == StackVerdict::Accept
            && invalid_intermediate_signature.observation.verdict == StackVerdict::Reject,
    );
    let root_outcome = outcome(
        builder.observation.verdict,
        invalid_root_path.observation.verdict,
        root_signature.observation.verdict == StackVerdict::Accept
            && invalid_root_signature.observation.verdict == StackVerdict::Reject,
    );
    evidence.push(Evidence {
        id: "intermediate-ecdsa-signature".to_owned(),
        certificate_id: "intermediate".to_owned(),
        position: PathPosition::Intermediate,
        certificate_der_sha256: Some(intermediate_hash.clone()),
        issuer_edge_sha256: Some(intermediate_edge_hash.clone()),
        kind: EvidenceKind::Classical,
        present: pass,
        recognized: pass,
        signature: check_from_verdict(intermediate_signature.observation.verdict),
        binding: not_applicable,
        path: check_from_verdict(builder.observation.verdict),
        validity: check_certificate_validity(
            &config.controls.join("cross-ica-classical.pem"),
            &config.validation_time,
            INPUT_LIMIT,
        )?,
        revocation: check_from_verdict(root_crl.observation.verdict),
        decision_sensitive_for_fixture: intermediate_outcome,
    });
    evidence.push(Evidence {
        id: "root-ecdsa-signature".to_owned(),
        certificate_id: "root".to_owned(),
        position: PathPosition::TrustAnchor,
        certificate_der_sha256: Some(root_hash.clone()),
        issuer_edge_sha256: None,
        kind: EvidenceKind::Classical,
        present: pass,
        recognized: pass,
        signature: check_from_verdict(root_signature.observation.verdict),
        binding: not_applicable,
        path: check_from_verdict(builder.observation.verdict),
        validity: check_certificate_validity(
            &config.controls.join("cross-root-classical.pem"),
            &config.validation_time,
            INPUT_LIMIT,
        )?,
        revocation: check_from_verdict(root_crl.observation.verdict),
        decision_sensitive_for_fixture: root_outcome,
    });
    Ok(evaluate_scopes(
        config,
        builder,
        vec![
            node(
                "leaf",
                PathPosition::EndEntity,
                AlgorithmSecurity::Classical,
                AlgorithmSecurity::Hybrid,
                BindingDesign::AtomicComposite,
                Some(leaf_hash),
                Some(leaf_edge_hash),
            ),
            node(
                "intermediate",
                PathPosition::Intermediate,
                AlgorithmSecurity::Classical,
                AlgorithmSecurity::Classical,
                BindingDesign::None,
                Some(intermediate_hash),
                Some(intermediate_edge_hash),
            ),
            node(
                "root",
                PathPosition::TrustAnchor,
                AlgorithmSecurity::Classical,
                AlgorithmSecurity::Classical,
                BindingDesign::None,
                Some(root_hash),
                None,
            ),
        ],
        evidence,
    )?)
}

fn evaluate_scopes(
    config: &CrossSignedPathConfig,
    builder: &AdapterExecution,
    certificate_path: Vec<CertificateNode>,
    evidence: Vec<Evidence>,
) -> Result<Vec<ScopedVerificationResult>, OracleError> {
    [PathScope::EndEntity, PathScope::CertificationPath]
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
                    stack: builder.observation.clone(),
                    certificate_path: certificate_path.clone(),
                    evidence: evidence.clone(),
                })?,
            })
        })
        .collect()
}

fn node(
    id: &str,
    position: PathPosition,
    subject_public_key_scheme: AlgorithmSecurity,
    certificate_signature_scheme: AlgorithmSecurity,
    binding_design: BindingDesign,
    der_sha256: Option<String>,
    issuer_edge_sha256: Option<String>,
) -> CertificateNode {
    CertificateNode {
        id: id.to_owned(),
        position,
        subject_public_key_scheme,
        certificate_signature_scheme,
        binding_design,
        der_sha256,
        issuer_edge_sha256,
    }
}

fn outcome(valid: StackVerdict, invalid: StackVerdict, direct: bool) -> CheckResult {
    if valid != StackVerdict::Accept || !direct {
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

fn certificate_hash(path: &Path) -> Result<String, PemError> {
    let bytes = read_der(path, PemKind::Certificate, INPUT_LIMIT)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn run_builder(
    config: &CrossSignedPathConfig,
    roots: &Path,
    intermediates: &Path,
    leaf: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        roots,
        intermediates,
        leaf,
        BouncyCastleMode::PathBuilder,
        None,
    )
}

fn run_direct(
    config: &CrossSignedPathConfig,
    issuer: &Path,
    certificate: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        issuer,
        issuer,
        certificate,
        BouncyCastleMode::CertificateSignature,
        None,
    )
}

fn run_crl(
    config: &CrossSignedPathConfig,
    issuer: &Path,
    certificate: &Path,
    crl: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        issuer,
        issuer,
        certificate,
        BouncyCastleMode::CrlStatus,
        Some(crl.to_owned()),
    )
}

fn run(
    config: &CrossSignedPathConfig,
    root: &Path,
    intermediate: &Path,
    leaf: &Path,
    mode: BouncyCastleMode,
    crl: Option<PathBuf>,
) -> Result<AdapterExecution, BouncyCastleError> {
    verify_bouncy_castle(&BouncyCastleConfig {
        docker: config.docker.clone(),
        image: config.image.clone(),
        trust_store: root.to_owned(),
        intermediate: intermediate.to_owned(),
        leaf: leaf.to_owned(),
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
    fn builder_records_atomic_selection_and_detects_classical_fallback() {
        let _guard = crate::adapter_test_lock();
        let report = analyze(&CrossSignedPathConfig {
            controls: Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/generated-controls"),
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            policy: Policy::P2RequiredHybrid,
            previous_authentication: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(report.selected_path.route, SelectedRoute::Atomic);
        assert_eq!(
            report.selected_scopes[1].result.policy_verdict,
            PolicyVerdict::HybridClaimSetSatisfied
        );
        assert_eq!(
            report.classical_fallback_scopes[1].result.policy_verdict,
            PolicyVerdict::Reject
        );
        assert!(
            report.classical_fallback_scopes[1]
                .result
                .classical_only_fallback
        );
        assert_eq!(
            report
                .invalid_classical_intermediate_path
                .observation
                .verdict,
            StackVerdict::Reject
        );
        assert_eq!(
            report.invalid_classical_root_path.observation.verdict,
            StackVerdict::Accept
        );
    }
}
