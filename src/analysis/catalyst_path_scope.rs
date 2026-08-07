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
    mutation::{MutationError, corrupt_outer_signature, encode_certificate_pem},
    pem::{
        CrlStatusResult, PemError, PemKind, check_certificate_validity, check_crl_status,
        inspect_certificate, read_der,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;

const INPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CatalystPathScopeConfig {
    pub docker: PathBuf,
    pub image: String,
    pub root: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub invalid_alternative_root: PathBuf,
    pub invalid_alternative_intermediate: PathBuf,
    pub invalid_alternative_leaf: PathBuf,
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
pub struct CatalystPathPositionReport {
    pub position: PathPosition,
    pub crl_status: CrlStatusResult,
    pub validity: CheckResult,
    pub valid_alternative_signature: AdapterReport,
    pub invalid_alternative_signature: AdapterReport,
    pub invalid_alternative_default_path: AdapterReport,
    pub invalid_classical_default_path: AdapterReport,
    pub classical_decision_sensitive_for_fixture: CheckResult,
    pub post_quantum_decision_sensitive_for_fixture: CheckResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalystPathScopeReport {
    pub api_version: String,
    pub valid_default_path: AdapterReport,
    pub positions: Vec<CatalystPathPositionReport>,
    pub scopes: Vec<ScopedVerificationResult>,
}

#[derive(Debug, Error)]
pub enum CatalystPathScopeError {
    #[error("all path-scope certificates must use the Catalyst scheme")]
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

struct PositionAnalysis {
    position: PathPosition,
    certificate_der_sha256: String,
    issuer_edge_sha256: Option<String>,
    crl_status: CrlStatusResult,
    validity: CheckResult,
    valid_alternative: AdapterExecution,
    invalid_alternative: AdapterExecution,
    invalid_alternative_path: AdapterExecution,
    invalid_classical_path: AdapterExecution,
    classical_outcome: CheckResult,
    post_quantum_outcome: CheckResult,
}

pub fn analyze(
    config: &CatalystPathScopeConfig,
) -> Result<CatalystPathScopeReport, CatalystPathScopeError> {
    for path in [
        &config.root,
        &config.intermediate,
        &config.leaf,
        &config.invalid_alternative_root,
        &config.invalid_alternative_intermediate,
        &config.invalid_alternative_leaf,
    ] {
        if inspect_certificate(path, INPUT_LIMIT)?.binding_design != BindingDesign::Catalyst {
            return Err(CatalystPathScopeError::WrongScheme);
        }
    }

    let valid_path = run_path(config, &config.root, &config.intermediate, &config.leaf)?;
    let analyses = [
        analyze_position(config, PathPosition::EndEntity)?,
        analyze_position(config, PathPosition::Intermediate)?,
        analyze_position(config, PathPosition::TrustAnchor)?,
    ];
    let certificate_path = analyses
        .iter()
        .filter(|analysis| analysis.position != PathPosition::TrustAnchor)
        .map(|analysis| CertificateNode {
            id: position_id(analysis.position).to_owned(),
            position: analysis.position,
            subject_public_key_scheme: AlgorithmSecurity::Classical,
            certificate_signature_scheme: AlgorithmSecurity::Classical,
            binding_design: BindingDesign::Catalyst,
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
            let request = VerificationRequest {
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
            };
            Ok(ScopedVerificationResult {
                scope,
                result: evaluate(&request)?,
            })
        })
        .collect::<Result<Vec<_>, OracleError>>()?;

    let positions = analyses
        .into_iter()
        .map(|analysis| {
            Ok(CatalystPathPositionReport {
                position: analysis.position,
                crl_status: analysis.crl_status,
                validity: analysis.validity,
                valid_alternative_signature: analysis.valid_alternative.report()?,
                invalid_alternative_signature: analysis.invalid_alternative.report()?,
                invalid_alternative_default_path: analysis.invalid_alternative_path.report()?,
                invalid_classical_default_path: analysis.invalid_classical_path.report()?,
                classical_decision_sensitive_for_fixture: analysis.classical_outcome,
                post_quantum_decision_sensitive_for_fixture: analysis.post_quantum_outcome,
            })
        })
        .collect::<Result<Vec<_>, AdapterSupportError>>()?;

    Ok(CatalystPathScopeReport {
        api_version: API_VERSION.to_owned(),
        valid_default_path: valid_path.report()?,
        positions,
        scopes,
    })
}

fn analyze_position(
    config: &CatalystPathScopeConfig,
    position: PathPosition,
) -> Result<PositionAnalysis, CatalystPathScopeError> {
    let (certificate, issuer, crl, invalid_alternative) = match position {
        PathPosition::EndEntity => (
            &config.leaf,
            &config.intermediate,
            &config.intermediate_crl,
            &config.invalid_alternative_leaf,
        ),
        PathPosition::Intermediate => (
            &config.intermediate,
            &config.root,
            &config.root_crl,
            &config.invalid_alternative_intermediate,
        ),
        PathPosition::TrustAnchor => (
            &config.root,
            &config.root,
            &config.root_crl,
            &config.invalid_alternative_root,
        ),
    };
    let valid_alternative = run_direct(config, issuer, certificate)?;
    let invalid_alternative_direct = run_direct(config, issuer, invalid_alternative)?;
    let invalid_alternative_path = path_with_replacement(config, position, invalid_alternative)?;

    let der = read_der(certificate, PemKind::Certificate, INPUT_LIMIT)?;
    let mut invalid_classical_file = tempfile::NamedTempFile::new()?;
    invalid_classical_file
        .write_all(encode_certificate_pem(&corrupt_outer_signature(&der)?).as_bytes())?;
    let invalid_classical_path =
        path_with_replacement(config, position, invalid_classical_file.path())?;

    let direct_controls = valid_alternative.observation.verdict == StackVerdict::Accept
        && invalid_alternative_direct.observation.verdict == StackVerdict::Reject;
    let valid_default = run_path(config, &config.root, &config.intermediate, &config.leaf)?
        .observation
        .verdict;
    let classical_outcome = outcome_check(
        valid_default,
        invalid_classical_path.observation.verdict,
        true,
    );
    let post_quantum_outcome = outcome_check(
        valid_default,
        invalid_alternative_path.observation.verdict,
        direct_controls,
    );

    Ok(PositionAnalysis {
        position,
        certificate_der_sha256: certificate_der_hash(certificate, INPUT_LIMIT)?,
        issuer_edge_sha256: (position != PathPosition::TrustAnchor)
            .then(|| issuer_edge_hash(certificate, issuer, INPUT_LIMIT))
            .transpose()?,
        crl_status: check_crl_status(
            certificate,
            issuer,
            crl,
            &config.validation_time,
            INPUT_LIMIT,
        )?,
        validity: check_certificate_validity(certificate, &config.validation_time, INPUT_LIMIT)?,
        valid_alternative,
        invalid_alternative: invalid_alternative_direct,
        invalid_alternative_path,
        invalid_classical_path,
        classical_outcome,
        post_quantum_outcome,
    })
}

fn outcome_check(
    valid_verdict: StackVerdict,
    invalid_verdict: StackVerdict,
    control_established: bool,
) -> CheckResult {
    if valid_verdict != StackVerdict::Accept || !control_established {
        return behavioral_check(false, CheckState::Indeterminate);
    }
    match invalid_verdict {
        StackVerdict::Reject => behavioral_check(true, CheckState::Pass),
        StackVerdict::Accept => behavioral_check(true, CheckState::Fail),
        StackVerdict::Indeterminate | StackVerdict::Unsupported => {
            behavioral_check(false, CheckState::Indeterminate)
        }
    }
}

fn position_evidence(
    analysis: &PositionAnalysis,
    valid_path_verdict: StackVerdict,
) -> [Evidence; 2] {
    let id = position_id(analysis.position);
    let pass = CheckResult::observed(CheckState::Pass);
    let path = check_from_verdict(valid_path_verdict);
    let alternative = check_from_verdict(analysis.valid_alternative.observation.verdict);
    [
        Evidence {
            id: format!("{id}-classical-signature"),
            certificate_id: id.to_owned(),
            position: analysis.position,
            certificate_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            evidence_artifact_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
            authentication_operation_id: None,
            kind: EvidenceKind::Classical,
            present: pass,
            recognized: pass,
            signature: analysis.crl_status.issuer,
            binding: CheckResult::observed(CheckState::NotApplicable),
            path,
            validity: analysis.validity,
            revocation: analysis.crl_status.revocation,
            revocation_method: crate::RevocationMethod::Crl,
            applied_revocation_policy: crate::RevocationPolicy::crl_hard_fail(),
            decision_sensitive_for_fixture: analysis.classical_outcome,
        },
        Evidence {
            id: format!("{id}-alternative-signature"),
            certificate_id: id.to_owned(),
            position: analysis.position,
            certificate_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            evidence_artifact_der_sha256: Some(analysis.certificate_der_sha256.clone()),
            issuer_edge_sha256: analysis.issuer_edge_sha256.clone(),
            authentication_operation_id: None,
            kind: EvidenceKind::PostQuantum,
            present: pass,
            recognized: pass,
            signature: alternative,
            binding: alternative,
            path: alternative,
            validity: analysis.validity,
            revocation: analysis.crl_status.revocation,
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
    config: &CatalystPathScopeConfig,
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
    config: &CatalystPathScopeConfig,
    root: &Path,
    intermediate: &Path,
    leaf: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        root.to_path_buf(),
        intermediate.to_path_buf(),
        leaf.to_path_buf(),
        BouncyCastleMode::Path,
    )
}

fn run_direct(
    config: &CatalystPathScopeConfig,
    issuer: &Path,
    certificate: &Path,
) -> Result<AdapterExecution, BouncyCastleError> {
    run(
        config,
        config.root.clone(),
        issuer.to_path_buf(),
        certificate.to_path_buf(),
        BouncyCastleMode::AlternativeSignature,
    )
}

fn run(
    config: &CatalystPathScopeConfig,
    root: PathBuf,
    intermediate: PathBuf,
    leaf: PathBuf,
    mode: BouncyCastleMode,
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
        crl: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyVerdict;
    use std::path::Path;

    #[test]
    fn detects_catalyst_fallback_at_every_path_scope() {
        let _guard = crate::adapter_test_lock();
        let controls =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/generated-controls");
        let report = analyze(&CatalystPathScopeConfig {
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            root: controls.join("catalyst-path-root.pem"),
            intermediate: controls.join("catalyst-path-ica.pem"),
            leaf: controls.join("catalyst-path-leaf.pem"),
            invalid_alternative_root: controls.join("catalyst-path-root-bad-alt.pem"),
            invalid_alternative_intermediate: controls.join("catalyst-path-ica-bad-alt.pem"),
            invalid_alternative_leaf: controls.join("catalyst-path-leaf-bad-alt.pem"),
            root_crl: controls.join("catalyst-path-root-crl.pem"),
            intermediate_crl: controls.join("catalyst-path-ica-crl.pem"),
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
        assert!(report.positions.iter().all(|position| {
            position
                .invalid_alternative_default_path
                .observation
                .verdict
                == StackVerdict::Accept
                && position.invalid_alternative_signature.observation.verdict
                    == StackVerdict::Reject
                && position.post_quantum_decision_sensitive_for_fixture.state == CheckState::Fail
        }));
        assert_eq!(
            report.positions[2]
                .classical_decision_sensitive_for_fixture
                .state,
            CheckState::Fail
        );
        assert!(
            report
                .scopes
                .iter()
                .all(|scope| scope.result.policy_verdict == PolicyVerdict::Reject)
        );
    }
}
