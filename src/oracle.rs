use crate::model::{
    API_VERSION, CheckState, Evidence, EvidenceKind, FailedCheck, Policy, PolicyVerdict, Scheme,
    StackVerdict, VerificationRequest, VerificationResult,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OracleError {
    #[error("unsupported API version: {0}")]
    UnsupportedApiVersion(String),
    #[error("evidence identifiers must be unique: {0}")]
    DuplicateEvidenceId(String),
    #[error("certificate identifiers must be unique: {0}")]
    DuplicateCertificateId(String),
    #[error("the certificate path must contain exactly one end-entity certificate")]
    InvalidEndEntityCount,
    #[error("validation_time must be an RFC 3339 timestamp: {0}")]
    InvalidValidationTime(String),
    #[error("evidence {evidence_id} refers to unknown certificate {certificate_id}")]
    UnknownCertificate {
        evidence_id: String,
        certificate_id: String,
    },
    #[error(
        "evidence {evidence_id} has a path position that differs from certificate {certificate_id}"
    )]
    PositionMismatch {
        evidence_id: String,
        certificate_id: String,
    },
}

pub fn evaluate(request: &VerificationRequest) -> Result<VerificationResult, OracleError> {
    validate_request(request)?;

    let certificates: Vec<_> = request
        .certificate_path
        .iter()
        .filter(|certificate| request.path_scope.includes(certificate.position))
        .collect();
    if certificates
        .iter()
        .any(|certificate| certificate.scheme == Scheme::Unknown)
        || request.stack.verdict == StackVerdict::Unsupported
    {
        return Ok(result(
            request,
            PolicyVerdict::Unsupported,
            false,
            false,
            Vec::new(),
            "The certificate scheme or validation stack is unsupported.",
        ));
    }

    let in_scope: Vec<&Evidence> = request
        .evidence
        .iter()
        .filter(|item| request.path_scope.includes(item.position))
        .collect();
    let classical: Vec<&Evidence> = in_scope
        .iter()
        .copied()
        .filter(|item| item.kind == EvidenceKind::Classical)
        .collect();
    let post_quantum: Vec<&Evidence> = in_scope
        .iter()
        .copied()
        .filter(|item| item.kind == EvidenceKind::PostQuantum)
        .collect();

    let classical_required: Vec<_> = certificates
        .iter()
        .copied()
        .filter(|certificate| certificate.scheme.requires_classical())
        .collect();
    let pq_required: Vec<_> = certificates
        .iter()
        .copied()
        .filter(|certificate| certificate.scheme.requires_post_quantum())
        .collect();
    let classical_state = evidence_state(&classical_required, &classical);
    let pq_state = evidence_state(&pq_required, &post_quantum);
    let classical_ok = classical_state == AggregateState::Pass;
    let pq_ok = pq_state == AggregateState::Pass;
    let has_classical_requirement = !classical_required.is_empty();
    let stack_state = match request.stack.verdict {
        StackVerdict::Accept => required_check_state(request.stack.validation_time, false),
        StackVerdict::Reject => AggregateState::Fail,
        StackVerdict::Indeterminate => AggregateState::Indeterminate,
        StackVerdict::Unsupported => unreachable!("unsupported stacks return before evaluation"),
    };
    let stack_accepted = stack_state == AggregateState::Pass;
    let all_hybrid = certificates
        .iter()
        .all(|certificate| certificate.scheme.is_hybrid());
    let fallback =
        stack_accepted && !classical_required.is_empty() && classical_ok && (!pq_ok || !all_hybrid);
    let lifecycle_desynchronization = fallback
        && post_quantum.iter().any(|item| {
            item.validity.state == CheckState::Fail || item.revocation.state == CheckState::Fail
        });

    let (verdict, reason) = match request.policy {
        Policy::P0Classical => match classical_state {
            AggregateState::Pass if stack_accepted && has_classical_requirement => (
                PolicyVerdict::AcceptClassical,
                "The classical evidence passed under policy P0.",
            ),
            AggregateState::Indeterminate => (
                PolicyVerdict::Indeterminate,
                "The classical evidence is incomplete or indeterminate.",
            ),
            AggregateState::Pass
                if has_classical_requirement && stack_state == AggregateState::Indeterminate =>
            {
                (
                    PolicyVerdict::Indeterminate,
                    "The validation stack result or validation time is indeterminate.",
                )
            }
            _ => (
                PolicyVerdict::Reject,
                "The classical evidence did not pass.",
            ),
        },
        Policy::P1OptionalHybrid => {
            if stack_accepted && all_hybrid && classical_ok && pq_ok {
                (
                    PolicyVerdict::AcceptHybrid,
                    "The classical and post-quantum evidence passed under policy P1.",
                )
            } else if stack_accepted && has_classical_requirement && classical_ok {
                (
                    PolicyVerdict::AcceptClassical,
                    "Only the classical evidence passed under policy P1.",
                )
            } else if !has_classical_requirement || classical_state == AggregateState::Fail {
                (
                    PolicyVerdict::Reject,
                    "The classical evidence did not pass.",
                )
            } else if classical_state == AggregateState::Indeterminate
                || stack_state == AggregateState::Indeterminate
            {
                (
                    PolicyVerdict::Indeterminate,
                    "The classical evidence is incomplete or indeterminate.",
                )
            } else {
                (
                    PolicyVerdict::Reject,
                    "The classical evidence did not pass.",
                )
            }
        }
        Policy::P2RequiredHybrid => {
            if stack_accepted && all_hybrid && classical_ok && pq_ok {
                (
                    PolicyVerdict::AcceptHybrid,
                    "All required classical and post-quantum evidence passed.",
                )
            } else if fallback && pq_state == AggregateState::Fail {
                (
                    PolicyVerdict::Reject,
                    "The stack accepted through classical evidence without valid, outcome-bearing post-quantum evidence.",
                )
            } else if !all_hybrid
                || classical_state == AggregateState::Fail
                || pq_state == AggregateState::Fail
                || stack_state == AggregateState::Fail
            {
                (
                    PolicyVerdict::Reject,
                    "Required classical or post-quantum evidence did not pass.",
                )
            } else if classical_state == AggregateState::Indeterminate
                || pq_state == AggregateState::Indeterminate
                || stack_state == AggregateState::Indeterminate
            {
                (
                    PolicyVerdict::Indeterminate,
                    "Required evidence is incomplete or indeterminate.",
                )
            } else {
                unreachable!("all P2 aggregate states are covered")
            }
        }
        Policy::P3Continuity => match request.previous_authentication {
            Some(crate::model::AuthenticationLevel::Hybrid) => {
                if stack_accepted && all_hybrid && classical_ok && pq_ok {
                    (
                        PolicyVerdict::AcceptHybrid,
                        "Hybrid authentication continuity was preserved.",
                    )
                } else if !all_hybrid
                    || classical_state == AggregateState::Fail
                    || pq_state == AggregateState::Fail
                    || stack_state == AggregateState::Fail
                {
                    (
                        PolicyVerdict::Reject,
                        "The current authentication would downgrade a previous hybrid authentication.",
                    )
                } else if classical_state == AggregateState::Indeterminate
                    || pq_state == AggregateState::Indeterminate
                    || stack_state == AggregateState::Indeterminate
                {
                    (
                        PolicyVerdict::Indeterminate,
                        "Hybrid authentication continuity could not be established.",
                    )
                } else {
                    unreachable!("all P3 hybrid aggregate states are covered")
                }
            }
            Some(crate::model::AuthenticationLevel::Classical) => {
                if stack_accepted && all_hybrid && classical_ok && pq_ok {
                    (
                        PolicyVerdict::AcceptHybrid,
                        "Authentication advanced from classical to hybrid.",
                    )
                } else if stack_accepted && has_classical_requirement && classical_ok {
                    (
                        PolicyVerdict::AcceptClassical,
                        "Classical authentication continuity was preserved.",
                    )
                } else if !has_classical_requirement || classical_state == AggregateState::Fail {
                    (
                        PolicyVerdict::Reject,
                        "The classical authentication did not pass.",
                    )
                } else if classical_state == AggregateState::Indeterminate
                    || stack_state == AggregateState::Indeterminate
                {
                    (
                        PolicyVerdict::Indeterminate,
                        "Classical authentication continuity could not be established.",
                    )
                } else {
                    unreachable!("all P3 classical aggregate states are covered")
                }
            }
            None => (
                PolicyVerdict::Indeterminate,
                "Policy P3 requires a previous authentication level.",
            ),
        },
    };

    let mut failed_checks: Vec<_> = in_scope
        .into_iter()
        .flat_map(|item| {
            item.checks()
                .into_iter()
                .filter(|(_, check)| {
                    check.state != CheckState::NotApplicable
                        && (check.state != CheckState::Pass
                            || matches!(
                                check.confidence,
                                crate::model::Confidence::Inferred
                                    | crate::model::Confidence::Unknown
                            ))
                })
                .map(|(check, result)| FailedCheck {
                    evidence_id: item.id.clone(),
                    check: check.to_owned(),
                    state: result.state,
                    confidence: result.confidence,
                })
        })
        .collect();
    add_missing_evidence_checks(
        &mut failed_checks,
        &classical_required,
        &classical,
        EvidenceKind::Classical,
    );
    add_missing_evidence_checks(
        &mut failed_checks,
        &pq_required,
        &post_quantum,
        EvidenceKind::PostQuantum,
    );

    Ok(result(
        request,
        verdict,
        fallback,
        lifecycle_desynchronization,
        failed_checks,
        reason,
    ))
}

fn validate_request(request: &VerificationRequest) -> Result<(), OracleError> {
    if request.api_version != API_VERSION {
        return Err(OracleError::UnsupportedApiVersion(
            request.api_version.clone(),
        ));
    }
    if chrono::DateTime::parse_from_rfc3339(&request.validation_time).is_err() {
        return Err(OracleError::InvalidValidationTime(
            request.validation_time.clone(),
        ));
    }

    let mut ids = std::collections::HashSet::new();
    for item in &request.evidence {
        if !ids.insert(&item.id) {
            return Err(OracleError::DuplicateEvidenceId(item.id.clone()));
        }
    }

    let mut certificate_ids = std::collections::HashMap::new();
    let mut end_entity_count = 0;
    for certificate in &request.certificate_path {
        if certificate.position == crate::model::PathPosition::EndEntity {
            end_entity_count += 1;
        }
        if certificate_ids
            .insert(&certificate.id, certificate.position)
            .is_some()
        {
            return Err(OracleError::DuplicateCertificateId(certificate.id.clone()));
        }
    }
    if end_entity_count != 1 {
        return Err(OracleError::InvalidEndEntityCount);
    }

    for item in &request.evidence {
        let Some(position) = certificate_ids.get(&item.certificate_id) else {
            return Err(OracleError::UnknownCertificate {
                evidence_id: item.id.clone(),
                certificate_id: item.certificate_id.clone(),
            });
        };
        if *position != item.position {
            return Err(OracleError::PositionMismatch {
                evidence_id: item.id.clone(),
                certificate_id: item.certificate_id.clone(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregateState {
    Pass,
    Fail,
    Indeterminate,
}

fn evidence_state(
    required_certificates: &[&crate::model::CertificateNode],
    items: &[&Evidence],
) -> AggregateState {
    if required_certificates.is_empty() {
        return AggregateState::Pass;
    }
    let mut indeterminate = false;
    for certificate in required_certificates {
        let certificate_items: Vec<_> = items
            .iter()
            .copied()
            .filter(|item| item.certificate_id == certificate.id)
            .collect();
        if certificate_items.is_empty() {
            return AggregateState::Fail;
        }
        for item in certificate_items {
            for (name, check) in item.checks() {
                match required_check_state(check, name == "binding") {
                    AggregateState::Pass => {}
                    AggregateState::Fail => return AggregateState::Fail,
                    AggregateState::Indeterminate => indeterminate = true,
                }
            }
        }
    }
    if indeterminate {
        AggregateState::Indeterminate
    } else {
        AggregateState::Pass
    }
}

fn required_check_state(
    check: crate::model::CheckResult,
    allow_not_applicable: bool,
) -> AggregateState {
    if matches!(
        check.confidence,
        crate::model::Confidence::Inferred | crate::model::Confidence::Unknown
    ) {
        return AggregateState::Indeterminate;
    }
    match check.state {
        CheckState::Pass => AggregateState::Pass,
        CheckState::NotApplicable if allow_not_applicable => AggregateState::Pass,
        CheckState::Fail | CheckState::NotApplicable => AggregateState::Fail,
        CheckState::Indeterminate | CheckState::NotChecked => AggregateState::Indeterminate,
    }
}

fn add_missing_evidence_checks(
    failed_checks: &mut Vec<FailedCheck>,
    required_certificates: &[&crate::model::CertificateNode],
    items: &[&Evidence],
    kind: EvidenceKind,
) {
    for certificate in required_certificates {
        if !items
            .iter()
            .any(|item| item.certificate_id == certificate.id)
        {
            failed_checks.push(FailedCheck {
                evidence_id: format!("{}:{kind:?}", certificate.id),
                check: "present".to_owned(),
                state: CheckState::Fail,
                confidence: crate::model::Confidence::Observed,
            });
        }
    }
}

fn result(
    request: &VerificationRequest,
    policy_verdict: PolicyVerdict,
    classical_only_fallback: bool,
    lifecycle_desynchronization: bool,
    failed_checks: Vec<FailedCheck>,
    reason: &str,
) -> VerificationResult {
    VerificationResult {
        api_version: API_VERSION.to_owned(),
        policy: request.policy,
        path_scope: request.path_scope,
        validation_time: request.validation_time.clone(),
        previous_authentication: request.previous_authentication,
        stack: request.stack.clone(),
        certificate_path: request.certificate_path.clone(),
        stack_verdict: request.stack.verdict,
        policy_verdict,
        classical_only_fallback,
        lifecycle_desynchronization,
        evaluated_evidence: request.evidence.clone(),
        failed_checks,
        reason: reason.to_owned(),
    }
}
