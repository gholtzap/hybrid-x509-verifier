use crate::model::{
    API_VERSION, AlgorithmSecurity, BindingDesign, CheckState, Evidence, EvidenceKind, FailedCheck,
    PathObservationSource, PathPosition, Policy, PolicyVerdict, StackVerdict, ValidationProfile,
    VerificationRequest, VerificationResult,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OracleError {
    #[error("unsupported API version: {0}")]
    UnsupportedApiVersion(String),
    #[error("evidence identifiers must be unique: {0}")]
    DuplicateEvidenceId(String),
    #[error("evidence kind {kind:?} for certificate {certificate_id} is not unique")]
    DuplicateEvidenceKind {
        certificate_id: String,
        kind: EvidenceKind,
    },
    #[error("certificate identifiers must be unique: {0}")]
    DuplicateCertificateId(String),
    #[error("the certificate path must contain exactly one end-entity certificate")]
    InvalidEndEntityCount,
    #[error("the certificate path must contain exactly one trust anchor")]
    InvalidTrustAnchorCount,
    #[error("the certificate path must be ordered as end-entity, intermediates, trust anchor")]
    InvalidCertificatePathOrder,
    #[error("the stack selected path does not match the request certificate path")]
    SelectedPathMismatch,
    #[error("the stack trust anchor does not match the request trust anchor")]
    TrustAnchorMismatch,
    #[error("certificate {certificate_id} has inconsistent cryptographic properties")]
    InvalidCertificateProperties { certificate_id: String },
    #[error("validation_time must be an RFC 3339 timestamp: {0}")]
    InvalidValidationTime(String),
    #[error(
        "stack applied validation time {applied_validation_time} does not match request validation time {request_validation_time}"
    )]
    ValidationTimeMismatch {
        request_validation_time: String,
        applied_validation_time: String,
    },
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
    #[error("{field} must be 64 lowercase hexadecimal characters")]
    InvalidSha256Hex { field: &'static str },
    #[error("evidence {evidence_id} is not bound to certificate DER for {certificate_id}")]
    CertificateDerHashMismatch {
        evidence_id: String,
        certificate_id: String,
    },
    #[error("evidence {evidence_id} is not bound to issuer edge for {certificate_id}")]
    IssuerEdgeHashMismatch {
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
        .any(|certificate| certificate.has_unknown_crypto_property())
        || request.stack.verdict == StackVerdict::Unsupported
    {
        return Ok(result(
            request,
            PolicyVerdict::Unsupported,
            false,
            false,
            Vec::new(),
            "The certificate cryptographic properties or validation stack are unsupported.",
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
        .filter(|certificate| certificate.requires_classical_certificate_signature_evidence())
        .collect();
    let pq_required: Vec<_> = certificates
        .iter()
        .copied()
        .filter(|certificate| certificate.requires_post_quantum_certificate_signature_evidence())
        .collect();
    let classical_state = evidence_state(&classical_required, &classical);
    let pq_state = evidence_state(&pq_required, &post_quantum);
    let classical_ok = classical_state == AggregateState::Pass;
    let pq_ok = pq_state == AggregateState::Pass;
    let validated_path_state = validated_path_state(request);
    let validated_path_ok = validated_path_state == AggregateState::Pass;
    let has_classical_requirement = !classical_required.is_empty();
    let stack_state = match request.stack.verdict {
        StackVerdict::Accept => stack_validation_time_state(request),
        StackVerdict::Reject => AggregateState::Fail,
        StackVerdict::Indeterminate => AggregateState::Indeterminate,
        StackVerdict::Unsupported => unreachable!("unsupported stacks return before evaluation"),
    };
    let profile_state = authentication_profile_state(request.stack.validation_profile);
    let stack_accepted = stack_state == AggregateState::Pass;
    let profile_accepted = profile_state == AggregateState::Pass;
    let all_hybrid = certificates
        .iter()
        .all(|certificate| certificate.has_hybrid_certificate_signature_design());
    let fallback =
        stack_accepted && !classical_required.is_empty() && classical_ok && (!pq_ok || !all_hybrid);
    let lifecycle_desynchronization = fallback
        && post_quantum.iter().any(|item| {
            item.validity.state == CheckState::Fail || item.revocation.state == CheckState::Fail
        });

    let (verdict, reason) = match request.policy {
        Policy::P0Classical => match classical_state {
            AggregateState::Pass
                if stack_accepted && profile_accepted && has_classical_requirement =>
            {
                (
                    PolicyVerdict::ClassicalClaimSetSatisfied,
                    "The classical evidence passed under policy P0.",
                )
            }
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
            if stack_accepted
                && profile_accepted
                && all_hybrid
                && classical_ok
                && pq_ok
                && validated_path_ok
            {
                (
                    PolicyVerdict::HybridClaimSetSatisfied,
                    "The classical and post-quantum evidence passed under policy P1.",
                )
            } else if stack_accepted
                && profile_accepted
                && all_hybrid
                && classical_ok
                && pq_ok
                && validated_path_state == AggregateState::Indeterminate
            {
                (
                    PolicyVerdict::Indeterminate,
                    "The selected certificate path or trust anchor is not fully bound.",
                )
            } else if stack_accepted
                && profile_accepted
                && has_classical_requirement
                && classical_ok
            {
                (
                    PolicyVerdict::ClassicalClaimSetSatisfied,
                    "Only the classical evidence passed under policy P1.",
                )
            } else if !has_classical_requirement || classical_state == AggregateState::Fail {
                (
                    PolicyVerdict::Reject,
                    "The classical evidence did not pass.",
                )
            } else if classical_state == AggregateState::Indeterminate
                || stack_state == AggregateState::Indeterminate
                || profile_state == AggregateState::Indeterminate
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
            if stack_accepted
                && profile_accepted
                && all_hybrid
                && classical_ok
                && pq_ok
                && validated_path_ok
            {
                (
                    PolicyVerdict::HybridClaimSetSatisfied,
                    "All required classical and post-quantum evidence passed.",
                )
            } else if fallback && pq_state == AggregateState::Fail {
                (
                    PolicyVerdict::Reject,
                    "The stack accepted through classical evidence without valid, decision-sensitive-for-fixture post-quantum evidence.",
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
                || profile_state == AggregateState::Indeterminate
                || validated_path_state == AggregateState::Indeterminate
            {
                (
                    PolicyVerdict::Indeterminate,
                    "Required evidence or selected path binding is incomplete or indeterminate.",
                )
            } else {
                unreachable!("all P2 aggregate states are covered")
            }
        }
        Policy::P3Continuity => (
            PolicyVerdict::Indeterminate,
            "Policy P3 requires an authenticated continuity record; a caller-supplied previous level is not sufficient.",
        ),
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
    let mut evidence_kinds = std::collections::HashSet::new();
    for item in &request.evidence {
        if !ids.insert(&item.id) {
            return Err(OracleError::DuplicateEvidenceId(item.id.clone()));
        }
        if !evidence_kinds.insert((&item.certificate_id, item.kind)) {
            return Err(OracleError::DuplicateEvidenceKind {
                certificate_id: item.certificate_id.clone(),
                kind: item.kind,
            });
        }
    }

    let mut certificates_by_id = std::collections::HashMap::new();
    let mut end_entity_count = 0;
    let mut trust_anchor_count = 0;
    for certificate in &request.certificate_path {
        validate_sha256_hex("certificate.der_sha256", &certificate.der_sha256)?;
        validate_sha256_hex(
            "certificate.issuer_edge_sha256",
            &certificate.issuer_edge_sha256,
        )?;
        validate_certificate_properties(certificate)?;
        if certificate.position == crate::model::PathPosition::EndEntity {
            end_entity_count += 1;
        }
        if certificate.position == crate::model::PathPosition::TrustAnchor {
            trust_anchor_count += 1;
        }
        if certificates_by_id
            .insert(&certificate.id, certificate)
            .is_some()
        {
            return Err(OracleError::DuplicateCertificateId(certificate.id.clone()));
        }
    }
    if end_entity_count != 1 {
        return Err(OracleError::InvalidEndEntityCount);
    }
    if trust_anchor_count != 1 {
        return Err(OracleError::InvalidTrustAnchorCount);
    }
    validate_certificate_path_order(request)?;
    validate_stack_selected_path(request)?;

    for item in &request.evidence {
        validate_sha256_hex(
            "evidence.certificate_der_sha256",
            &item.certificate_der_sha256,
        )?;
        validate_sha256_hex("evidence.issuer_edge_sha256", &item.issuer_edge_sha256)?;
        let Some(certificate) = certificates_by_id.get(&item.certificate_id) else {
            return Err(OracleError::UnknownCertificate {
                evidence_id: item.id.clone(),
                certificate_id: item.certificate_id.clone(),
            });
        };
        if certificate.position != item.position {
            return Err(OracleError::PositionMismatch {
                evidence_id: item.id.clone(),
                certificate_id: item.certificate_id.clone(),
            });
        }
        if mismatched_optional_hash(&certificate.der_sha256, &item.certificate_der_sha256) {
            return Err(OracleError::CertificateDerHashMismatch {
                evidence_id: item.id.clone(),
                certificate_id: item.certificate_id.clone(),
            });
        }
        if mismatched_optional_hash(&certificate.issuer_edge_sha256, &item.issuer_edge_sha256) {
            return Err(OracleError::IssuerEdgeHashMismatch {
                evidence_id: item.id.clone(),
                certificate_id: item.certificate_id.clone(),
            });
        }
    }
    if request.stack.validation_time.state == CheckState::Pass
        && request.stack.applied_validation_time != request.validation_time
    {
        return Err(OracleError::ValidationTimeMismatch {
            request_validation_time: request.validation_time.clone(),
            applied_validation_time: request.stack.applied_validation_time.clone(),
        });
    }
    Ok(())
}

fn validate_certificate_properties(
    certificate: &crate::model::CertificateNode,
) -> Result<(), OracleError> {
    let valid = match certificate.binding_design {
        BindingDesign::AtomicComposite => {
            certificate.certificate_signature_scheme == AlgorithmSecurity::Hybrid
        }
        BindingDesign::Catalyst
        | BindingDesign::Chameleon
        | BindingDesign::RelatedCertificate
        | BindingDesign::None
        | BindingDesign::Unknown => true,
    };
    if valid {
        Ok(())
    } else {
        Err(OracleError::InvalidCertificateProperties {
            certificate_id: certificate.id.clone(),
        })
    }
}

fn mismatched_optional_hash(left: &Option<String>, right: &Option<String>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if left != right)
}

fn validate_certificate_path_order(request: &VerificationRequest) -> Result<(), OracleError> {
    let Some(first) = request.certificate_path.first() else {
        return Err(OracleError::InvalidEndEntityCount);
    };
    let Some(last) = request.certificate_path.last() else {
        return Err(OracleError::InvalidTrustAnchorCount);
    };
    if first.position != PathPosition::EndEntity || last.position != PathPosition::TrustAnchor {
        return Err(OracleError::InvalidCertificatePathOrder);
    }
    if request.certificate_path[1..request.certificate_path.len() - 1]
        .iter()
        .any(|certificate| certificate.position != PathPosition::Intermediate)
    {
        return Err(OracleError::InvalidCertificatePathOrder);
    }
    Ok(())
}

fn validate_stack_selected_path(request: &VerificationRequest) -> Result<(), OracleError> {
    for hash in &request.stack.selected_path_der_sha256 {
        validate_required_sha256_hex("stack.selected_path_der_sha256", hash)?;
    }
    validate_required_sha256_hex(
        "stack.trust_anchor_der_sha256",
        &request.stack.trust_anchor_der_sha256,
    )?;
    let path_hashes = request
        .certificate_path
        .iter()
        .map(|certificate| certificate.der_sha256.as_deref())
        .collect::<Option<Vec<_>>>()
        .ok_or(OracleError::SelectedPathMismatch)?;
    if path_hashes != request.stack.selected_path_der_sha256 {
        return Err(OracleError::SelectedPathMismatch);
    }
    if path_hashes
        .last()
        .is_none_or(|anchor| *anchor != request.stack.trust_anchor_der_sha256)
    {
        return Err(OracleError::TrustAnchorMismatch);
    }
    Ok(())
}

fn validate_sha256_hex(field: &'static str, value: &Option<String>) -> Result<(), OracleError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(OracleError::InvalidSha256Hex { field })
    }
}

fn validate_required_sha256_hex(field: &'static str, value: &str) -> Result<(), OracleError> {
    validate_sha256_hex(field, &Some(value.to_owned()))
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
            match evidence_binding_state(certificate, item) {
                AggregateState::Pass => {}
                AggregateState::Fail => return AggregateState::Fail,
                AggregateState::Indeterminate => indeterminate = true,
            }
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

fn evidence_binding_state(
    certificate: &crate::model::CertificateNode,
    item: &Evidence,
) -> AggregateState {
    if certificate.der_sha256.is_none() || item.certificate_der_sha256.is_none() {
        return AggregateState::Indeterminate;
    }
    if certificate.position == PathPosition::TrustAnchor {
        return AggregateState::Pass;
    }
    if certificate.issuer_edge_sha256.is_none() || item.issuer_edge_sha256.is_none() {
        return AggregateState::Indeterminate;
    }
    AggregateState::Pass
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

fn stack_validation_time_state(request: &VerificationRequest) -> AggregateState {
    if request.stack.applied_validation_time != request.validation_time {
        return AggregateState::Indeterminate;
    }
    required_check_state(request.stack.validation_time, false)
}

fn authentication_profile_state(profile: ValidationProfile) -> AggregateState {
    match profile {
        ValidationProfile::X509Path | ValidationProfile::WebPkiServer => AggregateState::Pass,
        ValidationProfile::EvidenceSignature => AggregateState::Indeterminate,
    }
}

fn validated_path_state(request: &VerificationRequest) -> AggregateState {
    if request.stack.selected_path_source != PathObservationSource::AdapterSelected {
        return AggregateState::Indeterminate;
    }
    let mut has_end_entity = false;
    let mut has_trust_anchor = false;
    for certificate in &request.certificate_path {
        match certificate.position {
            PathPosition::EndEntity => {
                has_end_entity = true;
                if certificate.der_sha256.is_none() || certificate.issuer_edge_sha256.is_none() {
                    return AggregateState::Indeterminate;
                }
            }
            PathPosition::Intermediate => {
                if certificate.der_sha256.is_none() || certificate.issuer_edge_sha256.is_none() {
                    return AggregateState::Indeterminate;
                }
            }
            PathPosition::TrustAnchor => {
                has_trust_anchor = true;
                if certificate.der_sha256.is_none() {
                    return AggregateState::Indeterminate;
                }
            }
        }
    }
    if has_end_entity && has_trust_anchor {
        AggregateState::Pass
    } else {
        AggregateState::Indeterminate
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
