use hybrid_x509_verifier::*;

fn evidence(id: &str, kind: EvidenceKind) -> Evidence {
    let pass = CheckResult::observed(CheckState::Pass);
    Evidence {
        id: id.to_owned(),
        certificate_id: "leaf".to_owned(),
        position: PathPosition::EndEntity,
        kind,
        present: pass,
        recognized: pass,
        signature: pass,
        binding: pass,
        path: pass,
        validity: pass,
        revocation: pass,
        outcome_bearing: pass,
    }
}

fn request(policy: Policy) -> VerificationRequest {
    VerificationRequest {
        api_version: API_VERSION.to_owned(),
        policy,
        path_scope: PathScope::EndEntity,
        validation_time: "2026-06-20T00:00:00Z".to_owned(),
        previous_authentication: None,
        stack: StackObservation {
            adapter: "test".to_owned(),
            version: "1".to_owned(),
            verdict: StackVerdict::Accept,
            version_track: VersionTrack::UserSupplied,
            validation_profile: ValidationProfile::X509Path,
            execution_isolation: hybrid_x509_verifier::ExecutionIsolation::Container,
            validation_time: CheckResult::observed(CheckState::Pass),
        },
        certificate_path: vec![CertificateNode {
            id: "leaf".to_owned(),
            position: PathPosition::EndEntity,
            scheme: Scheme::Related,
        }],
        evidence: vec![
            evidence("classical", EvidenceKind::Classical),
            evidence("pq", EvidenceKind::PostQuantum),
        ],
    }
}

#[test]
fn p2_accepts_only_when_both_evidence_sets_pass() {
    let result = evaluate(&request(Policy::P2RequiredHybrid)).unwrap();
    assert_eq!(result.policy, Policy::P2RequiredHybrid);
    assert_eq!(result.path_scope, PathScope::EndEntity);
    assert_eq!(result.validation_time, "2026-06-20T00:00:00Z");
    assert_eq!(result.stack.adapter, "test");
    assert_eq!(result.certificate_path.len(), 1);
    assert_eq!(result.policy_verdict, PolicyVerdict::AcceptHybrid);
    assert!(!result.classical_only_fallback);
}

#[test]
fn p2_rejects_classical_acceptance_when_pq_is_not_outcome_bearing() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[1].outcome_bearing.state = CheckState::Fail;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Reject);
    assert!(result.classical_only_fallback);
}

#[test]
fn p2_detects_revocation_desynchronization() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[1].revocation.state = CheckState::Fail;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Reject);
    assert!(result.classical_only_fallback);
    assert!(result.lifecycle_desynchronization);
}

#[test]
fn p2_rejects_revoked_classical_evidence_when_pq_is_valid() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[0].revocation.state = CheckState::Fail;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Reject);
    assert!(!result.lifecycle_desynchronization);
}

#[test]
fn unknown_revocation_state_cannot_be_hybrid_acceptance() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[1].revocation.state = CheckState::Indeterminate;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Indeterminate);
    assert!(result.classical_only_fallback);
}

#[test]
fn p1_labels_fallback_as_classical() {
    let mut request = request(Policy::P1OptionalHybrid);
    request.evidence[1].signature.state = CheckState::Fail;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::AcceptClassical);
    assert!(result.classical_only_fallback);
}

#[test]
fn path_scope_requires_evidence_for_each_included_position() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.path_scope = PathScope::FullPath;
    let mut issuer_classical = evidence("issuer-classical", EvidenceKind::Classical);
    issuer_classical.certificate_id = "issuer".to_owned();
    issuer_classical.position = PathPosition::Intermediate;
    let mut issuer_pq = evidence("issuer-pq", EvidenceKind::PostQuantum);
    issuer_pq.certificate_id = "issuer".to_owned();
    issuer_pq.position = PathPosition::Intermediate;
    issuer_pq.signature.state = CheckState::Fail;
    request.evidence.extend([issuer_classical, issuer_pq]);
    request.certificate_path.push(CertificateNode {
        id: "issuer".to_owned(),
        position: PathPosition::Intermediate,
        scheme: Scheme::Related,
    });

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Reject);
}

#[test]
fn omitted_intermediate_pq_evidence_is_a_policy_failure() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.path_scope = PathScope::IssuingPath;
    request.certificate_path.push(CertificateNode {
        id: "issuer".to_owned(),
        position: PathPosition::Intermediate,
        scheme: Scheme::Related,
    });
    let mut issuer_classical = evidence("issuer-classical", EvidenceKind::Classical);
    issuer_classical.certificate_id = "issuer".to_owned();
    issuer_classical.position = PathPosition::Intermediate;
    request.evidence.push(issuer_classical);

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Reject);
    assert!(result.classical_only_fallback);
    assert!(
        result
            .failed_checks
            .iter()
            .any(|check| { check.evidence_id == "issuer:PostQuantum" && check.check == "present" })
    );
}

#[test]
fn duplicate_evidence_identifiers_are_rejected() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[1].id = request.evidence[0].id.clone();

    assert_eq!(
        evaluate(&request),
        Err(OracleError::DuplicateEvidenceId("classical".to_owned()))
    );
}

#[test]
fn p2_does_not_promote_a_classical_certificate() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.certificate_path[0].scheme = Scheme::Classical;
    request.evidence.pop();

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Reject);
    assert!(result.classical_only_fallback);
}

#[test]
fn pure_pq_acceptance_is_not_classical_authentication() {
    for policy in [
        Policy::P0Classical,
        Policy::P1OptionalHybrid,
        Policy::P3Continuity,
    ] {
        let mut request = request(policy);
        request.certificate_path[0].scheme = Scheme::PurePostQuantum;
        request.evidence.remove(0);
        request.previous_authentication =
            (policy == Policy::P3Continuity).then_some(AuthenticationLevel::Classical);

        let result = evaluate(&request).unwrap();

        assert_eq!(result.policy_verdict, PolicyVerdict::Reject, "{policy:?}");
    }
}

#[test]
fn required_checks_cannot_be_bypassed_as_not_applicable() {
    for index in [0, 1] {
        for check in [
            "present",
            "recognized",
            "signature",
            "path",
            "validity",
            "revocation",
            "outcome-bearing",
        ] {
            let mut request = request(Policy::P2RequiredHybrid);
            let evidence = &mut request.evidence[index];
            match check {
                "present" => evidence.present.state = CheckState::NotApplicable,
                "recognized" => evidence.recognized.state = CheckState::NotApplicable,
                "signature" => evidence.signature.state = CheckState::NotApplicable,
                "path" => evidence.path.state = CheckState::NotApplicable,
                "validity" => evidence.validity.state = CheckState::NotApplicable,
                "revocation" => evidence.revocation.state = CheckState::NotApplicable,
                "outcome-bearing" => evidence.outcome_bearing.state = CheckState::NotApplicable,
                _ => unreachable!(),
            }

            assert_ne!(
                evaluate(&request).unwrap().policy_verdict,
                PolicyVerdict::AcceptHybrid,
                "evidence {index} check {check}"
            );
        }
    }

    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[0].binding.state = CheckState::NotApplicable;
    assert_eq!(
        evaluate(&request).unwrap().policy_verdict,
        PolicyVerdict::AcceptHybrid
    );
}

#[test]
fn acceptance_requires_the_stack_to_apply_the_common_validation_time() {
    for state in [
        CheckState::Fail,
        CheckState::Indeterminate,
        CheckState::NotChecked,
        CheckState::NotApplicable,
    ] {
        let mut request = request(Policy::P2RequiredHybrid);
        request.stack.validation_time.state = state;

        let result = evaluate(&request).unwrap();

        assert_ne!(
            result.policy_verdict,
            PolicyVerdict::AcceptHybrid,
            "{state:?}"
        );
    }

    let mut request = request(Policy::P2RequiredHybrid);
    request.stack.validation_time.confidence = Confidence::Inferred;
    assert_eq!(
        evaluate(&request).unwrap().policy_verdict,
        PolicyVerdict::Indeterminate
    );
}

#[test]
fn known_required_failure_dominates_an_indeterminate_stack_result() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[1].signature.state = CheckState::Fail;
    request.stack.validation_time.state = CheckState::Indeterminate;

    assert_eq!(
        evaluate(&request).unwrap().policy_verdict,
        PolicyVerdict::Reject
    );
}

#[test]
fn unsupported_schemes_affect_only_the_selected_path_scope() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.certificate_path.push(CertificateNode {
        id: "root".to_owned(),
        position: PathPosition::TrustAnchor,
        scheme: Scheme::Unknown,
    });

    assert_eq!(
        evaluate(&request).unwrap().policy_verdict,
        PolicyVerdict::AcceptHybrid
    );

    request.path_scope = PathScope::FullPath;
    assert_eq!(
        evaluate(&request).unwrap().policy_verdict,
        PolicyVerdict::Unsupported
    );
}

#[test]
fn inferred_evidence_cannot_establish_hybrid_authentication() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[1].signature.confidence = Confidence::Inferred;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Indeterminate);
}

#[test]
fn invalid_validation_time_is_rejected_at_the_api_boundary() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.validation_time = "tomorrow".to_owned();

    assert_eq!(
        evaluate(&request),
        Err(OracleError::InvalidValidationTime("tomorrow".to_owned()))
    );
}

#[test]
fn p3_rejects_a_downgrade_after_hybrid_authentication() {
    let mut request = request(Policy::P3Continuity);
    request.previous_authentication = Some(AuthenticationLevel::Hybrid);
    request.evidence[1].signature.state = CheckState::Fail;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Reject);
    assert!(result.classical_only_fallback);
}

#[test]
fn p3_preserves_classical_continuity_before_hybrid_upgrade() {
    let mut request = request(Policy::P3Continuity);
    request.previous_authentication = Some(AuthenticationLevel::Classical);
    request.evidence[1].signature.state = CheckState::Fail;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::AcceptClassical);
}

#[test]
fn p3_advances_classical_authentication_to_hybrid() {
    let mut request = request(Policy::P3Continuity);
    request.previous_authentication = Some(AuthenticationLevel::Classical);

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::AcceptHybrid);
}

#[test]
fn p3_without_previous_state_is_indeterminate() {
    let result = evaluate(&request(Policy::P3Continuity)).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Indeterminate);
}
