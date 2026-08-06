use hybrid_x509_evidence::*;

const LEAF_DER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_DER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const LEAF_EDGE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const OTHER_EDGE: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const ROOT_DER: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn evidence(id: &str, kind: EvidenceKind) -> Evidence {
    let pass = CheckResult::observed(CheckState::Pass);
    Evidence {
        id: id.to_owned(),
        certificate_id: "leaf".to_owned(),
        position: PathPosition::EndEntity,
        certificate_der_sha256: Some(LEAF_DER.to_owned()),
        issuer_edge_sha256: Some(LEAF_EDGE.to_owned()),
        kind,
        present: pass,
        recognized: pass,
        signature: pass,
        binding: pass,
        path: pass,
        validity: pass,
        revocation: pass,
        decision_sensitive_for_fixture: pass,
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
            execution_isolation: hybrid_x509_evidence::ExecutionIsolation::Container,
            selected_path_der_sha256: vec![LEAF_DER.to_owned(), ROOT_DER.to_owned()],
            selected_path_source: PathObservationSource::PresentedInput,
            trust_anchor_der_sha256: ROOT_DER.to_owned(),
            applied_validation_time: "2026-06-20T00:00:00Z".to_owned(),
            validation_time: CheckResult::observed(CheckState::Pass),
        },
        certificate_path: vec![
            CertificateNode {
                id: "leaf".to_owned(),
                position: PathPosition::EndEntity,
                subject_public_key_scheme: AlgorithmSecurity::Classical,
                certificate_signature_scheme: AlgorithmSecurity::Hybrid,
                binding_design: BindingDesign::AtomicComposite,
                der_sha256: Some(LEAF_DER.to_owned()),
                issuer_edge_sha256: Some(LEAF_EDGE.to_owned()),
            },
            CertificateNode {
                id: "root".to_owned(),
                position: PathPosition::TrustAnchor,
                subject_public_key_scheme: AlgorithmSecurity::Classical,
                certificate_signature_scheme: AlgorithmSecurity::Classical,
                binding_design: BindingDesign::None,
                der_sha256: Some(ROOT_DER.to_owned()),
                issuer_edge_sha256: None,
            },
        ],
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
    assert_eq!(result.certificate_path.len(), 2);
    assert_eq!(
        result.policy_verdict,
        PolicyVerdict::HybridClaimSetSatisfied
    );
    assert!(!result.classical_only_fallback);
}

#[test]
fn evidence_signature_profile_cannot_produce_authentication_acceptance() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.stack.validation_profile = ValidationProfile::EvidenceSignature;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Indeterminate);
}

#[test]
fn inconsistent_certificate_properties_are_rejected() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.certificate_path[0].certificate_signature_scheme = AlgorithmSecurity::Classical;

    assert_eq!(
        evaluate(&request),
        Err(OracleError::InvalidCertificateProperties {
            certificate_id: "leaf".to_owned()
        })
    );
}

#[test]
fn p2_without_a_declared_trust_anchor_is_rejected_at_the_api_boundary() {
    let mut request = request(Policy::P2RequiredHybrid);
    request
        .certificate_path
        .retain(|certificate| certificate.position != PathPosition::TrustAnchor);
    request.stack.selected_path_der_sha256 = vec![LEAF_DER.to_owned()];

    assert_eq!(
        evaluate(&request),
        Err(OracleError::InvalidTrustAnchorCount)
    );
}

#[test]
fn p2_rejects_classical_acceptance_when_pq_is_not_decision_sensitive_for_fixture() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[1].decision_sensitive_for_fixture.state = CheckState::Fail;

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

    assert_eq!(
        result.policy_verdict,
        PolicyVerdict::ClassicalClaimSetSatisfied
    );
    assert!(result.classical_only_fallback);
}

#[test]
fn path_scope_requires_evidence_for_each_included_position() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.path_scope = PathScope::CertificationPath;
    let mut issuer_classical = evidence("issuer-classical", EvidenceKind::Classical);
    issuer_classical.certificate_id = "issuer".to_owned();
    issuer_classical.position = PathPosition::Intermediate;
    issuer_classical.certificate_der_sha256 = Some(OTHER_DER.to_owned());
    issuer_classical.issuer_edge_sha256 = Some(OTHER_EDGE.to_owned());
    let mut issuer_pq = evidence("issuer-pq", EvidenceKind::PostQuantum);
    issuer_pq.certificate_id = "issuer".to_owned();
    issuer_pq.position = PathPosition::Intermediate;
    issuer_pq.certificate_der_sha256 = Some(OTHER_DER.to_owned());
    issuer_pq.issuer_edge_sha256 = Some(OTHER_EDGE.to_owned());
    issuer_pq.signature.state = CheckState::Fail;
    request.evidence.extend([issuer_classical, issuer_pq]);
    request.certificate_path.insert(
        1,
        CertificateNode {
            id: "issuer".to_owned(),
            position: PathPosition::Intermediate,
            subject_public_key_scheme: AlgorithmSecurity::Classical,
            certificate_signature_scheme: AlgorithmSecurity::Hybrid,
            binding_design: BindingDesign::AtomicComposite,
            der_sha256: Some(OTHER_DER.to_owned()),
            issuer_edge_sha256: Some(OTHER_EDGE.to_owned()),
        },
    );
    request.stack.selected_path_der_sha256 = vec![
        LEAF_DER.to_owned(),
        OTHER_DER.to_owned(),
        ROOT_DER.to_owned(),
    ];

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Reject);
}

#[test]
fn omitted_intermediate_pq_evidence_is_a_policy_failure() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.path_scope = PathScope::CertificationPath;
    request.certificate_path.insert(
        1,
        CertificateNode {
            id: "issuer".to_owned(),
            position: PathPosition::Intermediate,
            subject_public_key_scheme: AlgorithmSecurity::Classical,
            certificate_signature_scheme: AlgorithmSecurity::Hybrid,
            binding_design: BindingDesign::AtomicComposite,
            der_sha256: Some(OTHER_DER.to_owned()),
            issuer_edge_sha256: Some(OTHER_EDGE.to_owned()),
        },
    );
    request.stack.selected_path_der_sha256 = vec![
        LEAF_DER.to_owned(),
        OTHER_DER.to_owned(),
        ROOT_DER.to_owned(),
    ];
    let mut issuer_classical = evidence("issuer-classical", EvidenceKind::Classical);
    issuer_classical.certificate_id = "issuer".to_owned();
    issuer_classical.position = PathPosition::Intermediate;
    issuer_classical.certificate_der_sha256 = Some(OTHER_DER.to_owned());
    issuer_classical.issuer_edge_sha256 = Some(OTHER_EDGE.to_owned());
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
fn duplicate_evidence_kind_for_one_certificate_is_rejected() {
    let mut request = request(Policy::P2RequiredHybrid);
    let mut extra = evidence("extra-pq", EvidenceKind::PostQuantum);
    extra.signature.state = CheckState::Fail;
    request.evidence.push(extra);

    assert_eq!(
        evaluate(&request),
        Err(OracleError::DuplicateEvidenceKind {
            certificate_id: "leaf".to_owned(),
            kind: EvidenceKind::PostQuantum,
        })
    );
}

#[test]
fn p2_does_not_promote_a_classical_certificate() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.certificate_path[0].binding_design = BindingDesign::None;
    request.evidence.pop();

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Reject);
    assert!(result.classical_only_fallback);
}

#[test]
fn pure_pq_acceptance_is_not_classical_authentication() {
    for policy in [Policy::P0Classical, Policy::P1OptionalHybrid] {
        let mut request = request(policy);
        request.certificate_path[0].subject_public_key_scheme = AlgorithmSecurity::PostQuantum;
        request.certificate_path[0].certificate_signature_scheme = AlgorithmSecurity::PostQuantum;
        request.certificate_path[0].binding_design = BindingDesign::None;
        request.evidence.remove(0);

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
            "decision-sensitive-for-fixture",
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
                "decision-sensitive-for-fixture" => {
                    evidence.decision_sensitive_for_fixture.state = CheckState::NotApplicable
                }
                _ => unreachable!(),
            }

            assert_ne!(
                evaluate(&request).unwrap().policy_verdict,
                PolicyVerdict::HybridClaimSetSatisfied,
                "evidence {index} check {check}"
            );
        }
    }

    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[0].binding.state = CheckState::NotApplicable;
    assert_eq!(
        evaluate(&request).unwrap().policy_verdict,
        PolicyVerdict::HybridClaimSetSatisfied
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
            PolicyVerdict::HybridClaimSetSatisfied,
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
fn applied_validation_time_must_match_the_request_time() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.stack.applied_validation_time = "2026-06-21T00:00:00Z".to_owned();

    assert_eq!(
        evaluate(&request),
        Err(OracleError::ValidationTimeMismatch {
            request_validation_time: "2026-06-20T00:00:00Z".to_owned(),
            applied_validation_time: "2026-06-21T00:00:00Z".to_owned(),
        })
    );
}

#[test]
fn evidence_certificate_der_hash_must_match_selected_certificate() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.certificate_path[0].der_sha256 = Some(LEAF_DER.to_owned());
    request.evidence[1].certificate_der_sha256 = Some(OTHER_DER.to_owned());

    assert_eq!(
        evaluate(&request),
        Err(OracleError::CertificateDerHashMismatch {
            evidence_id: "pq".to_owned(),
            certificate_id: "leaf".to_owned(),
        })
    );
}

#[test]
fn evidence_issuer_edge_hash_must_match_selected_path() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.certificate_path[0].issuer_edge_sha256 = Some(LEAF_EDGE.to_owned());
    request.evidence[0].issuer_edge_sha256 = Some(OTHER_EDGE.to_owned());

    assert_eq!(
        evaluate(&request),
        Err(OracleError::IssuerEdgeHashMismatch {
            evidence_id: "classical".to_owned(),
            certificate_id: "leaf".to_owned(),
        })
    );
}

#[test]
fn stack_selected_path_must_match_request_path() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.stack.selected_path_der_sha256 = vec![OTHER_DER.to_owned(), ROOT_DER.to_owned()];

    assert_eq!(evaluate(&request), Err(OracleError::SelectedPathMismatch));
}

#[test]
fn stack_trust_anchor_must_match_request_anchor() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.stack.trust_anchor_der_sha256 = OTHER_DER.to_owned();

    assert_eq!(evaluate(&request), Err(OracleError::TrustAnchorMismatch));
}

#[test]
fn certificate_path_must_be_ordered_leaf_to_anchor() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.certificate_path.reverse();

    assert_eq!(
        evaluate(&request),
        Err(OracleError::InvalidCertificatePathOrder)
    );
}

#[test]
fn invalid_hash_format_is_rejected() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[0].certificate_der_sha256 = Some("not-a-sha256".to_owned());

    assert_eq!(
        evaluate(&request),
        Err(OracleError::InvalidSha256Hex {
            field: "evidence.certificate_der_sha256",
        })
    );
}

#[test]
fn missing_certificate_hash_on_node_prevents_hybrid_acceptance() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.certificate_path[0].der_sha256 = None;

    assert_eq!(evaluate(&request), Err(OracleError::SelectedPathMismatch));
}

#[test]
fn missing_certificate_hash_on_evidence_prevents_hybrid_acceptance() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[0].certificate_der_sha256 = None;

    assert_eq!(
        evaluate(&request).unwrap().policy_verdict,
        PolicyVerdict::Indeterminate
    );
}

#[test]
fn missing_certificate_hash_on_both_sides_prevents_hybrid_acceptance() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.certificate_path[0].der_sha256 = None;
    request.evidence[0].certificate_der_sha256 = None;

    assert_eq!(evaluate(&request), Err(OracleError::SelectedPathMismatch));
}

#[test]
fn missing_issuer_edge_hash_prevents_hybrid_acceptance_except_for_trust_anchor() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.evidence[0].issuer_edge_sha256 = None;

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
fn trust_anchor_certificate_crypto_is_not_selected_path_evidence() {
    let mut request = request(Policy::P2RequiredHybrid);
    request.certificate_path[1].binding_design = BindingDesign::Unknown;

    assert_eq!(
        evaluate(&request).unwrap().policy_verdict,
        PolicyVerdict::HybridClaimSetSatisfied
    );

    request.path_scope = PathScope::CertificationPath;
    assert_eq!(
        evaluate(&request).unwrap().policy_verdict,
        PolicyVerdict::HybridClaimSetSatisfied
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
fn p3_cannot_establish_downgrade_from_a_previous_level_alone() {
    let mut request = request(Policy::P3Continuity);
    request.previous_authentication = Some(AuthenticationLevel::Hybrid);
    request.evidence[1].signature.state = CheckState::Fail;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Indeterminate);
    assert!(result.classical_only_fallback);
}

#[test]
fn p3_cannot_preserve_classical_continuity_from_a_previous_level_alone() {
    let mut request = request(Policy::P3Continuity);
    request.previous_authentication = Some(AuthenticationLevel::Classical);
    request.evidence[1].signature.state = CheckState::Fail;

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Indeterminate);
}

#[test]
fn p3_cannot_upgrade_to_hybrid_from_a_previous_level_alone() {
    let mut request = request(Policy::P3Continuity);
    request.previous_authentication = Some(AuthenticationLevel::Classical);

    let result = evaluate(&request).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Indeterminate);
}

#[test]
fn p3_without_previous_state_is_indeterminate() {
    let result = evaluate(&request(Policy::P3Continuity)).unwrap();

    assert_eq!(result.policy_verdict, PolicyVerdict::Indeterminate);
}
