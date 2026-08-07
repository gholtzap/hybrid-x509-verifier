use crate::{
    AlgorithmSecurity, BindingDesign, CertificateNode, CheckResult, CheckState, Confidence,
    PathPosition, PathScope, TrustAnchor, VerificationResult,
    pem::{PemError, PemKind, RelatedConformanceResult, read_der},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopedVerificationResult {
    pub scope: PathScope,
    pub result: VerificationResult,
}

pub(crate) fn behavioral_check(established: bool, state: CheckState) -> CheckResult {
    if established {
        CheckResult {
            state,
            confidence: Confidence::BehaviorallyEstablished,
        }
    } else {
        CheckResult {
            state: CheckState::Indeterminate,
            confidence: Confidence::Unknown,
        }
    }
}

pub(crate) fn certificate_der_hash(path: &Path, limit: usize) -> Result<String, PemError> {
    Ok(sha256_hex(&read_der(path, PemKind::Certificate, limit)?))
}

pub(crate) fn certificate_trust_anchor(path: &Path, limit: usize) -> Result<TrustAnchor, PemError> {
    Ok(TrustAnchor::CertificateDerSha256 {
        der_sha256: certificate_der_hash(path, limit)?,
    })
}

pub(crate) fn issuer_edge_hash(
    certificate: &Path,
    issuer: &Path,
    limit: usize,
) -> Result<String, PemError> {
    let certificate = read_der(certificate, PemKind::Certificate, limit)?;
    let issuer = read_der(issuer, PemKind::Certificate, limit)?;
    let mut hasher = Sha256::new();
    hasher.update((certificate.len() as u64).to_be_bytes());
    hasher.update(&certificate);
    hasher.update((issuer.len() as u64).to_be_bytes());
    hasher.update(&issuer);
    Ok(hex_lower(&hasher.finalize()))
}

pub(crate) fn related_conformance_check(result: &RelatedConformanceResult) -> CheckResult {
    let state = [
        result.rfc9763.binding.check,
        result.rfc9763.extension_in_end_entity,
        result.rfc9763.related_certificate_is_end_entity,
        result.rfc9763.key_usage_subset,
        result.rfc9763.extended_key_usage_subset,
        result
            .hybrid_application_policy
            .reference_subject_public_key_is_classical,
        result
            .hybrid_application_policy
            .related_subject_public_key_is_post_quantum,
        result.hybrid_application_policy.dns_identity_overlap,
    ]
    .into_iter()
    .map(|check| check.state)
    .find(|state| *state != CheckState::Pass)
    .unwrap_or(CheckState::Pass);

    CheckResult::observed(state)
}

pub(crate) struct LeafPathProperties {
    pub subject_public_key_scheme: AlgorithmSecurity,
    pub certificate_signature_scheme: AlgorithmSecurity,
    pub binding_design: BindingDesign,
}

pub(crate) fn end_entity_certification_path(
    leaf: &Path,
    issuer: &Path,
    trust_anchor: &Path,
    properties: LeafPathProperties,
    limit: usize,
) -> Result<Vec<CertificateNode>, PemError> {
    Ok(vec![
        CertificateNode {
            id: "end-entity".to_owned(),
            position: PathPosition::EndEntity,
            subject_public_key_scheme: properties.subject_public_key_scheme,
            certificate_signature_scheme: properties.certificate_signature_scheme,
            binding_design: properties.binding_design,
            der_sha256: Some(certificate_der_hash(leaf, limit)?),
            issuer_edge_sha256: Some(issuer_edge_hash(leaf, issuer, limit)?),
        },
        CertificateNode {
            id: "issuer".to_owned(),
            position: PathPosition::Intermediate,
            subject_public_key_scheme: AlgorithmSecurity::Classical,
            certificate_signature_scheme: AlgorithmSecurity::Classical,
            binding_design: BindingDesign::None,
            der_sha256: Some(certificate_der_hash(issuer, limit)?),
            issuer_edge_sha256: Some(issuer_edge_hash(issuer, trust_anchor, limit)?),
        },
    ])
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub mod atomic_path_scope;
pub mod atomic_tls;
pub mod catalyst_bouncy_castle;
pub mod catalyst_path_scope;
pub mod catalyst_tls;
pub mod chameleon_path_scope;
pub mod chameleon_tls;
pub mod cross_signed_path;
pub mod matrix;
pub mod pure_path_scope;
pub mod related_openssl;
pub mod related_path_scope;
pub mod related_tls;
pub mod tls;
