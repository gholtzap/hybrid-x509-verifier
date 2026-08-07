use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const API_VERSION: &str = "hybrid-x509-evidence/v9";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    P0Classical,
    P1OptionalHybrid,
    P2RequiredHybrid,
    P3Continuity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PathScope {
    EndEntity,
    #[serde(
        rename = "certification-path",
        alias = "issuing-path",
        alias = "full-path",
        alias = "full-path-with-trust-anchor-evidence"
    )]
    CertificationPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PathPosition {
    EndEntity,
    Intermediate,
    TrustAnchor,
}

impl PathScope {
    pub fn includes(self, position: PathPosition) -> bool {
        match self {
            Self::EndEntity => position == PathPosition::EndEntity,
            Self::CertificationPath => position != PathPosition::TrustAnchor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AlgorithmSecurity {
    Classical,
    PostQuantum,
    Hybrid,
    Unknown,
}

impl AlgorithmSecurity {
    pub fn is_classical(self) -> bool {
        matches!(self, Self::Classical | Self::Hybrid)
    }

    pub fn is_post_quantum(self) -> bool {
        matches!(self, Self::PostQuantum | Self::Hybrid)
    }

    pub fn is_unknown(self) -> bool {
        self == Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BindingDesign {
    None,
    AtomicComposite,
    Catalyst,
    Chameleon,
    RelatedCertificate,
    Unknown,
}

impl BindingDesign {
    pub fn is_hybrid_certificate_signature_design(self) -> bool {
        matches!(
            self,
            Self::AtomicComposite | Self::Catalyst | Self::Chameleon
        )
    }

    pub fn is_unknown(self) -> bool {
        self == Self::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateNode {
    pub id: String,
    pub position: PathPosition,
    pub subject_public_key_scheme: AlgorithmSecurity,
    pub certificate_signature_scheme: AlgorithmSecurity,
    pub binding_design: BindingDesign,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub der_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_edge_sha256: Option<String>,
}

impl CertificateNode {
    pub fn has_unknown_crypto_property(&self) -> bool {
        self.subject_public_key_scheme.is_unknown()
            || self.certificate_signature_scheme.is_unknown()
            || self.binding_design.is_unknown()
    }

    pub fn requires_classical_certificate_signature_evidence(&self) -> bool {
        self.certificate_signature_scheme.is_classical()
            || self.binding_design.is_hybrid_certificate_signature_design()
    }

    pub fn requires_post_quantum_certificate_signature_evidence(&self) -> bool {
        self.certificate_signature_scheme.is_post_quantum()
            || self.binding_design.is_hybrid_certificate_signature_design()
            || self.binding_design == BindingDesign::RelatedCertificate
    }

    pub fn has_hybrid_certificate_signature_design(&self) -> bool {
        self.binding_design.is_hybrid_certificate_signature_design()
            || self.certificate_signature_scheme == AlgorithmSecurity::Hybrid
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Classical,
    PostQuantum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CheckState {
    Pass,
    Fail,
    Indeterminate,
    NotChecked,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Observed,
    BehaviorallyEstablished,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub state: CheckState,
    pub confidence: Confidence,
}

impl CheckResult {
    pub const fn observed(state: CheckState) -> Self {
        Self {
            state,
            confidence: Confidence::Observed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub id: String,
    pub certificate_id: String,
    pub position: PathPosition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_der_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_artifact_der_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_edge_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_operation_id: Option<String>,
    pub kind: EvidenceKind,
    pub present: CheckResult,
    pub recognized: CheckResult,
    pub signature: CheckResult,
    pub binding: CheckResult,
    pub path: CheckResult,
    pub validity: CheckResult,
    pub revocation: CheckResult,
    pub revocation_method: RevocationMethod,
    pub applied_revocation_policy: RevocationPolicy,
    pub decision_sensitive_for_fixture: CheckResult,
}

impl Evidence {
    pub fn checks(&self) -> [(&'static str, CheckResult); 8] {
        [
            ("present", self.present),
            ("recognized", self.recognized),
            ("signature", self.signature),
            ("binding", self.binding),
            ("path", self.path),
            ("validity", self.validity),
            ("revocation", self.revocation),
            (
                "decision-sensitive-for-fixture",
                self.decision_sensitive_for_fixture,
            ),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum StackVerdict {
    Accept,
    Reject,
    Indeterminate,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationProfile {
    X509Path,
    WebPkiServer,
    EvidenceSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionIsolation {
    Container,
    ProcessOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum VersionTrack {
    Current,
    Study,
    CurrentAndStudy,
    UserSupplied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PathObservationSource {
    PresentedInput,
    AdapterSelected,
    NotReported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TrustAnchor {
    CertificateDerSha256 { der_sha256: String },
    NameAndSpkiSha256 { name: String, spki_sha256: String },
    LocalIdentifier { identifier: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RevocationMethod {
    Ocsp,
    Crl,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RevocationPolicyMode {
    HardFail,
    SoftFail,
    NotRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationPolicy {
    pub mode: RevocationPolicyMode,
    pub max_age_seconds: Option<u64>,
    pub clock_skew_seconds: Option<u64>,
}

impl RevocationPolicy {
    pub const fn crl_hard_fail() -> Self {
        Self {
            mode: RevocationPolicyMode::HardFail,
            max_age_seconds: None,
            clock_skew_seconds: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackObservation {
    pub adapter: String,
    pub version: String,
    pub verdict: StackVerdict,
    pub version_track: VersionTrack,
    pub validation_profile: ValidationProfile,
    pub execution_isolation: ExecutionIsolation,
    pub certification_path_der_sha256: Vec<String>,
    pub selected_path_source: PathObservationSource,
    pub trust_anchor: TrustAnchor,
    pub applied_validation_time: String,
    pub validation_time: CheckResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EncodedStream {
    pub encoding: String,
    pub data: String,
    pub sha256: String,
    pub captured_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessRecord {
    pub status_code: Option<i32>,
    pub timed_out: bool,
    pub elapsed_milliseconds: u64,
    pub stdout: EncodedStream,
    pub stderr: EncodedStream,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdapterReport {
    pub api_version: String,
    pub observation: StackObservation,
    pub inputs: Vec<InputArtifact>,
    pub executable: String,
    pub arguments: Vec<String>,
    pub version: ProcessRecord,
    pub verification: ProcessRecord,
    pub adapter_trace: Option<SourceInstrumentation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputArtifact {
    pub path: String,
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceInstrumentation {
    pub confidence: Confidence,
    pub instrumentation_scope: InstrumentationScope,
    pub events: Vec<SourceTraceEvent>,
    pub extensions: Vec<ObservedExtension>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum InstrumentationScope {
    Adapter,
    LibrarySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceTraceEvent {
    pub operation: String,
    pub target: String,
    pub algorithm: Option<String>,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedExtension {
    pub oid: String,
    pub critical: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticationLevel {
    Classical,
    Hybrid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerificationRequest {
    pub api_version: String,
    pub policy: Policy,
    pub path_scope: PathScope,
    pub validation_time: String,
    pub previous_authentication: Option<AuthenticationLevel>,
    pub revocation_policy: RevocationPolicy,
    pub stack: StackObservation,
    pub expected_trust_anchor: TrustAnchor,
    pub certificate_path: Vec<CertificateNode>,
    pub paired_authentications: Vec<PairedAuthentication>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairedAuthentication {
    pub operation_id: String,
    pub classical_certificate_id: String,
    pub post_quantum_certificate_der_sha256: String,
    pub same_authentication_operation: CheckResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyVerdict {
    ClassicalClaimSetSatisfied,
    HybridClaimSetSatisfied,
    Reject,
    Indeterminate,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailedCheck {
    pub evidence_id: String,
    pub check: String,
    pub state: CheckState,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerificationResult {
    pub api_version: String,
    pub policy: Policy,
    pub path_scope: PathScope,
    pub validation_time: String,
    pub previous_authentication: Option<AuthenticationLevel>,
    pub revocation_policy: RevocationPolicy,
    pub stack: StackObservation,
    pub expected_trust_anchor: TrustAnchor,
    pub certificate_path: Vec<CertificateNode>,
    pub paired_authentications: Vec<PairedAuthentication>,
    pub stack_verdict: StackVerdict,
    pub policy_verdict: PolicyVerdict,
    pub classical_only_fallback: bool,
    pub lifecycle_desynchronization: bool,
    pub evaluated_evidence: Vec<Evidence>,
    pub failed_checks: Vec<FailedCheck>,
    pub reason: String,
}
