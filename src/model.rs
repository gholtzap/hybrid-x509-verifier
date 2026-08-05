use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const API_VERSION: &str = "hybrid-x509-verifier/v1";

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
    IssuingPath,
    FullPath,
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
            Self::IssuingPath => position != PathPosition::TrustAnchor,
            Self::FullPath => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Scheme {
    Classical,
    PurePostQuantum,
    AtomicComposite,
    Catalyst,
    Chameleon,
    Related,
    Unknown,
}

impl Scheme {
    pub fn is_hybrid(self) -> bool {
        matches!(
            self,
            Self::AtomicComposite | Self::Catalyst | Self::Chameleon | Self::Related
        )
    }

    pub fn requires_classical(self) -> bool {
        matches!(
            self,
            Self::Classical
                | Self::AtomicComposite
                | Self::Catalyst
                | Self::Chameleon
                | Self::Related
        )
    }

    pub fn requires_post_quantum(self) -> bool {
        self == Self::PurePostQuantum || self.is_hybrid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateNode {
    pub id: String,
    pub position: PathPosition,
    pub scheme: Scheme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    pub kind: EvidenceKind,
    pub present: CheckResult,
    pub recognized: CheckResult,
    pub signature: CheckResult,
    pub binding: CheckResult,
    pub path: CheckResult,
    pub validity: CheckResult,
    pub revocation: CheckResult,
    pub outcome_bearing: CheckResult,
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
            ("outcome-bearing", self.outcome_bearing),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackObservation {
    pub adapter: String,
    pub version: String,
    pub verdict: StackVerdict,
    pub version_track: VersionTrack,
    pub validation_profile: ValidationProfile,
    pub execution_isolation: ExecutionIsolation,
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
    pub source_instrumentation: Option<SourceInstrumentation>,
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
    pub events: Vec<SourceTraceEvent>,
    pub extensions: Vec<ObservedExtension>,
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
    pub stack: StackObservation,
    pub certificate_path: Vec<CertificateNode>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyVerdict {
    AcceptClassical,
    AcceptHybrid,
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
    pub stack: StackObservation,
    pub certificate_path: Vec<CertificateNode>,
    pub stack_verdict: StackVerdict,
    pub policy_verdict: PolicyVerdict,
    pub classical_only_fallback: bool,
    pub lifecycle_desynchronization: bool,
    pub evaluated_evidence: Vec<Evidence>,
    pub failed_checks: Vec<FailedCheck>,
    pub reason: String,
}
