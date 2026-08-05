use crate::{CheckResult, CheckState, Confidence, PathScope, VerificationResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
