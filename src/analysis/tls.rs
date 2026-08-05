use crate::{
    AdapterReport, CheckResult, CheckState, Confidence, StackVerdict,
    adapters::{
        AdapterSupportError,
        bouncy_castle::{
            BouncyCastleConfig, BouncyCastleError, BouncyCastleMode, verify as verify_bouncy_castle,
        },
        openssl::{OpenSslError, OpenSslTlsConfig, verify_tls},
    },
    pem::{PemError, PemKind, read_der},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};
use thiserror::Error;

const INPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsHandshakeEvidence {
    pub report: AdapterReport,
    pub certificate_sha256: String,
    pub certificate_subject: Option<String>,
    pub protocol: Option<String>,
    pub cipher_suite: Option<String>,
    pub authentication_signature: Option<String>,
    pub key_exchange_group: Option<String>,
    pub certificate_selection: CheckResult,
    pub hostname_verification: CheckResult,
    pub proof_of_possession: CheckResult,
    pub transcript_binding: CheckResult,
}

#[derive(Debug, Clone)]
pub struct TlsTranscriptConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub private_key: PathBuf,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsTranscriptEvidence {
    pub report: AdapterReport,
    pub valid_handshake: CheckResult,
    pub altered_transcript_rejected: CheckResult,
    pub incompatible_signature_rejected: CheckResult,
    pub signature: Option<String>,
    pub binding: CheckResult,
}

#[derive(Debug, Deserialize)]
struct TlsTranscriptOutput {
    verdict: String,
    valid_handshake: String,
    altered_transcript_handshake: String,
    incompatible_signature_handshake: String,
    signature: String,
}

#[derive(Debug, Error)]
pub enum TlsObservationError {
    #[error(transparent)]
    OpenSsl(#[from] OpenSslError),
    #[error(transparent)]
    BouncyCastle(#[from] BouncyCastleError),
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Pem(#[from] PemError),
}

pub fn observe_transcript(
    config: &TlsTranscriptConfig,
) -> Result<TlsTranscriptEvidence, TlsObservationError> {
    let execution = verify_bouncy_castle(&BouncyCastleConfig {
        docker: config.docker.clone(),
        image: config.image.clone(),
        trust_store: config.trust_store.clone(),
        intermediate: config.intermediate.clone(),
        leaf: config.leaf.clone(),
        validation_time: config.validation_time.clone(),
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
        mode: BouncyCastleMode::TlsTranscript,
        private_key: Some(config.private_key.clone()),
        crl: None,
    })?;
    let parsed =
        serde_json::from_slice::<TlsTranscriptOutput>(&execution.verification_output.stdout.bytes)
            .ok();
    let established = execution.observation.verdict == StackVerdict::Accept
        && parsed.as_ref().is_some_and(|output| {
            output.verdict == "accept"
                && output.valid_handshake == "accept"
                && output.altered_transcript_handshake == "reject"
                && output.incompatible_signature_handshake == "reject"
        });
    Ok(TlsTranscriptEvidence {
        report: execution.report()?,
        valid_handshake: behavioral_check(established),
        altered_transcript_rejected: behavioral_check(established),
        incompatible_signature_rejected: behavioral_check(established),
        signature: parsed.map(|output| output.signature),
        binding: behavioral_check(established),
    })
}

pub fn observe(config: &OpenSslTlsConfig) -> Result<TlsHandshakeEvidence, TlsObservationError> {
    let execution = verify_tls(config)?;
    let accepted = execution.observation.verdict == StackVerdict::Accept;
    let output = String::from_utf8_lossy(&execution.verification_output.stdout.bytes);
    let authentication_signature = line_value(&output, "Signature type: ");
    let complete = accepted
        && line_value(&output, "Verification: ").as_deref() == Some("OK")
        && line_value(&output, "Verified peername: ").as_deref() == Some(config.hostname.as_str());
    let certificate_der = read_der(&config.leaf, PemKind::Certificate, INPUT_LIMIT)?;

    Ok(TlsHandshakeEvidence {
        report: execution.report()?,
        certificate_sha256: sha256_hex(&certificate_der),
        certificate_subject: line_value(&output, "Peer certificate: "),
        protocol: line_value(&output, "Protocol version: "),
        cipher_suite: line_value(&output, "Ciphersuite: "),
        authentication_signature: authentication_signature.clone(),
        key_exchange_group: line_value(&output, "Negotiated TLS1.3 group: "),
        certificate_selection: behavioral_check(complete),
        hostname_verification: CheckResult::observed(if complete {
            CheckState::Pass
        } else {
            CheckState::Indeterminate
        }),
        proof_of_possession: behavioral_check(complete && authentication_signature.is_some()),
        transcript_binding: if complete && authentication_signature.is_some() {
            CheckResult {
                state: CheckState::Pass,
                confidence: Confidence::Inferred,
            }
        } else {
            CheckResult {
                state: CheckState::Indeterminate,
                confidence: Confidence::Unknown,
            }
        },
    })
}

fn line_value(output: &str, prefix: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix).map(str::to_owned))
}

fn behavioral_check(established: bool) -> CheckResult {
    if established {
        CheckResult {
            state: CheckState::Pass,
            confidence: Confidence::BehaviorallyEstablished,
        }
    } else {
        CheckResult {
            state: CheckState::Indeterminate,
            confidence: Confidence::Unknown,
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
