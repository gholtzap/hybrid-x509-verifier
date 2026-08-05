use crate::input::{BoundedInputError, read_bounded_file};
use crate::{
    API_VERSION, AdapterReport, Confidence, InputArtifact, ObservedExtension, ProcessRecord,
    SourceInstrumentation, SourceTraceEvent, StackObservation, process::ProcessOutput,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fmt::Write as _,
    io,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct AdapterExecution {
    pub observation: StackObservation,
    pub inputs: Vec<InputArtifact>,
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub version_output: ProcessOutput,
    pub verification_output: ProcessOutput,
}

impl AdapterExecution {
    pub fn report(&self) -> Result<AdapterReport, AdapterSupportError> {
        Ok(AdapterReport {
            api_version: API_VERSION.to_owned(),
            observation: self.observation.clone(),
            inputs: self.inputs.clone(),
            executable: self
                .executable
                .to_str()
                .ok_or(AdapterSupportError::NonUtf8Command)?
                .to_owned(),
            arguments: self
                .arguments
                .iter()
                .map(|argument| {
                    argument
                        .to_str()
                        .map(str::to_owned)
                        .ok_or(AdapterSupportError::NonUtf8Command)
                })
                .collect::<Result<_, _>>()?,
            version: ProcessRecord::from(&self.version_output),
            verification: ProcessRecord::from(&self.verification_output),
            source_instrumentation: source_instrumentation(&self.verification_output),
        })
    }
}

#[derive(Debug, Error)]
pub enum AdapterSupportError {
    #[error("executable was not found: {0}")]
    ExecutableNotFound(PathBuf),
    #[error("a command path or argument is not valid UTF-8")]
    NonUtf8Command,
    #[error(transparent)]
    Input(#[from] BoundedInputError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub(crate) fn record_inputs(paths: &[&Path]) -> Result<Vec<InputArtifact>, AdapterSupportError> {
    paths
        .iter()
        .map(|path| {
            let bytes = read_bounded_file(path, MAX_INPUT_BYTES as usize)?;
            Ok(InputArtifact {
                path: path
                    .to_str()
                    .ok_or(AdapterSupportError::NonUtf8Command)?
                    .to_owned(),
                bytes: bytes.len(),
                sha256: hex_lower(&Sha256::digest(&bytes)),
            })
        })
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

pub(crate) fn resolve_executable(path: &Path) -> Result<PathBuf, AdapterSupportError> {
    if path.components().count() > 1 {
        return path
            .is_file()
            .then(|| path.to_owned())
            .ok_or_else(|| AdapterSupportError::ExecutableNotFound(path.to_owned()));
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .map(|directory| directory.join(path))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| AdapterSupportError::ExecutableNotFound(path.to_owned()))
}

#[derive(Debug, Deserialize)]
struct JsonVerdict {
    verdict: String,
}

#[derive(Debug, Deserialize)]
struct InstrumentedOutput {
    trace: Vec<SourceTraceEvent>,
    #[serde(default)]
    extensions: Vec<ObservedExtension>,
}

fn source_instrumentation(output: &ProcessOutput) -> Option<SourceInstrumentation> {
    if output.timed_out
        || output.stdout.truncated
        || output.stderr.truncated
        || output.status_code != Some(0)
    {
        return None;
    }
    let parsed = serde_json::from_slice::<InstrumentedOutput>(&output.stdout.bytes).ok()?;
    Some(SourceInstrumentation {
        confidence: Confidence::Observed,
        events: parsed.trace,
        extensions: parsed.extensions,
    })
}

pub(crate) fn classify_json_verdict(output: &ProcessOutput) -> crate::StackVerdict {
    if output.timed_out
        || output.stdout.truncated
        || output.stderr.truncated
        || output.status_code != Some(0)
    {
        return crate::StackVerdict::Indeterminate;
    }
    match serde_json::from_slice::<JsonVerdict>(&output.stdout.bytes)
        .ok()
        .map(|result| result.verdict)
        .as_deref()
    {
        Some("accept") => crate::StackVerdict::Accept,
        Some("reject") => crate::StackVerdict::Reject,
        Some("unsupported") => crate::StackVerdict::Unsupported,
        _ => crate::StackVerdict::Indeterminate,
    }
}

pub(crate) fn check_from_verdict(verdict: crate::StackVerdict) -> crate::CheckResult {
    match verdict {
        crate::StackVerdict::Accept => crate::CheckResult::observed(crate::CheckState::Pass),
        crate::StackVerdict::Reject => crate::CheckResult::observed(crate::CheckState::Fail),
        crate::StackVerdict::Indeterminate | crate::StackVerdict::Unsupported => {
            crate::CheckResult {
                state: crate::CheckState::Indeterminate,
                confidence: crate::Confidence::Observed,
            }
        }
    }
}

pub mod bouncy_castle;
mod container;
pub mod gnutls;
pub mod go_x509;
pub mod nss;
pub mod openssl;
pub mod oqs_provider;
pub mod pyca;
pub mod wolfssl;
