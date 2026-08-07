use crate::input::{BoundedInputError, read_bounded_file};
use crate::{
    API_VERSION, AdapterReport, Confidence, InputArtifact, InstrumentationScope, ObservedExtension,
    ProcessRecord, SourceInstrumentation, SourceTraceEvent, StackObservation, TrustAnchor,
    pem::{PemError, PemKind, read_der},
    process::ProcessOutput,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::OsString,
    fmt::Write as _,
    io,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
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
            adapter_trace: adapter_trace(&self.verification_output),
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
    Pem(#[from] PemError),
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

pub(crate) fn certificate_sha256(path: &Path) -> Result<String, AdapterSupportError> {
    let bytes = read_der(path, PemKind::Certificate, MAX_INPUT_BYTES as usize)?;
    Ok(hex_lower(&Sha256::digest(&bytes)))
}

pub(crate) fn selected_path_hashes(
    leaf: &Path,
    intermediate: Option<&Path>,
    trust_anchor: &Path,
) -> Result<(Vec<String>, TrustAnchor), AdapterSupportError> {
    let leaf = certificate_sha256(leaf)?;
    let intermediate = intermediate.map(certificate_sha256).transpose()?;
    let trust_anchor = certificate_sha256(trust_anchor)?;
    let mut certification_path = vec![leaf];
    certification_path.extend(intermediate);
    Ok((
        certification_path,
        TrustAnchor::CertificateDerSha256 {
            der_sha256: trust_anchor,
        },
    ))
}

pub(crate) fn cached_version_output(
    executable: &Path,
    arguments: &[OsString],
    limits: crate::process::ProcessLimits,
) -> io::Result<ProcessOutput> {
    static CACHE: OnceLock<Mutex<HashMap<String, ProcessOutput>>> = OnceLock::new();
    let key = version_cache_key(executable, arguments);
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(output) = cache
        .lock()
        .map_err(|_| io::Error::other("adapter version cache is poisoned"))?
        .get(&key)
        .cloned()
    {
        return Ok(output);
    }
    let output = crate::process::run_program(executable, arguments, limits)?;
    if output.status_code == Some(0)
        && !output.timed_out
        && !output.stdout.truncated
        && !output.stderr.truncated
    {
        cache
            .lock()
            .map_err(|_| io::Error::other("adapter version cache is poisoned"))?
            .insert(key, output.clone());
    }
    Ok(output)
}

fn version_cache_key(executable: &Path, arguments: &[OsString]) -> String {
    let mut key = executable.display().to_string();
    for argument in arguments {
        key.push('\0');
        key.push_str(&argument.to_string_lossy());
    }
    key
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

fn adapter_trace(output: &ProcessOutput) -> Option<SourceInstrumentation> {
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
        instrumentation_scope: InstrumentationScope::Adapter,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessLimits;
    use std::{ffi::OsString, time::Duration};

    #[test]
    fn version_output_is_cached_by_command() {
        let directory = tempfile::tempdir().unwrap();
        let count = directory.path().join("count");
        let script = directory.path().join("version.sh");
        std::fs::write(
            &script,
            format!(
                "count=$(cat '{}' 2>/dev/null || echo 0)\ncount=$((count + 1))\nprintf '%s' \"$count\" > '{}'\nprintf 'cached-version'\n",
                count.display(),
                count.display()
            ),
        )
        .unwrap();
        let arguments = [OsString::from(script.as_os_str())];
        let limits = ProcessLimits {
            timeout: Duration::from_secs(1),
            max_output_bytes: 1024,
        };

        let first = cached_version_output(Path::new("/bin/sh"), &arguments, limits).unwrap();
        let second = cached_version_output(Path::new("/bin/sh"), &arguments, limits).unwrap();

        assert_eq!(first.stdout.bytes, b"cached-version");
        assert_eq!(second.stdout.bytes, b"cached-version");
        assert_eq!(std::fs::read_to_string(count).unwrap(), "1");
    }

    #[test]
    fn failed_version_output_is_not_cached() {
        let directory = tempfile::tempdir().unwrap();
        let count = directory.path().join("count");
        let script = directory.path().join("version.sh");
        std::fs::write(
            &script,
            format!(
                "count=$(cat '{}' 2>/dev/null || echo 0)\ncount=$((count + 1))\nprintf '%s' \"$count\" > '{}'\nif [ \"$count\" = 1 ]; then exit 7; fi\nprintf 'cached-version'\n",
                count.display(),
                count.display()
            ),
        )
        .unwrap();
        let arguments = [OsString::from(script.as_os_str())];
        let limits = ProcessLimits {
            timeout: Duration::from_secs(1),
            max_output_bytes: 1024,
        };

        let first = cached_version_output(Path::new("/bin/sh"), &arguments, limits).unwrap();
        let second = cached_version_output(Path::new("/bin/sh"), &arguments, limits).unwrap();
        let third = cached_version_output(Path::new("/bin/sh"), &arguments, limits).unwrap();

        assert_eq!(first.status_code, Some(7));
        assert_eq!(second.stdout.bytes, b"cached-version");
        assert_eq!(third.stdout.bytes, b"cached-version");
        assert_eq!(std::fs::read_to_string(count).unwrap(), "2");
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
