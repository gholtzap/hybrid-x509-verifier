use super::{
    AdapterExecution, AdapterSupportError, cached_version_output, classify_json_verdict,
    container::isolated_arguments, record_inputs, resolve_executable, selected_path_hashes,
};
use crate::{
    CheckResult, CheckState, ExecutionIsolation, StackObservation, ValidationProfile, VersionTrack,
    process::{ProcessLimits, run_program},
};
use std::{ffi::OsString, io, path::PathBuf, time::Duration};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct WolfSslConfig {
    pub docker: PathBuf,
    pub image: String,
    pub mode: WolfSslMode,
    pub scheme: String,
    pub trust_store: PathBuf,
    pub intermediate: Option<PathBuf>,
    pub leaf: PathBuf,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WolfSslMode {
    Default,
    DualAlgorithm,
}

impl WolfSslMode {
    fn argument(self) -> &'static str {
        match self {
            Self::Default => "mode1",
            Self::DualAlgorithm => "mode2",
        }
    }
}

#[derive(Debug, Error)]
pub enum WolfSslError {
    #[error("invalid RFC 3339 validation time: {0}")]
    InvalidValidationTime(String),
    #[error("wolfSSL version command did not complete successfully")]
    VersionFailed,
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn verify(config: &WolfSslConfig) -> Result<AdapterExecution, WolfSslError> {
    let executable = resolve_executable(&config.docker)?;
    let mut input_paths = vec![config.trust_store.as_path(), config.leaf.as_path()];
    input_paths.extend(config.intermediate.as_deref());
    let inputs = record_inputs(&input_paths)?;
    let (selected_path_der_sha256, trust_anchor_der_sha256) = selected_path_hashes(
        &config.leaf,
        config.intermediate.as_deref(),
        &config.trust_store,
    )?;
    let validation_time = chrono::DateTime::parse_from_rfc3339(&config.validation_time)
        .map_err(|_| WolfSslError::InvalidValidationTime(config.validation_time.clone()))?
        .with_timezone(&chrono::Utc)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let limits = ProcessLimits {
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    };
    let mut mounts = vec![
        (config.trust_store.as_path(), "/input/root.pem"),
        (config.leaf.as_path(), "/input/leaf.pem"),
    ];
    if let Some(intermediate) = &config.intermediate {
        mounts.push((intermediate.as_path(), "/input/intermediate.pem"));
    }
    let version_arguments = isolated_arguments(
        &config.image,
        &[],
        &[
            OsString::from(config.mode.argument()),
            OsString::from("--version"),
        ],
    )?;
    let version_output = cached_version_output(&executable, &version_arguments, limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(WolfSslError::VersionFailed);
    }
    let version = String::from_utf8_lossy(&version_output.stdout.bytes)
        .trim()
        .to_owned();
    let mut command = vec![
        OsString::from(config.mode.argument()),
        OsString::from(validation_time),
        OsString::from("--scheme"),
        OsString::from(&config.scheme),
        OsString::from("--root"),
        OsString::from("/input/root.pem"),
    ];
    if config.intermediate.is_some() {
        command.extend([
            OsString::from("--ca"),
            OsString::from("/input/intermediate.pem"),
        ]);
    }
    command.extend([OsString::from("--leaf"), OsString::from("/input/leaf.pem")]);
    let arguments = isolated_arguments(&config.image, &mounts, &command)?;
    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify_json_verdict(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: format!("wolfssl-{}", config.mode.argument()),
            version,
            verdict,
            version_track: VersionTrack::CurrentAndStudy,
            validation_profile: ValidationProfile::X509Path,
            execution_isolation: ExecutionIsolation::Container,
            selected_path_der_sha256,
            selected_path_source: crate::PathObservationSource::PresentedInput,
            trust_anchor_der_sha256,
            applied_validation_time: config.validation_time.clone(),
            validation_time: CheckResult::observed(CheckState::Pass),
        },
        inputs,
        executable,
        arguments,
        version_output,
        verification_output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StackVerdict;
    use std::path::Path;

    #[test]
    fn reproduces_the_published_wolfssl_roundtrip() {
        let _guard = crate::adapter_test_lock();
        let fixtures =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2/wolfgen");
        for (mode, leaf, expected) in [
            (
                WolfSslMode::Default,
                "wolfgen-leaf-good.pem",
                StackVerdict::Accept,
            ),
            (
                WolfSslMode::Default,
                "wolfgen-leaf-bad.pem",
                StackVerdict::Accept,
            ),
            (
                WolfSslMode::DualAlgorithm,
                "wolfgen-leaf-good.pem",
                StackVerdict::Accept,
            ),
            (
                WolfSslMode::DualAlgorithm,
                "wolfgen-leaf-bad.pem",
                StackVerdict::Reject,
            ),
        ] {
            let result = verify(&WolfSslConfig {
                docker: "docker".into(),
                image: "hybrid-x509-wolfssl:5.9.2".to_owned(),
                mode,
                scheme: "catalyst-wolfgen".to_owned(),
                trust_store: fixtures.join("wolfgen-ca.pem"),
                intermediate: None,
                leaf: fixtures.join(leaf),
                validation_time: "2026-07-07T11:59:59Z".to_owned(),
                timeout: Duration::from_secs(5),
                max_output_bytes: 64 * 1024,
            })
            .unwrap();

            assert_eq!(result.observation.verdict, expected, "{mode:?} {leaf}");
        }
    }
}
