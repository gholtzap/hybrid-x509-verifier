use super::{
    AdapterExecution, AdapterSupportError, classify_json_verdict, container::isolated_arguments,
    record_inputs, resolve_executable,
};
use crate::{
    CheckResult, CheckState, ExecutionIsolation, StackObservation, ValidationProfile, VersionTrack,
    process::{ProcessLimits, run_program},
};
use chrono::{DateTime, Timelike, Utc};
use std::{ffi::OsString, io, path::PathBuf, time::Duration};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct NssConfig {
    pub docker: PathBuf,
    pub image: String,
    pub release: NssRelease,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssRelease {
    Study98,
    Current126,
}

#[derive(Debug, Error)]
pub enum NssError {
    #[error("invalid RFC 3339 validation time: {0}")]
    InvalidValidationTime(String),
    #[error("NSS validation time has one-minute precision; seconds must be zero")]
    InvalidTimePrecision,
    #[error("NSS adapter version command did not complete successfully")]
    VersionFailed,
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn verify(config: &NssConfig) -> Result<AdapterExecution, NssError> {
    let executable = resolve_executable(&config.docker)?;
    let inputs = record_inputs(&[
        config.trust_store.as_path(),
        config.intermediate.as_path(),
        config.leaf.as_path(),
    ])?;
    let time = DateTime::parse_from_rfc3339(&config.validation_time)
        .map_err(|_| NssError::InvalidValidationTime(config.validation_time.clone()))?
        .with_timezone(&Utc);
    if time.second() != 0 || time.nanosecond() != 0 {
        return Err(NssError::InvalidTimePrecision);
    }
    let limits = ProcessLimits {
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    };
    let mounts = [
        (config.trust_store.as_path(), "/input/root.pem"),
        (config.intermediate.as_path(), "/input/intermediate.pem"),
        (config.leaf.as_path(), "/input/leaf.pem"),
    ];
    let version_arguments =
        isolated_arguments(&config.image, &mounts, &[OsString::from("--version")])?;
    let version_output = run_program(&executable, &version_arguments, limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(NssError::VersionFailed);
    }
    let version = String::from_utf8_lossy(&version_output.stdout.bytes)
        .trim()
        .to_owned();
    let arguments = isolated_arguments(
        &config.image,
        &mounts,
        &[
            OsString::from("--root"),
            OsString::from("/input/root.pem"),
            OsString::from("--intermediate"),
            OsString::from("/input/intermediate.pem"),
            OsString::from("--leaf"),
            OsString::from("/input/leaf.pem"),
            OsString::from("--time"),
            OsString::from(time.format("%y%m%d%H%MZ").to_string()),
        ],
    )?;
    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify_json_verdict(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: match config.release {
                NssRelease::Study98 => "mozilla-nss-study",
                NssRelease::Current126 => "mozilla-nss-current",
            }
            .to_owned(),
            version,
            verdict,
            version_track: match config.release {
                NssRelease::Study98 => VersionTrack::Study,
                NssRelease::Current126 => VersionTrack::Current,
            },
            validation_profile: ValidationProfile::WebPkiServer,
            execution_isolation: ExecutionIsolation::Container,
            validation_time: CheckResult::observed(CheckState::Pass),
        },
        inputs,
        executable,
        arguments,
        version_output,
        verification_output,
    })
}
