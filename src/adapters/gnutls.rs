use super::{
    AdapterExecution, AdapterSupportError, cached_version_output, container::isolated_arguments,
    record_inputs, resolve_executable, selected_path_hashes,
};
use crate::{
    CheckResult, CheckState, Confidence, ExecutionIsolation, StackObservation, StackVerdict,
    ValidationProfile, VersionTrack,
    input::{BoundedInputError, read_bounded_file},
    process::{ProcessLimits, ProcessOutput, run_program},
};
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct GnuTlsConfig {
    pub executable: PathBuf,
    pub trust_store: PathBuf,
    pub untrusted_chain: Option<PathBuf>,
    pub leaf: PathBuf,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct GnuTlsContainerConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

pub type GnuTlsStudyConfig = GnuTlsContainerConfig;

#[derive(Debug, Error)]
pub enum GnuTlsError {
    #[error("invalid RFC 3339 validation time: {0}")]
    InvalidValidationTime(String),
    #[error("GnuTLS version command did not complete successfully")]
    VersionFailed,
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Input(#[from] BoundedInputError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn verify(config: &GnuTlsConfig) -> Result<AdapterExecution, GnuTlsError> {
    let executable = resolve_executable(&config.executable)?;
    let mut input_paths = vec![config.trust_store.as_path(), config.leaf.as_path()];
    input_paths.extend(config.untrusted_chain.as_deref());
    let inputs = record_inputs(&input_paths)?;
    let (selected_path_der_sha256, trust_anchor_der_sha256) = selected_path_hashes(
        &config.leaf,
        config.untrusted_chain.as_deref(),
        &config.trust_store,
    )?;

    let limits = ProcessLimits {
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    };
    let version_output =
        cached_version_output(&executable, &[OsString::from("--version")], limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(GnuTlsError::VersionFailed);
    }
    let version = first_line(&version_output);

    let mut authorities = tempfile::NamedTempFile::new()?;
    authorities.write_all(&read_bounded_file(
        &config.trust_store,
        super::MAX_INPUT_BYTES as usize,
    )?)?;
    if let Some(path) = &config.untrusted_chain {
        authorities.write_all(b"\n")?;
        authorities.write_all(&read_bounded_file(path, super::MAX_INPUT_BYTES as usize)?)?;
    }
    authorities.flush()?;

    let arguments = vec![
        OsString::from("--verify"),
        OsString::from("--load-ca-certificate"),
        authorities.path().as_os_str().to_owned(),
        OsString::from("--infile"),
        config.leaf.as_os_str().to_owned(),
    ];
    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: "gnutls".to_owned(),
            version,
            verdict,
            version_track: VersionTrack::UserSupplied,
            validation_profile: ValidationProfile::X509Path,
            execution_isolation: ExecutionIsolation::ProcessOnly,
            selected_path_der_sha256,
            selected_path_source: crate::PathObservationSource::PresentedInput,
            trust_anchor_der_sha256,
            applied_validation_time: String::new(),
            validation_time: CheckResult {
                state: CheckState::NotChecked,
                confidence: Confidence::Observed,
            },
        },
        inputs,
        executable,
        arguments,
        version_output,
        verification_output,
    })
}

pub fn verify_container(config: &GnuTlsContainerConfig) -> Result<AdapterExecution, GnuTlsError> {
    verify_container_as(config, "gnutls-current", VersionTrack::Current)
}

pub fn verify_study(config: &GnuTlsStudyConfig) -> Result<AdapterExecution, GnuTlsError> {
    verify_container_as(config, "gnutls-study", VersionTrack::Study)
}

fn verify_container_as(
    config: &GnuTlsContainerConfig,
    adapter: &str,
    version_track: VersionTrack,
) -> Result<AdapterExecution, GnuTlsError> {
    let executable = resolve_executable(&config.docker)?;
    let inputs = record_inputs(&[
        config.trust_store.as_path(),
        config.intermediate.as_path(),
        config.leaf.as_path(),
    ])?;
    let (selected_path_der_sha256, trust_anchor_der_sha256) = selected_path_hashes(
        &config.leaf,
        Some(&config.intermediate),
        &config.trust_store,
    )?;
    let validation_time = chrono::DateTime::parse_from_rfc3339(&config.validation_time)
        .map_err(|_| GnuTlsError::InvalidValidationTime(config.validation_time.clone()))?
        .with_timezone(&chrono::Utc)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
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
    let version_output = cached_version_output(&executable, &version_arguments, limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(GnuTlsError::VersionFailed);
    }
    let version = first_line(&version_output);
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
            OsString::from(validation_time),
        ],
    )?;
    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: adapter.to_owned(),
            version,
            verdict,
            version_track,
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

fn first_line(output: &ProcessOutput) -> String {
    String::from_utf8_lossy(&output.stdout.bytes)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn classify(output: &ProcessOutput) -> StackVerdict {
    if output.timed_out || output.stdout.truncated || output.stderr.truncated {
        return StackVerdict::Indeterminate;
    }
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout.bytes),
        String::from_utf8_lossy(&output.stderr.bytes)
    );
    if output.status_code == Some(0)
        && message.contains("Chain verification output: Verified. The certificate is trusted.")
    {
        StackVerdict::Accept
    } else if message.to_lowercase().contains("unsupported")
        || ["2.16.840.1.101.3.4.3.17", "1.3.6.1.5.5.7.6.40"]
            .iter()
            .any(|oid| message.contains(&format!("Signature algorithm: {oid}")))
    {
        StackVerdict::Unsupported
    } else {
        StackVerdict::Reject
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/paper-v1.0.2")
            .join(name)
    }

    #[test]
    fn accepts_the_valid_classical_path_of_a_related_certificate() {
        let _guard = crate::adapter_test_lock();
        let result = verify(&GnuTlsConfig {
            executable: "/opt/homebrew/opt/gnutls/bin/gnutls-certtool".into(),
            trust_store: fixture("root.pem"),
            untrusted_chain: Some(fixture("ica.pem")),
            leaf: fixture("related-certA.pem"),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(result.observation.verdict, StackVerdict::Accept);
        assert!(result.observation.version.contains("3.8.13"));
    }

    #[test]
    fn current_container_accepts_the_valid_related_path() {
        let _guard = crate::adapter_test_lock();
        let result = verify_container(&GnuTlsContainerConfig {
            docker: "docker".into(),
            image: "hybrid-x509-gnutls:3.8.13".to_owned(),
            trust_store: fixture("root.pem"),
            intermediate: fixture("ica.pem"),
            leaf: fixture("related-certA.pem"),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(result.observation.verdict, StackVerdict::Accept);
        assert!(result.observation.version.contains("3.8.13"));
        assert_eq!(result.observation.version_track, VersionTrack::Current);
    }
}
