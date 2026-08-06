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
pub struct PycaConfig {
    pub python: PathBuf,
    pub script: PathBuf,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub dns_name: String,
    pub validation_time: String,
    pub hybrid_extension_oid: Option<String>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct PycaContainerConfig {
    pub docker: PathBuf,
    pub image: String,
    pub release: PycaRelease,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub dns_name: String,
    pub validation_time: String,
    pub hybrid_extension_oid: Option<String>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PycaRelease {
    Study49,
    Current50,
}

#[derive(Debug, Error)]
pub enum PycaError {
    #[error("Python cryptography adapter version command did not complete successfully")]
    VersionFailed,
    #[error("invalid RFC 3339 validation time: {0}")]
    InvalidValidationTime(String),
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn verify(config: &PycaConfig) -> Result<AdapterExecution, PycaError> {
    let executable = resolve_executable(&config.python)?;
    let inputs = record_inputs(&[
        config.script.as_path(),
        config.trust_store.as_path(),
        config.intermediate.as_path(),
        config.leaf.as_path(),
    ])?;
    let (selected_path_der_sha256, trust_anchor_der_sha256) = selected_path_hashes(
        &config.leaf,
        Some(&config.intermediate),
        &config.trust_store,
    )?;
    let limits = ProcessLimits {
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    };
    let version_arguments = vec![
        config.script.as_os_str().to_owned(),
        OsString::from("--version"),
    ];
    let version_output = cached_version_output(&executable, &version_arguments, limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(PycaError::VersionFailed);
    }
    let version = String::from_utf8_lossy(&version_output.stdout.bytes)
        .trim()
        .to_owned();
    let mut arguments = vec![
        config.script.as_os_str().to_owned(),
        OsString::from("--root"),
        config.trust_store.as_os_str().to_owned(),
        OsString::from("--intermediate"),
        config.intermediate.as_os_str().to_owned(),
        OsString::from("--leaf"),
        config.leaf.as_os_str().to_owned(),
        OsString::from("--dns"),
        OsString::from(&config.dns_name),
        OsString::from("--time"),
        OsString::from(&config.validation_time),
    ];
    if let Some(oid) = &config.hybrid_extension_oid {
        arguments.extend([
            OsString::from("--hybrid-extension-oid"),
            OsString::from(oid),
        ]);
    }
    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify_json_verdict(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: "pyca-cryptography".to_owned(),
            version,
            verdict,
            version_track: VersionTrack::UserSupplied,
            validation_profile: ValidationProfile::WebPkiServer,
            execution_isolation: ExecutionIsolation::ProcessOnly,
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

pub fn verify_container(config: &PycaContainerConfig) -> Result<AdapterExecution, PycaError> {
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
    chrono::DateTime::parse_from_rfc3339(&config.validation_time)
        .map_err(|_| PycaError::InvalidValidationTime(config.validation_time.clone()))?;
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
        isolated_arguments(&config.image, &[], &[OsString::from("--version")])?;
    let version_output = cached_version_output(&executable, &version_arguments, limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(PycaError::VersionFailed);
    }
    let version = String::from_utf8_lossy(&version_output.stdout.bytes)
        .trim()
        .to_owned();
    let mut command = vec![
        OsString::from("--root"),
        OsString::from("/input/root.pem"),
        OsString::from("--intermediate"),
        OsString::from("/input/intermediate.pem"),
        OsString::from("--leaf"),
        OsString::from("/input/leaf.pem"),
        OsString::from("--dns"),
        OsString::from(&config.dns_name),
        OsString::from("--time"),
        OsString::from(&config.validation_time),
    ];
    if let Some(oid) = &config.hybrid_extension_oid {
        command.extend([
            OsString::from("--hybrid-extension-oid"),
            OsString::from(oid),
        ]);
    }
    let arguments = isolated_arguments(&config.image, &mounts, &command)?;
    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify_json_verdict(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: match config.release {
                PycaRelease::Study49 => "pyca-cryptography-study",
                PycaRelease::Current50 => "pyca-cryptography-current",
            }
            .to_owned(),
            version,
            verdict,
            version_track: match config.release {
                PycaRelease::Study49 => VersionTrack::Study,
                PycaRelease::Current50 => VersionTrack::Current,
            },
            validation_profile: ValidationProfile::WebPkiServer,
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

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/paper-v1.0.2")
            .join(name)
    }

    #[test]
    fn accepts_the_valid_classical_path_of_a_related_certificate() {
        let _guard = crate::adapter_test_lock();
        let result = verify(&PycaConfig {
            python: "python3".into(),
            script: Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/pyca-x509-adapter.py"),
            trust_store: fixture("root.pem"),
            intermediate: fixture("ica.pem"),
            leaf: fixture("related-certA.pem"),
            dns_name: "related-a.pqc-probe.test".to_owned(),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            hybrid_extension_oid: Some("1.3.6.1.5.5.7.1.36".to_owned()),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(result.observation.verdict, StackVerdict::Accept);
        assert_eq!(result.observation.version, "46.0.4");
        let instrumentation = result.report().unwrap().source_instrumentation.unwrap();
        assert_eq!(
            instrumentation.events[0].operation,
            "verify-server-certificate-path"
        );
        assert!(
            instrumentation
                .extensions
                .iter()
                .any(|extension| extension.oid == "1.3.6.1.5.5.7.1.36")
        );
    }
}
