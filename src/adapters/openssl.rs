use super::{
    AdapterExecution, AdapterSupportError, cached_version_output, container::isolated_arguments,
    record_inputs, resolve_executable, selected_path_hashes,
};
use crate::{
    CheckResult, CheckState, ExecutionIsolation, StackObservation, StackVerdict, ValidationProfile,
    VersionTrack,
    process::{ProcessLimits, ProcessOutput, run_program},
};
use chrono::DateTime;
use std::{ffi::OsString, io, path::PathBuf, time::Duration};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct OpenSslConfig {
    pub executable: PathBuf,
    pub trust_store: PathBuf,
    pub untrusted_chain: Option<PathBuf>,
    pub leaf: PathBuf,
    pub crl: Option<PathBuf>,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct OpenSslContainerConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub crl: Option<PathBuf>,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

pub type OpenSslStudyConfig = OpenSslContainerConfig;

#[derive(Debug, Clone)]
pub struct OpenSslTlsConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub private_key: PathBuf,
    pub hostname: String,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

pub type OpenSslResult = AdapterExecution;

#[derive(Debug, Error)]
pub enum OpenSslError {
    #[error("invalid RFC 3339 validation time: {0}")]
    InvalidValidationTime(String),
    #[error("TLS hostname is empty")]
    EmptyHostname,
    #[error("OpenSSL version command did not complete successfully")]
    VersionFailed,
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn verify(config: &OpenSslConfig) -> Result<OpenSslResult, OpenSslError> {
    let executable = resolve_executable(&config.executable)?;
    let mut input_paths = vec![config.trust_store.as_path(), config.leaf.as_path()];
    input_paths.extend(config.untrusted_chain.as_deref());
    input_paths.extend(config.crl.as_deref());
    let inputs = record_inputs(&input_paths)?;
    let (selected_path_der_sha256, trust_anchor_der_sha256) = selected_path_hashes(
        &config.leaf,
        config.untrusted_chain.as_deref(),
        &config.trust_store,
    )?;

    let validation_time = DateTime::parse_from_rfc3339(&config.validation_time)
        .map_err(|_| OpenSslError::InvalidValidationTime(config.validation_time.clone()))?;
    let limits = ProcessLimits {
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    };
    let version_output = cached_version_output(&executable, &[OsString::from("version")], limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(OpenSslError::VersionFailed);
    }
    let version = String::from_utf8_lossy(&version_output.stdout.bytes)
        .trim()
        .to_owned();

    let mut arguments = vec![
        OsString::from("verify"),
        OsString::from("-attime"),
        OsString::from(validation_time.timestamp().to_string()),
        OsString::from("-CAfile"),
        config.trust_store.as_os_str().to_owned(),
    ];
    if let Some(path) = &config.untrusted_chain {
        arguments.extend([OsString::from("-untrusted"), path.as_os_str().to_owned()]);
    }
    if let Some(path) = &config.crl {
        arguments.extend([
            OsString::from("-crl_check"),
            OsString::from("-CRLfile"),
            path.as_os_str().to_owned(),
        ]);
    }
    arguments.push(config.leaf.as_os_str().to_owned());

    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: "openssl".to_owned(),
            version,
            verdict,
            version_track: VersionTrack::UserSupplied,
            validation_profile: ValidationProfile::X509Path,
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

pub fn verify_container(config: &OpenSslContainerConfig) -> Result<OpenSslResult, OpenSslError> {
    verify_container_as(config, "openssl-current", VersionTrack::Current)
}

pub fn verify_study(config: &OpenSslStudyConfig) -> Result<OpenSslResult, OpenSslError> {
    verify_container_with_prefix(
        config,
        "openssl-study",
        VersionTrack::Study,
        &[OsString::from("--default-only")],
    )
}

pub fn verify_tls(config: &OpenSslTlsConfig) -> Result<OpenSslResult, OpenSslError> {
    if config.hostname.is_empty() {
        return Err(OpenSslError::EmptyHostname);
    }
    let validation_time = DateTime::parse_from_rfc3339(&config.validation_time)
        .map_err(|_| OpenSslError::InvalidValidationTime(config.validation_time.clone()))?;
    let executable = resolve_executable(&config.docker)?;
    let inputs = record_inputs(&[
        config.trust_store.as_path(),
        config.intermediate.as_path(),
        config.leaf.as_path(),
        config.private_key.as_path(),
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
    let mounts = [
        (config.trust_store.as_path(), "/input/root.pem"),
        (config.intermediate.as_path(), "/input/intermediate.pem"),
        (config.leaf.as_path(), "/input/leaf.pem"),
        (config.private_key.as_path(), "/input/key.pem"),
    ];
    let version_arguments =
        isolated_arguments(&config.image, &mounts, &[OsString::from("--version")])?;
    let version_output = cached_version_output(&executable, &version_arguments, limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(OpenSslError::VersionFailed);
    }
    let version = String::from_utf8_lossy(&version_output.stdout.bytes)
        .trim()
        .to_owned();
    let arguments = isolated_arguments(
        &config.image,
        &mounts,
        &[
            OsString::from("--tls-server-client"),
            OsString::from("/input/root.pem"),
            OsString::from("/input/intermediate.pem"),
            OsString::from("/input/leaf.pem"),
            OsString::from("/input/key.pem"),
            OsString::from(&config.hostname),
            OsString::from(validation_time.timestamp().to_string()),
        ],
    )?;
    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: "openssl-current-tls".to_owned(),
            version,
            verdict,
            version_track: VersionTrack::Current,
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

pub(crate) fn verify_container_as(
    config: &OpenSslContainerConfig,
    adapter: &str,
    version_track: VersionTrack,
) -> Result<OpenSslResult, OpenSslError> {
    verify_container_with_prefix(config, adapter, version_track, &[])
}

pub(crate) fn verify_container_with_prefix(
    config: &OpenSslContainerConfig,
    adapter: &str,
    version_track: VersionTrack,
    prefix: &[OsString],
) -> Result<OpenSslResult, OpenSslError> {
    let executable = resolve_executable(&config.docker)?;
    let mut input_paths = vec![
        config.trust_store.as_path(),
        config.intermediate.as_path(),
        config.leaf.as_path(),
    ];
    input_paths.extend(config.crl.as_deref());
    let inputs = record_inputs(&input_paths)?;
    let (selected_path_der_sha256, trust_anchor_der_sha256) = selected_path_hashes(
        &config.leaf,
        Some(&config.intermediate),
        &config.trust_store,
    )?;
    let validation_time = DateTime::parse_from_rfc3339(&config.validation_time)
        .map_err(|_| OpenSslError::InvalidValidationTime(config.validation_time.clone()))?;
    let limits = ProcessLimits {
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    };
    let mut mounts = vec![
        (config.trust_store.as_path(), "/input/root.pem"),
        (config.intermediate.as_path(), "/input/intermediate.pem"),
        (config.leaf.as_path(), "/input/leaf.pem"),
    ];
    if let Some(crl) = &config.crl {
        mounts.push((crl.as_path(), "/input/crl.pem"));
    }
    let mut version_command = prefix.to_vec();
    version_command.push(OsString::from("--version"));
    let version_arguments = isolated_arguments(&config.image, &mounts, &version_command)?;
    let version_output = cached_version_output(&executable, &version_arguments, limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(OpenSslError::VersionFailed);
    }
    let version = String::from_utf8_lossy(&version_output.stdout.bytes)
        .trim()
        .to_owned();
    let arguments = isolated_arguments(&config.image, &mounts, &{
        let mut command = prefix.to_vec();
        command.extend([
            OsString::from("-attime"),
            OsString::from(validation_time.timestamp().to_string()),
            OsString::from("-CAfile"),
            OsString::from("/input/root.pem"),
            OsString::from("-untrusted"),
            OsString::from("/input/intermediate.pem"),
        ]);
        if config.crl.is_some() {
            command.extend([
                OsString::from("-crl_check"),
                OsString::from("-CRLfile"),
                OsString::from("/input/crl.pem"),
            ]);
        }
        command.push(OsString::from("/input/leaf.pem"));
        command
    })?;
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

pub(crate) fn classify(output: &ProcessOutput) -> StackVerdict {
    if output.timed_out || output.stdout.truncated || output.stderr.truncated {
        return StackVerdict::Indeterminate;
    }
    if output.status_code == Some(0) {
        return StackVerdict::Accept;
    }

    let mut message = String::from_utf8_lossy(&output.stdout.bytes).to_lowercase();
    message.push_str(&String::from_utf8_lossy(&output.stderr.bytes).to_lowercase());
    if [
        "unsupported",
        "unknown signature algorithm",
        "decode error",
        "unknown public key type",
    ]
    .iter()
    .any(|marker| message.contains(marker))
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

    fn control(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/generated-controls")
            .join(name)
    }

    fn config(leaf: &str) -> OpenSslConfig {
        OpenSslConfig {
            executable: PathBuf::from("openssl"),
            trust_store: fixture("root.pem"),
            untrusted_chain: Some(fixture("ica.pem")),
            leaf: fixture(leaf),
            crl: None,
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        }
    }

    #[test]
    fn accepts_the_valid_classical_path_of_a_related_certificate() {
        let _guard = crate::adapter_test_lock();
        let result = verify(&config("related-certA.pem")).unwrap();

        assert_eq!(result.observation.verdict, StackVerdict::Accept);
        assert!(result.observation.version.starts_with("OpenSSL 3."));
    }

    #[test]
    fn detects_revocation_when_the_pq_certificate_is_checked_directly() {
        let _guard = crate::adapter_test_lock();
        let mut config = config("related-leafB.pem");
        config.crl = Some(fixture("related-crl.pem"));

        let result = verify(&config).unwrap();

        assert_eq!(result.observation.verdict, StackVerdict::Reject);
        let output = format!(
            "{}{}",
            String::from_utf8_lossy(&result.verification_output.stdout.bytes),
            String::from_utf8_lossy(&result.verification_output.stderr.bytes)
        );
        assert!(output.contains("certificate revoked"));
    }

    #[test]
    fn report_preserves_raw_output_as_hashed_base64() {
        let _guard = crate::adapter_test_lock();
        let report = verify(&config("related-certA.pem"))
            .unwrap()
            .report()
            .unwrap();

        assert_eq!(report.inputs.len(), 3);
        assert!(
            report
                .inputs
                .iter()
                .all(|input| input.bytes > 0 && input.sha256.len() == 64)
        );
        assert_eq!(report.verification.stdout.encoding, "base64");
        assert_eq!(report.verification.stdout.sha256.len(), 64);
        assert!(!report.verification.stdout.truncated);
    }

    #[test]
    fn current_container_accepts_the_valid_related_path() {
        let _guard = crate::adapter_test_lock();
        let result = verify_container(&OpenSslContainerConfig {
            docker: "docker".into(),
            image: "hybrid-x509-openssl:4.0.1".to_owned(),
            trust_store: fixture("root.pem"),
            intermediate: fixture("ica.pem"),
            leaf: fixture("related-certA.pem"),
            crl: None,
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(result.observation.verdict, StackVerdict::Accept);
        assert!(result.observation.version.starts_with("OpenSSL 4.0.1 "));
        assert_eq!(result.observation.version_track, VersionTrack::Current);
    }

    #[test]
    fn current_container_proves_pure_post_quantum_tls_key_possession() {
        let _guard = crate::adapter_test_lock();
        let result = verify_tls(&OpenSslTlsConfig {
            docker: "docker".into(),
            image: "hybrid-x509-openssl:4.0.1".to_owned(),
            trust_store: fixture("root.pem"),
            intermediate: fixture("ica.pem"),
            leaf: fixture("pure-leaf.pem"),
            private_key: control("pure-leaf-key.pem"),
            hostname: "pure.pqc-probe.test".to_owned(),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(result.observation.verdict, StackVerdict::Accept);
        let output = String::from_utf8_lossy(&result.verification_output.stdout.bytes);
        assert!(output.contains("Protocol version: TLSv1.3"));
        assert!(output.contains("Signature type: mldsa44"));
        assert!(output.contains("Verification: OK"));
    }
}
