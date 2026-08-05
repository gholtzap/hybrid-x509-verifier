use super::{
    AdapterExecution, AdapterSupportError, classify_json_verdict, container::isolated_arguments,
    record_inputs, resolve_executable,
};
use crate::{
    CheckResult, CheckState, ExecutionIsolation, StackObservation, ValidationProfile, VersionTrack,
    process::{ProcessLimits, run_program},
};
use std::{ffi::OsString, io, path::PathBuf, time::Duration};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct BouncyCastleConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub mode: BouncyCastleMode,
    pub private_key: Option<PathBuf>,
    pub crl: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BouncyCastleMode {
    Path,
    PathBuilder,
    AlternativeSignature,
    DeltaSignature,
    TlsTranscript,
    CrlStatus,
    CertificateSignature,
}

#[derive(Debug, Error)]
pub enum BouncyCastleError {
    #[error("Bouncy Castle adapter version command did not complete successfully")]
    VersionFailed,
    #[error("TLS transcript mode requires a private key")]
    MissingPrivateKey,
    #[error("CRL status mode requires a CRL")]
    MissingCrl,
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn verify(config: &BouncyCastleConfig) -> Result<AdapterExecution, BouncyCastleError> {
    let executable = resolve_executable(&config.docker)?;
    if config.private_key.is_none() && config.mode == BouncyCastleMode::TlsTranscript {
        return Err(BouncyCastleError::MissingPrivateKey);
    }
    if config.crl.is_none() && config.mode == BouncyCastleMode::CrlStatus {
        return Err(BouncyCastleError::MissingCrl);
    }
    let mut input_paths = vec![
        config.trust_store.as_path(),
        config.intermediate.as_path(),
        config.leaf.as_path(),
    ];
    input_paths.extend(config.private_key.as_deref());
    input_paths.extend(config.crl.as_deref());
    let inputs = record_inputs(&input_paths)?;
    let limits = ProcessLimits {
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    };
    let version_arguments = container_arguments(config, &[OsString::from("--version")])?;
    let version_output = run_program(&executable, &version_arguments, limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(BouncyCastleError::VersionFailed);
    }
    let version = String::from_utf8_lossy(&version_output.stdout.bytes)
        .trim()
        .to_owned();
    let (adapter, version_track) = match version.as_str() {
        "1.84" => ("bouncycastle-java-study", VersionTrack::Study),
        "1.85" => ("bouncycastle-java-current", VersionTrack::Current),
        _ => ("bouncycastle-java", VersionTrack::UserSupplied),
    };
    let mut adapter_arguments = vec![
        OsString::from("--root"),
        OsString::from("/input/root.pem"),
        OsString::from("--intermediate"),
        OsString::from("/input/intermediate.pem"),
        OsString::from("--leaf"),
        OsString::from("/input/leaf.pem"),
        OsString::from("--time"),
        OsString::from(&config.validation_time),
        OsString::from("--mode"),
        OsString::from(match config.mode {
            BouncyCastleMode::Path => "path",
            BouncyCastleMode::PathBuilder => "path-builder",
            BouncyCastleMode::AlternativeSignature => "alternative-signature",
            BouncyCastleMode::DeltaSignature => "delta-signature",
            BouncyCastleMode::TlsTranscript => "tls-transcript",
            BouncyCastleMode::CrlStatus => "crl-status",
            BouncyCastleMode::CertificateSignature => "certificate-signature",
        }),
    ];
    if config.mode == BouncyCastleMode::TlsTranscript {
        adapter_arguments.extend([OsString::from("--key"), OsString::from("/input/key.pem")]);
    }
    if config.mode == BouncyCastleMode::CrlStatus {
        adapter_arguments.extend([OsString::from("--crl"), OsString::from("/input/crl.pem")]);
    }
    let arguments = container_arguments(config, &adapter_arguments)?;
    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify_json_verdict(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: adapter.to_owned(),
            version,
            verdict,
            version_track,
            validation_profile: match config.mode {
                BouncyCastleMode::Path | BouncyCastleMode::PathBuilder => {
                    ValidationProfile::X509Path
                }
                BouncyCastleMode::AlternativeSignature
                | BouncyCastleMode::DeltaSignature
                | BouncyCastleMode::TlsTranscript => ValidationProfile::EvidenceSignature,
                BouncyCastleMode::CrlStatus => ValidationProfile::X509Path,
                BouncyCastleMode::CertificateSignature => ValidationProfile::EvidenceSignature,
            },
            execution_isolation: ExecutionIsolation::Container,
            validation_time: CheckResult::observed(match config.mode {
                BouncyCastleMode::Path | BouncyCastleMode::PathBuilder => CheckState::Pass,
                BouncyCastleMode::AlternativeSignature | BouncyCastleMode::DeltaSignature => {
                    CheckState::NotApplicable
                }
                BouncyCastleMode::TlsTranscript => CheckState::Pass,
                BouncyCastleMode::CrlStatus => CheckState::Pass,
                BouncyCastleMode::CertificateSignature => CheckState::NotApplicable,
            }),
        },
        inputs,
        executable,
        arguments,
        version_output,
        verification_output,
    })
}

fn container_arguments(
    config: &BouncyCastleConfig,
    adapter_arguments: &[OsString],
) -> Result<Vec<OsString>, io::Error> {
    let mut mounts = vec![
        (config.trust_store.as_path(), "/input/root.pem"),
        (config.intermediate.as_path(), "/input/intermediate.pem"),
        (config.leaf.as_path(), "/input/leaf.pem"),
    ];
    if let Some(key) = &config.private_key {
        mounts.push((key.as_path(), "/input/key.pem"));
    }
    if let Some(crl) = &config.crl {
        mounts.push((crl.as_path(), "/input/crl.pem"));
    }
    isolated_arguments(&config.image, &mounts, adapter_arguments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StackVerdict;
    use std::path::Path;

    fn config(leaf: PathBuf, mode: BouncyCastleMode) -> BouncyCastleConfig {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        BouncyCastleConfig {
            docker: "docker".into(),
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            trust_store: repository.join("tests/fixtures/paper-v1.0.2/root.pem"),
            intermediate: repository.join("tests/fixtures/paper-v1.0.2/ica.pem"),
            leaf,
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
            mode,
            private_key: None,
            crl: None,
        }
    }

    #[test]
    fn chameleon_delta_signature_is_independent_from_default_path_acceptance() {
        let controls =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/generated-controls");
        let valid = controls.join("chameleon-base-valid-delta.pem");
        let invalid = controls.join("chameleon-base-bad-delta.pem");

        assert_eq!(
            verify(&config(valid.clone(), BouncyCastleMode::Path))
                .unwrap()
                .observation
                .verdict,
            StackVerdict::Accept
        );
        assert_eq!(
            verify(&config(invalid.clone(), BouncyCastleMode::Path))
                .unwrap()
                .observation
                .verdict,
            StackVerdict::Accept
        );
        let valid_delta = verify(&config(valid, BouncyCastleMode::DeltaSignature)).unwrap();
        let invalid_delta = verify(&config(invalid, BouncyCastleMode::DeltaSignature)).unwrap();
        let published = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/paper-v1.0.2/chameleon-base.pem");
        let published_delta = verify(&config(published, BouncyCastleMode::DeltaSignature)).unwrap();
        assert_eq!(valid_delta.observation.verdict, StackVerdict::Accept);
        assert_eq!(invalid_delta.observation.verdict, StackVerdict::Reject);
        assert_eq!(published_delta.observation.verdict, StackVerdict::Reject);
        assert_eq!(
            valid_delta
                .report()
                .unwrap()
                .source_instrumentation
                .unwrap()
                .events[0]
                .operation,
            "check-delta-certificate-signature"
        );
    }
}
