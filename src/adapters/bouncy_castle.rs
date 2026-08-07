use super::{
    AdapterExecution, AdapterSupportError, cached_version_output, classify_json_verdict,
    container::isolated_arguments, record_inputs, resolve_executable, selected_path_hashes,
};
use crate::{
    CheckResult, CheckState, ExecutionIsolation, PathObservationSource, ProcessRecord,
    StackObservation, ValidationProfile, VersionTrack,
    process::{ProcessLimits, run_program},
};
use serde::Deserialize;
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

#[derive(Debug, Deserialize)]
struct PathBuilderOutput {
    selected_path_sha256: Vec<String>,
}

#[derive(Debug, Error)]
pub enum BouncyCastleError {
    #[error("Bouncy Castle adapter version command did not complete successfully: {output:?}")]
    VersionFailed { output: Box<ProcessRecord> },
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
    let version_arguments = isolated_arguments(&config.image, &[], &[OsString::from("--version")])?;
    let version_output = cached_version_output(&executable, &version_arguments, limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(BouncyCastleError::VersionFailed {
            output: Box::new(ProcessRecord::from(&version_output)),
        });
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
    let (selected_path_der_sha256, selected_path_source, trust_anchor_der_sha256) =
        if config.mode == BouncyCastleMode::PathBuilder && verdict == crate::StackVerdict::Accept {
            let output: PathBuilderOutput =
                serde_json::from_slice(&verification_output.stdout.bytes)
                    .map_err(io::Error::other)?;
            let mut certification_path = output.selected_path_sha256;
            let trust_anchor = certification_path
                .pop()
                .ok_or_else(|| io::Error::other("path-builder did not report a selected path"))?;
            (
                certification_path,
                PathObservationSource::AdapterSelected,
                crate::TrustAnchor::CertificateDerSha256 {
                    der_sha256: trust_anchor,
                },
            )
        } else if config.mode == BouncyCastleMode::PathBuilder {
            (
                Vec::new(),
                PathObservationSource::NotReported,
                crate::TrustAnchor::LocalIdentifier {
                    identifier: "not-reported".to_owned(),
                },
            )
        } else {
            let (path, anchor) = selected_path_hashes(
                &config.leaf,
                Some(&config.intermediate),
                &config.trust_store,
            )?;
            (path, PathObservationSource::PresentedInput, anchor)
        };

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
                BouncyCastleMode::AlternativeSignature | BouncyCastleMode::DeltaSignature => {
                    ValidationProfile::EvidenceSignature
                }
                BouncyCastleMode::TlsTranscript => ValidationProfile::WebPkiServer,
                BouncyCastleMode::CrlStatus => ValidationProfile::X509Path,
                BouncyCastleMode::CertificateSignature => ValidationProfile::EvidenceSignature,
            },
            execution_isolation: ExecutionIsolation::Container,
            certification_path_der_sha256: selected_path_der_sha256,
            selected_path_source,
            trust_anchor: trust_anchor_der_sha256,
            applied_validation_time: config.validation_time.clone(),
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
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
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
        let _guard = crate::adapter_test_lock();
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
            valid_delta.report().unwrap().adapter_trace.unwrap().events[0].operation,
            "check-delta-certificate-signature"
        );
    }

    #[test]
    fn version_failure_preserves_process_evidence() {
        let error = verify(&BouncyCastleConfig {
            docker: "/usr/bin/false".into(),
            image: "unused".to_owned(),
            trust_store: "tests/fixtures/paper-v1.0.2/root.pem".into(),
            intermediate: "tests/fixtures/paper-v1.0.2/ica.pem".into(),
            leaf: "tests/fixtures/paper-v1.0.2/related-certA.pem".into(),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(1),
            max_output_bytes: 64 * 1024,
            mode: BouncyCastleMode::Path,
            private_key: None,
            crl: None,
        })
        .unwrap_err();

        match error {
            BouncyCastleError::VersionFailed { output } => {
                assert_eq!(output.status_code, Some(1));
                assert!(!output.timed_out);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn version_probe_is_cached_per_image_not_per_leaf() {
        let directory = tempfile::tempdir().unwrap();
        let count = directory.path().join("count");
        let docker = directory.path().join("docker");
        fs::write(
            &docker,
            format!(
                "#!/bin/sh\nfor argument in \"$@\"; do\n  if [ \"$argument\" = --version ]; then\n    count=$(cat '{}' 2>/dev/null || echo 0)\n    count=$((count + 1))\n    printf '%s' \"$count\" > '{}'\n    printf '1.84'\n    exit 0\n  fi\ndone\nprintf '{{\"verdict\":\"reject\"}}'\n",
                count.display(),
                count.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&docker).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&docker, permissions).unwrap();
        }

        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let base = BouncyCastleConfig {
            docker,
            image: "hybrid-x509-bouncycastle:1.84".to_owned(),
            trust_store: repository.join("tests/fixtures/paper-v1.0.2/root.pem"),
            intermediate: repository.join("tests/fixtures/paper-v1.0.2/ica.pem"),
            leaf: repository.join("tests/fixtures/paper-v1.0.2/related-certA.pem"),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(1),
            max_output_bytes: 64 * 1024,
            mode: BouncyCastleMode::Path,
            private_key: None,
            crl: None,
        };
        let mut other = base.clone();
        other.leaf = repository.join("tests/fixtures/paper-v1.0.2/pure-leaf.pem");

        verify(&base).unwrap();
        verify(&other).unwrap();

        assert_eq!(fs::read_to_string(count).unwrap(), "1");
    }
}
