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
pub struct GoX509Config {
    pub executable: PathBuf,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub dns_name: String,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct GoX509ContainerConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub dns_name: String,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub release: GoX509Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoX509Release {
    Study1264,
    Current1265,
}

#[derive(Debug, Error)]
pub enum GoX509Error {
    #[error("Go adapter version command did not complete successfully")]
    VersionFailed,
    #[error(transparent)]
    Support(#[from] AdapterSupportError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn verify(config: &GoX509Config) -> Result<AdapterExecution, GoX509Error> {
    let executable = resolve_executable(&config.executable)?;
    let inputs = record_inputs(&[
        config.trust_store.as_path(),
        config.intermediate.as_path(),
        config.leaf.as_path(),
    ])?;
    let limits = ProcessLimits {
        timeout: config.timeout,
        max_output_bytes: config.max_output_bytes,
    };
    let version_output = run_program(&executable, &[OsString::from("--version")], limits)?;
    if version_output.timed_out || version_output.status_code != Some(0) {
        return Err(GoX509Error::VersionFailed);
    }
    let version = String::from_utf8_lossy(&version_output.stdout.bytes)
        .trim()
        .to_owned();
    let arguments = vec![
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
    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify_json_verdict(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: "go-crypto-x509".to_owned(),
            version,
            verdict,
            version_track: VersionTrack::UserSupplied,
            validation_profile: ValidationProfile::WebPkiServer,
            execution_isolation: ExecutionIsolation::ProcessOnly,
            validation_time: CheckResult::observed(CheckState::Pass),
        },
        inputs,
        executable,
        arguments,
        version_output,
        verification_output,
    })
}

pub fn verify_container(config: &GoX509ContainerConfig) -> Result<AdapterExecution, GoX509Error> {
    let executable = resolve_executable(&config.docker)?;
    let inputs = record_inputs(&[
        config.trust_store.as_path(),
        config.intermediate.as_path(),
        config.leaf.as_path(),
    ])?;
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
        return Err(GoX509Error::VersionFailed);
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
            OsString::from("--dns"),
            OsString::from(&config.dns_name),
            OsString::from("--time"),
            OsString::from(&config.validation_time),
        ],
    )?;
    let verification_output = run_program(&executable, &arguments, limits)?;
    let verdict = classify_json_verdict(&verification_output);

    Ok(AdapterExecution {
        observation: StackObservation {
            adapter: match config.release {
                GoX509Release::Study1264 => "go-crypto-x509-study",
                GoX509Release::Current1265 => "go-crypto-x509-current",
            }
            .to_owned(),
            version,
            verdict,
            version_track: match config.release {
                GoX509Release::Study1264 => VersionTrack::Study,
                GoX509Release::Current1265 => VersionTrack::Current,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StackVerdict;
    use std::{path::Path, process::Command, sync::OnceLock};

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/paper-v1.0.2")
            .join(name)
    }

    fn adapter() -> &'static PathBuf {
        static ADAPTER: OnceLock<PathBuf> = OnceLock::new();
        ADAPTER.get_or_init(|| {
            let directory = tempfile::tempdir().unwrap().keep();
            let executable = directory.join("go-x509-adapter");
            let status = Command::new("go")
                .args(["build", "-o"])
                .arg(&executable)
                .arg(".")
                .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/go-x509-adapter"))
                .status()
                .unwrap();
            assert!(status.success());
            executable
        })
    }

    #[test]
    fn accepts_the_valid_classical_path_of_a_related_certificate() {
        let result = verify(&GoX509Config {
            executable: adapter().clone(),
            trust_store: fixture("root.pem"),
            intermediate: fixture("ica.pem"),
            leaf: fixture("related-certA.pem"),
            dns_name: "related-a.pqc-probe.test".to_owned(),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(result.observation.verdict, StackVerdict::Accept);
        assert!(result.observation.version.starts_with("go1.26."));
        let report = result.report().unwrap();
        let instrumentation = report.source_instrumentation.unwrap();
        assert_eq!(instrumentation.confidence, crate::Confidence::Observed);
        assert_eq!(instrumentation.events[0].operation, "check-signature-from");
        assert_eq!(instrumentation.events[0].outcome, "pass");
        assert!(
            instrumentation
                .extensions
                .iter()
                .any(|extension| extension.oid == "1.3.6.1.5.5.7.1.36")
        );
    }
}
