use crate::{
    input::{BoundedInputError, read_bounded_file},
    pem::{PemError, PemKind, read_der},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Deserialize)]
struct Manifest {
    artifacts: Vec<Artifact>,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    der_sha256: String,
    der_bytes: usize,
    generator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CorpusVerificationReport {
    pub generator: String,
    pub checked: usize,
    pub passed: bool,
}

#[derive(Debug, Error)]
pub enum CorpusError {
    #[error("invalid corpus manifest: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Input(#[from] BoundedInputError),
    #[error("manifest has no artifacts for generator {0}")]
    EmptySelection(String),
    #[error("unsupported artifact type {kind} for {path}")]
    UnsupportedType { path: String, kind: String },
    #[error("cannot parse {path}: {source}")]
    Pem {
        path: String,
        #[source]
        source: PemError,
    },
    #[error("DER size mismatch for {path}: expected {expected}, got {actual}")]
    Size {
        path: String,
        expected: usize,
        actual: usize,
    },
    #[error("DER SHA-256 mismatch for {path}: expected {expected}, got {actual}")]
    Digest {
        path: String,
        expected: String,
        actual: String,
    },
}

pub fn verify_corpus(
    manifest_path: &Path,
    root: &Path,
    generator: &str,
    input_limit: usize,
) -> Result<CorpusVerificationReport, CorpusError> {
    let manifest: Manifest =
        serde_json::from_slice(&read_bounded_file(manifest_path, input_limit)?)?;
    let selected: Vec<_> = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.generator == generator)
        .collect();
    if selected.is_empty() {
        return Err(CorpusError::EmptySelection(generator.to_owned()));
    }

    for artifact in &selected {
        let kind = match artifact.kind.as_str() {
            "certificate" => PemKind::Certificate,
            "crl" => PemKind::CertificateRevocationList,
            _ => {
                return Err(CorpusError::UnsupportedType {
                    path: artifact.path.clone(),
                    kind: artifact.kind.clone(),
                });
            }
        };
        let path = root.join(&artifact.path);
        let der = read_der(&path, kind, input_limit).map_err(|source| CorpusError::Pem {
            path: artifact.path.clone(),
            source,
        })?;
        if der.len() != artifact.der_bytes {
            return Err(CorpusError::Size {
                path: artifact.path.clone(),
                expected: artifact.der_bytes,
                actual: der.len(),
            });
        }
        let actual = hex_lower(&Sha256::digest(&der));
        if actual != artifact.der_sha256 {
            return Err(CorpusError::Digest {
                path: artifact.path.clone(),
                expected: artifact.der_sha256.clone(),
                actual,
            });
        }
    }

    Ok(CorpusVerificationReport {
        generator: generator.to_owned(),
        checked: selected.len(),
        passed: true,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn verifies_an_imported_generator_artifact() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{"artifacts":[{"path":"root.pem","type":"certificate","der_sha256":"414005efd6544ead5ac13a50c0a72664e1c6acb72a6b38bafac019057d4050d7","der_bytes":451,"generator":"gen.GenValid (BouncyCastle)"}]}"#,
        )
        .unwrap();
        let report =
            verify_corpus(&manifest, &root, "gen.GenValid (BouncyCastle)", 1_048_576).unwrap();
        assert_eq!(report.checked, 1);
        assert!(report.passed);
    }

    #[test]
    fn verifies_the_three_published_wolfssl_fixed_vectors() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let report = verify_corpus(
            &root.join("manifest.json"),
            &root,
            "wolfssl_gen_catalyst.c",
            1_048_576,
        )
        .unwrap();

        assert_eq!(report.checked, 3);
        assert!(report.passed);
    }
}
