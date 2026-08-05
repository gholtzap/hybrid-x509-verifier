use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;
use x509_parser::prelude::FromDer;

#[derive(Debug, Error)]
pub enum MutationError {
    #[error("the input is not one complete X.509 certificate")]
    MalformedCertificate,
    #[error("the certificate has no mutable signature bytes")]
    MissingSignature,
    #[error("the mutation changed the to-be-signed certificate")]
    ChangedSignedContent,
}

pub fn corrupt_outer_signature(der: &[u8]) -> Result<Vec<u8>, MutationError> {
    let (remaining, certificate) = x509_parser::certificate::X509Certificate::from_der(der)
        .map_err(|_| MutationError::MalformedCertificate)?;
    if !remaining.is_empty() {
        return Err(MutationError::MalformedCertificate);
    }
    let signature = certificate.signature_value.data.as_ref();
    if signature.is_empty() {
        return Err(MutationError::MissingSignature);
    }
    let signature_start = (signature.as_ptr() as usize)
        .checked_sub(der.as_ptr() as usize)
        .ok_or(MutationError::MalformedCertificate)?;
    let mutation_index = signature_start
        .checked_add(signature.len() - 1)
        .filter(|index| *index < der.len())
        .ok_or(MutationError::MalformedCertificate)?;
    let signed_content = certificate.tbs_certificate.as_ref().to_vec();

    let mut mutated = der.to_vec();
    mutated[mutation_index] ^= 1;
    let (remaining, changed) = x509_parser::certificate::X509Certificate::from_der(&mutated)
        .map_err(|_| MutationError::MalformedCertificate)?;
    if !remaining.is_empty() || changed.tbs_certificate.as_ref() != signed_content {
        return Err(MutationError::ChangedSignedContent);
    }
    Ok(mutated)
}

pub fn encode_certificate_pem(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is valid UTF-8"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        StackVerdict,
        adapters::openssl::{OpenSslConfig, verify},
        pem::{PemKind, read_der},
    };
    use std::{io::Write, path::Path, time::Duration};

    #[test]
    fn openssl_rejects_the_controlled_classical_signature_mutation() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let der = read_der(
            &fixtures.join("related-certA.pem"),
            PemKind::Certificate,
            64 * 1024,
        )
        .unwrap();
        let mutated = corrupt_outer_signature(&der).unwrap();
        let mut leaf = tempfile::NamedTempFile::new().unwrap();
        leaf.write_all(encode_certificate_pem(&mutated).as_bytes())
            .unwrap();

        let result = verify(&OpenSslConfig {
            executable: "openssl".into(),
            trust_store: fixtures.join("root.pem"),
            untrusted_chain: Some(fixtures.join("ica.pem")),
            leaf: leaf.path().to_owned(),
            crl: Some(fixtures.join("related-crl.pem")),
            validation_time: "2026-06-20T00:00:00Z".to_owned(),
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        })
        .unwrap();

        assert_eq!(result.observation.verdict, StackVerdict::Reject);
    }

    #[test]
    fn composite_control_changes_only_the_mldsa_component() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let valid_der = read_der(
            &repository.join("tests/fixtures/paper-v1.0.2/composite-leaf.pem"),
            PemKind::Certificate,
            64 * 1024,
        )
        .unwrap();
        let invalid_der = read_der(
            &repository.join("tests/fixtures/generated-controls/composite-leaf-bad-mldsa.pem"),
            PemKind::Certificate,
            64 * 1024,
        )
        .unwrap();
        let (_, valid) = x509_parser::certificate::X509Certificate::from_der(&valid_der).unwrap();
        let (_, invalid) =
            x509_parser::certificate::X509Certificate::from_der(&invalid_der).unwrap();
        assert_eq!(
            valid.tbs_certificate.as_ref(),
            invalid.tbs_certificate.as_ref()
        );
        assert_eq!(valid.signature_algorithm, invalid.signature_algorithm);

        let valid_signature = valid.signature_value.data.as_ref();
        let invalid_signature = invalid.signature_value.data.as_ref();
        let mldsa44_signature_bytes = 2420;
        assert_eq!(valid_signature.len(), invalid_signature.len());
        assert_eq!(
            &valid_signature[mldsa44_signature_bytes..],
            &invalid_signature[mldsa44_signature_bytes..]
        );
        assert_eq!(
            valid_signature[..mldsa44_signature_bytes]
                .iter()
                .zip(&invalid_signature[..mldsa44_signature_bytes])
                .filter(|(left, right)| left != right)
                .count(),
            1
        );
    }

    #[test]
    fn outer_mutation_changes_only_the_composite_ecdsa_component() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let valid_der = read_der(
            &repository.join("tests/fixtures/paper-v1.0.2/composite-leaf.pem"),
            PemKind::Certificate,
            64 * 1024,
        )
        .unwrap();
        let invalid_der = corrupt_outer_signature(&valid_der).unwrap();
        let (_, valid) = x509_parser::certificate::X509Certificate::from_der(&valid_der).unwrap();
        let (_, invalid) =
            x509_parser::certificate::X509Certificate::from_der(&invalid_der).unwrap();
        let valid_signature = valid.signature_value.data.as_ref();
        let invalid_signature = invalid.signature_value.data.as_ref();
        let mldsa44_signature_bytes = 2420;

        assert_eq!(
            &valid_signature[..mldsa44_signature_bytes],
            &invalid_signature[..mldsa44_signature_bytes]
        );
        assert_eq!(
            valid_signature[mldsa44_signature_bytes..]
                .iter()
                .zip(&invalid_signature[mldsa44_signature_bytes..])
                .filter(|(left, right)| left != right)
                .count(),
            1
        );
    }
}
