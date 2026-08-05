use crate::{
    CheckResult, CheckState, Confidence,
    input::{BoundedInputError, read_bounded_file},
    pem::{PemError, PemKind, read_der},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::DateTime;
use der::{Decode, Encode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{io, path::Path, time::Duration};
use thiserror::Error;
use x509_ocsp::{
    BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId, ext::Nonce,
};
use x509_parser::{
    der_parser::asn1_rs::BitString, error::X509Error, prelude::FromDer, time::ASN1Time,
    verify::verify_signature, x509::AlgorithmIdentifier,
};

const BASIC_OCSP_RESPONSE_OID: &str = "1.3.6.1.5.5.7.48.1.1";
const OCSP_NONCE_OID: &str = "1.3.6.1.5.5.7.48.1.2";

#[derive(Debug, Clone, Copy)]
pub struct OcspPolicy {
    pub max_age: Duration,
    pub clock_skew: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OcspCertificateStatus {
    Good,
    Revoked,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OcspStatusResult {
    pub response_status: CheckResult,
    pub signature: CheckResult,
    pub responder: CheckResult,
    pub issuer: CheckResult,
    pub certificate_id: CheckResult,
    pub freshness: CheckResult,
    pub extensions: CheckResult,
    pub nonce: CheckResult,
    pub revocation: CheckResult,
    pub certificate_status: OcspCertificateStatus,
}

#[derive(Debug, Error)]
pub enum OcspError {
    #[error("{path} is not a regular file")]
    NotAFile { path: String },
    #[error("{path} exceeds the {limit}-byte input limit")]
    InputTooLarge { path: String, limit: usize },
    #[error("{path} contains malformed OCSP DER")]
    MalformedDer { path: String },
    #[error("the OCSP response uses unsupported response type {0}")]
    UnsupportedResponseType(String),
    #[error("the OCSP response uses unsupported CertID digest algorithm {0}")]
    UnsupportedDigestAlgorithm(String),
    #[error("the OCSP response contains more than one matching SingleResponse")]
    DuplicateSingleResponse,
    #[error("the OCSP response signature algorithm is malformed")]
    MalformedSignatureAlgorithm,
    #[error("invalid RFC 3339 validation time: {0}")]
    InvalidValidationTime(String),
    #[error("the expected OCSP nonce is not valid Base64")]
    InvalidExpectedNonceBase64,
    #[error("the expected OCSP nonce must contain 1 to 32 bytes")]
    InvalidExpectedNonceLength,
    #[error(transparent)]
    Pem(#[from] PemError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn check_ocsp_status(
    certificate_path: &Path,
    issuer_path: &Path,
    response_path: &Path,
    validation_time: &str,
    expected_nonce_base64: Option<&str>,
    policy: OcspPolicy,
    limit: usize,
) -> Result<OcspStatusResult, OcspError> {
    let response_der = read_bounded(response_path, limit)?;
    let Some(basic) = parse_ocsp_der(&response_der, &response_path.display().to_string())? else {
        return Ok(unavailable_result());
    };
    let certificate_der = read_der(certificate_path, PemKind::Certificate, limit)?;
    let issuer_der = read_der(issuer_path, PemKind::Certificate, limit)?;
    let (certificate_remaining, certificate) =
        x509_parser::certificate::X509Certificate::from_der(&certificate_der).map_err(|_| {
            OcspError::MalformedDer {
                path: certificate_path.display().to_string(),
            }
        })?;
    if !certificate_remaining.is_empty() {
        return Err(OcspError::MalformedDer {
            path: certificate_path.display().to_string(),
        });
    }
    let (issuer_remaining, issuer) =
        x509_parser::certificate::X509Certificate::from_der(&issuer_der).map_err(|_| {
            OcspError::MalformedDer {
                path: issuer_path.display().to_string(),
            }
        })?;
    if !issuer_remaining.is_empty() {
        return Err(OcspError::MalformedDer {
            path: issuer_path.display().to_string(),
        });
    }
    let validation_timestamp = DateTime::parse_from_rfc3339(validation_time)
        .map_err(|_| OcspError::InvalidValidationTime(validation_time.to_owned()))?
        .timestamp();
    let expected_nonce = expected_nonce_base64
        .map(|value| {
            STANDARD
                .decode(value)
                .map_err(|_| OcspError::InvalidExpectedNonceBase64)
        })
        .transpose()?;
    if expected_nonce
        .as_ref()
        .is_some_and(|nonce| nonce.is_empty() || nonce.len() > 32)
    {
        return Err(OcspError::InvalidExpectedNonceLength);
    }

    let (responder_state, signature_state) =
        responder_and_signature_states(&basic, &issuer, validation_timestamp)?;
    let issuer_state = if certificate.issuer() != issuer.subject()
        || certificate.signature_algorithm != certificate.tbs_certificate.signature
    {
        CheckState::Fail
    } else {
        crypto_state(certificate.verify_signature(Some(issuer.public_key())))
    };
    let matching: Vec<_> = basic
        .tbs_response_data
        .responses
        .iter()
        .map(|single| {
            cert_id_matches(single, &certificate, &issuer).map(|matches| (single, matches))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|(single, matches)| matches.then_some(single))
        .collect();
    if matching.len() > 1 {
        return Err(OcspError::DuplicateSingleResponse);
    }
    let single = matching.first().copied();
    let certificate_id_matches = single.is_some();
    let freshness = single.is_some_and(|single| {
        is_fresh(
            &basic,
            single,
            validation_timestamp,
            policy.max_age.as_secs(),
            policy.clock_skew.as_secs(),
        )
    });
    let nonce_state = check_nonce(&basic, expected_nonce.as_deref());
    let extensions_state = state(ocsp_extensions_valid(&basic));
    let certificate_status = single.map_or(OcspCertificateStatus::Unknown, |single| {
        match single.cert_status {
            CertStatus::Good(_) => OcspCertificateStatus::Good,
            CertStatus::Revoked(_) => OcspCertificateStatus::Revoked,
            CertStatus::Unknown(_) => OcspCertificateStatus::Unknown,
        }
    });
    let prerequisites = responder_state == CheckState::Pass
        && signature_state == CheckState::Pass
        && issuer_state == CheckState::Pass
        && certificate_id_matches
        && freshness
        && extensions_state == CheckState::Pass
        && (expected_nonce.is_none() || nonce_state == CheckState::Pass);
    let revocation_state = if !prerequisites || certificate_status == OcspCertificateStatus::Unknown
    {
        CheckState::Indeterminate
    } else if certificate_status == OcspCertificateStatus::Revoked {
        CheckState::Fail
    } else {
        CheckState::Pass
    };

    Ok(OcspStatusResult {
        response_status: observed(CheckState::Pass),
        signature: observed(signature_state),
        responder: observed(responder_state),
        issuer: observed(issuer_state),
        certificate_id: observed(state(certificate_id_matches)),
        freshness: observed(state(freshness)),
        extensions: observed(extensions_state),
        nonce: observed(nonce_state),
        revocation: observed(revocation_state),
        certificate_status,
    })
}

pub fn validate_ocsp_der(bytes: &[u8], limit: usize) -> Result<(), OcspError> {
    if bytes.len() > limit {
        return Err(OcspError::InputTooLarge {
            path: "memory".to_owned(),
            limit,
        });
    }
    parse_ocsp_der(bytes, "memory").map(|_| ())
}

fn parse_ocsp_der(bytes: &[u8], source: &str) -> Result<Option<BasicOcspResponse>, OcspError> {
    let response = OcspResponse::from_der(bytes).map_err(|_| OcspError::MalformedDer {
        path: source.to_owned(),
    })?;
    if response.response_status != OcspResponseStatus::Successful {
        return Ok(None);
    }
    let response_bytes = response
        .response_bytes
        .ok_or_else(|| OcspError::MalformedDer {
            path: source.to_owned(),
        })?;
    if response_bytes.response_type.to_string() != BASIC_OCSP_RESPONSE_OID {
        return Err(OcspError::UnsupportedResponseType(
            response_bytes.response_type.to_string(),
        ));
    }
    BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .map(Some)
        .map_err(|_| OcspError::MalformedDer {
            path: source.to_owned(),
        })
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, OcspError> {
    let display = path.display().to_string();
    read_bounded_file(path, limit).map_err(|error| match error {
        BoundedInputError::NotAFile(_) => OcspError::NotAFile {
            path: display.clone(),
        },
        BoundedInputError::TooLarge { .. } => OcspError::InputTooLarge {
            path: display.clone(),
            limit,
        },
        BoundedInputError::Io { source, .. } => OcspError::Io(source),
    })
}

fn unavailable_result() -> OcspStatusResult {
    let indeterminate = observed(CheckState::Indeterminate);
    OcspStatusResult {
        response_status: observed(CheckState::Fail),
        signature: indeterminate,
        responder: indeterminate,
        issuer: indeterminate,
        certificate_id: indeterminate,
        freshness: indeterminate,
        extensions: indeterminate,
        nonce: indeterminate,
        revocation: indeterminate,
        certificate_status: OcspCertificateStatus::Unavailable,
    }
}

fn check_nonce(basic: &BasicOcspResponse, expected: Option<&[u8]>) -> CheckState {
    let Some(expected) = expected else {
        return CheckState::Indeterminate;
    };
    let matching: Vec<_> = basic
        .tbs_response_data
        .response_extensions
        .iter()
        .flatten()
        .filter(|extension| extension.extn_id.to_string() == OCSP_NONCE_OID)
        .collect();
    if matching.len() != 1 {
        return CheckState::Fail;
    }
    Nonce::from_der(matching[0].extn_value.as_bytes()).map_or(CheckState::Fail, |nonce| {
        state(nonce.0.as_bytes() == expected)
    })
}

fn ocsp_extensions_valid(basic: &BasicOcspResponse) -> bool {
    let mut response_oids = std::collections::HashSet::new();
    if basic
        .tbs_response_data
        .response_extensions
        .iter()
        .flatten()
        .any(|extension| !response_oids.insert(extension.extn_id) || extension.critical)
    {
        return false;
    }
    for single in &basic.tbs_response_data.responses {
        let mut single_oids = std::collections::HashSet::new();
        if single
            .single_extensions
            .iter()
            .flatten()
            .any(|extension| !single_oids.insert(extension.extn_id) || extension.critical)
        {
            return false;
        }
    }
    true
}

fn responder_matches_certificate(
    basic: &BasicOcspResponse,
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> bool {
    match &basic.tbs_response_data.responder_id {
        ResponderId::ByName(name) => name
            .to_der()
            .map(|der| der == certificate.subject().as_raw())
            .unwrap_or(false),
        ResponderId::ByKey(key_hash) => {
            Sha1::digest(certificate.public_key().subject_public_key.data.as_ref()).as_slice()
                == key_hash.as_bytes()
        }
    }
}

fn responder_and_signature_states(
    basic: &BasicOcspResponse,
    issuer: &x509_parser::certificate::X509Certificate<'_>,
    validation_timestamp: i64,
) -> Result<(CheckState, CheckState), OcspError> {
    if responder_matches_certificate(basic, issuer) {
        return Ok((CheckState::Pass, basic_signature_state(basic, issuer)?));
    }

    let mut result = None;
    for encoded in basic
        .certs
        .iter()
        .flatten()
        .filter_map(|cert| cert.to_der().ok())
    {
        let Ok((remaining, candidate)) =
            x509_parser::certificate::X509Certificate::from_der(&encoded)
        else {
            continue;
        };
        if !remaining.is_empty() || !responder_matches_certificate(basic, &candidate) {
            continue;
        }
        if result.is_some() {
            return Ok((CheckState::Fail, CheckState::Indeterminate));
        }
        result = Some((
            delegated_responder_state(&candidate, issuer, validation_timestamp),
            basic_signature_state(basic, &candidate)?,
        ));
    }
    Ok(result.unwrap_or((CheckState::Fail, CheckState::Indeterminate)))
}

fn delegated_responder_state(
    responder: &x509_parser::certificate::X509Certificate<'_>,
    issuer: &x509_parser::certificate::X509Certificate<'_>,
    validation_timestamp: i64,
) -> CheckState {
    if responder.issuer() != issuer.subject()
        || responder.signature_algorithm != responder.tbs_certificate.signature
    {
        return CheckState::Fail;
    }
    let issuer_signature = crypto_state(responder.verify_signature(Some(issuer.public_key())));
    if issuer_signature != CheckState::Pass {
        return issuer_signature;
    }
    let Ok(validation_time) = ASN1Time::from_timestamp(validation_timestamp) else {
        return CheckState::Fail;
    };
    if !responder.validity().is_valid_at(validation_time) {
        return CheckState::Fail;
    }
    let Ok(Some(extended_usage)) = responder.extended_key_usage() else {
        return CheckState::Fail;
    };
    if !extended_usage.value.ocsp_signing {
        return CheckState::Fail;
    }
    match responder.key_usage() {
        Ok(Some(usage)) if !usage.value.digital_signature() => CheckState::Fail,
        Err(_) => CheckState::Fail,
        _ => CheckState::Pass,
    }
}

fn basic_signature_state(
    basic: &BasicOcspResponse,
    signer: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<CheckState, OcspError> {
    let algorithm_der = basic
        .signature_algorithm
        .to_der()
        .map_err(|_| OcspError::MalformedSignatureAlgorithm)?;
    let (remaining, algorithm) = AlgorithmIdentifier::from_der(&algorithm_der)
        .map_err(|_| OcspError::MalformedSignatureAlgorithm)?;
    if !remaining.is_empty() {
        return Err(OcspError::MalformedSignatureAlgorithm);
    }
    let signature_bytes = basic
        .signature
        .as_bytes()
        .ok_or(OcspError::MalformedSignatureAlgorithm)?;
    let signature = BitString::new(0, signature_bytes);
    let signed_data = basic
        .tbs_response_data
        .to_der()
        .map_err(|_| OcspError::MalformedSignatureAlgorithm)?;
    Ok(crypto_state(verify_signature(
        signer.public_key(),
        &algorithm,
        &signature,
        &signed_data,
    )))
}

fn crypto_state(result: Result<(), X509Error>) -> CheckState {
    match result {
        Ok(()) => CheckState::Pass,
        Err(X509Error::SignatureVerificationError | X509Error::InvalidSignatureValue) => {
            CheckState::Fail
        }
        Err(_) => CheckState::Indeterminate,
    }
}

fn cert_id_matches(
    single: &x509_ocsp::SingleResponse,
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    issuer: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<bool, OcspError> {
    let oid = single.cert_id.hash_algorithm.oid.to_string();
    let issuer_name_hash = digest(&oid, issuer.subject().as_raw())?;
    let issuer_key_hash = digest(&oid, issuer.public_key().subject_public_key.data.as_ref())?;
    Ok(
        single.cert_id.issuer_name_hash.as_bytes() == issuer_name_hash
            && single.cert_id.issuer_key_hash.as_bytes() == issuer_key_hash
            && normalized_serial(single.cert_id.serial_number.as_bytes())
                == normalized_serial(certificate.raw_serial()),
    )
}

fn digest(oid: &str, bytes: &[u8]) -> Result<Vec<u8>, OcspError> {
    match oid {
        "1.3.14.3.2.26" => Ok(Sha1::digest(bytes).to_vec()),
        "2.16.840.1.101.3.4.2.1" => Ok(Sha256::digest(bytes).to_vec()),
        "2.16.840.1.101.3.4.2.2" => Ok(Sha384::digest(bytes).to_vec()),
        "2.16.840.1.101.3.4.2.3" => Ok(Sha512::digest(bytes).to_vec()),
        _ => Err(OcspError::UnsupportedDigestAlgorithm(oid.to_owned())),
    }
}

fn normalized_serial(serial: &[u8]) -> &[u8] {
    let first_nonzero = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len());
    &serial[first_nonzero..]
}

fn is_fresh(
    basic: &BasicOcspResponse,
    single: &x509_ocsp::SingleResponse,
    validation_timestamp: i64,
    max_age: u64,
    clock_skew: u64,
) -> bool {
    let Ok(validation) = u64::try_from(validation_timestamp) else {
        return false;
    };
    let produced_at = basic
        .tbs_response_data
        .produced_at
        .0
        .to_unix_duration()
        .as_secs();
    let this_update = single.this_update.0.to_unix_duration().as_secs();
    let upper = validation.saturating_add(clock_skew);
    if produced_at > upper
        || this_update > upper
        || validation.saturating_sub(this_update) > max_age
    {
        return false;
    }
    single.next_update.is_none_or(|next_update| {
        validation
            <= next_update
                .0
                .to_unix_duration()
                .as_secs()
                .saturating_add(clock_skew)
    })
}

fn state(value: bool) -> CheckState {
    if value {
        CheckState::Pass
    } else {
        CheckState::Fail
    }
}

fn observed(state: CheckState) -> CheckResult {
    CheckResult {
        state,
        confidence: Confidence::Observed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use std::{io::Write, path::PathBuf};

    fn imported_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ocsp-imported")
            .join(name)
    }

    fn imported_response() -> Vec<u8> {
        STANDARD
            .decode(include_str!("../tests/fixtures/ocsp-imported/response.der.b64").trim())
            .unwrap()
    }

    fn generated_response(name: &str) -> Vec<u8> {
        let encoded = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/generated-controls")
                .join(name),
        )
        .unwrap();
        STANDARD.decode(encoded.trim()).unwrap()
    }

    fn check_at(response: &[u8], validation_time: &str) -> OcspStatusResult {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(response).unwrap();
        check_ocsp_status(
            &imported_fixture("leaf.pem"),
            &imported_fixture("issuer.pem"),
            file.path(),
            validation_time,
            None,
            OcspPolicy {
                max_age: Duration::from_secs(7 * 24 * 60 * 60),
                clock_skew: Duration::from_secs(5 * 60),
            },
            64 * 1024,
        )
        .unwrap()
    }

    #[test]
    fn normalizes_positive_serial_numbers() {
        assert_eq!(normalized_serial(&[0, 0, 1, 2]), &[1, 2]);
        assert_eq!(normalized_serial(&[0, 0]), &[] as &[u8]);
    }

    #[test]
    fn unsupported_signature_is_not_reported_as_invalid() {
        assert_eq!(
            crypto_state(Err(X509Error::SignatureUnsupportedAlgorithm)),
            CheckState::Indeterminate
        );
        assert_eq!(
            crypto_state(Err(X509Error::SignatureVerificationError)),
            CheckState::Fail
        );
    }

    #[test]
    fn non_success_response_cannot_supply_revocation_evidence() {
        let result = unavailable_result();
        assert_eq!(result.response_status, observed(CheckState::Fail));
        assert_eq!(result.revocation, observed(CheckState::Indeterminate));
        assert_eq!(
            result.certificate_status,
            OcspCertificateStatus::Unavailable
        );
    }

    #[test]
    fn independently_accepts_a_signed_good_response() {
        let result = check_at(&imported_response(), "2023-04-18T00:00:00Z");
        assert_eq!(result.response_status, observed(CheckState::Pass));
        assert_eq!(result.signature, observed(CheckState::Pass));
        assert_eq!(result.responder, observed(CheckState::Pass));
        assert_eq!(result.issuer, observed(CheckState::Pass));
        assert_eq!(result.certificate_id, observed(CheckState::Pass));
        assert_eq!(result.freshness, observed(CheckState::Pass));
        assert_eq!(result.revocation, observed(CheckState::Pass));
        assert_eq!(result.certificate_status, OcspCertificateStatus::Good);
    }

    #[test]
    fn a_bad_response_signature_cannot_supply_revocation_evidence() {
        let mut response = imported_response();
        *response.last_mut().unwrap() ^= 1;
        let result = check_at(&response, "2023-04-18T00:00:00Z");
        assert_eq!(result.signature, observed(CheckState::Fail));
        assert_eq!(result.revocation, observed(CheckState::Indeterminate));
    }

    #[test]
    fn a_stale_response_cannot_supply_revocation_evidence() {
        let result = check_at(&imported_response(), "2023-04-25T00:00:00Z");
        assert_eq!(result.signature, observed(CheckState::Pass));
        assert_eq!(result.freshness, observed(CheckState::Fail));
        assert_eq!(result.revocation, observed(CheckState::Indeterminate));
    }

    #[test]
    fn a_responder_error_cannot_supply_revocation_evidence() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&OcspResponse::try_later().to_der().unwrap())
            .unwrap();
        let result = check_ocsp_status(
            Path::new("not-read.pem"),
            Path::new("not-read.pem"),
            file.path(),
            "2023-04-18T00:00:00Z",
            None,
            OcspPolicy {
                max_age: Duration::from_secs(60),
                clock_skew: Duration::ZERO,
            },
            64 * 1024,
        )
        .unwrap();
        assert_eq!(result.response_status, observed(CheckState::Fail));
        assert_eq!(result.revocation, observed(CheckState::Indeterminate));
    }

    #[test]
    fn deterministic_controls_cover_classical_and_pq_statuses() {
        let paper = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let cases = [
            (
                "related-certA-good-ocsp.der.b64",
                "related-certA.pem",
                OcspCertificateStatus::Good,
                CheckState::Pass,
                CheckState::Pass,
            ),
            (
                "related-certA-revoked-ocsp.der.b64",
                "related-certA.pem",
                OcspCertificateStatus::Revoked,
                CheckState::Pass,
                CheckState::Fail,
            ),
            (
                "related-leafB-good-ocsp.der.b64",
                "related-leafB.pem",
                OcspCertificateStatus::Good,
                CheckState::Pass,
                CheckState::Pass,
            ),
            (
                "related-leafB-revoked-ocsp.der.b64",
                "related-leafB.pem",
                OcspCertificateStatus::Revoked,
                CheckState::Pass,
                CheckState::Fail,
            ),
            (
                "related-leafB-unknown-ocsp.der.b64",
                "related-leafB.pem",
                OcspCertificateStatus::Unknown,
                CheckState::Pass,
                CheckState::Indeterminate,
            ),
            (
                "related-leafB-stale-ocsp.der.b64",
                "related-leafB.pem",
                OcspCertificateStatus::Good,
                CheckState::Fail,
                CheckState::Indeterminate,
            ),
            (
                "related-leafB-unavailable-ocsp.der.b64",
                "related-leafB.pem",
                OcspCertificateStatus::Unavailable,
                CheckState::Indeterminate,
                CheckState::Indeterminate,
            ),
        ];

        for (response, certificate, status, freshness, revocation) in cases {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(&generated_response(response)).unwrap();
            let result = check_ocsp_status(
                &paper.join(certificate),
                &paper.join("ica.pem"),
                file.path(),
                "2026-06-21T00:00:00Z",
                None,
                OcspPolicy {
                    max_age: Duration::from_secs(7 * 24 * 60 * 60),
                    clock_skew: Duration::from_secs(5 * 60),
                },
                64 * 1024,
            )
            .unwrap();
            assert_eq!(result.certificate_status, status, "{response}");
            assert_eq!(result.freshness.state, freshness, "{response}");
            assert_eq!(result.revocation.state, revocation, "{response}");
        }
    }

    #[test]
    fn nonce_binding_is_required_when_the_request_supplies_one() {
        let paper = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let response = generated_response("related-leafB-nonce-ocsp.der.b64");
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&response).unwrap();
        let check = |nonce| {
            check_ocsp_status(
                &paper.join("related-leafB.pem"),
                &paper.join("ica.pem"),
                file.path(),
                "2026-06-21T00:00:00Z",
                Some(nonce),
                OcspPolicy {
                    max_age: Duration::from_secs(7 * 24 * 60 * 60),
                    clock_skew: Duration::from_secs(5 * 60),
                },
                64 * 1024,
            )
            .unwrap()
        };

        let matching = check("ABEiM0RVZneImaq7zN3u/w==");
        assert_eq!(matching.nonce, observed(CheckState::Pass));
        assert_eq!(matching.revocation, observed(CheckState::Pass));

        let mismatched = check("/+7dzLuqmYh3ZlVEMyIRAA==");
        assert_eq!(mismatched.nonce, observed(CheckState::Fail));
        assert_eq!(mismatched.revocation, observed(CheckState::Indeterminate));
    }

    #[test]
    fn malformed_control_is_rejected_as_der() {
        assert!(matches!(
            validate_ocsp_der(
                &generated_response("related-leafB-malformed-ocsp.der.b64"),
                64 * 1024
            ),
            Err(OcspError::MalformedDer { .. })
        ));
    }

    #[test]
    fn delegated_responder_requires_ocsp_signing_authorization() {
        let paper = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        for (name, responder_state, revocation_state) in [
            (
                "related-leafB-delegated-ocsp.der.b64",
                CheckState::Pass,
                CheckState::Pass,
            ),
            (
                "related-leafB-delegated-no-eku-ocsp.der.b64",
                CheckState::Fail,
                CheckState::Indeterminate,
            ),
        ] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(&generated_response(name)).unwrap();
            let result = check_ocsp_status(
                &paper.join("related-leafB.pem"),
                &paper.join("ica.pem"),
                file.path(),
                "2026-06-21T00:00:00Z",
                None,
                OcspPolicy {
                    max_age: Duration::from_secs(7 * 24 * 60 * 60),
                    clock_skew: Duration::from_secs(5 * 60),
                },
                64 * 1024,
            )
            .unwrap();
            assert_eq!(result.responder.state, responder_state, "{name}");
            assert_eq!(result.signature.state, CheckState::Pass, "{name}");
            assert_eq!(result.revocation.state, revocation_state, "{name}");
        }
    }
}
