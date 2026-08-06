use crate::{
    AlgorithmSecurity, BindingDesign, CheckResult, CheckState, Confidence,
    input::{BoundedInputError, read_bounded_file},
};
use chrono::DateTime;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{io, path::Path};
use thiserror::Error;
use x509_parser::{
    der_parser::der::parse_der_sequence, extensions::GeneralName, pem::parse_x509_pem,
    prelude::FromDer,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemKind {
    Certificate,
    CertificateRevocationList,
}

impl PemKind {
    fn labels(self) -> &'static [&'static str] {
        match self {
            Self::Certificate => &["CERTIFICATE"],
            Self::CertificateRevocationList => &["X509 CRL", "CRL"],
        }
    }
}

#[derive(Debug, Error)]
pub enum PemError {
    #[error("{path} is not a regular file")]
    NotAFile { path: String },
    #[error("{path} exceeds the {limit}-byte input limit")]
    InputTooLarge { path: String, limit: usize },
    #[error("{path} is not a valid PEM document")]
    Malformed { path: String },
    #[error("{path} has PEM label {actual}; expected {expected}")]
    WrongLabel {
        path: String,
        actual: String,
        expected: String,
    },
    #[error("{path} contains data after its PEM document")]
    TrailingData { path: String },
    #[error("{path} contains malformed X.509 DER")]
    MalformedDer { path: String },
    #[error("{path} contains duplicate certificate extensions")]
    DuplicateExtensions { path: String },
    #[error("{path} does not contain a RelatedCertificate extension")]
    MissingRelatedCertificate { path: String },
    #[error("{path} contains a malformed RelatedCertificate extension")]
    MalformedRelatedCertificate { path: String },
    #[error("the RelatedCertificate extension uses unsupported digest algorithm {0}")]
    UnsupportedDigestAlgorithm(String),
    #[error("invalid RFC 3339 validation time: {0}")]
    InvalidValidationTime(String),
    #[error("{path} contains invalid or duplicate certificate extensions")]
    InvalidCertificateExtensions { path: String },
    #[error("{path} contains invalid or duplicate CRL extensions")]
    InvalidCrlExtensions { path: String },
    #[error("{path} uses unsupported CRL semantics in extension {oid}")]
    UnsupportedCrlSemantics { path: String, oid: String },
    #[error("{path} contains unsupported critical CRL extension {oid}")]
    UnsupportedCriticalCrlExtension { path: String, oid: String },
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateProfile {
    pub subject_public_key_scheme: AlgorithmSecurity,
    pub certificate_signature_scheme: AlgorithmSecurity,
    pub binding_design: BindingDesign,
    pub signature_algorithm_oid: String,
    pub subject_public_key_algorithm_oid: String,
    pub extension_oids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelatedBindingResult {
    pub check: CheckResult,
    pub digest_algorithm_oid: String,
    pub embedded_digest: String,
    pub calculated_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rfc9763ProfileChecks {
    pub binding: RelatedBindingResult,
    pub extension_in_end_entity: CheckResult,
    pub related_certificate_is_end_entity: CheckResult,
    pub key_usage_subset: CheckResult,
    pub extended_key_usage_subset: CheckResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HybridApplicationPolicyChecks {
    pub reference_subject_public_key_is_classical: CheckResult,
    pub related_subject_public_key_is_post_quantum: CheckResult,
    pub dns_identity_overlap: CheckResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelatedConformanceResult {
    pub rfc9763: Rfc9763ProfileChecks,
    pub hybrid_application_policy: HybridApplicationPolicyChecks,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CrlStatusResult {
    pub signature: CheckResult,
    pub issuer: CheckResult,
    pub freshness: CheckResult,
    pub revocation: CheckResult,
}

pub fn read_der(path: &Path, kind: PemKind, limit: usize) -> Result<Vec<u8>, PemError> {
    let display = path.display().to_string();
    let bytes = read_bounded_file(path, limit).map_err(|error| match error {
        BoundedInputError::NotAFile(_) => PemError::NotAFile {
            path: display.clone(),
        },
        BoundedInputError::TooLarge { .. } => PemError::InputTooLarge {
            path: display.clone(),
            limit,
        },
        BoundedInputError::Io { source, .. } => PemError::Io(source),
    })?;
    decode_pem(&bytes, kind, limit, &display)
}

pub fn decode_pem(
    bytes: &[u8],
    kind: PemKind,
    limit: usize,
    source: &str,
) -> Result<Vec<u8>, PemError> {
    if bytes.len() > limit {
        return Err(PemError::InputTooLarge {
            path: source.to_owned(),
            limit,
        });
    }
    let (remaining, pem) = parse_x509_pem(bytes).map_err(|_| PemError::Malformed {
        path: source.to_owned(),
    })?;
    if !remaining.iter().all(u8::is_ascii_whitespace) {
        return Err(PemError::TrailingData {
            path: source.to_owned(),
        });
    }
    if !kind.labels().contains(&pem.label.as_str()) {
        return Err(PemError::WrongLabel {
            path: source.to_owned(),
            actual: pem.label,
            expected: kind.labels().join(" or "),
        });
    }
    Ok(pem.contents)
}

pub fn inspect_certificate(path: &Path, limit: usize) -> Result<CertificateProfile, PemError> {
    let der = read_der(path, PemKind::Certificate, limit)?;
    let (remaining, certificate) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|_| PemError::MalformedDer {
            path: path.display().to_string(),
        })?;
    if !remaining.is_empty() {
        return Err(PemError::MalformedDer {
            path: path.display().to_string(),
        });
    }

    let signature_algorithm_oid = certificate.signature_algorithm.algorithm.to_id_string();
    let subject_public_key_algorithm_oid =
        certificate.public_key().algorithm.algorithm.to_id_string();
    let extension_oids: Vec<_> = certificate
        .extensions()
        .iter()
        .map(|extension| extension.oid.to_id_string())
        .collect();
    Ok(CertificateProfile {
        subject_public_key_scheme: algorithm_security(&subject_public_key_algorithm_oid),
        certificate_signature_scheme: algorithm_security(&signature_algorithm_oid),
        binding_design: binding_design(&signature_algorithm_oid, &extension_oids),
        signature_algorithm_oid,
        subject_public_key_algorithm_oid,
        extension_oids,
    })
}

pub fn verify_related_binding(
    certificate_with_extension: &Path,
    related_certificate: &Path,
    limit: usize,
) -> Result<RelatedBindingResult, PemError> {
    let reference_der = read_der(certificate_with_extension, PemKind::Certificate, limit)?;
    let related_der = read_der(related_certificate, PemKind::Certificate, limit)?;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(&reference_der)
        .map_err(|_| PemError::MalformedDer {
            path: certificate_with_extension.display().to_string(),
        })?;
    certificate
        .extensions_map()
        .map_err(|_| PemError::DuplicateExtensions {
            path: certificate_with_extension.display().to_string(),
        })?;
    let extension = certificate
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.36")
        .ok_or_else(|| PemError::MissingRelatedCertificate {
            path: certificate_with_extension.display().to_string(),
        })?;
    let (remaining, sequence) =
        parse_der_sequence(extension.value).map_err(|_| PemError::MalformedRelatedCertificate {
            path: certificate_with_extension.display().to_string(),
        })?;
    let fields = sequence
        .as_sequence()
        .map_err(|_| PemError::MalformedRelatedCertificate {
            path: certificate_with_extension.display().to_string(),
        })?;
    if !remaining.is_empty() || fields.len() != 2 {
        return Err(PemError::MalformedRelatedCertificate {
            path: certificate_with_extension.display().to_string(),
        });
    }
    let algorithm_fields =
        fields[0]
            .as_sequence()
            .map_err(|_| PemError::MalformedRelatedCertificate {
                path: certificate_with_extension.display().to_string(),
            })?;
    let digest_algorithm_oid = algorithm_fields
        .first()
        .ok_or_else(|| PemError::MalformedRelatedCertificate {
            path: certificate_with_extension.display().to_string(),
        })?
        .as_oid_val()
        .map_err(|_| PemError::MalformedRelatedCertificate {
            path: certificate_with_extension.display().to_string(),
        })?
        .to_id_string();
    let embedded_digest =
        fields[1]
            .as_slice()
            .map_err(|_| PemError::MalformedRelatedCertificate {
                path: certificate_with_extension.display().to_string(),
            })?;
    let calculated_digest = digest(&digest_algorithm_oid, &related_der)?;

    Ok(RelatedBindingResult {
        check: CheckResult {
            state: if embedded_digest == calculated_digest {
                CheckState::Pass
            } else {
                CheckState::Fail
            },
            confidence: Confidence::Observed,
        },
        digest_algorithm_oid,
        embedded_digest: hex_lower(embedded_digest),
        calculated_digest: hex_lower(&calculated_digest),
    })
}

pub fn verify_related_certificate_conformance(
    certificate_with_extension: &Path,
    related_certificate: &Path,
    limit: usize,
) -> Result<RelatedConformanceResult, PemError> {
    let binding = verify_related_binding(certificate_with_extension, related_certificate, limit)?;
    let reference_der = read_der(certificate_with_extension, PemKind::Certificate, limit)?;
    let related_der = read_der(related_certificate, PemKind::Certificate, limit)?;
    let (_, reference) = x509_parser::certificate::X509Certificate::from_der(&reference_der)
        .map_err(|_| PemError::MalformedDer {
            path: certificate_with_extension.display().to_string(),
        })?;
    let (_, related) =
        x509_parser::certificate::X509Certificate::from_der(&related_der).map_err(|_| {
            PemError::MalformedDer {
                path: related_certificate.display().to_string(),
            }
        })?;
    let reference_profile = inspect_certificate(certificate_with_extension, limit)?;
    let related_profile = inspect_certificate(related_certificate, limit)?;

    Ok(RelatedConformanceResult {
        rfc9763: Rfc9763ProfileChecks {
            binding,
            extension_in_end_entity: observed_bool(is_end_entity(
                &reference,
                certificate_with_extension,
            )?),
            related_certificate_is_end_entity: observed_bool(is_end_entity(
                &related,
                related_certificate,
            )?),
            key_usage_subset: observed_bool(key_usage_is_subset(
                &reference,
                certificate_with_extension,
                &related,
                related_certificate,
            )?),
            extended_key_usage_subset: observed_bool(extended_key_usage_is_subset(
                &reference,
                certificate_with_extension,
                &related,
                related_certificate,
            )?),
        },
        hybrid_application_policy: hybrid_application_policy_checks(
            reference_profile.subject_public_key_scheme,
            related_profile.subject_public_key_scheme,
            dns_names_overlap(
                &reference,
                certificate_with_extension,
                &related,
                related_certificate,
            )?,
        ),
    })
}

fn hybrid_application_policy_checks(
    reference_subject_public_key_scheme: AlgorithmSecurity,
    related_subject_public_key_scheme: AlgorithmSecurity,
    dns_identity_overlap: bool,
) -> HybridApplicationPolicyChecks {
    HybridApplicationPolicyChecks {
        reference_subject_public_key_is_classical: observed_bool(
            reference_subject_public_key_scheme == AlgorithmSecurity::Classical,
        ),
        related_subject_public_key_is_post_quantum: observed_bool(
            related_subject_public_key_scheme == AlgorithmSecurity::PostQuantum,
        ),
        dns_identity_overlap: observed_bool(dns_identity_overlap),
    }
}

fn observed_bool(value: bool) -> CheckResult {
    CheckResult::observed(if value {
        CheckState::Pass
    } else {
        CheckState::Fail
    })
}

fn is_end_entity(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    path: &Path,
) -> Result<bool, PemError> {
    Ok(!certificate
        .basic_constraints()
        .map_err(|_| PemError::InvalidCertificateExtensions {
            path: path.display().to_string(),
        })?
        .is_some_and(|extension| extension.value.ca))
}

fn key_usage_is_subset(
    reference: &x509_parser::certificate::X509Certificate<'_>,
    reference_path: &Path,
    related: &x509_parser::certificate::X509Certificate<'_>,
    related_path: &Path,
) -> Result<bool, PemError> {
    let reference = reference
        .key_usage()
        .map_err(|_| PemError::InvalidCertificateExtensions {
            path: reference_path.display().to_string(),
        })?;
    let Some(reference) = reference else {
        return Ok(true);
    };
    let related = related
        .key_usage()
        .map_err(|_| PemError::InvalidCertificateExtensions {
            path: related_path.display().to_string(),
        })?;
    let Some(related) = related else {
        return Ok(false);
    };
    Ok(reference.value.flags & !related.value.flags == 0)
}

fn extended_key_usage_is_subset(
    reference: &x509_parser::certificate::X509Certificate<'_>,
    reference_path: &Path,
    related: &x509_parser::certificate::X509Certificate<'_>,
    related_path: &Path,
) -> Result<bool, PemError> {
    let reference =
        reference
            .extended_key_usage()
            .map_err(|_| PemError::InvalidCertificateExtensions {
                path: reference_path.display().to_string(),
            })?;
    let Some(reference) = reference else {
        return Ok(true);
    };
    let related =
        related
            .extended_key_usage()
            .map_err(|_| PemError::InvalidCertificateExtensions {
                path: related_path.display().to_string(),
            })?;
    let Some(related) = related else {
        return Ok(false);
    };
    if related.value.any {
        return Ok(true);
    }
    Ok((!reference.value.any || related.value.any)
        && (!reference.value.server_auth || related.value.server_auth)
        && (!reference.value.client_auth || related.value.client_auth)
        && (!reference.value.code_signing || related.value.code_signing)
        && (!reference.value.email_protection || related.value.email_protection)
        && (!reference.value.time_stamping || related.value.time_stamping)
        && (!reference.value.ocsp_signing || related.value.ocsp_signing)
        && reference.value.other.iter().all(|oid| {
            let id = oid.to_id_string();
            related
                .value
                .other
                .iter()
                .any(|candidate| candidate.to_id_string() == id)
        }))
}

fn dns_names_overlap(
    reference: &x509_parser::certificate::X509Certificate<'_>,
    reference_path: &Path,
    related: &x509_parser::certificate::X509Certificate<'_>,
    related_path: &Path,
) -> Result<bool, PemError> {
    let reference = dns_names(reference, reference_path)?;
    let related = dns_names(related, related_path)?;
    Ok(!reference.is_empty()
        && !related.is_empty()
        && reference
            .iter()
            .any(|name| related.iter().any(|candidate| candidate == name)))
}

fn dns_names(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    path: &Path,
) -> Result<Vec<String>, PemError> {
    let Some(names) = certificate.subject_alternative_name().map_err(|_| {
        PemError::InvalidCertificateExtensions {
            path: path.display().to_string(),
        }
    })?
    else {
        return Ok(Vec::new());
    };
    Ok(names
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some(name.to_string()),
            _ => None,
        })
        .collect())
}

pub fn check_crl_status(
    certificate_path: &Path,
    issuer_path: &Path,
    crl_path: &Path,
    validation_time: &str,
    limit: usize,
) -> Result<CrlStatusResult, PemError> {
    let certificate_der = read_der(certificate_path, PemKind::Certificate, limit)?;
    let issuer_der = read_der(issuer_path, PemKind::Certificate, limit)?;
    let crl_der = read_der(crl_path, PemKind::CertificateRevocationList, limit)?;
    let (certificate_remaining, certificate) =
        x509_parser::certificate::X509Certificate::from_der(&certificate_der).map_err(|_| {
            PemError::MalformedDer {
                path: certificate_path.display().to_string(),
            }
        })?;
    if !certificate_remaining.is_empty() {
        return Err(PemError::MalformedDer {
            path: certificate_path.display().to_string(),
        });
    }
    let (issuer_remaining, issuer) =
        x509_parser::certificate::X509Certificate::from_der(&issuer_der).map_err(|_| {
            PemError::MalformedDer {
                path: issuer_path.display().to_string(),
            }
        })?;
    if !issuer_remaining.is_empty() {
        return Err(PemError::MalformedDer {
            path: issuer_path.display().to_string(),
        });
    }
    let (crl_remaining, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(
        &crl_der,
    )
    .map_err(|_| PemError::MalformedDer {
        path: crl_path.display().to_string(),
    })?;
    if !crl_remaining.is_empty() {
        return Err(PemError::MalformedDer {
            path: crl_path.display().to_string(),
        });
    }
    let timestamp = DateTime::parse_from_rfc3339(validation_time)
        .map_err(|_| PemError::InvalidValidationTime(validation_time.to_owned()))?
        .timestamp();

    validate_crl_extensions(&crl, crl_path)?;

    let certificate_signature_valid = certificate.signature_algorithm
        == certificate.tbs_certificate.signature
        && certificate
            .verify_signature(Some(issuer.public_key()))
            .is_ok();
    let issuer_matches = certificate.issuer() == issuer.subject()
        && crl.issuer() == issuer.subject()
        && certificate_signature_valid;
    let signer_is_authorized = match issuer.key_usage() {
        Ok(Some(usage)) => usage.value.crl_sign(),
        Ok(None) => true,
        Err(_) => false,
    };
    let signature_valid = crl.signature_algorithm == crl.tbs_cert_list.signature
        && signer_is_authorized
        && crl.verify_signature(issuer.public_key()).is_ok();
    let fresh = crl.last_update().timestamp() <= timestamp
        && crl
            .next_update()
            .is_some_and(|next_update| timestamp < next_update.timestamp());
    let revoked = crl.iter_revoked_certificates().any(|entry| {
        entry.revocation_date.timestamp() <= timestamp
            && entry
                .reason_code()
                .is_none_or(|(_, reason)| reason != x509_parser::x509::ReasonCode::RemoveFromCRL)
            && normalized_serial(entry.raw_serial()) == normalized_serial(certificate.raw_serial())
    });
    let prerequisites_pass = issuer_matches && signature_valid && fresh;

    Ok(CrlStatusResult {
        signature: CheckResult::observed(if signature_valid {
            CheckState::Pass
        } else {
            CheckState::Fail
        }),
        issuer: CheckResult::observed(if issuer_matches {
            CheckState::Pass
        } else {
            CheckState::Fail
        }),
        freshness: CheckResult::observed(if fresh {
            CheckState::Pass
        } else {
            CheckState::Fail
        }),
        revocation: CheckResult {
            state: if prerequisites_pass {
                if revoked {
                    CheckState::Fail
                } else {
                    CheckState::Pass
                }
            } else {
                CheckState::Indeterminate
            },
            confidence: Confidence::Observed,
        },
    })
}

pub fn check_certificate_validity(
    certificate_path: &Path,
    validation_time: &str,
    limit: usize,
) -> Result<CheckResult, PemError> {
    let der = read_der(certificate_path, PemKind::Certificate, limit)?;
    let (remaining, certificate) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|_| PemError::MalformedDer {
            path: certificate_path.display().to_string(),
        })?;
    if !remaining.is_empty() {
        return Err(PemError::MalformedDer {
            path: certificate_path.display().to_string(),
        });
    }
    let timestamp = DateTime::parse_from_rfc3339(validation_time)
        .map_err(|_| PemError::InvalidValidationTime(validation_time.to_owned()))?
        .timestamp();
    let time = x509_parser::time::ASN1Time::from_timestamp(timestamp)
        .map_err(|_| PemError::InvalidValidationTime(validation_time.to_owned()))?;
    Ok(CheckResult::observed(
        if certificate.validity().is_valid_at(time) {
            CheckState::Pass
        } else {
            CheckState::Fail
        },
    ))
}

fn validate_crl_extensions(
    crl: &x509_parser::revocation_list::CertificateRevocationList<'_>,
    path: &Path,
) -> Result<(), PemError> {
    let display = path.display().to_string();
    crl.tbs_cert_list
        .extensions_map()
        .map_err(|_| PemError::InvalidCrlExtensions {
            path: display.clone(),
        })?;
    for extension in crl.extensions() {
        let oid = extension.oid.to_id_string();
        if matches!(oid.as_str(), "2.5.29.27" | "2.5.29.28") {
            return Err(PemError::UnsupportedCrlSemantics { path: display, oid });
        }
        if extension.critical
            && (extension.parsed_extension().unsupported()
                || extension.parsed_extension().error().is_some())
        {
            return Err(PemError::UnsupportedCriticalCrlExtension { path: display, oid });
        }
    }
    for entry in crl.iter_revoked_certificates() {
        entry
            .extensions_map()
            .map_err(|_| PemError::InvalidCrlExtensions {
                path: display.clone(),
            })?;
        for extension in entry.extensions() {
            let oid = extension.oid.to_id_string();
            if oid == "2.5.29.29" {
                return Err(PemError::UnsupportedCrlSemantics { path: display, oid });
            }
            if extension.critical
                && (extension.parsed_extension().unsupported()
                    || extension.parsed_extension().error().is_some())
            {
                return Err(PemError::UnsupportedCriticalCrlExtension { path: display, oid });
            }
        }
    }
    Ok(())
}

fn normalized_serial(serial: &[u8]) -> &[u8] {
    let first_nonzero = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len());
    &serial[first_nonzero..]
}

fn digest(oid: &str, bytes: &[u8]) -> Result<Vec<u8>, PemError> {
    match oid {
        "2.16.840.1.101.3.4.2.1" => Ok(Sha256::digest(bytes).to_vec()),
        "2.16.840.1.101.3.4.2.2" => Ok(Sha384::digest(bytes).to_vec()),
        "2.16.840.1.101.3.4.2.3" => Ok(Sha512::digest(bytes).to_vec()),
        _ => Err(PemError::UnsupportedDigestAlgorithm(oid.to_owned())),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing to a string cannot fail");
    }
    hex
}

fn binding_design(signature_oid: &str, extensions: &[String]) -> BindingDesign {
    if extensions.iter().any(|oid| oid == "2.5.29.74") {
        BindingDesign::Catalyst
    } else if extensions
        .iter()
        .any(|oid| oid == "2.16.840.1.114027.80.6.1")
    {
        BindingDesign::Chameleon
    } else if extensions.iter().any(|oid| oid == "1.3.6.1.5.5.7.1.36") {
        BindingDesign::RelatedCertificate
    } else if is_composite_mldsa_oid(signature_oid) {
        BindingDesign::AtomicComposite
    } else {
        BindingDesign::None
    }
}

fn algorithm_security(oid: &str) -> AlgorithmSecurity {
    if is_ml_dsa_oid(oid) {
        AlgorithmSecurity::PostQuantum
    } else if is_composite_mldsa_oid(oid) {
        AlgorithmSecurity::Hybrid
    } else {
        AlgorithmSecurity::Classical
    }
}

fn is_ml_dsa_oid(oid: &str) -> bool {
    matches!(
        oid,
        "2.16.840.1.101.3.4.3.17" | "2.16.840.1.101.3.4.3.18" | "2.16.840.1.101.3.4.3.19"
    )
}

fn is_composite_mldsa_oid(oid: &str) -> bool {
    matches!(
        oid,
        "1.3.6.1.5.5.7.6.37"
            | "1.3.6.1.5.5.7.6.38"
            | "1.3.6.1.5.5.7.6.39"
            | "1.3.6.1.5.5.7.6.40"
            | "1.3.6.1.5.5.7.6.41"
            | "1.3.6.1.5.5.7.6.42"
            | "1.3.6.1.5.5.7.6.43"
            | "1.3.6.1.5.5.7.6.44"
            | "1.3.6.1.5.5.7.6.45"
            | "1.3.6.1.5.5.7.6.46"
            | "1.3.6.1.5.5.7.6.47"
            | "1.3.6.1.5.5.7.6.48"
            | "1.3.6.1.5.5.7.6.49"
            | "1.3.6.1.5.5.7.6.50"
            | "1.3.6.1.5.5.7.6.51"
            | "1.3.6.1.5.5.7.6.52"
            | "1.3.6.1.5.5.7.6.53"
            | "1.3.6.1.5.5.7.6.54"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_root_matches_the_published_der_digest() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2/root.pem");
        let der = read_der(&path, PemKind::Certificate, 64 * 1024).unwrap();
        let actual = hex_lower(&Sha256::digest(der));

        assert_eq!(
            actual,
            "414005efd6544ead5ac13a50c0a72664e1c6acb72a6b38bafac019057d4050d7"
        );
    }

    #[test]
    fn classifies_published_certificate_properties() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        for (name, subject, signature, binding) in [
            (
                "root.pem",
                AlgorithmSecurity::Classical,
                AlgorithmSecurity::Classical,
                BindingDesign::None,
            ),
            (
                "related-certA.pem",
                AlgorithmSecurity::Classical,
                AlgorithmSecurity::Classical,
                BindingDesign::RelatedCertificate,
            ),
            (
                "catalyst-leaf.pem",
                AlgorithmSecurity::Classical,
                AlgorithmSecurity::Classical,
                BindingDesign::Catalyst,
            ),
            (
                "chameleon-base.pem",
                AlgorithmSecurity::PostQuantum,
                AlgorithmSecurity::Classical,
                BindingDesign::Chameleon,
            ),
            (
                "composite-leaf.pem",
                AlgorithmSecurity::Classical,
                AlgorithmSecurity::Hybrid,
                BindingDesign::AtomicComposite,
            ),
            (
                "pure-leaf.pem",
                AlgorithmSecurity::PostQuantum,
                AlgorithmSecurity::Classical,
                BindingDesign::None,
            ),
            (
                "pure-mldsa-signed-leaf.pem",
                AlgorithmSecurity::Classical,
                AlgorithmSecurity::PostQuantum,
                BindingDesign::None,
            ),
        ] {
            let profile = inspect_certificate(&fixtures.join(name), 64 * 1024).unwrap();
            assert_eq!(profile.subject_public_key_scheme, subject, "{name} subject");
            assert_eq!(
                profile.certificate_signature_scheme, signature,
                "{name} signature"
            );
            assert_eq!(profile.binding_design, binding, "{name} binding");
        }
    }

    #[test]
    fn dsa_with_sha256_is_not_post_quantum() {
        assert_eq!(
            algorithm_security("2.16.840.1.101.3.4.3.2"),
            AlgorithmSecurity::Classical
        );
    }

    #[test]
    fn non_composite_pkix_algorithm_child_is_not_hybrid() {
        assert_eq!(
            algorithm_security("1.3.6.1.5.5.7.6.1"),
            AlgorithmSecurity::Classical
        );
        assert_eq!(
            binding_design("1.3.6.1.5.5.7.6.1", &[]),
            BindingDesign::None
        );
    }

    #[test]
    fn independently_verifies_the_published_related_certificate_binding() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let result = verify_related_binding(
            &fixtures.join("related-certA.pem"),
            &fixtures.join("related-leafB.pem"),
            64 * 1024,
        )
        .unwrap();

        assert_eq!(result.check, CheckResult::observed(CheckState::Pass));
        assert_eq!(result.digest_algorithm_oid, "2.16.840.1.101.3.4.2.1");
    }

    #[test]
    fn related_conformance_rejects_the_published_key_usage_and_dns_mismatch() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let result = verify_related_certificate_conformance(
            &fixtures.join("related-certA.pem"),
            &fixtures.join("related-leafB.pem"),
            64 * 1024,
        )
        .unwrap();

        assert_eq!(
            result.rfc9763.binding.check,
            CheckResult::observed(CheckState::Pass)
        );
        assert_eq!(
            result
                .hybrid_application_policy
                .related_subject_public_key_is_post_quantum,
            CheckResult::observed(CheckState::Pass)
        );
        assert_eq!(
            result.rfc9763.extension_in_end_entity,
            CheckResult::observed(CheckState::Pass)
        );
        assert_eq!(
            result.rfc9763.related_certificate_is_end_entity,
            CheckResult::observed(CheckState::Pass)
        );
        assert_eq!(
            result.rfc9763.key_usage_subset,
            CheckResult::observed(CheckState::Fail)
        );
        assert_eq!(
            result.rfc9763.extended_key_usage_subset,
            CheckResult::observed(CheckState::Pass)
        );
        assert_eq!(
            result.hybrid_application_policy.dns_identity_overlap,
            CheckResult::observed(CheckState::Fail)
        );
    }

    #[test]
    fn related_conformance_rejects_classical_related_certificate_claims() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let result = verify_related_certificate_conformance(
            &fixtures.join("related-certA.pem"),
            &fixtures.join("related-certA.pem"),
            64 * 1024,
        )
        .unwrap();

        assert_eq!(
            result
                .hybrid_application_policy
                .related_subject_public_key_is_post_quantum,
            CheckResult::observed(CheckState::Fail)
        );
    }

    #[test]
    fn hybrid_related_policy_rejects_pq_to_pq_pairs() {
        let result = hybrid_application_policy_checks(
            AlgorithmSecurity::PostQuantum,
            AlgorithmSecurity::PostQuantum,
            true,
        );

        assert_eq!(
            result.reference_subject_public_key_is_classical,
            CheckResult::observed(CheckState::Fail)
        );
        assert_eq!(
            result.related_subject_public_key_is_post_quantum,
            CheckResult::observed(CheckState::Pass)
        );
    }

    #[test]
    fn hybrid_related_policy_rejects_missing_reference_identity() {
        let result = hybrid_application_policy_checks(
            AlgorithmSecurity::Classical,
            AlgorithmSecurity::PostQuantum,
            false,
        );

        assert_eq!(
            result.dns_identity_overlap,
            CheckResult::observed(CheckState::Fail)
        );
    }

    #[test]
    fn related_conformance_rejects_related_extensions_in_ca_certificates() {
        let controls =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/generated-controls");
        let result = verify_related_certificate_conformance(
            &controls.join("related-path-root-a.pem"),
            &controls.join("related-path-root-b.pem"),
            64 * 1024,
        )
        .unwrap();

        assert_eq!(
            result.rfc9763.extension_in_end_entity,
            CheckResult::observed(CheckState::Fail)
        );
    }

    #[test]
    fn rejects_a_related_certificate_that_does_not_match_the_embedded_hash() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let result = verify_related_binding(
            &fixtures.join("related-certA.pem"),
            &fixtures.join("related-leafB-expired.pem"),
            64 * 1024,
        )
        .unwrap();

        assert_eq!(result.check, CheckResult::observed(CheckState::Fail));
    }

    #[test]
    fn independently_confirms_the_published_pq_revocation() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let result = check_crl_status(
            &fixtures.join("related-leafB.pem"),
            &fixtures.join("ica.pem"),
            &fixtures.join("related-crl.pem"),
            "2026-06-20T00:00:00Z",
            64 * 1024,
        )
        .unwrap();

        assert_eq!(result.signature, CheckResult::observed(CheckState::Pass));
        assert_eq!(result.issuer, CheckResult::observed(CheckState::Pass));
        assert_eq!(result.freshness, CheckResult::observed(CheckState::Pass));
        assert_eq!(result.revocation, CheckResult::observed(CheckState::Fail));
    }

    #[test]
    fn a_future_crl_entry_is_not_yet_revoked() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let published = repository.join("tests/fixtures/paper-v1.0.2");
        let controls = repository.join("tests/fixtures/generated-controls");
        let result = check_crl_status(
            &published.join("related-leafB.pem"),
            &published.join("ica.pem"),
            &controls.join("related-crl-future.pem"),
            "2026-06-21T00:00:00Z",
            64 * 1024,
        )
        .unwrap();

        assert_eq!(result.signature, CheckResult::observed(CheckState::Pass));
        assert_eq!(result.issuer, CheckResult::observed(CheckState::Pass));
        assert_eq!(result.freshness, CheckResult::observed(CheckState::Pass));
        assert_eq!(result.revocation, CheckResult::observed(CheckState::Pass));
    }

    #[test]
    fn a_stale_crl_cannot_produce_a_successful_status() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let result = check_crl_status(
            &fixtures.join("related-leafB.pem"),
            &fixtures.join("ica.pem"),
            &fixtures.join("related-crl.pem"),
            "2030-01-01T00:00:00Z",
            64 * 1024,
        )
        .unwrap();

        assert_eq!(result.freshness, CheckResult::observed(CheckState::Fail));
        assert_eq!(
            result.revocation,
            CheckResult::observed(CheckState::Indeterminate)
        );
    }

    #[test]
    fn crl_is_stale_at_exact_next_update() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let result = check_crl_status(
            &fixtures.join("related-leafB.pem"),
            &fixtures.join("ica.pem"),
            &fixtures.join("related-crl.pem"),
            "2027-01-01T00:00:00Z",
            64 * 1024,
        )
        .unwrap();

        assert_eq!(result.freshness, CheckResult::observed(CheckState::Fail));
        assert_eq!(
            result.revocation,
            CheckResult::observed(CheckState::Indeterminate)
        );
    }

    #[test]
    fn malformed_and_unavailable_crls_are_errors() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        let malformed = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(malformed.path(), b"not a CRL").unwrap();
        let unavailable = fixtures.join("missing-crl.pem");

        for crl in [malformed.path(), unavailable.as_path()] {
            assert!(
                check_crl_status(
                    &fixtures.join("related-leafB.pem"),
                    &fixtures.join("ica.pem"),
                    crl,
                    "2026-06-20T00:00:00Z",
                    64 * 1024,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn issuer_name_and_serial_cannot_replace_certificate_signature_proof() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let published = repository.join("tests/fixtures/paper-v1.0.2");
        let controls = repository.join("tests/fixtures/generated-controls");
        let result = check_crl_status(
            &controls.join("related-leafB-wrong-signer.pem"),
            &published.join("ica.pem"),
            &published.join("related-crl.pem"),
            "2026-06-21T00:00:00Z",
            64 * 1024,
        )
        .unwrap();

        assert_eq!(result.signature, CheckResult::observed(CheckState::Pass));
        assert_eq!(result.issuer, CheckResult::observed(CheckState::Fail));
        assert_eq!(
            result.revocation,
            CheckResult::observed(CheckState::Indeterminate)
        );
    }

    #[test]
    fn related_controls_have_distinct_reference_outcomes() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let controls = repository.join("tests/fixtures/generated-controls");
        let related = repository.join("tests/fixtures/paper-v1.0.2/related-leafB.pem");

        assert_eq!(
            inspect_certificate(&controls.join("related-certA-missing.pem"), 64 * 1024)
                .unwrap()
                .binding_design,
            BindingDesign::None
        );
        assert!(matches!(
            verify_related_binding(
                &controls.join("related-certA-missing.pem"),
                &related,
                64 * 1024
            ),
            Err(PemError::MissingRelatedCertificate { .. })
        ));
        assert_eq!(
            verify_related_binding(
                &controls.join("related-certA-broken-binding.pem"),
                &related,
                64 * 1024
            )
            .unwrap()
            .check,
            CheckResult::observed(CheckState::Fail)
        );
        assert!(matches!(
            verify_related_binding(
                &controls.join("related-certA-unknown-digest.pem"),
                &related,
                64 * 1024
            ),
            Err(PemError::UnsupportedDigestAlgorithm(_))
        ));
        assert!(matches!(
            verify_related_binding(
                &controls.join("related-certA-malformed.pem"),
                &related,
                64 * 1024
            ),
            Err(PemError::MalformedRelatedCertificate { .. })
        ));
        assert_eq!(
            verify_related_binding(
                &controls.join("related-certA-critical.pem"),
                &related,
                64 * 1024
            )
            .unwrap()
            .check,
            CheckResult::observed(CheckState::Pass)
        );
    }

    #[test]
    fn checks_validity_at_the_requested_time() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paper-v1.0.2");
        assert_eq!(
            check_certificate_validity(
                &fixtures.join("related-leafB.pem"),
                "2026-06-20T00:00:00Z",
                64 * 1024,
            )
            .unwrap()
            .state,
            CheckState::Pass
        );
        assert_eq!(
            check_certificate_validity(
                &fixtures.join("related-leafB-expired.pem"),
                "2026-06-20T00:00:00Z",
                64 * 1024,
            )
            .unwrap()
            .state,
            CheckState::Fail
        );
    }
}
