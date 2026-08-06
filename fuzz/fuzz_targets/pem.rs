#![no_main]

use hybrid_x509_evidence::pem::{PemKind, decode_pem};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_pem(data, PemKind::Certificate, 1_048_576, "fuzz-input");
    let _ = decode_pem(
        data,
        PemKind::CertificateRevocationList,
        1_048_576,
        "fuzz-input",
    );
});
