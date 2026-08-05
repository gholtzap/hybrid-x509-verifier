#![no_main]

use hybrid_x509_verifier::ocsp::validate_ocsp_der;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = validate_ocsp_der(data, 1_048_576);
});
