#![no_main]

use hybrid_x509_verifier::{VerificationRequest, evaluate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<VerificationRequest>(data) {
        let _ = evaluate(&request);
    }
});
