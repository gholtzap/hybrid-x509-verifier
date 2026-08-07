use std::{fs, path::Path};

const EXPECTED_MARKERS: [(&str, &str, &str); 6] = [
    (
        "reports/local-arm64/atomic-path-scope-report.json",
        "/scopes/0/result/policy_verdict",
        "indeterminate",
    ),
    (
        "reports/local-arm64/atomic-path-scope-report.json",
        "/scopes/1/result/policy_verdict",
        "indeterminate",
    ),
    (
        "reports/local-arm64/related-openssl-report.json",
        "/result/policy_verdict",
        "reject",
    ),
    (
        "reports/local-arm64/related-openssl-report.json",
        "/result/classical_only_fallback",
        "true",
    ),
    (
        "reports/local-arm64/related-openssl-report.json",
        "/result/lifecycle_desynchronization",
        "true",
    ),
    (
        "reports/local-arm64/matrix-report.json",
        "/provenance/source_clean",
        "false",
    ),
];

#[test]
fn documented_report_values_match_generated_reports() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let document = fs::read_to_string(repository.join("docs/verification-status.md")).unwrap();
    let markers = document
        .lines()
        .filter_map(|line| {
            line.strip_prefix("<!-- report-value ")
                .and_then(|line| line.strip_suffix(" -->"))
        })
        .map(|marker| {
            let mut fields = marker.split_whitespace();
            let report_path = fields.next().unwrap();
            let pointer = fields.next().unwrap();
            let expected = fields.next().unwrap();
            assert!(fields.next().is_none(), "invalid report-value marker");
            (report_path, pointer, expected)
        })
        .collect::<Vec<_>>();
    assert_eq!(markers, EXPECTED_MARKERS);

    for (report_path, pointer, expected) in markers {
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(repository.join(report_path)).unwrap()).unwrap();
        let expected = serde_json::from_str(expected)
            .unwrap_or_else(|_| serde_json::Value::String(expected.to_owned()));
        assert_eq!(
            report.pointer(pointer),
            Some(&expected),
            "{report_path} {pointer}"
        );
    }
}
