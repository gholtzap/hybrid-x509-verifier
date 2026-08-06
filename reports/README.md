# Verification transcripts

`local-arm64` contains raw local JSON reports. The stack adapters
execute in isolated Linux arm64 containers unless a report names a native executable. Each report
contains the exact command arguments, input file hashes, validation time, stack version,
execution-isolation record, raw-output hashes, and available adapter instrumentation.
Regenerate these reports after schema or confidence-model changes before treating them as current
local artifacts.

`available-matrix.json`, `matrix-report.json`, `sbom-rust.cdx.json`, and `sbom-all.cdx.json`
were regenerated for the `hybrid-x509-evidence/v8` contract from clean source commit
`4f4626bcb1e03c72a861905d412080340ed53c71`. Other `local-arm64` JSON reports are stale against
the current contract and must not be published as current results until regenerated from a clean
commit.

Regenerate the reports with the commands in the project README from a clean commit. Do not treat
these local reports as publication-grade, hosted continuous-integration, independent-review, or
security-boundary verification evidence.
