# Verification transcripts

`local-arm64` contains raw local JSON reports. The stack adapters
execute in isolated Linux arm64 containers unless a report names a native executable. Each report
contains the exact command arguments, input file hashes, validation time, stack version,
execution-isolation record, raw-output hashes, and available adapter instrumentation.
Regenerate these reports after schema or confidence-model changes before treating them as current
local artifacts.

The v9 matrix reports contain the source commit, source tree, dirty-state result, platform, and
adapter image content digests. A dirty-state result prevents publication use. The atomic path,
atomic TLS, Related OpenSSL, Related TLS, Related path, and two OCSP reports were also regenerated
for this working change. Other `local-arm64` JSON reports and both SBOM files are stale against the
v9 contract and must not be published as current results until they are regenerated from a clean
commit.

Regenerate the reports with the commands in the project README from a clean commit. Do not treat
these local reports as publication-grade, hosted continuous-integration, independent-review, or
security-boundary verification evidence.
