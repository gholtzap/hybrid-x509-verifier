# Verification transcripts

`local-arm64` contains raw local JSON reports. The stack adapters
execute in isolated Linux arm64 containers unless a report names a native executable. Each report
contains the exact command arguments, input file hashes, validation time, stack version,
execution-isolation record, raw-output hashes, and available adapter instrumentation.
Regenerate these reports after schema or confidence-model changes before treating them as current
local artifacts.

The v9 matrix reports contain the source commit, source tree, dirty-state result, platform, and
adapter image content digests. All 30 JSON reports and both root SBOM files were regenerated from
clean source commit `ee72f1cb5403866130c66dbe6d4522c93eed6074`. The matrix records 345 entries,
no process, support, or verdict mismatch, and `source_clean: true`.

These are fixture-specific local reports. Do not treat them as independent review, general library
support, or security-boundary verification evidence.
