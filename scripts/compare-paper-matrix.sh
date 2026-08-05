#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
matrix=${1:-"$repo/reports/local-arm64/matrix-report.json"}
expected="$repo/tests/fixtures/paper-v1.0.2/expected-valid-matrix.json"
output=${2:-"$repo/reports/local-arm64/paper-comparison.json"}

jq --slurpfile expected "$expected" '
  . as $matrix
  | [$expected[0].profiles | to_entries[] as $profile
      | $profile.value.cases | to_entries[]
      | . as $case
      | [$matrix.entries[]
          | select(.variant == "valid"
              and .case_id == $case.key
              and .report.observation.adapter == $profile.key)][0] as $actual
      | {
          adapter: $profile.key,
          case_id: $case.key,
          expected_verdict: $case.value,
          actual_verdict: ($actual.report.observation.verdict // null),
          expected_version_contains: $profile.value.version_contains,
          actual_version: ($actual.report.observation.version // null),
          verdict_match: (($actual.report.observation.verdict // null) == $case.value),
          version_match: (($actual.report.observation.version // "") | contains($profile.value.version_contains))
        }
      | . + {matched: (.verdict_match and .version_match)}] as $comparisons
  | {
      paper_commit: $expected[0].paper_commit,
      compared_rows: ($comparisons | length),
      matched_rows: ([$comparisons[] | select(.matched)] | length),
      differences: [$comparisons[] | select(.matched | not)],
      comparisons: $comparisons
    }
' "$matrix" >"$output"

jq -e '.compared_rows == 54 and .matched_rows == 54 and (.differences | length) == 0' "$output" >/dev/null
