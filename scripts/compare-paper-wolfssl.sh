#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-"$repo/reports/local-arm64/paper-wolfssl-comparison.json"}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for mode in default dual-algorithm; do
  for case in good bad; do
    cargo run --quiet --locked --manifest-path "$repo/Cargo.toml" --bin hybrid-x509-verify -- \
      probe-wolf-ssl \
      --mode "$mode" \
      --scheme catalyst-wolfgen \
      --trust-store "$repo/tests/fixtures/paper-v1.0.2/wolfgen/wolfgen-ca.pem" \
      --leaf "$repo/tests/fixtures/paper-v1.0.2/wolfgen/wolfgen-leaf-$case.pem" \
      --validation-time 2026-07-07T11:59:59Z >"$tmp/$mode-$case.json"
  done
done

jq -s '
  [
    {adapter:"wolfssl-mode1", case:"valid", expected:"accept", report:.[0]},
    {adapter:"wolfssl-mode1", case:"pqc-corrupt", expected:"accept", report:.[1]},
    {adapter:"wolfssl-mode2", case:"valid", expected:"accept", report:.[2]},
    {adapter:"wolfssl-mode2", case:"pqc-corrupt", expected:"reject", report:.[3]}
  ]
  | map(. + {
      actual: .report.observation.verdict,
      matched: (.report.observation.verdict == .expected)
    }) as $comparisons
  | {
      paper_commit:"b1c2ee5e87862c4103b482571945505f82a0d0d9",
      validation_time:"2026-07-07T11:59:59Z",
      compared_rows:($comparisons | length),
      matched_rows:([$comparisons[] | select(.matched)] | length),
      differences:[$comparisons[] | select(.matched | not)],
      comparisons:$comparisons
    }
' \
  "$tmp/default-good.json" \
  "$tmp/default-bad.json" \
  "$tmp/dual-algorithm-good.json" \
  "$tmp/dual-algorithm-bad.json" >"$output"

jq -e '.compared_rows == 4 and .matched_rows == 4 and (.differences | length) == 0' \
  "$output" >/dev/null
