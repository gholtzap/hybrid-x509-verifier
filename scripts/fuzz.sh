#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
seconds=${1:-30}
toolchain=${FUZZ_TOOLCHAIN:-nightly-2026-08-04}
mkdir -p "$repo/target/tooling"

if [ ! -x "$repo/target/tooling/bin/cargo-fuzz" ]; then
  cargo install --root "$repo/target/tooling" cargo-fuzz --version 0.13.2 --locked
fi

rustup toolchain install "$toolchain" --profile minimal
cd "$repo"
mkdir -p fuzz/corpus/ocsp-der
openssl base64 -d -A -in tests/fixtures/ocsp-imported/response.der.b64 \
  -out fuzz/corpus/ocsp-der/signed-good.der
pids=
for target in pem oracle-json ocsp-der; do
  log="$repo/target/fuzz-$target.log"
  RUSTUP_TOOLCHAIN="$toolchain" "$repo/target/tooling/bin/cargo-fuzz" run "$target" \
    -- -max_total_time="$seconds" >"$log" 2>&1 &
  pids="$pids $!"
done
trap 'kill $pids 2>/dev/null || true' HUP INT TERM
status=0
for pid in $pids; do
  wait "$pid" || status=1
done
trap - HUP INT TERM
for target in pem oracle-json ocsp-der; do
  printf '%s\n' "== $target =="
  tail -20 "$repo/target/fuzz-$target.log"
done
exit "$status"
