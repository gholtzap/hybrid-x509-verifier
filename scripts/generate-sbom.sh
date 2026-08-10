#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$repo/target/tooling"

if [ ! -x "$repo/target/tooling/bin/cargo-cyclonedx" ]; then
  cargo install --root "$repo/target/tooling" cargo-cyclonedx --version 0.5.9 --locked
fi

cd "$repo"
SOURCE_DATE_EPOCH=1782000000 "$repo/target/tooling/bin/cargo-cyclonedx" cyclonedx \
  --format json \
  --spec-version 1.5 \
  --all-features \
  --target x86_64-unknown-linux-gnu \
  --override-filename sbom-rust.cdx

generate_all() {
  destination=$1
  raw="$destination.raw"
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    --network=none \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --tmpfs=/tmp:rw,noexec,nosuid,size=64m \
    --mount "type=bind,src=$repo,dst=/source,readonly" \
    --mount "type=bind,src=$repo/target,dst=/output" \
    anchore/syft@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026 \
    scan dir:/source \
    --exclude './target/**' \
    --exclude './.git/**' \
    --source-name hybrid-x509-evidence \
    --source-version 0.1.0 \
    --output "cyclonedx-json=/output/$(basename "$raw")" \
    --quiet
  jq '
    del(.serialNumber)
    | .metadata.timestamp = "2026-06-21T00:00:00Z"
    | .components |= sort_by(."bom-ref")
    | .dependencies |= (map(.dependsOn |= sort) | sort_by(.ref))
  ' "$raw" >"$destination"
  rm "$raw"
}

generate_all "$repo/target/sbom-all-1.cdx.json"
generate_all "$repo/target/sbom-all-2.cdx.json"
cmp "$repo/target/sbom-all-1.cdx.json" "$repo/target/sbom-all-2.cdx.json"
cp "$repo/target/sbom-all-1.cdx.json" "$repo/sbom-all.cdx.json"
