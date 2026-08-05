#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
docker build -t hybrid-x509-oqs-provider:0.11.0 "$repo/tools/oqs-provider-adapter"
