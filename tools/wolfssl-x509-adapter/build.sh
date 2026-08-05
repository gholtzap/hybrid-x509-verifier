#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
docker build -t hybrid-x509-wolfssl:5.9.2 "$repo/tools/wolfssl-x509-adapter"
