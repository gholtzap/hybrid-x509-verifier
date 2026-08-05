#!/bin/sh
set -eu
openssl=/opt/oqs-openssl/bin/openssl
providers='-provider oqsprovider -provider default'
if [ "${1:-}" = "--default-only" ]; then
  providers='-provider default'
  shift
fi
if [ "${1:-}" = "--version" ]; then
  "$openssl" version
  # shellcheck disable=SC2086
  "$openssl" list -providers $providers
  exit
fi
# shellcheck disable=SC2086
exec "$openssl" verify $providers "$@"
