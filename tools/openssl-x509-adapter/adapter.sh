#!/bin/sh
set -eu
openssl=/opt/openssl/bin/openssl
if [ "${1:-}" = "--version" ]; then
  exec "$openssl" version
fi
if [ "${1:-}" = "--tls-server-client" ]; then
  [ "$#" -eq 7 ] || exit 64
  root=$2
  intermediate=$3
  certificate=$4
  key=$5
  hostname=$6
  validation_time=$7
  server_log=/tmp/tls-server.log
  client_log=/tmp/tls-client.log
  "$openssl" s_server \
    -accept 127.0.0.1:4433 \
    -cert "$certificate" \
    -cert_chain "$intermediate" \
    -key "$key" \
    -www -tls1_3 -naccept 1 >"$server_log" 2>&1 &
  server_pid=$!
  trap 'kill "$server_pid" 2>/dev/null || true' EXIT
  sleep 0.2
  client_status=0
  printf 'GET / HTTP/1.0\r\n\r\n' | "$openssl" s_client \
    -connect 127.0.0.1:4433 \
    -servername "$hostname" \
    -verify_hostname "$hostname" \
    -verify_return_error \
    -attime "$validation_time" \
    -CAfile "$root" \
    -tls1_3 -brief >"$client_log" 2>&1 || client_status=$?
  server_status=0
  wait "$server_pid" || server_status=$?
  trap - EXIT
  cat "$client_log"
  cat "$server_log" >&2
  [ "$client_status" -eq 0 ] && [ "$server_status" -eq 0 ]
  exit
fi
exec "$openssl" verify "$@"
