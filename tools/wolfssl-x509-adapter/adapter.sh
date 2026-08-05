#!/bin/sh
set -eu
mode=${1:-}
shift || true
case "$mode" in
  mode1|mode2) ;;
  *) echo "mode must be mode1 or mode2" >&2; exit 2 ;;
esac
binary="/opt/wolfssl-$mode/bin/wolfssl_verify"
if [ "${1:-}" = "--version" ]; then
  exec "$binary" --version
fi
time=${1:-}
test -n "$time"
shift
faketime=$(find /usr/lib -name libfaketime.so.1 -type f -print -quit)
test -n "$faketime"
TZ=UTC FAKETIME="@$time" LD_PRELOAD="$faketime" exec "$binary" "$@"
