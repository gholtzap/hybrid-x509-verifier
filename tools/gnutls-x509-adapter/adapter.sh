#!/bin/sh
set -eu
if [ "${1:-}" = "--version" ]; then
  exec certtool --version
fi
root=
intermediate=
leaf=
time=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root=$2; shift 2 ;;
    --intermediate) intermediate=$2; shift 2 ;;
    --leaf) leaf=$2; shift 2 ;;
    --time) time=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
test -n "$root" && test -n "$intermediate" && test -n "$leaf" && test -n "$time"
cp "$root" /tmp/authorities.pem
printf '\n' >> /tmp/authorities.pem
cat "$intermediate" >> /tmp/authorities.pem
faketime=$(find /usr/lib -name libfaketime.so.1 -type f -print -quit)
test -n "$faketime"
TZ=UTC FAKETIME="@$time" LD_PRELOAD="$faketime" exec certtool --verify \
  --load-ca-certificate /tmp/authorities.pem --infile "$leaf"
