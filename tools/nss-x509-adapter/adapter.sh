#!/bin/sh
set -eu

run_nss_tool() {
  tool=$1
  shift
  "${NSS_BIN_DIR:+$NSS_BIN_DIR/}$tool" "$@"
}

if [ "${1:-}" = "--version" ]; then
  if [ -n "${NSS_ADAPTER_VERSION:-}" ]; then
    printf '%s\n' "$NSS_ADAPTER_VERSION"
  else
    dpkg-query -W -f='${Version}\n' libnss3-tools
  fi
  exit 0
fi

root=
intermediate=
leaf=
time=
while [ "$#" -gt 0 ]; do
  option=$1
  [ "$#" -ge 2 ] || { printf '%s\n' "option value is missing" >&2; exit 2; }
  value=$2
  shift 2
  case "$option" in
    --root) root=$value ;;
    --intermediate) intermediate=$value ;;
    --leaf) leaf=$value ;;
    --time) time=$value ;;
    *) printf '%s\n' "unknown option: $option" >&2; exit 2 ;;
  esac
done
[ -n "$root" ] && [ -n "$intermediate" ] && [ -n "$leaf" ] && [ -n "$time" ] || {
  printf '%s\n' "root, intermediate, leaf, and time are required" >&2
  exit 2
}

database=$(mktemp -d)
trap 'rm -rf "$database"' EXIT
run_nss_tool certutil -N -d "sql:$database" --empty-password
run_nss_tool certutil -A -d "sql:$database" -n root -t "CT,C,C" -i "$root"
set +e
import_output=$(run_nss_tool certutil -A -d "sql:$database" -n intermediate -t ",," -i "$intermediate" 2>&1)
import_status=$?
set -e
if [ "$import_status" -ne 0 ]; then
  printf '%s\n' "$import_output" >&2
  printf '{"verdict":"unsupported"}\n'
  exit 0
fi

verify_tool=${NSS_VERIFY_TOOL:-vfychain}
tool_path="${NSS_BIN_DIR:+$NSS_BIN_DIR/}$verify_tool"
command -v "$tool_path" >/dev/null 2>&1 || {
  printf '%s\n' "NSS verification tool was not found: $verify_tool" >&2
  exit 3
}

set +e
output=$(run_nss_tool "$verify_tool" -b "$time" -d "sql:$database" -u 1 -a "$leaf" -a "$intermediate" 2>&1)
status=$?
set -e
printf '%s\n' "$output" >&2

if [ "$status" -eq 0 ] && printf '%s' "$output" | grep -q "Chain is good"; then
  verdict=accept
elif printf '%s' "$output" | grep -Eqi "unknown|unsupported|SEC_ERROR_BAD_DER|SEC_ERROR_INVALID_ALGORITHM"; then
  verdict=unsupported
else
  verdict=reject
fi
printf '{"verdict":"%s"}\n' "$verdict"
