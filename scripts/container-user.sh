#!/bin/sh
set -eu

# Container root maps to the build account with a rootless engine.
options=$(docker info --format '{{json .SecurityOptions}}')
case "$options" in
  *'"name=rootless"'*) printf '0:0\n' ;;
  *) printf '%s:%s\n' "$(id -u)" "$(id -g)" ;;
esac
