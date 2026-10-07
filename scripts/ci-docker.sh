#!/bin/bash
set -euo pipefail

if [[ "${RUNNER_NAME:-}" != mini-linux-* || "${RUNNER_OS:-}" != Linux ]]; then
  exit 0
fi

export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
case "$1" in
  start)
    systemctl --user start docker.service
    echo "DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock" >> "$GITHUB_ENV"
    docker --host "unix://$XDG_RUNTIME_DIR/docker.sock" info
    ;;
  stop)
    systemctl --user stop docker.service
    ;;
  *)
    echo "Usage: ci-docker.sh start|stop" >&2
    exit 2
    ;;
esac
