#!/usr/bin/env bash
set -euo pipefail

export VANT_LINUX_DISTRO="zentyal"
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/../common" && pwd)/install_agent.sh" "$@"
