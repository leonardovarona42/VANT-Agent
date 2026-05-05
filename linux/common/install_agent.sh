#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${LINUX_DIR}/dist"
DISTRO="${VANT_LINUX_DISTRO:-${DISTRO:-}}"
PACKAGE_OVERRIDE="${VANT_AGENT_PACKAGE_DIR:-}"
INSTALL_ARGS=("$@")

if [[ -z "${DISTRO}" ]]; then
  echo "Set VANT_LINUX_DISTRO to debian, ubuntu or zentyal."
  exit 1
fi

validate_package_dir() {
  local package_dir="$1"
  if [[ ! -d "${package_dir}" ]]; then
    return 1
  fi
  if [[ ! -f "${package_dir}/install.sh" ]]; then
    return 1
  fi
  if [[ ! -f "${package_dir}/config/agent.yaml" ]]; then
    return 1
  fi
  if [[ ! -d "${package_dir}/agent" ]]; then
    return 1
  fi
  return 0
}

find_package_dir() {
  local candidate
  if [[ ! -d "${DIST_DIR}" ]]; then
    return 1
  fi
  for candidate in \
    "${PACKAGE_OVERRIDE}" \
    "${DIST_DIR}/${DISTRO}/vant-siem-agent-install" \
    "${DIST_DIR}/vant-siem-agent-install"; do
    if [[ -n "${candidate}" ]] && validate_package_dir "${candidate}"; then
      echo "${candidate}"
      return 0
    fi
  done
  candidate="$(find "${DIST_DIR}" -maxdepth 1 -type d -name "vant-siem-agent-install" | head -n 1)"
  if [[ -n "${candidate}" ]] && validate_package_dir "${candidate}"; then
    echo "${candidate}"
    return 0
  fi
  return 1
}

extract_package_tarball() {
  local tarball workdir extracted
  if [[ ! -d "${DIST_DIR}" ]]; then
    return 1
  fi
  tarball="$(find "${DIST_DIR}" -maxdepth 1 -type f -name "vant-siem-agent-linux-${DISTRO}-*.tar.gz" | sort | tail -n 1)"
  if [[ -z "${tarball}" ]]; then
    return 1
  fi

  workdir="$(mktemp -d /tmp/vant-siem-agent-linux.XXXXXX)"
  tar -xzf "${tarball}" -C "${workdir}"
  extracted="$(find "${workdir}" -maxdepth 1 -type d -name "vant-siem-agent-install" | head -n 1)"
  if [[ -z "${extracted}" ]] || ! validate_package_dir "${extracted}"; then
    echo "Failed to extract package payload from ${tarball}"
    exit 1
  fi
  echo "${extracted}"
}

PACKAGE_DIR=""
if PACKAGE_DIR="$(find_package_dir)"; then
  :
elif PACKAGE_DIR="$(extract_package_tarball)"; then
  :
else
  echo "Offline package not found under ${DIST_DIR}."
  echo "Build it first with: ./opensearch_agents/linux/build_linux.sh"
  exit 1
fi

INSTALL_SCRIPT="${PACKAGE_DIR}/install.sh"
if [[ ! -f "${INSTALL_SCRIPT}" ]]; then
  echo "Install script not found in package: ${INSTALL_SCRIPT}"
  exit 1
fi

chmod +x "${INSTALL_SCRIPT}"
(cd "${PACKAGE_DIR}" && bash "./install.sh" "${INSTALL_ARGS[@]}")

echo "Installed from offline package: ${PACKAGE_DIR}"
echo "Edit /etc/vant-siem/config.yaml to adjust the agent."
