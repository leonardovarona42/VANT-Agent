#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${AGENTS_DIR}/.." && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
BUILD_ROOT="${DIST_DIR}/.build"
AGENT_VERSION="${AGENT_VERSION:-1.0.0}"
BUILD_TS="$(date -u +"%Y%m%d%H%M%S")"
BUILD_DEB=0
BUILD_TARBALL=1
TARGET_DISTROS=()

log() { printf '%s\n' "$*"; }
info() { printf '  [info] %s\n' "$*"; }
ok() { printf '  [ok] %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*"; }
die() { printf '  [error] %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

usage() {
  cat <<'EOF'
Usage: build_linux.sh [options]

Options:
  --all             Build all detected Linux distros (default)
  --distro NAME     Build one distro: debian, ubuntu, zentyal, ...
  --deb             Also build a .deb package when dpkg-deb is available
  --no-tarball      Skip the tar.gz bundle
  --clean           Remove linux/dist and exit
  --help            Show this help
EOF
}

discover_distros() {
  local distro_dir
  for distro_dir in "${SCRIPT_DIR}"/*; do
    [[ -d "${distro_dir}" ]] || continue
    case "$(basename "${distro_dir}")" in
      common|dist) continue ;;
    esac
    [[ -f "${distro_dir}/config.yaml" ]] || continue
    TARGET_DISTROS+=("$(basename "${distro_dir}")")
  done
}

copy_tree() {
  local src="$1"
  local dst="$2"
  if [[ -d "${src}" ]]; then
    mkdir -p "${dst}"
    cp -R "${src}/." "${dst}/"
  elif [[ -f "${src}" ]]; then
    mkdir -p "$(dirname "${dst}")"
    cp "${src}" "${dst}"
  fi
}

prepare_venv() {
  local venv_dir="$1"
  python3 -m venv "${venv_dir}"
  # shellcheck disable=SC1091
  source "${venv_dir}/bin/activate"
  pip install --upgrade pip >/dev/null
  pip install pyyaml requests PyQt6 pyinstaller >/dev/null
  deactivate
}

LINUX_AGENT_DIR="${AGENTS_DIR}/linux/agent"

build_linux_binaries() {
  local venv_dir="$1"
  local build_root="$2"
  local dist_dir="${build_root}/pyinstaller-dist"
  local work_dir="${build_root}/pyinstaller-work"
  local spec_dir="${build_root}/pyinstaller-spec"
  local pyinstaller_python="${venv_dir}/bin/python"
  local add_data_sep=":"

  rm -rf "${dist_dir}" "${work_dir}" "${spec_dir}"
  mkdir -p "${dist_dir}" "${work_dir}" "${spec_dir}"

  info "Compiling Linux binaries with PyInstaller"
  "${pyinstaller_python}" -m PyInstaller \
    --noconfirm \
    --clean \
    --onefile \
    --name "vant-opensearch-agent" \
    --paths "${LINUX_AGENT_DIR}" \
    --paths "${AGENTS_DIR}" \
    --hidden-import yaml \
    --hidden-import requests \
    --distpath "${dist_dir}" \
    --workpath "${work_dir}/agent" \
    --specpath "${spec_dir}" \
    "${LINUX_AGENT_DIR}/agent.py" >/dev/null

  "${pyinstaller_python}" -m PyInstaller \
    --noconfirm \
    --clean \
    --onefile \
    --windowed \
    --name "vant-opensearch-agent-tray" \
    --paths "${LINUX_AGENT_DIR}" \
    --paths "${AGENTS_DIR}" \
    --hidden-import agent \
    --hidden-import requests \
    --hidden-import yaml \
    --hidden-import PyQt6.sip \
    --hidden-import PyQt6.QtCore \
    --hidden-import PyQt6.QtGui \
    --hidden-import PyQt6.QtWidgets \
    --add-data "${REPO_DIR}/staticfiles/img/logo.png${add_data_sep}staticfiles/img/logo.png" \
    --distpath "${dist_dir}" \
    --workpath "${work_dir}/tray" \
    --specpath "${spec_dir}" \
    "${LINUX_AGENT_DIR}/agent_tray.py" >/dev/null

  "${pyinstaller_python}" -m PyInstaller \
    --noconfirm \
    --clean \
    --onefile \
    --name "vant-agent-tools" \
    --paths "${AGENTS_DIR}" \
    --hidden-import yaml \
    --hidden-import requests \
    --distpath "${dist_dir}" \
    --workpath "${work_dir}/tools" \
    --specpath "${spec_dir}" \
    "${AGENTS_DIR}/linux/common/agent_tools.py" >/dev/null

  "${pyinstaller_python}" -m PyInstaller \
    --noconfirm \
    --clean \
    --onefile \
    --name "vant-agent-cli" \
    --paths "${AGENTS_DIR}" \
    --hidden-import yaml \
    --hidden-import requests \
    --distpath "${dist_dir}" \
    --workpath "${work_dir}/cli" \
    --specpath "${spec_dir}" \
    "${AGENTS_DIR}/linux/common/agent_installer_cli.py" >/dev/null

  [[ -x "${dist_dir}/vant-opensearch-agent" ]] || die "Missing compiled agent binary"
  [[ -x "${dist_dir}/vant-opensearch-agent-tray" ]] || die "Missing compiled tray binary"
  [[ -x "${dist_dir}/vant-agent-tools" ]] || die "Missing compiled tools binary"
  [[ -x "${dist_dir}/vant-agent-cli" ]] || die "Missing compiled installer CLI binary"
}

write_install_script() {
  local package_dir="$1"
  cat > "${package_dir}/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

GUI_DISABLED="${VANT_AGENT_GDISABLE:-0}"
RUN_WIZARD="${VANT_AGENT_WIZARD:-1}"
NON_INTERACTIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gdisable)
      GUI_DISABLED=1
      shift
      ;;
    --gui)
      GUI_DISABLED=0
      shift
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    --skip-wizard)
      RUN_WIZARD=0
      shift
      ;;
    *)
      echo "Unknown installer option: $1"
      exit 1
      ;;
  esac
done

INSTALL_SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_ROOT="/opt/vant-siem-agent"
TARGET_CFG_DIR="/etc/vant-siem"
TARGET_LOG_DIR="/var/log/vant-siem"
TARGET_BIN_DIR="${TARGET_ROOT}/bin"
TARGET_INSTALL_META="${TARGET_CFG_DIR}/install-meta.env"
INSTALL_OWNER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
INSTALL_GROUP="$(id -gn "${INSTALL_OWNER}" 2>/dev/null || echo "${INSTALL_OWNER}")"
TRAY_DESKTOP_SRC="${INSTALL_SOURCE}/desktop/vant-siem-agent-tray.desktop"
TRAY_DESKTOP_DST="/etc/xdg/autostart/vant-siem-agent-tray.desktop"
SERVICE_SRC="${INSTALL_SOURCE}/systemd/vant-siem-agent.service"
SERVICE_DST="/etc/systemd/system/vant-siem-agent.service"
LOCAL_TOOLS=(sendheartbeat opena_mover opena_checker opena_enroll)

mkdir -p "${TARGET_ROOT}" "${TARGET_CFG_DIR}" "${TARGET_LOG_DIR}" "${TARGET_BIN_DIR}" /etc/xdg/autostart
mkdir -p "${TARGET_ROOT}/scripts" "${TARGET_ROOT}/docs"
cp -a "${INSTALL_SOURCE}/agent/." "${TARGET_ROOT}/"
cp "${INSTALL_SOURCE}/config/agent.yaml" "${TARGET_CFG_DIR}/config.yaml"
cp "${INSTALL_SOURCE}/uninstall.sh" "${TARGET_ROOT}/uninstall.sh"

if [[ -d "${INSTALL_SOURCE}/scripts" ]]; then
  cp -a "${INSTALL_SOURCE}/scripts/." "${TARGET_ROOT}/scripts/"
fi
if [[ -d "${INSTALL_SOURCE}/bin" ]]; then
  cp -a "${INSTALL_SOURCE}/bin/." "${TARGET_BIN_DIR}/"
fi
if [[ -d "${INSTALL_SOURCE}/docs" ]]; then
  cp -a "${INSTALL_SOURCE}/docs/." "${TARGET_ROOT}/docs/"
fi

if [[ -f "${SERVICE_SRC}" ]]; then
  cp "${SERVICE_SRC}" "${SERVICE_DST}"
fi

chmod +x "${TARGET_ROOT}/agent.py" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/agent_tray.py" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/opensearchcheck.py" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/opensearchmover.py" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/vant-opensearch-agent" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/vant-opensearch-agent-tray" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/vant-agent-tools" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/vant-agent-cli" 2>/dev/null || true
  chmod +x "${TARGET_BIN_DIR}"/* 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/uninstall.sh" 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/scripts/"*.sh 2>/dev/null || true
  chmod +x "${TARGET_ROOT}/venv/bin/"* 2>/dev/null || true

run_cli_wizard() {
  local cli_bin="${TARGET_ROOT}/vant-agent-cli"
  local config_path="${TARGET_CFG_DIR}/config.yaml"

  if [[ "${RUN_WIZARD}" = "0" || "${NON_INTERACTIVE}" = "1" || ! -t 0 ]]; then
    return 1
  fi
  if [[ ! -x "${cli_bin}" || ! -f "${config_path}" ]]; then
    echo "Interactive CLI unavailable; using existing config."
    return 1
  fi

  local cmd=("${cli_bin}" "--config" "${config_path}" "--template" "${config_path}")
  if [[ "${GUI_DISABLED}" = "1" ]]; then
    cmd+=("--gdisable")
  fi
  "${cmd[@]}"
  return 0
}

configure_graphics_mode() {
  cat > "${TARGET_INSTALL_META}" <<META
VANT_AGENT_GDISABLE=${GUI_DISABLED}
META

  if [[ "${GUI_DISABLED}" = "1" ]]; then
    rm -f "${TRAY_DESKTOP_DST}"
    echo "Graphic tray disabled by --gdisable."
  elif [[ -f "${TRAY_DESKTOP_SRC}" ]]; then
    cp "${TRAY_DESKTOP_SRC}" "${TRAY_DESKTOP_DST}"
    echo "Graphic tray enabled."
  fi
}

for tool in "${LOCAL_TOOLS[@]}"; do
  if [[ -f "${TARGET_BIN_DIR}/${tool}" ]]; then
    ln -sf "${TARGET_BIN_DIR}/${tool}" "/usr/local/bin/${tool}"
  fi
done
ln -sf "${TARGET_ROOT}/vant-agent-tools" "/usr/local/bin/vant-agent-tools"
ln -sf "${TARGET_ROOT}/vant-agent-cli" "/usr/local/bin/vant-agent-cli"

auto_enroll() {
  local config_path="${TARGET_CFG_DIR}/config.yaml"
  local tools_bin="${TARGET_ROOT}/vant-agent-tools"
  local python_bin="${TARGET_ROOT}/venv/bin/python"
  local tools_path="${TARGET_ROOT}/scripts/agent_tools.py"
  local bootstrap_key="${VANT_AGENT_BOOTSTRAP_KEY:-}"
  local enrollment_code="${VANT_AGENT_ENROLLMENT_CODE:-}"
  local cmd=()
  local token_present=0

  if [[ "${VANT_AGENT_AUTO_ENROLL:-1}" = "0" ]]; then
    echo "Auto-enrollment skipped by VANT_AGENT_AUTO_ENROLL=0"
    return 0
  fi
  if grep -q "token:" "${config_path}" 2>/dev/null && ! grep -q "token: ''" "${config_path}" 2>/dev/null; then
    token_present=1
  fi
  if [[ "${token_present}" = "1" ]]; then
    echo "Enrollment already present in config."
    return 0
  fi
  if [[ -x "${tools_bin}" ]]; then
    cmd=("${tools_bin}" --config "${config_path}" enroll --quiet)
  elif [[ -x "${python_bin}" && -f "${tools_path}" ]]; then
    cmd=("${python_bin}" "${tools_path}" --config "${config_path}" enroll --quiet)
  fi
  if [[ ${#cmd[@]} -eq 0 || ! -f "${config_path}" ]]; then
    echo "Auto-enrollment unavailable: missing runtime files."
    return 0
  fi

  if [[ -n "${enrollment_code}" ]]; then
    cmd+=(--enrollment-code "${enrollment_code}")
  fi

  if VANT_AGENT_BOOTSTRAP_KEY="${bootstrap_key}" "${cmd[@]}"; then
    echo "Agent enrolled automatically."
  else
    echo "Warning: automatic enrollment failed. Run 'sudo opena_enroll' after installation."
  fi
}

if id "${INSTALL_OWNER}" >/dev/null 2>&1; then
  chown -R "${INSTALL_OWNER}:${INSTALL_GROUP}" "${TARGET_ROOT}" || true
fi

run_cli_wizard || true
configure_graphics_mode
auto_enroll

if command -v systemctl >/dev/null 2>&1 && [[ -f "${SERVICE_DST}" ]]; then
  systemctl daemon-reload || true
  systemctl enable vant-siem-agent.service || true
  systemctl restart vant-siem-agent.service || true
fi

echo "Installed VANT-SIEM Linux agent into ${TARGET_ROOT}"
echo "Config: ${TARGET_CFG_DIR}/config.yaml"
echo "Service: ${SERVICE_DST}"
EOF
  chmod +x "${package_dir}/install.sh"
}

write_uninstall_script() {
  local package_dir="$1"
  cat > "${package_dir}/uninstall.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop vant-siem-agent.service 2>/dev/null || true
  systemctl disable vant-siem-agent.service 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
fi

rm -rf /opt/vant-siem-agent
rm -f /etc/vant-siem/config.yaml
rm -f /etc/systemd/system/vant-siem-agent.service
rm -f /etc/xdg/autostart/vant-siem-agent-tray.desktop
echo "VANT-SIEM Linux agent removed."
EOF
  chmod +x "${package_dir}/uninstall.sh"
}

stage_bundle() {
  local distro="$1"
  local distro_dir="${SCRIPT_DIR}/${distro}"
  local stage_root="${DIST_DIR}/${distro}/vant-siem-agent-install"
  local build_root="${BUILD_ROOT}/${distro}"
  local venv_dir="${build_root}/venv"
  local binary_dist="${build_root}/pyinstaller-dist"
  local deb_dir="${DIST_DIR}/${distro}/deb-root"

  [[ -f "${distro_dir}/config.yaml" ]] || die "Missing config for distro: ${distro}"

  rm -rf "${stage_root}" "${build_root}" "${deb_dir}"
  mkdir -p "${stage_root}/agent" "${stage_root}/config" "${stage_root}/scripts" \
    "${stage_root}/docs" "${stage_root}/desktop" "${stage_root}/systemd" "${build_root}"

  info "Preparing build environment for ${distro}"
  prepare_venv "${venv_dir}"
  build_linux_binaries "${venv_dir}" "${build_root}"

  info "Copying runtime files for ${distro}"
  copy_tree "${LINUX_AGENT_DIR}/agent.py" "${stage_root}/agent/agent.py"
  copy_tree "${LINUX_AGENT_DIR}/agent_tray.py" "${stage_root}/agent/agent_tray.py"
  copy_tree "${LINUX_AGENT_DIR}/collectors" "${stage_root}/agent/collectors"
  copy_tree "${LINUX_AGENT_DIR}/services" "${stage_root}/agent/services"
  copy_tree "${LINUX_AGENT_DIR}/output.py" "${stage_root}/agent/output.py"
  copy_tree "${AGENTS_DIR}/opensearchcheck.py" "${stage_root}/agent/opensearchcheck.py"
  copy_tree "${AGENTS_DIR}/opensearchmover.py" "${stage_root}/agent/opensearchmover.py"
  copy_tree "${AGENTS_DIR}/requirements.txt" "${stage_root}/agent/requirements.txt"
  copy_tree "${AGENTS_DIR}/linux/common/agent_installer_cli.py" "${stage_root}/scripts/agent_installer_cli.py"
  copy_tree "${AGENTS_DIR}/linux/common/agent_tools.py" "${stage_root}/scripts/agent_tools.py"
  copy_tree "${AGENTS_DIR}/linux/${distro}/enable_logs.sh" "${stage_root}/scripts/enable_logs.sh"
  copy_tree "${AGENTS_DIR}/linux/common/bin" "${stage_root}/bin"
  copy_tree "${AGENTS_DIR}/linux/common/VANT-SIEM-Agent-Tray.desktop" "${stage_root}/desktop/vant-siem-agent-tray.desktop"
  copy_tree "${AGENTS_DIR}/linux/${distro}/README.md" "${stage_root}/docs/README-${distro}.md"
  copy_tree "${AGENTS_DIR}/linux/README.md" "${stage_root}/docs/README.md"
  copy_tree "${AGENTS_DIR}/linux/OFFLINE_PACKAGING.md" "${stage_root}/docs/OFFLINE_PACKAGING.md"
  copy_tree "${AGENTS_DIR}/AGENT_MANUAL.md" "${stage_root}/docs/AGENT_MANUAL.md"
  copy_tree "${REPO_DIR}/staticfiles/img/logo.png" "${stage_root}/agent/staticfiles/img/logo.png"
  copy_tree "${distro_dir}/config.yaml" "${stage_root}/config/agent.yaml"
  copy_tree "${binary_dist}/vant-opensearch-agent" "${stage_root}/agent/vant-opensearch-agent"
  copy_tree "${binary_dist}/vant-opensearch-agent-tray" "${stage_root}/agent/vant-opensearch-agent-tray"
  copy_tree "${binary_dist}/vant-agent-tools" "${stage_root}/agent/vant-agent-tools"
  copy_tree "${binary_dist}/vant-agent-cli" "${stage_root}/agent/vant-agent-cli"

  cat > "${stage_root}/systemd/vant-siem-agent.service" <<'EOF'
[Unit]
Description=VANT-SIEM Linux Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/vant-siem-agent
ExecStart=/opt/vant-siem-agent/vant-opensearch-agent --config /etc/vant-siem/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  cat > "${stage_root}/desktop/vant-siem-agent-tray.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=VANT-SIEM Agent Tray
Comment=Control del agente en la bandeja del sistema
Exec=/opt/vant-siem-agent/vant-opensearch-agent-tray --config /etc/vant-siem/config.yaml
Icon=/opt/vant-siem-agent/staticfiles/img/logo.png
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=5
X-KDE-autostart-after=panel
X-KDE-StartupNotify=false
Categories=Utility;
EOF

  write_install_script "${stage_root}"
  write_uninstall_script "${stage_root}"

  cat > "${DIST_DIR}/${distro}/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vant-siem-agent-install"
if [[ ! -f "${PACKAGE_DIR}/install.sh" ]]; then
  echo "Offline package not found: ${PACKAGE_DIR}"
  exit 1
fi

chmod +x "${PACKAGE_DIR}/install.sh"
(cd "${PACKAGE_DIR}" && bash "./install.sh")
EOF
  chmod +x "${DIST_DIR}/${distro}/install.sh"

  cat > "${DIST_DIR}/${distro}/uninstall.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ -x /opt/vant-siem-agent/uninstall.sh ]]; then
  /opt/vant-siem-agent/uninstall.sh
  exit 0
fi

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vant-siem-agent-install"
if [[ -x "${PACKAGE_DIR}/uninstall.sh" ]]; then
  (cd "${PACKAGE_DIR}" && bash "./uninstall.sh")
  exit 0
fi

echo "Uninstall script not found."
exit 1
EOF
  chmod +x "${DIST_DIR}/${distro}/uninstall.sh"

  cat > "${stage_root}/manifest.json" <<EOF
{
  "distro": "${distro}",
  "version": "${AGENT_VERSION}",
  "build_timestamp_utc": "${BUILD_TS}",
  "maintainer_name": "Leonardo L. Varona Tabares",
  "maintainer_email": "leoanrdovarona42@gmail.com",
  "package": "vant-siem-agent-install"
}
EOF

  info "Validating bundle structure for ${distro}"
  local required=(
    "${stage_root}/install.sh"
    "${stage_root}/uninstall.sh"
    "${stage_root}/config/agent.yaml"
    "${stage_root}/agent/agent.py"
    "${stage_root}/agent/agent_tray.py"
    "${stage_root}/agent/vant-opensearch-agent"
    "${stage_root}/agent/vant-opensearch-agent-tray"
    "${stage_root}/agent/vant-agent-tools"
    "${stage_root}/agent/vant-agent-cli"
    "${stage_root}/scripts/enable_logs.sh"
    "${stage_root}/scripts/agent_tools.py"
    "${stage_root}/bin/sendheartbeat"
    "${stage_root}/bin/opena_mover"
    "${stage_root}/bin/opena_checker"
    "${stage_root}/bin/opena_enroll"
    "${stage_root}/desktop/vant-siem-agent-tray.desktop"
    "${stage_root}/systemd/vant-siem-agent.service"
  )
  local item
  for item in "${required[@]}"; do
    [[ -e "${item}" ]] || die "Missing required bundle file: ${item}"
  done

  bash -n "${stage_root}/install.sh"
  bash -n "${stage_root}/uninstall.sh"
  bash -n "${stage_root}/scripts/enable_logs.sh"
  bash -n "${stage_root}/bin/sendheartbeat"
  bash -n "${stage_root}/bin/opena_mover"
  bash -n "${stage_root}/bin/opena_checker"
  bash -n "${stage_root}/bin/opena_enroll"

  "${venv_dir}/bin/python" - <<PY
from pathlib import Path
import yaml

cfg = yaml.safe_load(Path(r"${stage_root}/config/agent.yaml").read_text(encoding="utf-8"))
assert isinstance(cfg, dict)
assert "agent" in cfg and "output" in cfg and "control" in cfg
assert "aegis_dlp" in cfg and "collectors" in cfg
print("YAML validation ok for ${distro}")
PY

  if [[ "${BUILD_DEB}" -eq 1 ]] && command -v dpkg-deb >/dev/null 2>&1; then
    local deb_build_dir="/tmp/vant-siem-agent-${distro}-${BUILD_TS}"
    info "Creating .deb layout for ${distro}"
    rm -rf "${deb_build_dir}"
    mkdir -p "${deb_build_dir}/opt/vant-siem-agent" "${deb_build_dir}/etc/vant-siem" "${deb_build_dir}/etc/xdg/autostart" \
      "${deb_build_dir}/usr/local/bin" "${deb_build_dir}/lib/systemd/system"
    cp -a "${stage_root}/agent/." "${deb_build_dir}/opt/vant-siem-agent/"
    cp -a "${stage_root}/scripts" "${deb_build_dir}/opt/vant-siem-agent/scripts"
    cp -a "${stage_root}/bin" "${deb_build_dir}/opt/vant-siem-agent/bin"
    cp -a "${stage_root}/docs" "${deb_build_dir}/opt/vant-siem-agent/docs"
    cp "${stage_root}/uninstall.sh" "${deb_build_dir}/opt/vant-siem-agent/uninstall.sh"
    cp "${stage_root}/config/agent.yaml" "${deb_build_dir}/etc/vant-siem/config.yaml"
    cp "${stage_root}/desktop/vant-siem-agent-tray.desktop" "${deb_build_dir}/etc/xdg/autostart/vant-siem-agent-tray.desktop"
    cp "${stage_root}/systemd/vant-siem-agent.service" "${deb_build_dir}/lib/systemd/system/vant-siem-agent.service"
    cp "${stage_root}/scripts/enable_logs.sh" "${deb_build_dir}/usr/local/bin/vant-siem-enable-logs.sh"
    cp "${stage_root}/bin/sendheartbeat" "${deb_build_dir}/usr/local/bin/sendheartbeat"
    cp "${stage_root}/bin/opena_mover" "${deb_build_dir}/usr/local/bin/opena_mover"
    cp "${stage_root}/bin/opena_checker" "${deb_build_dir}/usr/local/bin/opena_checker"
    cp "${stage_root}/bin/opena_enroll" "${deb_build_dir}/usr/local/bin/opena_enroll"
    chmod +x "${deb_build_dir}/usr/local/bin/vant-siem-enable-logs.sh"
    chmod +x "${deb_build_dir}/usr/local/bin/sendheartbeat" "${deb_build_dir}/usr/local/bin/opena_mover" \
      "${deb_build_dir}/usr/local/bin/opena_checker" "${deb_build_dir}/usr/local/bin/opena_enroll"
    chmod +x "${deb_build_dir}/opt/vant-siem-agent/vant-opensearch-agent" \
      "${deb_build_dir}/opt/vant-siem-agent/vant-opensearch-agent-tray" \
      "${deb_build_dir}/opt/vant-siem-agent/vant-agent-tools" \
      "${deb_build_dir}/opt/vant-siem-agent/uninstall.sh"
    mkdir -p "${deb_build_dir}/DEBIAN"
    chmod 755 "${deb_build_dir}/DEBIAN"
    cat > "${deb_build_dir}/DEBIAN/control" <<EOF
Package: vant-siem-agent
Version: ${AGENT_VERSION}
Section: net
Priority: optional
Architecture: all
Maintainer: Leonardo L. Varona Tabares <leonardovarona42@gmail.com>
Description: VANT-SIEM OpenSearch agent for offline Linux deployments
EOF
    cat > "${deb_build_dir}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
chmod +x /opt/vant-siem-agent/vant-opensearch-agent /opt/vant-siem-agent/vant-opensearch-agent-tray /opt/vant-siem-agent/vant-agent-tools 2>/dev/null || true
chmod +x /opt/vant-siem-agent/vant-agent-cli 2>/dev/null || true
mkdir -p /etc/vant-siem /etc/xdg/autostart
printf 'VANT_AGENT_GDISABLE=%s\n' "${VANT_AGENT_GDISABLE:-0}" > /etc/vant-siem/install-meta.env
if [ "${VANT_AGENT_GDISABLE:-0}" = "1" ]; then
  rm -f /etc/xdg/autostart/vant-siem-agent-tray.desktop
fi
if [ "${VANT_AGENT_WIZARD:-1}" != "0" ] && [ -t 0 ] && [ -x /opt/vant-siem-agent/vant-agent-cli ]; then
  if [ "${VANT_AGENT_GDISABLE:-0}" = "1" ]; then
    /opt/vant-siem-agent/vant-agent-cli --config /etc/vant-siem/config.yaml --template /etc/vant-siem/config.yaml --gdisable || true
  else
    /opt/vant-siem-agent/vant-agent-cli --config /etc/vant-siem/config.yaml --template /etc/vant-siem/config.yaml || true
  fi
fi
if [ -x /opt/vant-siem-agent/vant-agent-tools ]; then
  /opt/vant-siem-agent/vant-agent-tools --config /etc/vant-siem/config.yaml enroll --quiet >/dev/null 2>&1 || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable --now vant-siem-agent.service || true
fi
exit 0
EOF
    chmod 755 "${deb_build_dir}/DEBIAN/postinst"
    cat > "${deb_build_dir}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop vant-siem-agent.service 2>/dev/null || true
  systemctl disable vant-siem-agent.service 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
fi
exit 0
EOF
    chmod 755 "${deb_build_dir}/DEBIAN/prerm"
    dpkg-deb --build "${deb_build_dir}" "${DIST_DIR}/vant-siem-agent-${distro}_${AGENT_VERSION}_all.deb" >/dev/null
    rm -rf "${deb_build_dir}"
    ok "Built .deb for ${distro}"
  fi

  if [[ "${BUILD_TARBALL}" -eq 1 ]]; then
    (cd "${DIST_DIR}/${distro}" && tar -czf "${DIST_DIR}/vant-siem-agent-linux-${distro}-${AGENT_VERSION}.tar.gz" vant-siem-agent-install)
    ok "Built tarball for ${distro}"
  fi

  ok "Bundle staged at ${stage_root}"
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --all)
        shift
        ;;
      --distro)
        [[ $# -ge 2 ]] || die "--distro requires a value"
        TARGET_DISTROS+=("$2")
        shift 2
        ;;
      --deb)
        BUILD_DEB=1
        shift
        ;;
      --no-tarball)
        BUILD_TARBALL=0
        shift
        ;;
      --clean)
        rm -rf "${DIST_DIR}"
        ok "Removed ${DIST_DIR}"
        exit 0
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done

  need_cmd python3
  need_cmd tar
  if [[ "${BUILD_DEB}" -eq 1 ]] && ! command -v dpkg-deb >/dev/null 2>&1; then
    warn "dpkg-deb not found; continuing with tarballs only"
    BUILD_DEB=0
  fi

  if [[ ${#TARGET_DISTROS[@]} -eq 0 ]]; then
    if [[ -n "${VANT_LINUX_DISTRO:-}" ]]; then
      TARGET_DISTROS+=("${VANT_LINUX_DISTRO}")
    else
      discover_distros
    fi
  fi

  [[ ${#TARGET_DISTROS[@]} -gt 0 ]] || die "No Linux distros found under ${SCRIPT_DIR}"

  mkdir -p "${DIST_DIR}"
  log "VANT-SIEM Linux packaging"
  info "Target distros: ${TARGET_DISTROS[*]}"
  info "Output directory: ${DIST_DIR}"

  local distro
  for distro in "${TARGET_DISTROS[@]}"; do
    stage_bundle "${distro}"
  done

  ok "Linux packaging finished"
}

main "$@"
