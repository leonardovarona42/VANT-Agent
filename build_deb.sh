#!/bin/bash
#
# VANT-SIEM Agent - Offline .deb Package Builder
#
# Creates a completely offline .deb package with:
#   - All Python dependencies bundled as wheels
#   - Interactive configuration wizard (postinst)
#   - Systemd service integration
#   - Architecture: all (pure Python)
#
# Usage:
#   ./build_deb.sh                        # Build .deb package
#   ./build_deb.sh --wheels-only          # Only download Python wheels
#   ./build_deb.sh --clean                # Clean build artifacts
#
# Requirements (build host):
#   - python3 (>= 3.9), python3-pip, python3-venv
#   - dpkg-deb
#   - Internet access for wheel downloads
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$ROOT_DIR/linux/dist"
BUILD_DIR="$DIST_DIR/.build/deb-debian"
AGENT_VERSION="1.0.0"
AGENT_NAME="vant-siem-agent"

WHEELS=(
    PyYAML
    requests
    urllib3
    certifi
    charset-normalizer
    idna
)

print_step()  { echo -e "${CYAN}${BOLD}==>${NC} $1"; }
print_ok()    { echo -e "  ${GREEN}OK${NC}  $1"; }
print_skip()  { echo -e "  ${YELLOW}SKIP${NC} $1"; }
print_fail()  { echo -e "  ${RED}FAIL${NC} $1"; }

clean_build() {
    print_step "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR/opt/vant-siem-agent"
    rm -rf "$BUILD_DIR/DEBIAN"
    rm -rf "$BUILD_DIR/lib"
    rm -rf "$BUILD_DIR/etc/systemd"
    rm -rf "$BUILD_DIR/etc/xdg"
    rm -f  "$DIST_DIR/${AGENT_NAME}-debian_${AGENT_VERSION}_all.deb"
    print_ok "Build directory cleaned"
}

download_wheels() {
    local wheel_dir="$BUILD_DIR/opt/vant-siem-agent/wheels"
    mkdir -p "$wheel_dir"

    print_step "Downloading Python wheels for offline install..."

    if pip3 download --only-binary=:all: \
        --dest "$wheel_dir" \
        "${WHEELS[@]}" 2>&1; then
        print_ok "Wheels downloaded: $(ls "$wheel_dir"/*.whl 2>/dev/null | wc -l)"
        return 0
    fi

    print_skip "pip download failed locally"
    print_skip "Run manually on a Linux host:"
    print_skip "  pip3 download --only-binary=:all: --dest '$wheel_dir' ${WHEELS[*]}"
}

create_directory_structure() {
    print_step "Creating package directory structure..."

    mkdir -p "$BUILD_DIR/DEBIAN"
    mkdir -p "$BUILD_DIR/opt/vant-siem-agent/collectors"
    mkdir -p "$BUILD_DIR/opt/vant-siem-agent/services"
    mkdir -p "$BUILD_DIR/opt/vant-siem-agent/scripts"
    mkdir -p "$BUILD_DIR/opt/vant-siem-agent/wheels"
    mkdir -p "$BUILD_DIR/opt/vant-siem-agent/bin"
    mkdir -p "$BUILD_DIR/etc/vant-siem"
    mkdir -p "$BUILD_DIR/lib/systemd/system"
    mkdir -p "$BUILD_DIR/etc/xdg/autostart"

    print_ok "Directory structure created"
}

copy_agent_files() {
    print_step "Copying agent source files..."

    cp "$ROOT_DIR/agent.py"           "$BUILD_DIR/opt/vant-siem-agent/"
    cp "$ROOT_DIR/output.py"          "$BUILD_DIR/opt/vant-siem-agent/"
    cp "$ROOT_DIR/agent_tray.py"      "$BUILD_DIR/opt/vant-siem-agent/"
    print_ok "Core agent files copied"

    for f in "$ROOT_DIR/collectors/"*.py; do
        [ -f "$f" ] && cp "$f" "$BUILD_DIR/opt/vant-siem-agent/collectors/"
    done
    print_ok "Collectors copied"

    for f in "$ROOT_DIR/services/"*.py; do
        [ -f "$f" ] && cp "$f" "$BUILD_DIR/opt/vant-siem-agent/services/"
    done
    print_ok "Services copied"

    cp "$ROOT_DIR/linux/common/agent_installer_cli.py" "$BUILD_DIR/opt/vant-siem-agent/scripts/"
    cp "$ROOT_DIR/linux/common/agent_tools.py"         "$BUILD_DIR/opt/vant-siem-agent/scripts/"
    cp "$ROOT_DIR/linux/debian/enable_logs.sh"         "$BUILD_DIR/opt/vant-siem-agent/scripts/"
    chmod +x "$BUILD_DIR/opt/vant-siem-agent/scripts/enable_logs.sh"
    print_ok "Scripts copied"

    if [ -d "$ROOT_DIR/linux/common/bin" ]; then
        cp -r "$ROOT_DIR/linux/common/bin/"* "$BUILD_DIR/opt/vant-siem-agent/bin/"
        chmod +x "$BUILD_DIR/opt/vant-siem-agent/bin/"* 2>/dev/null || true
        print_ok "Binary tools copied"
    fi

    rm -f "$BUILD_DIR/opt/vant-siem-agent/"__pycache__ 2>/dev/null || true
    find "$BUILD_DIR/opt/vant-siem-agent" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    find "$BUILD_DIR/opt/vant-siem-agent" -name "*.pyc" -delete 2>/dev/null || true
    print_ok "Cleaned up cache files"
}

copy_config() {
    print_step "Copying configuration..."

    if [ -f "$ROOT_DIR/config.template.yaml" ]; then
        cp "$ROOT_DIR/config.template.yaml" "$BUILD_DIR/opt/vant-siem-agent/config.template.yaml"
    elif [ -f "$BUILD_DIR/etc/vant-siem/config.yaml" ]; then
        cp "$BUILD_DIR/etc/vant-siem/config.yaml" "$BUILD_DIR/opt/vant-siem-agent/config.template.yaml"
    elif [ -f "$ROOT_DIR/config.example.yaml" ]; then
        cp "$ROOT_DIR/config.example.yaml" "$BUILD_DIR/opt/vant-siem-agent/config.template.yaml"
    fi

    if [ -f "$ROOT_DIR/linux/dist/.build/deb-debian/etc/vant-siem/config.yaml" ]; then
        cp "$ROOT_DIR/linux/dist/.build/deb-debian/etc/vant-siem/config.yaml" "$BUILD_DIR/etc/vant-siem/config.yaml"
    elif [ -f "$BUILD_DIR/opt/vant-siem-agent/config.template.yaml" ]; then
        cp "$BUILD_DIR/opt/vant-siem-agent/config.template.yaml" "$BUILD_DIR/etc/vant-siem/config.yaml"
    fi

    print_ok "Configuration files copied"
}

create_systemd_service() {
    print_step "Creating systemd service unit..."

    cat > "$BUILD_DIR/lib/systemd/system/vant-siem-agent.service" << 'EOF'
[Unit]
Description=VANT-SIEM Linux Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vant-siem
Group=vant-siem
WorkingDirectory=/opt/vant-siem-agent
ExecStart=/usr/bin/python3 /opt/vant-siem-agent/agent.py --config /etc/vant-siem/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    print_ok "Systemd service created"
}

create_autostart_desktop() {
    print_step "Creating XDG autostart entry..."

    cat > "$BUILD_DIR/etc/xdg/autostart/vant-siem-agent-tray.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=VANT-SIEM Agent Tray
Comment=Control del agente en la bandeja del sistema
Exec=/opt/vant-siem-agent/venv/bin/python /opt/vant-siem-agent/agent_tray.py --config /etc/vant-siem/config.yaml
Icon=/opt/vant-siem-agent/staticfiles/img/logo.png
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=5
X-KDE-autostart-after=panel
X-KDE-StartupNotify=false
Categories=Utility;
EOF

    print_ok "Autostart desktop entry created"
}

create_control_file() {
    print_step "Creating DEBIAN/control..."

    cat > "$BUILD_DIR/DEBIAN/control" << EOF
Package: vant-siem-agent
Version: ${AGENT_VERSION}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), python3-pip, adduser
Maintainer: Leonardo L. Varona Tabares <leonardovarona42@gmail.com>
Description: VANT-SIEM Linux Agent - Security monitoring and inventory collection
 Agent for the VANT-SIEM platform.
 Collects system inventory, log events (snort, suricata, postgresql, file logs),
 and provides DLP scanning capabilities.
 .
 This package bundles all Python dependencies as wheels for fully offline
 installation. An interactive configuration wizard runs on first install
 when a terminal is available.
Homepage: https://github.com/vant-siem/vant-siem
EOF

    print_ok "DEBIAN/control created"
}

create_postinst() {
    print_step "Creating DEBIAN/postinst..."

    cat > "$BUILD_DIR/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
set -e

AGENT_USER=vant-siem
AGENT_ROOT=/opt/vant-siem-agent
AGENT_CFG_DIR=/etc/vant-siem
AGENT_LOG_DIR=/var/log/vant-siem

case "$1" in
  configure)
    # --- Create system user ---
    if ! getent passwd "$AGENT_USER" >/dev/null 2>&1; then
        adduser --system --group --no-create-home --quiet "$AGENT_USER" || true
    fi

    # --- Create required directories ---
    mkdir -p "$AGENT_ROOT" "$AGENT_CFG_DIR" "$AGENT_LOG_DIR"
    mkdir -p /var/log/suricata /var/log/snort /var/log/postgresql

    # --- Install Python wheels (offline) ---
    if [ -d "$AGENT_ROOT/wheels" ] && ls "$AGENT_ROOT"/wheels/*.whl >/dev/null 2>&1; then
        pip3 install --no-index --find-links="$AGENT_ROOT/wheels" \
            "$AGENT_ROOT"/wheels/*.whl 2>/dev/null || \
            echo "Advertencia: No se pudieron instalar algunas wheels (posiblemente ya instaladas)"
    fi

    # --- Set permissions ---
    chown -R "$AGENT_USER:$AGENT_USER" "$AGENT_ROOT" 2>/dev/null || chown -R root:root "$AGENT_ROOT"
    chown -R "$AGENT_USER:$AGENT_USER" "$AGENT_LOG_DIR" 2>/dev/null || true
    chown "$AGENT_USER:$AGENT_USER" "$AGENT_CFG_DIR" 2>/dev/null || true
    if getent group adm >/dev/null 2>&1; then
        adduser "$AGENT_USER" adm 2>/dev/null || true
    fi

    # --- Reload systemd ---
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
    fi

    # --- Copy default config if it does not exist ---
    if [ ! -f "$AGENT_CFG_DIR/config.yaml" ] && [ -f "$AGENT_ROOT/config.template.yaml" ]; then
        cp "$AGENT_ROOT/config.template.yaml" "$AGENT_CFG_DIR/config.yaml" 2>/dev/null || true
    fi

    # --- Interactive wizard ---
    WIZARD_SCRIPT="$AGENT_ROOT/scripts/agent_installer_cli.py"
    if [ "${VANT_AGENT_WIZARD:-1}" != "0" ] && [ -f "$WIZARD_SCRIPT" ]; then
        echo ""
        echo "============================================"
        echo "  VANT-SIEM Agent - Configuracion Inicial"
        echo "============================================"
        echo ""
        python3 -u "$WIZARD_SCRIPT" \
            --config "$AGENT_CFG_DIR/config.yaml" \
            --template "$AGENT_ROOT/config.template.yaml" || true
    fi

    # --- Enable and start service ---
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable vant-siem-agent.service || true
        systemctl start vant-siem-agent.service || true
    fi

    echo ""
    echo "VANT-SIEM Agent installed."
    echo "  Agent:  $AGENT_ROOT/agent.py"
    echo "  Config: $AGENT_CFG_DIR/config.yaml"
    echo "  Logs:   $AGENT_LOG_DIR"

    if [ "${VANT_AGENT_WIZARD:-1}" = "0" ]; then
        echo ""
        echo "Para configurar el agente ejecute:"
        echo "  sudo python3 $AGENT_ROOT/scripts/agent_installer_cli.py \\"
        echo "    --config $AGENT_CFG_DIR/config.yaml \\"
        echo "    --template $AGENT_ROOT/config.template.yaml"
    fi
    echo ""
    ;;
esac
exit 0
POSTINST

    chmod 755 "$BUILD_DIR/DEBIAN/postinst"
    print_ok "DEBIAN/postinst created"
}

create_prerm() {
    print_step "Creating DEBIAN/prerm..."

    cat > "$BUILD_DIR/DEBIAN/prerm" << 'PRERM'
#!/bin/sh
set -e

case "$1" in
  remove|purge|upgrade|deconfigure)
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop vant-siem-agent.service 2>/dev/null || true
        systemctl disable vant-siem-agent.service 2>/dev/null || true
    fi
    ;;
esac

exit 0
PRERM

    chmod 755 "$BUILD_DIR/DEBIAN/prerm"
    print_ok "DEBIAN/prerm created"
}

build_package() {
    print_step "Building .deb package..."

    local output_deb="$DIST_DIR/${AGENT_NAME}-debian_${AGENT_VERSION}_all.deb"
    dpkg-deb --build "$BUILD_DIR" "$output_deb"

    echo ""
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  Package built successfully!${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Package: $output_deb"
    echo "  Version: $AGENT_VERSION"
    echo "  Size:    $(du -h "$output_deb" | cut -f1)"
    echo ""
    echo "  Contents:"
    dpkg-deb --contents "$output_deb" | head -40
    echo ""
    echo "  Install with:"
    echo "    sudo dpkg -i \"$output_deb\""
    echo "    sudo apt-get install -f   # if dependencies missing"
    echo ""
}

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --clean          Clean build directories"
    echo "  --wheels-only    Only download Python wheels"
    echo "  --skip-wheels    Build without downloading wheels"
    echo "  --help, -h       Show this help"
    echo ""
    echo "Environment:"
    echo "  VANT_BUILD_HOST  SSH host for remote wheel download (optional)"
    echo ""
    echo "Examples:"
    echo "  $0                              # Full build"
    echo "  $0 --skip-wheels                # Build without wheels"
    echo "  $0 --clean                      # Clean build artifacts"
    echo "  VANT_BUILD_HOST=debian $0       # Build using remote host for wheels"
    exit 0
}

main() {
    local do_clean=false
    local do_wheels=true
    local do_build=true

    while [[ $# -gt 0 ]]; do
        case $1 in
            --clean)        do_clean=true; do_build=false ;;
            --wheels-only)  do_clean=true; do_wheels=true; do_build=false ;;
            --skip-wheels)  do_wheels=false ;;
            --help|-h)      usage ;;
            *)              echo "Unknown option: $1"; usage ;;
        esac
        shift
    done

    echo ""
    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║          VANT-SIEM Agent .deb Package Builder (Offline)             ║${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [ "$do_clean" = true ]; then
        clean_build
    fi

    if [ "$do_build" = true ] || [ "$do_wheels" = true ]; then
        create_directory_structure
        copy_agent_files
        copy_config

        if [ "$do_wheels" = true ]; then
            download_wheels
        fi

        create_systemd_service
        create_autostart_desktop
        create_control_file
        create_postinst
        create_prerm

        mkdir -p "$DIST_DIR"
        build_package
    fi
}

main "$@"
