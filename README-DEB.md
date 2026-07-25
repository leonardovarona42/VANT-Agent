# VANT-SIEM Agent - .deb Package (Offline)

## Build Instructions (on Debian/Ubuntu host)

### Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv dpkg-dev
```

### Build the .deb

```bash
# From the project root:
chmod +x build_deb.sh
./build_deb.sh
```

The package will be created at:
```
linux/dist/vant-siem-agent-debian_1.0.0_all.deb
```

### Build Options

```bash
./build_deb.sh --clean            # Clean build artifacts only
./build_deb.sh --skip-wheels      # Build without downloading wheels
./build_deb.sh --wheels-only      # Only download Python wheels
```

### Remote Build (from Windows)

If you are on Windows and cannot run `pip download` for Linux wheels:

```bash
# Set the environment variable before running (on Linux build host):
VANT_BUILD_HOST=debian-server ./build_deb.sh
```

Or download wheels manually on a Linux host:

```bash
pip3 download --only-binary=:all: \
  --platform manylinux_2_28_x86_64 \
  --python-version 313 \
  --dest ./wheels \
  PyYAML requests urllib3 certifi charset-normalizer idna
```

Then copy the `wheels/` directory to:
```
linux/dist/.build/deb-debian/opt/vant-siem-agent/wheels/
```

And re-run:
```bash
./build_deb.sh --skip-wheels
```

## Package Structure

```
vant-siem-agent-debian_1.0.0_all.deb
├── DEBIAN/
│   ├── control         # Package metadata (Architecture: all)
│   ├── postinst        # Post-install: user, wheels, wizard, service
│   └── prerm           # Pre-remove: stop service
├── etc/
│   ├── vant-siem/
│   │   └── config.yaml
│   └── xdg/
│       └── autostart/
│           └── vant-siem-agent-tray.desktop
├── lib/
│   └── systemd/
│       └── system/
│           └── vant-siem-agent.service
└── opt/
    └── vant-siem-agent/
        ├── agent.py
        ├── output.py
        ├── agent_tray.py
        ├── config.template.yaml
        ├── collectors/
        │   ├── base.py
        │   ├── file_log.py
        │   ├── postgres_log.py
        │   ├── snort.py
        │   ├── suricata.py
        │   └── windows_eventlog.py
        ├── scripts/
        │   ├── agent_installer_cli.py
        │   ├── agent_tools.py
        │   └── enable_logs.sh
        ├── services/
        │   ├── aegis_dlp.py
        │   └── audit_inventory.py
        ├── bin/
        │   ├── opena_checker
        │   ├── opena_enroll
        │   ├── opena_mover
        │   └── sendheartbeat
        └── wheels/
            ├── PyYAML-*.whl
            ├── requests-*.whl
            ├── urllib3-*.whl
            ├── certifi-*.whl
            ├── charset_normalizer-*.whl
            └── idna-*.whl
```

## Installation

```bash
sudo dpkg -i linux/dist/vant-siem-agent-debian_1.0.0_all.deb
sudo apt-get install -f   # if any system dependencies are missing
```

### Headless / Unattended Installation

```bash
# Skip the interactive wizard entirely:
sudo VANT_AGENT_WIZARD=0 dpkg -i vant-siem-agent-debian_1.0.0_all.deb

# Disable graphics/tray integration:
sudo VANT_AGENT_GDISABLE=1 VANT_AGENT_WIZARD=0 dpkg -i vant-siem-agent-debian_1.0.0_all.deb
```

### Reconfigure After Installation

```bash
sudo python3 /opt/vant-siem-agent/scripts/agent_installer_cli.py \
  --config /etc/vant-siem/config.yaml \
  --template /opt/vant-siem-agent/config.template.yaml
```

### Remove

```bash
sudo dpkg -r vant-siem-agent
sudo dpkg --purge vant-siem-agent   # also remove config
```

## Dependencies

| Dependency | Type | Notes |
|-----------|------|-------|
| python3 >= 3.9 | System | Python interpreter |
| python3-pip | System | Wheel installation |
| adduser | System | Create vant-siem user |
| PyYAML | Python | Bundled as wheel |
| requests | Python | Bundled as wheel |
| urllib3 | Python | Bundled as wheel |
| certifi | Python | Bundled as wheel |
| charset-normalizer | Python | Bundled as wheel |
| idna | Python | Bundled as wheel |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VANT_AGENT_WIZARD` | `1` | Set to `0` to skip interactive wizard |
| `VANT_AGENT_GDISABLE` | `0` | Set to `1` to disable graphics/tray integration |
| `VANT_BUILD_HOST` | - | SSH host for remote wheel download during build |
