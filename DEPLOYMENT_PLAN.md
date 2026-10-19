# VANT-SIEM Agent Deployment Plan for Test Environment

This document outlines the steps to deploy the improved VANT-SIEM Agent to the test environment with IPs:
- Server: 192.168.12.46 (VANT-SIEM server)
- Linux Agent 1: 192.168.12.45
- Linux Agent 2: 192.168.12.47

## Prerequisites

1. Access to the three machines with provided credentials:
   - Server (192.168.12.46): root / 1qazxsw2
   - Linux Agent 1 (192.168.12.45): [credentials needed]
   - Linux Agent 2 (192.168.12.47): [credentials needed]

2. VANT-SIEM server must be running and accessible at https://192.168.12.46:8000 (or as configured)

3. Improved VANT-SIEM Agent codebase with all new features:
   - Sigma rules engine
   - Cyber Threat Intelligence (CTI) integration
   - Compliance reporting capabilities
   - Optimized OpenSearch storage recommendations

## Deployment Steps

### 1. Prepare the Agent for Deployment

First, ensure the agent is built and ready:

```bash
# From the VANT-Agent directory
# Check that the executable exists
ls -la dist/VANT-Agent.exe

# If not built, build it first (Windows):
.\installer\build_installer.ps1

# Or create a distribution package:
# The dist/ directory should contain VANT-Agent.exe and default config.yaml
```

### 2. Deploy to Linux Agents (192.168.12.45 and 192.168.12.47)

#### Option A: Manual Installation (Recommended for Linux)

```bash
# SSH to each Linux agent
ssh root@192.168.12.45
# Password: [provide if needed]

# Create installation directory
mkdir -p /opt/vant-agent
cd /opt/vant-agent

# Copy the agent files from the build machine
# You can use scp or transfer the dist/ contents
# scp leona@build_machine:/path/to/VANT-Agent/dist/* .

# Alternative: Clone the repository and install dependencies
git clone https://github.com/leonardovarona42/VANT-Agent.git
cd VANT-Agent

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy the configuration template and customize
cp config.example.yaml config.yaml
# Edit config.yaml to set:
#   server.url: "https://192.168.12.46:8000"
#   server.logs_url: "https://192.168.12.46:9201"
#   agent.host_name: "[linux-agent-hostname]"
#   agent.interval_seconds: 10

# Test the agent
python -m vant.main --config config.yaml

# To run as a service, create a systemd service file:
# /etc/systemd/system/vant-agent.service
# [Unit]
# Description=VANT-SIEM Agent
# After=network.target
#
# [Service]
# Type=simple
# WorkingDirectory=/opt/vant-agent
# ExecStart=/opt/vant-agent/venv/bin/python -m vant.main --config /opt/vant-agent/config.yaml
# Restart=always
# RestartSec=10
#
# [Install]
# WantedBy=multi-user.target
#
# Then:
# sudo systemctl daemon-reload
# sudo systemctl enable vant-agent
# sudo systemctl start vant-agent
```

Repeat the above steps for the second Linux agent (192.168.12.47).

#### Option B: Using the Agent Executable (if cross-compiled for Linux)

If you have a Linux executable:
```bash
ssh root@192.168.12.45
mkdir -p /opt/vant-agent
cd /opt/vant-agent
# Copy VANT-Agent executable and config.yaml
# chmod +x VANT-Agent.exe
# ./VANT-Agent.exe --config config.yaml
```

Repeat for the second Linux agent.

### 3. Verify the Server is Ready

Ensure the VANT-SIEM server at 192.168.12.46 is running:
- Control API: https://192.168.12.46:8000
- Logs API: https://192.168.12.46:9201
- The server should be accepting agent registrations

### 4. Post-Deployment Verification

After deploying agents to both Linux machines:

1. Check that agents appear in the VANT-SIEM server inventory
2. Verify events are being received:
   - Linux agents: Should send system logs, auth logs, etc. (via available collectors)
3. Check that CTI enrichment is working (look for `cti_malicious_ip` tags in events)
4. Verify Sigma rules are processing (check for alerts if any rules match)
5. Confirm compliance reporting is scheduled (runs every 24 hours by default)

## Configuration Notes

### For config.yaml on both agents:
```yaml
agent:
  id: "unique-agent-id"  # Will be auto-generated if not set
  host_name: "[actual-hostname]"
  interval_seconds: 10

output:
  endpoint: "https://192.168.12.46:9201/logs/api/ingest/bulk/"
  source_endpoint: "https://192.168.12.46:9201/logs/api/sources/"
  timeout_seconds: 10
  auth:
    mode: "none"  # or "token" if server requires auth
    username: ""
    password: ""
    token: ""
  tls:
    enabled: false  # Set to true if using HTTPS with valid certs
    verify: false   # Set to true in production with valid certs
    ca_cert: ""

control:
  server_url: "https://192.168.12.46:8000"
  require_https: false
  token: ""  # For server authentication if needed
  poll_seconds: 30
  inventory_seconds: 86400
  dlp_poll_seconds: 60
  dlp_scan_seconds: 30

# New feature configurations:
rules:
  directory: "vant/modules/rules/examples"  # Relative to agent directory
  reload_interval: 300  # 5 minutes

cti:
  enabled: true
  update_interval: 3600  # 1 hour
  data_dir: "./cti_data"
  alienvault_otx:
    enabled: true
    update_interval: 3600
  abuse_ch:
    sslbl:
      enabled: true
      update_interval: 7200  # 2 hours
    feodotracker:
      enabled: true
      update_interval: 3600

compliance:
  enabled: true
  interval: 86400  # 24 hours
```

## Troubleshooting

### Common Issues:
1. **Agent not connecting to server**:
   - Check network connectivity (ping, telnet to ports 8000/9201)
   - Verify config.yaml has correct URLs
   - Check agent logs in `logs/` directory

2. **No events appearing**:
   - Verify collectors are enabled in config.yaml
   - Check if event sources are active on the endpoint
   - Look for errors in agent logs

3. **CTI not working**:
   - Verify internet connectivity for feed downloads
   - Check if cti_data directory is writable
   - Look for CTI service logs

4. **Compliance not running**:
   - Check if compliance service is initialized in logs
   - Verify the interval setting
   - Check for evidence collection errors

## Validation Checklist

After deployment, verify:
- [ ] Agent successfully registers with server
- [ ] Heartbeats are received regularly
- [ ] Events are being ingested (check volume in server UI)
- [ ] Linux agents collect relevant logs (syslog, auth, etc.)
- [ ] CTI enrichment is functioning (tags appear in events)
- [ ] Sigma rules are loaded and processing (check debug logs)
- [ ] Compliance service starts and schedules daily runs
- [ ] No critical errors in agent logs
- [ ] Agent handles network interruptions gracefully

---
*Deployment Plan Created: $(date)*
*For VANT-SIEM Agent with Sigma Rules, CTI, and Compliance Features*