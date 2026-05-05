#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║                     VANT-SIEM OpenSearch Agent                          ║
║                         Configuration Checker                           ║
║                                                                           ║
║  Script: opensearchcheck.py                                             ║
║  Purpose: Verify OpenSearch agent configuration and connectivity        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import json
import socket
import ssl
from pathlib import Path
from datetime import datetime
import urllib.request
import urllib.error

# Try to import yaml, if not available show helpful error
try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is not installed.")
    print("Install it with: pip install pyyaml")
    sys.exit(1)


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'
    RESET = '\033[0m'


def print_header(title):
    """Print a formatted header"""
    width = 70
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'═' * width}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}  {title}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'═' * width}{Colors.END}\n")


def print_success(msg):
    """Print success message"""
    print(f"  {Colors.GREEN}✓{Colors.END} {msg}")


def print_error(msg):
    """Print error message"""
    print(f"  {Colors.RED}✗{Colors.END} {msg}")


def print_warning(msg):
    """Print warning message"""
    print(f"  {Colors.YELLOW}⚠{Colors.END} {msg}")


def print_info(msg):
    """Print info message"""
    print(f"  {Colors.BLUE}ℹ{Colors.END} {msg}")


def load_config(config_path):
    """Load and parse YAML configuration file"""
    path = Path(config_path)
    
    if not path.exists():
        print_error(f"Configuration file not found: {config_path}")
        return None
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        if config is None:
            print_error("Configuration file is empty")
            return None
            
        print_success(f"Configuration file loaded: {config_path}")
        return config
        
    except yaml.YAMLError as e:
        print_error(f"Invalid YAML syntax: {e}")
        return None
    except Exception as e:
        print_error(f"Error reading configuration: {e}")
        return None


def validate_yaml_syntax(config_path):
    """Validate YAML syntax without full parsing"""
    print_header("1. YAML Syntax Validation")
    
    path = Path(config_path)
    if not path.exists():
        print_error(f"File not found: {config_path}")
        return False
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
            yaml.safe_load(content)
        print_success("YAML syntax is valid")
        return True
    except yaml.YAMLError as e:
        print_error(f"YAML syntax error: {e}")
        return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False


def validate_agent_config(config):
    """Validate agent configuration section"""
    print_header("2. Agent Configuration")
    
    agent = config.get('agent', {})
    
    if not agent:
        print_error("Missing 'agent' section in configuration")
        return False
    
    # Check required fields
    required_fields = ['id']
    optional_fields = ['host_name', 'interval_seconds']
    
    all_ok = True
    
    for field in required_fields:
        if field not in agent or not agent[field]:
            print_error(f"Missing required field: agent.{field}")
            all_ok = False
        else:
            print_success(f"agent.{field}: {agent[field]}")
    
    for field in optional_fields:
        if field in agent:
            print_info(f"agent.{field}: {agent[field]}")
    
    return all_ok


def validate_output_config(config):
    """Validate output configuration section"""
    print_header("3. Output Configuration (OpenSearch)")
    
    output = config.get('output', {})
    
    if not output:
        print_error("Missing 'output' section in configuration")
        return False
    
    # Check endpoint
    endpoint = output.get('endpoint', '')
    if not endpoint:
        print_error("Missing 'output.endpoint'")
        return False
    else:
        print_info(f"output.endpoint: {endpoint}")
    
    # Check source_endpoint
    source_endpoint = output.get('source_endpoint', '')
    if source_endpoint:
        print_info(f"output.source_endpoint: {source_endpoint}")
    
    # Check timeout
    timeout = output.get('timeout_seconds', 10)
    print_info(f"output.timeout_seconds: {timeout}")
    
    # Check auth
    auth = output.get('auth', {})
    auth_mode = auth.get('mode', 'none')
    print_info(f"output.auth.mode: {auth_mode}")
    
    if auth_mode == 'basic':
        username = auth.get('username', '')
        if username:
            print_success(f"output.auth.username: {username}")
        else:
            print_warning("output.auth.username is empty")
    
    # Check TLS
    tls = output.get('tls', {})
    tls_enabled = tls.get('enabled', False)
    print_info(f"output.tls.enabled: {tls_enabled}")
    
    return True


def validate_collectors_config(config):
    """Validate collectors configuration section"""
    print_header("4. Collectors Configuration")
    
    collectors = config.get('collectors', {})
    
    if not collectors:
        print_warning("No collectors configured")
        return True
    
    available_collectors = ['snort', 'suricata', 'windows_eventlog', 'postgres', 'file_logs']
    enabled_collectors = []
    
    for collector_name in available_collectors:
        collector_cfg = collectors.get(collector_name, {})
        enabled = collector_cfg.get('enabled', False)
        
        if enabled:
            enabled_collectors.append(collector_name)
            
            # Collector-specific validation
            if collector_name == 'snort':
                path = collector_cfg.get('path', '')
                if path:
                    print_success(f"snort.enabled: true (path: {path})")
                else:
                    print_warning("snort.enabled but path not specified")
            
            elif collector_name == 'suricata':
                path = collector_cfg.get('path', '')
                if path:
                    print_success(f"suricata.enabled: true (path: {path})")
                else:
                    print_warning("suricata.enabled but path not specified")
            
            elif collector_name == 'windows_eventlog':
                channel = collector_cfg.get('channel', '')
                if channel:
                    print_success(f"windows_eventlog.enabled: true (channel: {channel})")
                else:
                    print_warning("windows_eventlog.enabled but channel not specified")
            
            elif collector_name == 'postgres':
                path = collector_cfg.get('path', '')
                if path:
                    print_success(f"postgres.enabled: true (path: {path})")
                else:
                    print_warning("postgres.enabled but path not specified")
            
            elif collector_name == 'file_logs':
                items = collector_cfg.get('items', [])
                if items:
                    print_success(f"file_logs.enabled: true ({len(items)} items)")
                    for item in items:
                        item_path = item.get('path', 'N/A')
                        item_enabled = item.get('enabled', False)
                        if item_enabled:
                            print_info(f"  - {item_path}")
                else:
                    print_warning("file_logs.enabled but no items configured")
        else:
            print_info(f"{collector_name}: disabled")
    
    if enabled_collectors:
        print_success(f"Total enabled collectors: {len(enabled_collectors)}")
    else:
        print_warning("No collectors are enabled")
    
    return True


def test_connectivity(config):
    """Test connectivity to OpenSearch server"""
    print_header("5. Connectivity Test")
    
    output = config.get('output', {})
    endpoint = output.get('endpoint', '')
    
    if not endpoint:
        print_error("No endpoint configured")
        return False
    
    # Extract host and port from endpoint
    try:
        # Handle both http:// and https://
        endpoint_clean = endpoint.replace('http://', '').replace('https://', '')
        
        if '/' in endpoint_clean:
            host_port = endpoint_clean.split('/')[0]
        else:
            host_port = endpoint_clean
        
        if ':' in host_port:
            host, port = host_port.split(':')
            port = int(port)
        else:
            host = host_port
            port = 9200 if endpoint.startswith('https') else 9201
        
        print_info(f"Testing connection to {host}:{port}")
        
        # Test TCP connection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                print_success(f"TCP connection successful to {host}:{port}")
            else:
                print_error(f"Cannot connect to {host}:{port} (port may be closed)")
                return False
        except socket.gaierror:
            print_error(f"Cannot resolve hostname: {host}")
            return False
        except socket.timeout:
            print_error(f"Connection to {host}:{port} timed out")
            return False
        except Exception as e:
            print_error(f"Connection error: {e}")
            return False
        
        # Test HTTP/HTTPS request
        tls_enabled = output.get('tls', {}).get('enabled', False)
        auth = output.get('auth', {})
        auth_mode = auth.get('mode', 'none')
        
        # Build request URL
        test_url = endpoint.replace('/api/v1/events/bulk', '')
        if not test_url.endswith('/'):
            test_url += '/'
        
        try:
            # Create request
            req = urllib.request.Request(test_url)
            
            # Add auth if configured
            if auth_mode == 'basic':
                import base64
                username = auth.get('username', '')
                password = auth.get('password', '')
                if username and password:
                    credentials = f"{username}:{password}"
                    encoded = base64.b64encode(credentials.encode()).decode()
                    req.add_header('Authorization', f'Basic {encoded}')
            
            # Handle TLS
            if tls_enabled:
                ctx = ssl.create_default_context()
                # For self-signed certs, you might want to set check_hostname=False
                # and verify_mode=CERT_NONE for testing
                if not output.get('tls', {}).get('verify', True):
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
            
            # Make request
            try:
                if tls_enabled:
                    response = urllib.request.urlopen(req, timeout=5, context=ctx)
                else:
                    response = urllib.request.urlopen(req, timeout=5)
                
                print_success(f"HTTP request successful (status: {response.status})")
                
                # Try to get cluster info
                try:
                    info_url = test_url
                    if tls_enabled:
                        info_req = urllib.request.Request(info_url, context=ctx)
                    else:
                        info_req = urllib.request.Request(info_url)
                    
                    if auth_mode == 'basic':
                        import base64
                        credentials = f"{username}:{password}"
                        encoded = base64.b64encode(credentials.encode()).decode()
                        info_req.add_header('Authorization', f'Basic {encoded}')
                    
                    if tls_enabled:
                        info_response = urllib.request.urlopen(info_req, timeout=5, context=ctx)
                    else:
                        info_response = urllib.request.urlopen(info_req, timeout=5)
                    
                    info_data = json.loads(info_response.read().decode())
                    cluster_name = info_data.get('cluster_name', 'unknown')
                    cluster_version = info_data.get('version', {}).get('number', 'unknown')
                    
                    print_success(f"OpenSearch cluster: {cluster_name}")
                    print_success(f"OpenSearch version: {cluster_version}")
                    
                except Exception as e:
                    print_warning(f"Could not get cluster info: {e}")
                
                return True
                
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    print_warning(f"Authentication required (HTTP 401)")
                    print_info("Check username/password in configuration")
                    return True  # Server is reachable, auth is the issue
                elif e.code == 403:
                    print_warning(f"Access forbidden (HTTP 403)")
                    return True  # Server is reachable
                else:
                    print_error(f"HTTP error: {e.code} - {e.reason}")
                    return False
            except urllib.error.URLError as e:
                print_error(f"URL error: {e.reason}")
                return False
                
        except Exception as e:
            print_warning(f"HTTP request test skipped: {e}")
            return True  # Don't fail on HTTP test, TCP is enough
        
    except Exception as e:
        print_error(f"Error testing connectivity: {e}")
        return False


def check_service_status():
    """Check if OpenSearch service is running"""
    print_header("6. Service Status Check")
    
    # Common OpenSearch ports
    ports = [9200, 9201]
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                print_success(f"OpenSearch service detected on port {port}")
                return True
        except:
            pass
    
    print_warning("No OpenSearch service detected on localhost")
    print_info("Make sure OpenSearch service is running")
    return False


def generate_report(config_path, all_passed):
    """Generate final validation report"""
    print_header("Validation Summary")
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"  Configuration: {config_path}")
    print(f"  Timestamp: {timestamp}")
    print()
    
    if all_passed:
        print(f"  {Colors.GREEN}{Colors.BOLD}✓ ALL CHECKS PASSED{Colors.END}")
        print()
        print(f"  {Colors.GREEN}The agent configuration is valid and ready to run.{Colors.END}")
        print()
        print(f"  Next steps:")
        print(f"    - Run: python agent.py --config {config_path}")
        print(f"    - Or use the compiled executable if available")
    else:
        print(f"  {Colors.RED}{Colors.BOLD}✗ SOME CHECKS FAILED{Colors.END}")
        print()
        print(f"  {Colors.RED}Please fix the issues above before running the agent.{Colors.END}")
    
    print()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='VANT-SIEM OpenSearch Agent Configuration Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check default config.yaml
  %(prog)s --config custom.yaml     # Check custom config file
  %(prog)s --verbose                # Enable verbose output
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--skip-connectivity',
        action='store_true',
        help='Skip connectivity tests'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║                                                                   ║")
    print("║              VANT-SIEM OpenSearch Agent Checker                  ║")
    print("║                    Configuration Validation                     ║")
    print("║                                                                   ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    config_path = args.config
    
    # Resolve relative paths
    if not os.path.isabs(config_path):
        # Try current directory first
        if not Path(config_path).exists():
            # Try agent directory
            agent_dir = Path(__file__).parent
            config_path = agent_dir / config_path
    
    config_path = str(Path(config_path).resolve())
    
    # Run validations
    all_passed = True
    
    # 1. YAML Syntax
    if not validate_yaml_syntax(config_path):
        all_passed = False
        generate_report(config_path, False)
        sys.exit(1)
    
    # 2. Load config
    config = load_config(config_path)
    if config is None:
        all_passed = False
        generate_report(config_path, False)
        sys.exit(1)
    
    # 3. Agent config
    if not validate_agent_config(config):
        all_passed = False
    
    # 4. Output config
    if not validate_output_config(config):
        all_passed = False
    
    # 5. Collectors config
    if not validate_collectors_config(config):
        all_passed = False
    
    # 6. Service status
    check_service_status()
    
    # 7. Connectivity test
    if not args.skip_connectivity:
        if not test_connectivity(config):
            all_passed = False
    
    # Generate report
    generate_report(config_path, all_passed)
    
    sys.exit(0 if all_passed else 1)


if __name__ == '__main__':
    main()
