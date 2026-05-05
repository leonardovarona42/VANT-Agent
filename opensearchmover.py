#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║                     VANT-SIEM OpenSearch Agent                          ║
║                        Server Migration Tool                             ║
║                                                                           ║
║  Script: opensearchmover.py                                             ║
║  Purpose: Change the OpenSearch server configuration for the agent      ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import shutil
from pathlib import Path
from datetime import datetime

# Try to import yaml
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


def print_step(msg):
    """Print step message"""
    print(f"\n{Colors.MAGENTA}▶{Colors.END} {msg}")


def load_config(config_path):
    """Load YAML configuration"""
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
            
        return config
        
    except yaml.YAMLError as e:
        print_error(f"Invalid YAML syntax: {e}")
        return None
    except Exception as e:
        print_error(f"Error reading configuration: {e}")
        return None


def save_config(config, config_path):
    """Save YAML configuration"""
    path = Path(config_path)
    
    try:
        # Create backup
        backup_path = path.with_suffix('.yaml.bak')
        shutil.copy2(path, backup_path)
        print_success(f"Backup created: {backup_path}")
        
        # Save new config
        with open(path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        
        print_success(f"Configuration saved: {config_path}")
        return True
        
    except Exception as e:
        print_error(f"Error saving configuration: {e}")
        return False


def show_current_config(config):
    """Display current server configuration"""
    print_header("Current Configuration")
    
    output = config.get('output', {})
    
    endpoint = output.get('endpoint', 'Not configured')
    source_endpoint = output.get('source_endpoint', 'Not configured')
    
    print(f"  Event Endpoint:     {endpoint}")
    print(f"  Source Endpoint:   {source_endpoint}")
    print()
    
    # Show auth info (masked)
    auth = output.get('auth', {})
    auth_mode = auth.get('mode', 'none')
    print(f"  Auth Mode:         {auth_mode}")
    
    if auth_mode == 'basic':
        username = auth.get('username', '')
        password = auth.get('password', '')
        masked_password = '*' * len(password) if password else ''
        print(f"  Username:          {username}")
        print(f"  Password:          {masked_password}")
    
    # Show TLS info
    tls = output.get('tls', {})
    tls_enabled = tls.get('enabled', False)
    print(f"  TLS Enabled:       {tls_enabled}")


def update_endpoints(config, new_host, new_port=None, use_https=False):
    """Update the OpenSearch endpoints"""
    output = config.get('output', {})
    
    # Determine port
    if new_port is None:
        new_port = 9201 if use_https else 9200
    
    # Determine protocol
    protocol = "https" if use_https else "http"
    
    # Build new endpoints
    new_endpoint = f"{protocol}://{new_host}:{new_port}/api/v1/events/bulk"
    new_source_endpoint = f"{protocol}://{new_host}:{new_port}/api/v1/sources/upsert"
    
    old_endpoint = output.get('endpoint', '')
    old_source_endpoint = output.get('source_endpoint', '')
    
    print_info(f"Changing endpoint from: {old_endpoint}")
    print_info(f"               to: {new_endpoint}")
    
    output['endpoint'] = new_endpoint
    output['source_endpoint'] = new_source_endpoint
    
    # Update TLS setting based on protocol
    tls = output.get('tls', {})
    tls['enabled'] = use_https
    output['tls'] = tls
    
    config['output'] = output
    
    return config


def test_new_endpoint(config):
    """Test if the new endpoint is reachable"""
    import socket
    
    print_step("Testing new endpoint connectivity")
    
    output = config.get('output', {})
    endpoint = output.get('endpoint', '')
    
    try:
        # Extract host and port
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
            port = 9201
        
        print_info(f"Testing {host}:{port}...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print_success(f"New endpoint is reachable!")
            return True
        else:
            print_warning(f"Cannot reach {host}:{port} - server may be down")
            print_info("The configuration has been updated but server is not reachable")
            return False
            
    except socket.gaierror:
        print_error(f"Cannot resolve hostname: {host}")
        return False
    except Exception as e:
        print_error(f"Connection test failed: {e}")
        return False


def interactive_mode(config_path):
    """Interactive mode to change server configuration"""
    print_header("Server Migration - Interactive Mode")
    
    # Load current config
    config = load_config(config_path)
    if config is None:
        return False
    
    # Show current config
    show_current_config(config)
    
    print()
    print_info("Enter the new OpenSearch server details:")
    print()
    
    # Get new host
    new_host = input(f"  {Colors.CYAN}OpenSearch Server Host:{Colors.END} ").strip()
    
    if not new_host:
        print_error("Host cannot be empty")
        return False
    
    # Get new port (optional)
    port_input = input(f"  {Colors.CYAN}OpenSearch Server Port (default: 9200):{Colors.END} ").strip()
    new_port = int(port_input) if port_input else None
    
    # Get protocol
    https_input = input(f"  {Colors.CYAN}Use HTTPS? (y/N):{Colors.END} ").strip().lower()
    use_https = https_input in ['y', 'yes']
    
    # Confirm
    print()
    print_warning("Configuration will be updated. A backup will be created.")
    confirm = input(f"  {Colors.YELLOW}Proceed? (y/N):{Colors.END} ").strip().lower()
    
    if confirm != 'y':
        print_info("Operation cancelled")
        return False
    
    # Update configuration
    config = update_endpoints(config, new_host, new_port, use_https)
    
    # Save
    if save_config(config, config_path):
        # Test connectivity
        test_new_endpoint(config)
        return True
    
    return False


def batch_mode(config_path, new_host, new_port, use_https, backup):
    """Batch mode to change server configuration"""
    print_header("Server Migration - Batch Mode")
    
    # Load config
    config = load_config(config_path)
    if config is None:
        return False
    
    # Show current config
    show_current_config(config)
    
    # Check for backup
    if not backup:
        print_step("Creating backup")
        path = Path(config_path)
        backup_path = path.with_suffix('.yaml.bak')
        shutil.copy2(path, backup_path)
        print_success(f"Backup created: {backup_path}")
    
    # Update configuration
    print_step("Updating endpoints")
    config = update_endpoints(config, new_host, new_port, use_https)
    
    # Save
    if save_config(config, config_path):
        # Test connectivity
        test_new_endpoint(config)
        print_success("Server migration completed!")
        return True
    
    return False


def show_config_examples():
    """Show configuration examples"""
    print_header("Configuration Examples")
    
    examples = [
        ("Local development", "localhost", 9200, False),
        ("Local with custom port", "localhost", 9201, False),
        ("Remote server (HTTP)", "192.168.1.100", 9200, False),
        ("Remote server with TLS", "opensearch.example.com", 443, True),
        ("Cloud OpenSearch", "search-cluster.us-east-1.es.amazonaws.com", 443, True),
    ]
    
    for i, (name, host, port, https) in enumerate(examples, 1):
        protocol = "https" if https else "http"
        endpoint = f"{protocol}://{host}:{port}/api/v1/events/bulk"
        print(f"  {i}. {name}")
        print(f"     Host: {host}, Port: {port}, HTTPS: {https}")
        print(f"     Endpoint: {endpoint}")
        print()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='VANT-SIEM OpenSearch Agent Server Migration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i                      # Interactive mode
  %(prog)s --host 192.168.1.100    # Change to remote server
  %(prog)s --host localhost --port 9201  # Custom port
  %(proto)s --host opensearch.example.com --https  # With TLS
  %(prog)s --examples              # Show configuration examples
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Interactive mode for server migration'
    )
    
    parser.add_argument(
        '--host',
        help='New OpenSearch server hostname or IP'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        help='OpenSearch server port (default: 9200)'
    )
    
    parser.add_argument(
        '--https',
        action='store_true',
        help='Use HTTPS instead of HTTP'
    )
    
    parser.add_argument(
        '--http',
        action='store_true',
        help='Use HTTP (default)'
    )
    
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Skip creating backup file'
    )
    
    parser.add_argument(
        '--examples',
        action='store_true',
        help='Show configuration examples'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║                                                                   ║")
    print("║              VANT-SIEM OpenSearch Agent Mover                    ║")
    print("║                    Server Migration Tool                        ║")
    print("║                                                                   ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    # Show examples
    if args.examples:
        show_config_examples()
        sys.exit(0)
    
    # Resolve config path
    config_path = args.config
    if not os.path.isabs(config_path):
        if not Path(config_path).exists():
            agent_dir = Path(__file__).parent
            config_path = agent_dir / config_path
    
    config_path = str(Path(config_path).resolve())
    
    # Determine mode
    if args.interactive:
        success = interactive_mode(config_path)
    elif args.host:
        success = batch_mode(
            config_path,
            args.host,
            args.port,
            args.https,
            args.no_backup
        )
    else:
        print_error("No action specified")
        print_info("Use --interactive for interactive mode")
        print_info("Use --host <hostname> for batch mode")
        print_info("Use --examples to see configuration examples")
        print()
        parser.print_help()
        sys.exit(1)
    
    if success:
        print()
        print(f"{Colors.GREEN}{Colors.BOLD}Server migration completed successfully!{Colors.RESET}")
        print()
        print("Next steps:")
        print(f"  - Verify configuration: python opensearchcheck.py --config {config_path}")
        print(f"  - Restart the agent: python agent.py --config {config_path}")
    else:
        print()
        print(f"{Colors.RED}{Colors.BOLD}Server migration failed!{Colors.RESET}")
        sys.exit(1)


if __name__ == '__main__':
    main()
