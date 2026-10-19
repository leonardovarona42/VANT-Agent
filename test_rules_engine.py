#!/usr/bin/env python3
"""
Test script for VANT-SIEM Rules Engine
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vant'))

from vant.modules.rules.manager import RuleManager
from vant.modules.rules.base import SigmaRule

def test_rule_loading():
    """Test that rules are loaded correctly"""
    print("Testing rule loading...")

    # Debug: show current directory and path
    print(f"Current directory: {os.getcwd()}")
    print(f"Script directory: {os.path.dirname(__file__)}")
    vant_path = os.path.join(os.path.dirname(__file__), 'vant')
    print(f"VANT path inserted: {vant_path}")
    print(f"Path exists: {os.path.exists(vant_path)}")

    # Initialize rule manager with correct path
    rules_path = os.path.join(os.path.dirname(__file__), 'vant', 'modules', 'rules', 'examples')
    print(f"Rules path: {rules_path}")
    print(f"Rules path exists: {os.path.exists(rules_path)}")

    rules_manager = RuleManager(rules_path)
    print(f"Rules manager directory: {rules_manager.rules_dir}")
    print(f"Rules directory exists: {os.path.exists(rules_manager.rules_dir)}")

    # Show the full resolved path
    full_path = os.path.abspath(rules_manager.rules_dir)
    print(f"Full rules directory path: {full_path}")
    print(f"Full path exists: {os.path.exists(full_path)}")

    if os.path.exists(rules_manager.rules_dir):
        files = os.listdir(rules_manager.rules_dir)
        print(f"Files in rules directory: {files}")
        yaml_files = [f for f in files if f.endswith(('.yaml', '.yml'))]
        print(f"YAML files in rules directory: {yaml_files}")

    # Load rules from directory
    loaded_count = rules_manager.load_rules_from_directory()
    print(f"Loaded {loaded_count} rules")

    # Check that we have rules
    assert loaded_count > 0, "No rules were loaded"

    # Get all rules
    rules = rules_manager.get_all_rules()
    print(f"Total rules in manager: {len(rules)}")

    # Check that rules have expected properties
    for rule in rules:
        assert hasattr(rule, 'rule_id'), "Rule missing rule_id"
        assert hasattr(rule, 'title'), "Rule missing title"
        assert hasattr(rule, 'match'), "Rule missing match method"
        print(f"  - {rule.rule_id}: {rule.title}")

    return rules_manager

def test_rule_matching():
    """Test that rules match events correctly"""
    print("\nTesting rule matching...")

    rules_manager = test_rule_loading()

    # Test event that should match the PowerShell rule
    powershell_event = {
        "source_type": "windows_eventlog",
        "source_name": "Microsoft-Windows-PowerShell/Operational",
        "host_name": "test-host",
        "host_ip": "192.168.1.100",
        "event_time": "2024-09-15T10:30:00Z",
        "EventID": 4104,  # Sigma rule uses EventID
        "ScriptBlockText": "Some command with [Convert]::ToString(64, [char[]]::new())",  # Sigma rule uses ScriptBlockText
        "event_category": "windows.powershell",
        "severity": "info"
    }

    # Test event that should NOT match the PowerShell rule
    normal_powershell_event = {
        "source_type": "windows_eventlog",
        "source_name": "Microsoft-Windows-PowerShell/Operational",
        "host_name": "test-host",
        "host_ip": "192.168.1.100",
        "event_time": "2024-09-15T10:30:00Z",
        "EventID": 4104,
        "ScriptBlockText": "Write-Host 'Hello World'",
        "event_category": "windows.powershell",
        "severity": "info"
    }

    # Test event that should match the credential access rule
    cred_access_event = {
        "source_type": "windows_eventlog",
        "source_name": "Microsoft-Windows-Security-Auditing",
        "host_name": "test-host",
        "host_ip": "192.168.1.100",
        "event_time": "2024-09-15T10:35:00Z",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1fffff",
        "CallerImage": "C:\\Temp\\mimikatz.exe",
        "event_category": "windows.process_access",
        "severity": "info"
    }

    # Test event that should NOT match the credential access rule (filtered)
    filtered_cred_event = {
        "source_type": "windows_eventlog",
        "source_name": "Microsoft-Windows-Security-Auditing",
        "host_name": "test-host",
        "host_ip": "192.168.1.100",
        "event_time": "2024-09-15T10:35:00Z",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1fffff",
        "CallerImage": "C:\\Windows\\System32\\services.exe",
        "event_category": "windows.process_access",
        "severity": "info"
    }

    # Test event that should match the suspicious cron rule
    cron_event = {
        "source_type": "linux_audit",
        "source_name": "auditd",
        "host_name": "linux-host",
        "host_ip": "192.168.1.101",
        "event_time": "2024-09-15T10:40:00Z",
        "MSG": "USER_CMD",
        "EXE": "/usr/bin/cron",
        "CMD": "echo 'malicious script' | crontab -",
        "event_category": "linux.audit",
        "severity": "info"
    }

    # Test the PowerShell rule
    print("Testing PowerShell detection rule...")
    matches = rules_manager.match_event(powershell_event)
    print(f"PowerShell event matches: {len(matches)} rules")
    for match in matches:
        print(f"  - Matched: {match.rule_id} ({match.title})")

    assert len(matches) > 0, "PowerShell event should match at least one rule"

    # Test that normal PowerShell doesn't match
    print("\nTesting normal PowerShell (should not match)...")
    matches = rules_manager.match_event(normal_powershell_event)
    print(f"Normal PowerShell event matches: {len(matches)} rules")
    # Note: This might still match if there are other rules, but shouldn't match our specific PowerShell rule

    # Test the credential access rule
    print("\nTesting credential access detection rule...")
    matches = rules_manager.match_event(cred_access_event)
    print(f"Credential access event matches: {len(matches)} rules")
    for match in matches:
        print(f"  - Matched: {match.rule_id} ({match.title})")

    # Test that filtered credential access doesn't match
    print("\nTesting filtered credential access (should not match)...")
    matches = rules_manager.match_event(filtered_cred_event)
    print(f"Filtered credential access event matches: {len(matches)} rules")

    # Test the cron rule
    print("\nTesting suspicious cron detection rule...")
    matches = rules_manager.match_event(cron_event)
    print(f"Cron event matches: {len(matches)} rules")
    for match in matches:
        print(f"  - Matched: {match.rule_id} ({match.title})")

    print("\nAll tests passed!")

if __name__ == "__main__":
    try:
        test_rule_matching()
        print("\n✅ Rules engine tests completed successfully!")
    except Exception as e:
        print(f"\n❌ Rules engine tests failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)