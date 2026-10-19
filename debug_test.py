#!/usr/bin/env python3
"""
Debug test for VANT-SIEM Rules Engine
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vant'))

from vant.modules.rules.manager import RuleManager

def debug_test():
    print("Creating rule manager...")
    rules_manager = RuleManager(os.path.join(os.path.dirname(__file__), 'vant', 'modules', 'rules', 'examples'))

    print("Loading rules...")
    loaded_count = rules_manager.load_rules_from_directory()
    print(f"Loaded {loaded_count} rules")

    # Get the PowerShell rule
    rules = rules_manager.get_all_rules()
    powershell_rule = None
    for rule in rules:
        if "PowerShell" in rule.title:
            powershell_rule = rule
            break

    if not powershell_rule:
        print("ERROR: Could not find PowerShell rule")
        return

    print(f"Testing rule: {powershell_rule.rule_id} - {powershell_rule.title}")

    # Test with a simple event that should match
    test_event = {
        "EventID": 4104,
        "ScriptBlockText": "Some command with [Convert]::ToString(64, [char[]]::new())",
        "source_type": "windows",
        "source_name": "Microsoft-Windows-PowerShell/Operational"
    }

    print(f"Testing event: {test_event}")

    # Let's manually check what the rule's logsource and detection are
    print(f"Rule logsource: {getattr(powershell_rule, 'logsource', 'Not found')}")
    print(f"Rule detection: {getattr(powershell_rule, 'detection', 'Not found')}")

    # Test logsource matching
    print("\n--- Testing logsource matching ---")
    logsource_result = powershell_rule._match_logsource(test_event)
    print(f"Logsource match result: {logsource_result}")

    # Test detection matching
    print("\n--- Testing detection matching ---")
    detection_result = powershell_rule._match_detection(test_event)
    print(f"Detection match result: {detection_result}")

    # Test the full match
    print("\n--- Testing full match ---")
    try:
        matches = powershell_rule.match(test_event)
        print(f"Full match result: {matches}")
    except Exception as e:
        print(f"Error in match: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_test()