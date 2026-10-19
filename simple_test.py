#!/usr/bin/env python3
"""
Simple test for VANT-SIEM Rules Engine
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vant'))

from vant.modules.rules.manager import RuleManager

def simple_test():
    print("Creating rule manager...")
    rules_manager = RuleManager(os.path.join(os.path.dirname(__file__), 'vant', 'modules', 'rules', 'examples'))

    print("Loading rules...")
    loaded_count = rules_manager.load_rules_from_directory()
    print(f"Loaded {loaded_count} rules")

    rules = rules_manager.get_all_rules()
    print(f"Got {len(rules)} rules")

    for rule in rules:
        print(f"Rule: {rule.rule_id} - {rule.title}")

        # Test with a simple event
        test_event = {
            "EventID": 4104,
            "ScriptBlockText": "Some command with [Convert]::ToString(64, [char[]]::new())",
            "source_type": "windows",
            "source_name": "Microsoft-Windows-PowerShell/Operational"
        }

        print(f"Testing event: {test_event}")
        try:
            matches = rule.match(test_event)
            print(f"Match result: {matches}")
        except Exception as e:
            print(f"Error in match: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    simple_test()