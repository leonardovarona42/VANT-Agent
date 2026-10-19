"""
Rule manager for loading and managing rules in VANT-SIEM
"""
import os
import yaml
import logging
from typing import Dict, List, Optional, Any
from .base import BaseRule, SigmaRule

logger = logging.getLogger("vant-rules.manager")


class RuleManager:
    """Manages loading, storing, and applying rules"""

    def __init__(self, rules_dir: str = None):
        self.rules: Dict[str, BaseRule] = {}
        self.rules_dir = rules_dir or os.path.join(
            os.path.dirname(__file__), "rules"
        )
        self._ensure_rules_dir()

    def _ensure_rules_dir(self):
        """Ensure the rules directory exists"""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            logger.info(f"Created rules directory: {self.rules_dir}")

    def load_yaml_rule(self, file_path: str) -> Optional[SigmaRule]:
        """
        Load a single Sigma rule from YAML file

        Args:
            file_path: Path to the YAML file

        Returns:
            SigmaRule object or None if failed
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)

            if not rule_data:
                logger.warning(f"Empty rule file: {file_path}")
                return None

            # Extract Sigma rule metadata
            rule_id = rule_data.get('id', os.path.basename(file_path))
            title = rule_data.get('title', 'Untitled Rule')
            description = rule_data.get('description', '')
            level = rule_data.get('level', 'medium')

            # Create SigmaRule object
            sigma_rule = SigmaRule(
                rule_id=rule_id,
                title=title,
                description=description,
                level=level,
                sigma_yaml=rule_data
            )

            logger.info(f"Loaded Sigma rule: {rule_id} from {file_path}")
            return sigma_rule

        except Exception as e:
            logger.error(f"Failed to load rule from {file_path}: {e}")
            return None

    def load_rules_from_directory(self, directory: str = None) -> int:
        """
        Load all Sigma rules from a directory

        Args:
            directory: Directory to scan for YAML files (uses self.rules_dir if None)

        Returns:
            Number of rules successfully loaded
        """
        scan_dir = directory or self.rules_dir
        if not os.path.exists(scan_dir):
            logger.warning(f"Rules directory does not exist: {scan_dir}")
            return 0

        loaded_count = 0
        for filename in os.listdir(scan_dir):
            if filename.endswith(('.yaml', '.yml')):
                file_path = os.path.join(scan_dir, filename)
                rule = self.load_yaml_rule(file_path)
                if rule:
                    self.rules[rule.rule_id] = rule
                    loaded_count += 1

        logger.info(f"Loaded {loaded_count} rules from {scan_dir}")
        return loaded_count

    def add_rule(self, rule: BaseRule):
        """Add a rule to the manager"""
        self.rules[rule.rule_id] = rule
        logger.debug(f"Added rule: {rule.rule_id}")

    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a rule by ID

        Args:
            rule_id: ID of the rule to remove

        Returns:
            True if rule was removed, False if not found
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.debug(f"Removed rule: {rule_id}")
            return True
        return False

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        """Get a rule by ID"""
        return self.rules.get(rule_id)

    def get_all_rules(self) -> List[BaseRule]:
        """Get all rules"""
        return list(self.rules.values())

    def get_enabled_rules(self) -> List[BaseRule]:
        """Get all enabled rules"""
        return [rule for rule in self.rules.values() if rule.enabled]

    def match_event(self, event: Dict[str, Any]) -> List[BaseRule]:
        """
        Check event against all rules and return matching rules

        Args:
            event: The event to check

        Returns:
            List of rules that matched the event
        """
        matching_rules = []
        for rule in self.get_enabled_rules():
            if rule.match(event):
                matching_rules.append(rule)

        return matching_rules

    def reload_rules(self):
        """Reload all rules from the rules directory"""
        logger.info("Reloading all rules...")
        old_count = len(self.rules)
        self.rules.clear()
        loaded_count = self.load_rules_from_directory()
        logger.info(f"Reloaded rules: {old_count} -> {loaded_count}")