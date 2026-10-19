"""
Base rule class for VANT-SIEM rules engine
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
import logging

logger = logging.getLogger("vant-rules.base")


class BaseRule(ABC):
    """Base class for all rule types"""

    def __init__(self, rule_id: str, title: str, description: str, level: str = "medium"):
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.level = level  # low, medium, high, critical
        self.enabled = True
        self.tags = []

    @abstractmethod
    def match(self, event: Dict[str, Any]) -> bool:
        """
        Check if the event matches this rule

        Args:
            event: The event dictionary to check

        Returns:
            True if the event matches the rule, False otherwise
        """
        pass

    def enable(self):
        """Enable the rule"""
        self.enabled = True
        logger.debug(f"Rule {self.rule_id} enabled")

    def disable(self):
        """Disable the rule"""
        self.enabled = False
        logger.debug(f"Rule {self.rule_id} disabled")

    def add_tag(self, tag: str):
        """Add a tag to the rule"""
        if tag not in self.tags:
            self.tags.append(tag)

    def get_info(self) -> Dict[str, Any]:
        """Get rule information"""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "level": self.level,
            "enabled": self.enabled,
            "tags": self.tags
        }


class SigmaRule(BaseRule):
    """Sigma rule implementation"""

    def __init__(self, rule_id: str, title: str, description: str,
                 level: str = "medium", sigma_yaml: Dict[str, Any] = None):
        super().__init__(rule_id, title, description, level)
        self.sigma_yaml = sigma_yaml or {}
        self._parse_sigma_rule()

    def _parse_sigma_rule(self):
        """Parse Sigma rule YAML into usable components"""
        # Extract common Sigma fields
        self.logsource = self.sigma_yaml.get('logsource', {})
        self.detection = self.sigma_yaml.get('detection', {})
        self.fields = self.sigma_yaml.get('fields', [])
        self.falsepositives = self.sigma_yaml.get('falsepositives', [])
        self.level = self.sigma_yaml.get('level', self.level).lower()

        # Convert level string to standard format
        level_mapping = {
            'informational': 'low',
            'low': 'low',
            'medium': 'medium',
            'high': 'high',
            'critical': 'critical'
        }
        self.level = level_mapping.get(self.level, 'medium')

    def match(self, event: Dict[str, Any]) -> bool:
        """
        Check if event matches Sigma rule

        Args:
            event: The event dictionary to check

        Returns:
            True if event matches the rule
        """
        if not self.enabled:
            return False

        try:
            # Check logsource matching
            logsource_result = self._match_logsource(event)
            # print(f"Logsource match result: {logsource_result}")  # Debug
            if not logsource_result:
                return False

            # Check detection conditions
            detection_result = self._match_detection(event)
            # print(f"Detection match result: {detection_result}")  # Debug
            if not detection_result:
                return False

            return True
        except Exception as e:
            logger.warning(f"Error matching rule {self.rule_id}: {e}")
            return False

    def _match_logsource(self, event: Dict[str, Any]) -> bool:
        """Check if event matches logsource criteria"""
        if not self.logsource:
            return True

        # Check common logsource fields
        for key, value in self.logsource.items():
            if key == 'category':
                # Special handling for category
                event_category = event.get('event_category', '')
                if isinstance(value, list):
                    if event_category not in value:
                        return False
                elif event_category != value:
                    return False
            elif key == 'product':
                # Check product/source_type
                event_source = event.get('source_type', '')
                # Handle common variations for Windows product
                if value == 'windows':
                    # Accept various Windows event source types
                    windows_variants = ['windows', 'windows_eventlog', 'winlogbeat', 'wineventlog', 'microsoft-windows']
                    if event_source not in windows_variants:
                        return False
                elif isinstance(value, list):
                    if event_source not in value:
                        return False
                elif event_source != value:
                    return False
            elif key == 'service':
                # Check service - try service field first, then source_name as fallback
                event_service = event.get('service', '')
                if not event_service:
                    # Try to extract service from source_name (e.g., "Microsoft-Windows-PowerShell/Operational" -> "powershell")
                    source_name = event.get('source_name', '')
                    if 'Microsoft-Windows-' in source_name and '/' in source_name:
                        # Extract the service part: Microsoft-Windows-<service>-<part>
                        # Example: "Microsoft-Windows-PowerShell/Operational" -> "PowerShell"
                        parts = source_name.split('-')
                        if len(parts) >= 3:
                            # Take the part after "Microsoft-Windows-" and before the first "/" or end
                            service_part = parts[2]
                            # Remove anything after "/" (like "/Operational")
                            if '/' in service_part:
                                service_part = service_part.split('/')[0]
                            event_service = service_part
                    elif 'source_name' in event:
                        event_service = event.get('source_name', '')
                # Case-insensitive comparison
                if isinstance(value, list):
                    if event_service.lower() not in [v.lower() for v in value]:
                        return False
                elif event_service.lower() != value.lower():
                    return False
            else:
                # Generic field matching
                event_value = event.get(key)
                if isinstance(value, list):
                    if event_value not in value:
                        return False
                elif event_value != value:
                    return False

        return True

    def _match_detection(self, event: Dict[str, Any]) -> bool:
        """
        Check if event matches detection criteria

        Sigma detection section structure:
        detection:
            selection:
                Field1: value1
                Field2: value2
            filter:
                Field3: value3
            condition: selection and not filter
        """
        if not self.detection:
            return True

        # For simplicity, we'll implement basic selection matching
        # In a full implementation, we'd parse the condition expression

        # Process all selection-like sections
        selection_sections = [k for k in self.detection.keys()
                            if k not in ['condition', 'filter']]

        if not selection_sections:
            return True

        # For now, we'll AND all selection sections together
        # A more complete implementation would parse the condition
        for section_name in selection_sections:
            section = self.detection[section_name]
            if not self._match_selection_section(event, section):
                return False

        # Check filter sections (should NOT match)
        filter_sections = [k for k in self.detection.keys()
                          if k == 'filter']
        for section_name in filter_sections:
            section = self.detection[section_name]
            if self._match_selection_section(event, section):
                return False  # Filter matched, so rule doesn't match

        return True

    def _match_selection_section(self, event: Dict[str, Any],
                                selection: Dict[str, Any]) -> bool:
        """
        Match event against a selection section

        Args:
            event: The event to check
            selection: Dictionary of field-value pairs to match

        Returns:
            True if event matches all selection criteria
        """
        for field, expected_value in selection.items():
            # Handle field mapping (e.g., Image -> process_name)
            actual_value = self._get_field_value(event, field)

            if actual_value is None:
                return False

            # Handle different types of expected values
            if isinstance(expected_value, list):
                # Value must be in the list
                if actual_value not in expected_value:
                    return False
            elif isinstance(expected_value, dict):
                # Handle special modifiers like contains, startswith, etc.
                if not self._apply_modifier(actual_value, expected_value):
                    return False
            elif isinstance(expected_value, str):
                # Handle wildcard patterns in strings
                if '*' in expected_value or '?' in expected_value:
                    # Convert wildcard to regex pattern
                    import re
                    # Escape special regex characters except * and ?
                    pattern = re.escape(expected_value)
                    # Convert * to .* and ? to .
                    pattern = pattern.replace(r'\*', '.*').replace(r'\?', '.')
                    if not re.match(pattern, str(actual_value)):
                        return False
                else:
                    # Exact match
                    if actual_value != expected_value:
                        return False
            else:
                # Exact match for non-string types
                if actual_value != expected_value:
                    return False

        return True

    def _get_field_value(self, event: Dict[str, Any], field: str) -> Any:
        """
        Get field value from event, handling field mappings

        Args:
            event: The event dictionary
            field: Field name (may contain mappings like Image -> process_name)

        Returns:
            The field value or None if not found
        """
        # Direct field access
        if field in event:
            return event[field]

        # Common field mappings for Sigma rules
        field_mappings = {
            'Image': 'process_name',
            'TargetFilename': 'file_path',
            'SrcIpAddr': 'source_ip',
            'DstIpAddr': 'destination_ip',
            'SrcPort': 'source_port',
            'DstPort': 'destination_port',
            'Protocol': 'protocol',
            'User': 'user_name',
            'TargetUserName': 'target_user',
            'CommandLine': 'command_line',
            'ParentImage': 'parent_process_name'
        }

        mapped_field = field_mappings.get(field)
        if mapped_field and mapped_field in event:
            return event[mapped_field]

        # Try to find in raw_payload
        raw_payload = event.get('raw_payload', {})
        if isinstance(raw_payload, dict):
            if field in raw_payload:
                return raw_payload[field]

            # Check mapped fields in raw_payload
            if mapped_field and mapped_field in raw_payload:
                return raw_payload[mapped_field]

        return None

    def _apply_modifier(self, actual_value: Any, modifier_dict: Dict[str, Any]) -> bool:
        """
        Apply modifier to value comparison

        Args:
            actual_value: The actual value from the event
            modifier_dict: Dictionary containing modifier and value

        Returns:
            True if the modifier condition matches
        """
        if not isinstance(actual_value, str):
            return False

        for modifier, expected in modifier_dict.items():
            if modifier == 'contains':
                if expected not in actual_value:
                    return False
            elif modifier == 'startswith':
                if not actual_value.startswith(expected):
                    return False
            elif modifier == 'endswith':
                if not actual_value.endswith(expected):
                    return False
            elif modifier == 'endswith':
                if not actual_value.endswith(expected):
                    return False
            elif modifier == 'regex':
                import re
                if not re.search(expected, actual_value):
                    return False
            else:
                # Unknown modifier, treat as equality
                if actual_value != expected:
                    return False

        return True