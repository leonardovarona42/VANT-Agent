"""
Compliance Reporting Service for VANT-SIEM Agent
Supports HIPAA, GDPR, and PCI DSS frameworks
"""
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

from vant.utils import detect_host, run_hidden
from vant.modules.inventory.service import InventoryService


class ComplianceService:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.state_dir = Path(config_path).resolve().parent / ".vant_state" / "compliance"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "compliance_state.json"
        self._state = self._load_state()

        # Framework configurations
        self.frameworks = {
            "HIPAA": {
                "version": "1996",
                "controls": self._get_hipaa_controls()
            },
            "GDPR": {
                "version": "2016",
                "controls": self._get_gdpr_controls()
            },
            "PCI_DSS": {
                "version": "4.0",
                "controls": self._get_pci_dss_controls()  # We can reuse or map existing
            }
        }

        # Common control mappings (simplified example)
        self.common_controls = self._get_common_control_mappings()

    def _load_state(self) -> Dict:
        if self.state_file.exists():
            try:
                return json.loads(self.state_file.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_state(self):
        self.state_file.write_text(json.dumps(self._state, indent=2), encoding="utf-8")

    def _get_hipaa_controls(self) -> List[Dict]:
        """
        Return a list of HIPAA Security Rule controls that we can monitor.
        This is a subset focused on technical safeguards.
        """
        return [
            {
                "id": "HIPAA-164.306(d)",
                "title": "Technical Safeguards",
                "description": "Implement technical policies and procedures for electronic information systems that maintain ePHI.",
                "subcontrols": [
                    {
                        "id": "HIPAA-164.312(a)(1)",
                        "title": "Access Control",
                        "description": "Implement technical policies and procedures to allow access only to authorized persons.",
                        "evidence_collectors": ["access_control", "authentication_logs"]
                    },
                    {
                        "id": "HIPAA-164.312(a)(2)(i)",
                        "title": "Unique User Identification",
                        "description": "Assign a unique name and/or number for identifying and tracking user identity.",
                        "evidence_collectors": ["user_accounts", "authentication_logs"]
                    },
                    {
                        "id": "HIPAA-164.312(e)(1)",
                        "title": "Transmission Security",
                        "description": "Implement technical security measures to guard against unauthorized access to ePHI transmitted over an electronic network.",
                        "evidence_collectors": ["network_encryption", "transmission_logs"]
                    }
                ]
            }
        ]

    def _get_gdpr_controls(self) -> List[Dict]:
        """
        Return a list of GDPR Article 32 (security of processing) controls.
        """
        return [
            {
                "id": "GDPR-Article32",
                "title": "Security of processing",
                "description": "Implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk.",
                "subcontrols": [
                    {
                        "id": "GDPR-Article32-1",
                        "title": "Pseudonymisation and encryption",
                        "description": "The pseudonymisation and encryption of personal data.",
                        "evidence_collectors": ["data_encryption", "pseudonymisation_processes"]
                    },
                    {
                        "id": "GDPR-Article32-2",
                        "title": "Confidentiality, integrity, availability",
                        "description": "Ensure the ongoing confidentiality, integrity, availability and resilience of processing systems.",
                        "evidence_collectors": ["system_integrity", "backup_verification", "uptime_monitoring"]
                    },
                    {
                        "id": "GDPR-Article32-3",
                        "title": "Restoration of availability",
                        "description": "Ability to restore the availability and access to personal data in a timely manner.",
                        "evidence_collectors": ["disaster_recovery_tested", "backup_restore_timing"]
                    }
                ]
            }
        ]

    def _get_pci_dss_controls(self) -> List[Dict]:
        """
        Return a list of PCI DSS v4.0 controls that we already collect evidence for.
        This is a placeholder; in reality, we would map to existing collectors.
        """
        return [
            {
                "id": "PCI_DSS-v4.0-1.1",
                "title": "Firewall Configuration",
                "description": "Review firewall and router configuration standards at least once every six months.",
                "evidence_collectors": ["firewall_config_review"]
            },
            {
                "id": "PCI_DSS-v4.0-2.1",
                "title": "Default Passwords",
                "description": "Change vendor-supplied defaults before installing a system.",
                "evidence_collectors": ["default_password_scan"]
            }
        ]

    def _get_common_control_mappings(self) -> Dict[str, List[str]]:
        """
        Map common controls across frameworks.
        Key: common control description, Value: list of control IDs from each framework.
        """
        return {
            "Access Control": [
                "HIPAA-164.312(a)(1)",
                "GDPR-Article32-2",  # Partially related to access
                "PCI_DSS-v4.0-7.1"   # Not in our list but example
            ],
            "Encryption": [
                "HIPAA-164.312(e)(1)",
                "GDPR-Article32-1",
                "PCI_DSS-v4.0-3.4"   # Example
            ],
            "Audit Logs": [
                "HIPAA-164.308(a)(1)(ii)(D)",  # Audit controls
                "GDPR-Article30",               # Records of processing activities
                "PCI_DSS-v4.0-10.2"             # Audit trail mechanisms
            ]
        }

    def collect_evidence(self, agent_id: str, host_name: str, host_ip: str) -> Dict[str, Any]:
        """
        Collect evidence for all compliance frameworks.
        Returns a dictionary structured by framework and control.
        """
        hostname, ip = detect_host()
        if not host_name:
            host_name = hostname
        if not host_ip:
            host_ip = ip

        evidence = {
            "agent_id": agent_id,
            "host_name": host_name,
            "host_ip": host_ip,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "frameworks": {}
        }

        # For each framework, collect evidence
        for framework_name, framework_info in self.frameworks.items():
            framework_evidence = {
                "framework": framework_name,
                "version": framework_info["version"],
                "controls": []
            }

            for control in framework_info["controls"]:
                control_evidence = self._collect_control_evidence(control, host_name, host_ip)
                framework_evidence["controls"].append(control_evidence)

            evidence["frameworks"][framework_name] = framework_evidence

        # Update state
        self._state["last_evidence_collection"] = evidence["collected_at"]
        self._save_state()

        return evidence

    def _collect_control_evidence(self, control: Dict, host_name: str, host_ip: str) -> Dict:
        """
        Collect evidence for a specific control.
        This is a placeholder; in reality, we would invoke specific collectors.
        """
        # For now, we return a mock evidence structure
        # In a real implementation, we would:
        # 1. For each evidence_collector in control["subcontrols"][0]["evidence_collectors"] (if exists)
        # 2. Run the appropriate collection script or query
        # 3. Return the results

        # Since we don't have specific collectors implemented, we return a placeholder
        # that indicates the control is not automated and requires manual evidence.

        # Check if this control has subcontrols
        if "subcontrols" in control:
            subcontrol_evidence = []
            for subcontrol in control["subcontrols"]:
                subcontrol_evidence.append({
                    "id": subcontrol["id"],
                    "title": subcontrol["title"],
                    "description": subcontrol["description"],
                    "status": "collected",  # Would be based on actual evidence
                    "evidence": self._collect_subcontrol_evidence(subcontrol, host_name, host_ip),
                    "collected_at": datetime.now(timezone.utc).isoformat()
                })

            return {
                "id": control["id"],
                "title": control["title"],
                "description": control["description"],
                "subcontrols": subcontrol_evidence,
                "status": "collected"
            }
        else:
            return {
                "id": control["id"],
                "title": control["title"],
                "description": control["description"],
                "status": "collected",
                "evidence": self._collect_subcontrol_evidence(control, host_name, host_ip),
                "collected_at": datetime.now(timezone.utc).isoformat()
            }

    def _collect_subcontrol_evidence(self, subcontrol: Dict, host_name: str, host_ip: str) -> Any:
        """
        Collect evidence for a specific subcontrol (or control without subcontrols).
        This method should be extended to use actual collectors.
        """
        # Map evidence collector names to actual collection functions
        collector_map = {
            "access_control": self._collect_access_control_evidence,
            "authentication_logs": self._collect_authentication_logs_evidence,
            "user_accounts": self._collect_user_accounts_evidence,
            "network_encryption": self._collect_network_encryption_evidence,
            "transmission_logs": self._collect_transmission_logs_evidence,
            "data_encryption": self._collect_data_encryption_evidence,
            "pseudonymisation_processes": self._collect_pseudonymisation_evidence,
            "system_integrity": self._collect_system_integrity_evidence,
            "backup_verification": self._collect_backup_verification_evidence,
            "uptime_monitoring": self._collect_uptime_monitoring_evidence,
            "disaster_recovery_tested": self._collect_disaster_recovery_evidence,
            "backup_restore_timing": self._collect_backup_restore_timing_evidence,
            "firewall_config_review": self._collect_firewall_config_evidence,
            "default_password_scan": self._collect_default_password_evidence,
        }

        evidence = {}
        if "evidence_collectors" in subcontrol:
            for collector_name in subcontrol["evidence_collectors"]:
                if collector_name in collector_map:
                    try:
                        evidence[collector_name] = collector_map[collector_name](host_name, host_ip)
                    except Exception as e:
                        evidence[collector_name] = {"error": str(e)}
                else:
                    evidence[collector_name] = {"note": "Collector not implemented"}
        else:
            # If no specific collectors, try to match by control ID or title
            # For simplicity, we return a placeholder
            evidence = {"note": "Evidence collection not implemented for this control"}

        return evidence

    # --- Evidence Collector Implementations ---
    # These are simplified examples. In reality, they would query the system, logs, etc.

    def _collect_access_control_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "AccessControl",
            "status": "placeholder",
            "details": "Would check ACLs, permissions on sensitive data"
        }

    def _collect_authentication_logs_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "AuthenticationLogs",
            "status": "placeholder",
            "details": "Would check logs for successful/failed authentications"
        }

    def _collect_user_accounts_evidence(self, host_name: str, host_ip: str) -> Dict:
        # Use existing inventory service to get user accounts
        try:
            inv_service = InventoryService({"_config_path": self.config_path})
            # We don't have the full config, so we'll simulate
            return {
                "control": "UserAccounts",
                "status": "collected_via_inventory",
                "details": "User account information from inventory service"
            }
        except Exception as e:
            return {"error": str(e)}

    def _collect_network_encryption_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "NetworkEncryption",
            "status": "placeholder",
            "details": "Would check for use of TLS/VPN for data in transit"
        }

    def _collect_transmission_logs_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "TransmissionLogs",
            "status": "placeholder",
            "details": "Would check logs for data transmission events"
        }

    def _collect_data_encryption_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "DataEncryption",
            "status": "placeholder",
            "details": "Would check for encryption of data at rest"
        }

    def _collect_pseudonymisation_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "Pseudonymisation",
            "status": "placeholder",
            "details": "Would check for pseudonymisation processes"
        }

    def _collect_system_integrity_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "SystemIntegrity",
            "status": "placeholder",
            "details": "Would check file integrity, antivirus, etc."
        }

    def _collect_backup_verification_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "BackupVerification",
            "status": "placeholder",
            "details": "Would check backup logs and verification reports"
        }

    def _collect_uptime_monitoring_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "UptimeMonitoring",
            "status": "placeholder",
            "details": "Would check system uptime and monitoring alerts"
        }

    def _collect_disaster_recovery_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "DisasterRecoveryTested",
            "status": "placeholder",
            "details": "Would check DR test records"
        }

    def _collect_backup_restore_timing_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "BackupRestoreTiming",
            "status": "placeholder",
            "details": "Would check timing of backup restore tests"
        }

    def _collect_firewall_config_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "FirewallConfigReview",
            "status": "placeholder",
            "details": "Would check firewall rule review documentation"
        }

    def _collect_default_password_evidence(self, host_name: str, host_ip: str) -> Dict:
        return {
            "control": "DefaultPasswordScan",
            "status": "placeholder",
            "details": "Would check for default credentials"
        }

    def generate_report(self, evidence: Dict, framework: str, format: str = "json") -> str:
        """
        Generate a compliance report for the specified framework.
        Supported formats: json, html, txt (placeholder for pdf)
        """
        if framework not in self.frameworks:
            raise ValueError(f"Unsupported framework: {framework}")

        if format == "json":
            return json.dumps(evidence, indent=2)
        elif format == "txt":
            return self._generate_text_report(evidence, framework)
        elif format == "html":
            return self._generate_html_report(evidence, framework)
        else:
            # Default to JSON
            return json.dumps(evidence, indent=2)

    def _generate_text_report(self, evidence: Dict, framework: str) -> str:
        lines = [
            f"Compliance Report - {framework}",
            f"Agent ID: {evidence.get('agent_id')}",
            f"Host: {evidence.get('host_name')}",
            f"Collected At: {evidence.get('collected_at')}",
            "=" * 50
        ]

        framework_data = evidence.get("frameworks", {}).get(framework, {})
        for control in framework_data.get("controls", []):
            lines.append(f"Control: {control.get('id')} - {control.get('title')}")
            lines.append(f"  Description: {control.get('description')}")
            lines.append(f"  Status: {control.get('status', 'unknown')}")
            if "subcontrols" in control:
                for sub in control["subcontrols"]:
                    lines.append(f"    Subcontrol: {sub.get('id')} - {sub.get('title')}")
                    lines.append(f"      Status: {sub.get('status', 'unknown')}")
                    lines.append(f"      Evidence: {sub.get('evidence', {})}")
            else:
                lines.append(f"  Evidence: {control.get('evidence', {})}")
            lines.append("")

        return "\n".join(lines)

    def _generate_html_report(self, evidence: Dict, framework: str) -> str:
        # Simple HTML report - in reality, we would use a template engine
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Compliance Report - {framework}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                .control {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 5px; }}
                .subcontrol {{ border-left: 3px solid #3498db; margin: 10px 0; padding: 10px; background-color: #f8f9fa; }}
                .status-passed {{ color: green; }}
                .status-failed {{ color: red; }}
                .status-placeholder {{ color: orange; }}
            </style>
        </head>
        <body>
            <h1>Compliance Report - {framework}</h1>
            <p><strong>Agent ID:</strong> {evidence.get('agent_id')}</p>
            <p><strong>Host:</strong> {evidence.get('host_name')}</p>
            <p><strong>Collected At:</strong> {evidence.get('collected_at')}</p>
            <hr>
        """

        framework_data = evidence.get("frameworks", {}).get(framework, {})
        for control in framework_data.get("controls", []):
            status_class = f"status-{control.get('status', 'placeholder')}"
            html += f"""
            <div class="control">
                <h2>Control: {control.get('id')} - {control.get('title')}</h2>
                <p><strong>Description:</strong> {control.get('description')}</p>
                <p><strong>Status:</strong> <span class="{status_class}">{control.get('status', 'unknown')}</span></p>
            """
            if "subcontrols" in control:
                for sub in control["subcontrols"]:
                    sub_status_class = f"status-{sub.get('status', 'placeholder')}"
                    html += f"""
                    <div class="subcontrol">
                        <h3>Subcontrol: {sub.get('id')} - {sub.get('title')}</h3>
                        <p><strong>Description:</strong> {sub.get('description')}</p>
                        <p><strong>Status:</strong> <span class="{sub_status_class}">{sub.get('status', 'unknown')}</span></p>
                        <p><strong>Evidence:</strong> <pre>{json.dumps(sub.get('evidence', {}), indent=2)}</pre></p>
                    </div>
                    """
            else:
                html += f"""
                <p><strong>Evidence:</strong> <pre>{json.dumps(control.get('evidence', {}), indent=2)}</pre></p>
                """
            html += "</div>"

        html += """
        </body>
        </html>
        """
        return html

    def get_dashboard_widgets(self, evidence: Dict) -> List[Dict]:
        """
        Generate data for dashboard widgets showing compliance posture.
        Returns a list of widget definitions that can be consumed by a frontend.
        """
        widgets = []

        # Overall compliance score widget
        total_controls = 0
        passed_controls = 0

        for framework_name, framework_data in evidence.get("frameworks", {}).items():
            for control in framework_data.get("controls", []):
                total_controls += 1
                # We'll consider a control passed if status is "collected" and no errors in evidence
                # This is a simplification
                if control.get("status") == "collected":
                    passed_controls += 1
                # Check subcontrols
                for sub in control.get("subcontrols", []):
                    total_controls += 1
                    if sub.get("status") == "collected":
                        passed_controls += 1

        compliance_percentage = (passed_controls / total_controls * 100) if total_controls > 0 else 0

        widgets.append({
            "widget_type": "metric",
            "title": "Overall Compliance Score",
            "value": f"{compliance_percentage:.1f}%",
            "status": "good" if compliance_percentage >= 80 else "warning" if compliance_percentage >= 60 else "critical",
            "description": f"Based on {passed_controls}/{total_controls} controls passing"
        })

        # Per framework scores
        for framework_name, framework_data in evidence.get("frameworks", {}).items():
            fw_total = 0
            fw_passed = 0
            for control in framework_data.get("controls", []):
                fw_total += 1
                if control.get("status") == "collected":
                    fw_passed += 1
                for sub in control.get("subcontrols", []):
                    fw_total += 1
                    if sub.get("status") == "collected":
                        fw_passed += 1
            fw_percentage = (fw_passed / fw_total * 100) if fw_total > 0 else 0

            widgets.append({
                "widget_type": "metric",
                "title": f"{framework_name} Compliance",
                "value": f"{fw_percentage:.1f}%",
                "status": "good" if fw_percentage >= 80 else "warning" if fw_percentage >= 60 else "critical",
                "description": f"Based on {fw_passed}/{fw_total} controls passing"
            })

        # Recent events widget (placeholder)
        widgets.append({
            "widget_type": "list",
            "title": "Recent Compliance Events",
            "items": [
                {"time": "5 minutes ago", "event": "Access control check passed"},
                {"time": "1 hour ago", "event": "Encryption verification completed"}
            ]
        })

        return widgets


# Example usage (for testing)
if __name__ == "__main__":
    # This would normally be called from the agent's main loop
    config_path = r"E:\Desarrollo\VANT-SIEM\VANT-Agent\config.yaml"  # Adjust as needed
    service = ComplianceService(config_path)

    # Get agent ID from inventory service or config
    agent_id = "test-agent-001"
    host_name, _ = detect_host()

    evidence = service.collect_evidence(agent_id, host_name, "")

    # Generate reports
    json_report = service.generate_report(evidence, "HIPAA", "json")
    print("JSON Report (first 500 chars):")
    print(json_report[:500])

    # Get dashboard widgets
    widgets = service.get_dashboard_widgets(evidence)
    print("\nDashboard Widgets:")
    for widget in widgets:
        print(f"- {widget['title']}: {widget['value']} ({widget['status']})")