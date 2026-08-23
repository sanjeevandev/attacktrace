from typing import List
from src.models import AttackIncident, ThreatIntelData, MitigationAction


class IncidentReporter:
    def generate_markdown_report(
        self,
        incident: AttackIncident,
        threat_data: ThreatIntelData,
        actions: List[MitigationAction],
        output_path: str = "INCIDENT_REPORT.md"
    ) -> str:
        """
        Generates a comprehensive forensic Markdown incident report containing:
        - Executive Summary
        - Threat Intelligence Reputation Scores
        - Chronological Kill-Chain Matrix
        - Mitigation / SOAR command summaries
        - Rollback guidelines
        """
        # Determine Severity Color/Badge
        severity_label = incident.overall_severity.name
        badge_color = "red" if severity_label in ["CRITICAL", "HIGH"] else "orange" if severity_label == "MEDIUM" else "green"
        severity_badge = f"![{severity_label}](https://img.shields.io/badge/SEVERITY-{severity_label}-{badge_color})"

        report_lines = [
            f"# ATTACKTRACE Forensic Incident Report",
            f"**Incident ID:** `{incident.incident_id}`  ",
            f"**Report Generated:** {incident.end_time}  ",
            f"**Classification Severity:** {severity_badge}",
            "",
            "## 1. Executive Summary",
            f"An automated threat campaign was detected and reconstructed from the primary actor IP address **{incident.primary_actor_ip}**. ",
            f"The attack targeted system users **{', '.join(incident.targeted_users) or 'None'}** and was active between **{incident.start_time}** and **{incident.end_time}**. ",
            f"The correlation engine reconstructed **{len(incident.steps)} chronological attack steps** spanning **{len(incident.stages_detected)} kill-chain stages** with a security confidence rating of **{incident.confidence_score}%**.",
            "",
            "## 2. Threat Intel & Reputation Scoring",
            f"- **Attacker IP Address:** `{threat_data.ip}`",
            f"- **Threat Reputation Rating:** `{threat_data.reputation_score}/100` (Verified Malicious if >75)",
            f"- **Threat Actor Classification:** `{threat_data.threat_actor_category}`",
            f"- **Origin Country:** `{threat_data.country}`",
            f"- **Is Tor Proxy / Exit Node:** `{'YES' if threat_data.is_tor_exit_node else 'NO'}`",
            "",
            "## 3. Chronological Kill-Chain Reconstruction",
            "The following steps outline the forensic audit trail of actor behavior mapped to the MITRE ATT&CK framework:",
            "",
            "| Step | Timestamp | Kill-Chain Stage | Technique ID & Description | Mapped Details | Risk |",
            "|---|---|---|---|---|---|",
        ]

        for idx, step in enumerate(incident.steps, start=1):
            report_lines.append(
                f"| {idx} | `{step.timestamp}` | `{step.stage.name}` | `{step.technique}` | {step.description} | `{step.risk_score}` |"
            )

        report_lines.extend([
            "",
            "## 4. Recommended Mitigation Actions (SOAR)",
            "The following immediate automated and manual remediation actions have been prepared:",
            "",
            "| Action ID | Mitigation Type | Target | Execution Snippet | Status |",
            "|---|---|---|---|---|",
        ])

        for action in actions:
            report_lines.append(
                f"| `{action.action_id}` | **{action.action_type}** | `{action.target}` | `{action.command_snippet}` | `{action.status}` |"
            )

        report_lines.extend([
            "",
            "### Rollback Procedure Guidelines",
            "- **FIREWALL_BLOCK**: To unblock, execute the corresponding `-D` or `delete` rules in the generated script (`mitigate.sh`).",
            "- **ISOLATE_HOST**: Re-enable network interfaces manual commands (`ip link set dev eth0 up`).",
            "- **SESSION_REVOKE**: Require targeted administrators to run a credential reset before restarting their services.",
            ""
        ])

        # Import list type inside function to support typing definition
        from typing import List

        report_content = "\n".join(report_lines)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report_content)
        except Exception as e:
            print(f"Error writing forensic report to {output_path}: {e}")

        return report_content
