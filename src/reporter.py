import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.models import AttackIncident, MitigationAction, ThreatIntelData


class IncidentReporter:
    """
    Phase 6 — Forensic Reporting & Investigation Dossier Engine.

    Produces:
      1. Human-readable executive Markdown forensic reports
      2. Machine-readable forensic JSON dossiers (evidence packages)
      3. Official MITRE ATT&CK Navigator v4.5 layer files
    """

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _compute_duration(start_time: str, end_time: str) -> str:
        """
        Returns a human-readable duration string between two ISO-8601 timestamps.
        Falls back gracefully to 'N/A' on parse errors.
        """
        try:
            fmt_candidates = [
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
            ]
            start_dt: Optional[datetime] = None
            end_dt: Optional[datetime] = None
            for fmt in fmt_candidates:
                try:
                    start_dt = datetime.strptime(start_time, fmt)
                    end_dt = datetime.strptime(end_time, fmt)
                    break
                except ValueError:
                    continue
            if start_dt is None or end_dt is None:
                return "N/A"
            delta = end_dt - start_dt
            total_seconds = int(delta.total_seconds())
            if total_seconds < 0:
                return "N/A"
            minutes, seconds = divmod(total_seconds, 60)
            hours, minutes = divmod(minutes, 60)
            parts = []
            if hours:
                parts.append(f"{hours}h")
            if minutes:
                parts.append(f"{minutes}m")
            parts.append(f"{seconds}s")
            return " ".join(parts)
        except Exception:
            return "N/A"

    @staticmethod
    def _risk_to_navigator_color(risk_score: int) -> str:
        """Maps a 0-100 risk score to a hex colour for the Navigator layer."""
        if risk_score >= 80:
            return "#ff0000"  # Red — critical
        elif risk_score >= 60:
            return "#ff6600"  # Orange — high
        elif risk_score >= 40:
            return "#ffcc00"  # Yellow — medium
        elif risk_score >= 20:
            return "#66cc00"  # Light green — low
        return "#99ccff"      # Light blue — info

    # ------------------------------------------------------------------ #
    # 1. Enhanced Markdown Report
    # ------------------------------------------------------------------ #

    def generate_markdown_report(
        self,
        incident: AttackIncident,
        threat_data: ThreatIntelData,
        actions: List[MitigationAction],
        output_path: str = "INCIDENT_REPORT.md",
    ) -> str:
        """
        Generates a comprehensive forensic Markdown incident report containing:
        - Section 1: Executive Summary (with duration and blast radius)
        - Section 2: Threat Intelligence & Attribution
        - Section 3: Chronological Kill-Chain Audit Trail (with causality)
        - Section 4: Atomic SOAR Containment & Rollback Plan
        """
        # Severity badge
        severity_label = incident.overall_severity.name
        badge_color = (
            "red" if severity_label in ("CRITICAL", "HIGH")
            else "orange" if severity_label == "MEDIUM"
            else "green"
        )
        severity_badge = (
            f"![{severity_label}](https://img.shields.io/badge/"
            f"SEVERITY-{severity_label}-{badge_color})"
        )

        duration = self._compute_duration(incident.start_time, incident.end_time)
        blast_radius = (
            f"{len(incident.targeted_users)} user(s), "
            f"{len(incident.stages_detected)} kill-chain stage(s), "
            f"{len(incident.steps)} attack step(s)"
        )

        report_lines: List[str] = [
            "# ATTACKTRACE Forensic Incident Report",
            f"**Incident ID:** `{incident.incident_id}`  ",
            f"**Report Generated:** {incident.end_time}  ",
            f"**Classification Severity:** {severity_badge}",
            "",
            "## 1. Executive Summary",
            f"An automated threat campaign was detected and reconstructed from "
            f"the primary actor IP address **{incident.primary_actor_ip}**. ",
            f"The attack targeted system users "
            f"**{', '.join(incident.targeted_users) or 'None'}** and was active "
            f"between **{incident.start_time}** and **{incident.end_time}** "
            f"(duration: **{duration}**). ",
            f"The correlation engine reconstructed "
            f"**{len(incident.steps)} chronological attack steps** spanning "
            f"**{len(incident.stages_detected)} kill-chain stages** with a "
            f"security confidence rating of **{incident.confidence_score}%**.",
            f"**Blast Radius:** {blast_radius}",
            "",
            "## 2. Threat Intelligence & Attribution",
            f"- **Attacker IP Address:** `{threat_data.ip}`",
            f"- **Threat Reputation Rating:** "
            f"`{threat_data.reputation_score}/100` "
            f"(Verified Malicious if >75)",
            f"- **Threat Actor Classification:** "
            f"`{threat_data.threat_actor_category}`",
            f"- **Origin Country:** `{threat_data.country}`",
            f"- **Is Tor Proxy / Exit Node:** "
            f"`{'YES' if threat_data.is_tor_exit_node else 'NO'}`",
            "",
            "## 3. Chronological Kill-Chain Audit Trail",
            "The following steps outline the forensic audit trail of actor "
            "behavior mapped to the MITRE ATT&CK framework:",
            "",
            "| Step | Timestamp | Kill-Chain Stage | Technique ID & Name "
            "| Actor → Target | Causality | Risk |",
            "|---|---|---|---|---|---|---|",
        ]

        for idx, step in enumerate(incident.steps, start=1):
            parent_ref = (
                f"`{step.parent_step_id}`" if step.parent_step_id else "—"
            )
            target_users = ", ".join(incident.targeted_users) or "N/A"
            report_lines.append(
                f"| {idx} | `{step.timestamp}` | `{step.stage.name}` "
                f"| `{step.technique}` | {step.actor} → {target_users} "
                f"| {parent_ref} | `{step.risk_score}` |"
            )

        # Section 4 — SOAR Containment & Rollback
        report_lines.extend([
            "",
            "## 4. Atomic SOAR Containment & Rollback Plan",
            "The following immediate automated and manual remediation actions "
            "have been prepared:",
            "",
            "| Action ID | Mitigation Type | Target | Execution Snippet "
            "| Rollback Token | Rollback Command | Status |",
            "|---|---|---|---|---|---|---|",
        ])

        for action in actions:
            report_lines.append(
                f"| `{action.action_id}` | **{action.action_type}** "
                f"| `{action.target}` | `{action.command_snippet}` "
                f"| `{action.rollback_token}` | `{action.rollback_snippet}` "
                f"| `{action.status}` |"
            )

        report_lines.extend([
            "",
            "### Rollback Procedure Guidelines",
            "- **FIREWALL_BLOCK**: To unblock, execute the corresponding "
            "`-D` or `delete` rules in the generated script (`mitigate.sh`).",
            "- **ISOLATE_HOST**: Re-enable network interfaces manual commands "
            "(`ip link set dev eth0 up`).",
            "- **SESSION_REVOKE**: Require targeted administrators to run a "
            "credential reset before restarting their services.",
            "",
        ])

        report_content = "\n".join(report_lines)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report_content)
        except Exception as e:
            print(f"Error writing forensic report to {output_path}: {e}")

        return report_content

    # ------------------------------------------------------------------ #
    # 2. Forensic JSON Dossier
    # ------------------------------------------------------------------ #

    def generate_json_dossier(
        self,
        incident: AttackIncident,
        threat_data: ThreatIntelData,
        actions: List[MitigationAction],
        output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Serializes the entire incident story into a standardized JSON
        evidence package containing full provenance: raw telemetry references,
        enriched indicators, MITRE tactic matrix, threat intel snapshot,
        and cryptographic rollback tokens.
        """
        dossier: Dict[str, Any] = {
            "schema_version": "1.0",
            "incident_id": incident.incident_id,
            "primary_actor_ip": incident.primary_actor_ip,
            "targeted_users": list(incident.targeted_users),
            "start_time": incident.start_time,
            "end_time": incident.end_time,
            "duration": self._compute_duration(
                incident.start_time, incident.end_time
            ),
            "overall_severity": incident.overall_severity.name,
            "confidence_score": incident.confidence_score,
            "stages_detected": [s.name for s in incident.stages_detected],
            "kill_chain_steps": [step.to_dict() for step in incident.steps],
            "threat_intel": threat_data.to_dict(),
            "mitigations": [action.to_dict() for action in actions],
        }

        if output_path:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(dossier, f, indent=2, default=str)
            except Exception as e:
                print(
                    f"Error writing forensic JSON dossier to {output_path}: {e}"
                )

        return dossier

    # ------------------------------------------------------------------ #
    # 3. MITRE ATT&CK Navigator Layer (v4.5+)
    # ------------------------------------------------------------------ #

    def generate_navigator_layer(
        self,
        incident: AttackIncident,
        output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generates a valid MITRE ATT&CK Navigator (v4.5+ schema) JSON layer.

        Each technique observed in the incident is emitted with:
          - score: based on the maximum risk_score across steps using that technique
          - color: gradient mapped from risk_score
          - comment: describing the observed activity
        """
        # Aggregate techniques: keep highest risk and collect descriptions
        technique_map: Dict[str, Dict[str, Any]] = {}
        for step in incident.steps:
            # Technique string is formatted as "T1234 - Name" or just "T1234"
            tech_str = step.technique.strip()
            tech_id = tech_str.split(" - ")[0].strip() if " - " in tech_str else tech_str.split(" ")[0].strip()

            if tech_id not in technique_map:
                technique_map[tech_id] = {
                    "techniqueID": tech_id,
                    "score": step.risk_score,
                    "color": self._risk_to_navigator_color(step.risk_score),
                    "comment": step.description,
                    "enabled": True,
                }
            else:
                existing = technique_map[tech_id]
                if step.risk_score > existing["score"]:
                    existing["score"] = step.risk_score
                    existing["color"] = self._risk_to_navigator_color(
                        step.risk_score
                    )
                # Append additional observations
                if step.description and step.description not in existing["comment"]:
                    existing["comment"] += f"; {step.description}"

        layer: Dict[str, Any] = {
            "name": f"ATTACKTRACE Incident: {incident.incident_id}",
            "versions": {
                "attack": "14",
                "navigator": "4.5",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": (
                f"Auto-generated MITRE ATT&CK Navigator layer for incident "
                f"{incident.incident_id}. Severity: "
                f"{incident.overall_severity.name}, Confidence: "
                f"{incident.confidence_score}%."
            ),
            "sorting": 3,  # Sort descending by score
            "layout": {
                "layout": "side",
                "showID": True,
                "showName": True,
            },
            "techniques": list(technique_map.values()),
        }

        if output_path:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(layer, f, indent=2, default=str)
            except Exception as e:
                print(
                    f"Error writing Navigator layer to {output_path}: {e}"
                )

        return layer
