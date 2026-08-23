import os
from typing import List
from src.models import AttackIncident, MitigationAction, SeverityLevel, KillChainStage


class PlaybookEngine:
    def generate_mitigations(self, incident: AttackIncident) -> List[MitigationAction]:
        """
        Evaluates the severity and stages of an incident.
        Generates structured firewall blocks, session terminations,
        and host isolations if threat thresholds are exceeded.
        """
        actions = []
        if incident.overall_severity not in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            return actions

        # 1. FIREWALL_BLOCK for external actor IPs
        actor_ip = incident.primary_actor_ip
        if actor_ip and actor_ip != "127.0.0.1" and actor_ip != "N/A":
            block_cmd = (
                f"sudo iptables -A INPUT -s {actor_ip} -j DROP && "
                f"sudo ufw deny from {actor_ip}"
            )
            actions.append(MitigationAction(
                action_type="FIREWALL_BLOCK",
                target=actor_ip,
                command_snippet=block_cmd,
                status="SIMULATED"
            ))

        # 2. SESSION_REVOKE for targeted usernames
        for user in incident.targeted_users:
            if user and user != "None":
                revoke_cmd = (
                    f"sudo pkill -u {user} || true && "
                    f"echo 'Sessions revoked for local user: {user}'"
                )
                actions.append(MitigationAction(
                    action_type="SESSION_REVOKE",
                    target=user,
                    command_snippet=revoke_cmd,
                    status="SIMULATED"
                ))

        # 3. ISOLATE_HOST if root privilege escalation or exfiltration has occurred
        has_escalation_or_exfil = any(
            stage in incident.stages_detected 
            for stage in [KillChainStage.PRIVILEGE_ESCALATION, KillChainStage.EXFILTRATION]
        )
        if has_escalation_or_exfil:
            isolate_cmd = "sudo ip link set dev eth0 down || sudo ifconfig eth0 down"
            actions.append(MitigationAction(
                action_type="ISOLATE_HOST",
                target="compromised_host",
                command_snippet=isolate_cmd,
                status="SIMULATED"
            ))

        return actions

    def export_mitigation_script(self, actions: List[MitigationAction], output_file: str = "mitigate.sh") -> str:
        """
        Compiles the list of mitigation actions into an executable shell script,
        complete with diagnostic outputs and commented rollback commands.
        """
        if not actions:
            script_content = "#!/bin/bash\n# No high/critical threat mitigation actions needed.\necho 'No mitigation actions needed.'\n"
        else:
            script_lines = [
                "#!/bin/bash",
                "# ===========================================================================",
                "# ATTACKTRACE AUTOMATED SOAR REMEDIATION PLAYBOOK",
                "# Generated Automatically by Layer 5 Mitigation Engine",
                "# ===========================================================================",
                "",
                "echo '[+] Starting ATTACKTRACE automated SOAR remediation...'",
                ""
            ]

            rollback_lines = [
                "",
                "# ===========================================================================",
                "# ROLLBACK PROCEDURES (To revert the applied mitigations)",
                "# ===========================================================================",
            ]

            for action in actions:
                script_lines.append(f"# Action Type: {action.action_type} on Target: {action.target}")
                script_lines.append(f"echo '[+] Executing {action.action_type} mitigation on {action.target}...'")
                script_lines.append(action.command_snippet)
                script_lines.append("")

                if action.action_type == "FIREWALL_BLOCK":
                    rollback_lines.append(
                        f"# Revert firewall block for {action.target}:\n"
                        f"# sudo iptables -D INPUT -s {action.target} -j DROP\n"
                        f"# sudo ufw delete deny from {action.target}"
                    )
                elif action.action_type == "ISOLATE_HOST":
                    rollback_lines.append(
                        f"# Revert host network isolation:\n"
                        f"# sudo ip link set dev eth0 up || sudo ifconfig eth0 up"
                    )
                elif action.action_type == "SESSION_REVOKE":
                    rollback_lines.append(
                        f"# Re-enable user access for {action.target}:\n"
                        f"# manual credential reset / account unlock required."
                    )
                rollback_lines.append("")

            script_lines.append("echo '[+] SOAR Remediation complete.'")
            script_lines.extend(rollback_lines)
            script_content = "\n".join(script_lines)

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(script_content)
            os.chmod(output_file, 0o755)  # nosec
        except Exception as e:
            print(f"Error exporting mitigation script to {output_file}: {e}")

        return script_content
