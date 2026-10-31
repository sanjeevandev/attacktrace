import os
import platform as sys_platform
import secrets
from typing import Dict, List, Optional
from src.models import AttackIncident, MitigationAction, SeverityLevel, KillChainStage


class PlatformSOARAdapter:
    """
    Cross-platform handler generating OS-specific containment and atomic rollback commands
    for Windows (PowerShell), Linux (iptables/ufw), and macOS (pfctl).
    """

    @staticmethod
    def normalize_platform(platform_str: Optional[str]) -> str:
        if not platform_str or platform_str == "auto":
            sys_name = sys_platform.system().lower()
            if "win" in sys_name:
                return "windows"
            elif "darwin" in sys_name or "mac" in sys_name:
                return "macos"
            return "linux"
        p = platform_str.lower()
        if "win" in p:
            return "windows"
        elif "darwin" in p or "mac" in p:
            return "macos"
        return "linux"

    @staticmethod
    def generate_firewall_block(actor_ip: str, platform: str = "linux") -> Dict[str, str]:
        p = PlatformSOARAdapter.normalize_platform(platform)
        if p == "windows":
            rule_name = f"ATTACKTRACE_BLOCK_{actor_ip}"
            cmd = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Action Block -RemoteAddress {actor_ip}'
            rbk = f'Remove-NetFirewallRule -DisplayName "{rule_name}"'
        elif p == "macos":
            cmd = f'echo "block drop from {actor_ip} to any" | sudo pfctl -a attacktrace -f -'
            rbk = 'sudo pfctl -a attacktrace -F rules'
        else:  # linux
            cmd = f"sudo iptables -A INPUT -s {actor_ip} -j DROP && sudo ufw deny from {actor_ip}"
            rbk = f"sudo iptables -D INPUT -s {actor_ip} -j DROP && sudo ufw delete deny from {actor_ip}"
        return {"command": cmd, "rollback": rbk}

    @staticmethod
    def generate_session_revoke(username: str, platform: str = "linux") -> Dict[str, str]:
        p = PlatformSOARAdapter.normalize_platform(platform)
        if p == "windows":
            cmd = f'Get-Process -IncludeUserName | Where-Object {{ $_.UserName -like "*{username}" }} | Stop-Process -Force'
            rbk = f'Write-Host "Manual account unlock required for: {username}"'
        else:  # linux & macos
            cmd = f"sudo pkill -u {username} || true"
            rbk = f'echo "Account credential reset required for: {username}"'
        return {"command": cmd, "rollback": rbk}

    @staticmethod
    def generate_host_isolation(platform: str = "linux") -> Dict[str, str]:
        p = PlatformSOARAdapter.normalize_platform(platform)
        if p == "windows":
            cmd = 'Disable-NetAdapter -Name "*" -Confirm:$false'
            rbk = 'Enable-NetAdapter -Name "*"'
        elif p == "macos":
            cmd = "sudo ifconfig en0 down"
            rbk = "sudo ifconfig en0 up"
        else:  # linux
            cmd = "sudo ip link set dev eth0 down || sudo ifconfig eth0 down"
            rbk = "sudo ip link set dev eth0 up || sudo ifconfig eth0 up"
        return {"command": cmd, "rollback": rbk}


class PlaybookEngine:
    """
    Automated cross-platform SOAR orchestration engine.
    Generates OS-specific containment actions with matching atomic rollback procedures
    and strictly enforces simulation safety.
    """

    def generate_mitigations(
        self,
        incident: AttackIncident,
        platform: str = "auto",
    ) -> List[MitigationAction]:
        """
        Evaluates the severity and stages of an incident.
        Generates structured firewall blocks, session terminations,
        and host isolations targeting the specified platform.
        Every action includes an atomic rollback twin and unique rollback token.
        """
        actions: List[MitigationAction] = []
        if incident.overall_severity not in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            return actions

        target_platform = PlatformSOARAdapter.normalize_platform(platform)

        # 1. FIREWALL_BLOCK for external actor IPs
        actor_ip = incident.primary_actor_ip
        if actor_ip and actor_ip != "127.0.0.1" and actor_ip != "N/A":
            fw = PlatformSOARAdapter.generate_firewall_block(actor_ip, target_platform)
            rbk_token = f"RBK-{secrets.token_hex(4).upper()}"
            actions.append(MitigationAction(
                action_type="FIREWALL_BLOCK",
                target=actor_ip,
                command_snippet=fw["command"],
                rollback_snippet=fw["rollback"],
                rollback_token=rbk_token,
                status="SIMULATED",
            ))

        # 2. SESSION_REVOKE for targeted usernames
        for user in incident.targeted_users:
            if user and user != "None":
                sess = PlatformSOARAdapter.generate_session_revoke(user, target_platform)
                rbk_token = f"RBK-{secrets.token_hex(4).upper()}"
                actions.append(MitigationAction(
                    action_type="SESSION_REVOKE",
                    target=user,
                    command_snippet=sess["command"],
                    rollback_snippet=sess["rollback"],
                    rollback_token=rbk_token,
                    status="SIMULATED",
                ))

        # 3. ISOLATE_HOST if privilege escalation or exfiltration has occurred
        has_escalation_or_exfil = any(
            stage in incident.stages_detected
            for stage in [KillChainStage.PRIVILEGE_ESCALATION, KillChainStage.EXFILTRATION]
        )
        if has_escalation_or_exfil:
            iso = PlatformSOARAdapter.generate_host_isolation(target_platform)
            rbk_token = f"RBK-{secrets.token_hex(4).upper()}"
            actions.append(MitigationAction(
                action_type="ISOLATE_HOST",
                target="compromised_host",
                command_snippet=iso["command"],
                rollback_snippet=iso["rollback"],
                rollback_token=rbk_token,
                status="SIMULATED",
            ))

        return actions

    def export_mitigation_script(
        self,
        actions: List[MitigationAction],
        output_file: str = "mitigate.sh",
        platform: str = "auto",
    ) -> str:
        """
        Compiles the list of mitigation actions into an executable script (.sh or .ps1)
        complete with diagnostic outputs, safety comments, and rollback instructions.
        """
        target_p = PlatformSOARAdapter.normalize_platform(platform)
        is_ps1 = output_file.endswith(".ps1") or target_p == "windows"

        if not actions:
            if is_ps1:
                script_content = "# No high/critical threat mitigation actions needed.\nWrite-Host 'No mitigation actions needed.'\n"
            else:
                script_content = "#!/bin/bash\n# No high/critical threat mitigation actions needed.\necho 'No mitigation actions needed.'\n"
        else:
            if is_ps1:
                lines = [
                    "# ===========================================================================",
                    "# ATTACKTRACE AUTOMATED SOAR REMEDIATION PLAYBOOK (WINDOWS POWERSHELL)",
                    "# Generated Automatically by Layer 5 Mitigation Engine (SIMULATION ONLY)",
                    "# ===========================================================================",
                    "",
                    "Write-Host '[+] Starting ATTACKTRACE automated SOAR remediation (SIMULATION)...'",
                    "",
                ]
                rollback_lines = [
                    "",
                    "# ===========================================================================",
                    "# ROLLBACK PROCEDURES (To revert applied mitigations)",
                    "# ===========================================================================",
                ]
                for action in actions:
                    lines.append(f"# Action Type: {action.action_type} on Target: {action.target} [Token: {action.rollback_token}]")
                    lines.append(f"Write-Host '[+] Executing {action.action_type} mitigation on {action.target}...'")
                    lines.append(action.command_snippet)
                    lines.append("")

                    rollback_lines.append(f"# Rollback {action.action_type} on {action.target} [Token: {action.rollback_token}]:")
                    rollback_lines.append(f"# {action.rollback_snippet}")
                    rollback_lines.append("")

                lines.append("Write-Host '[+] SOAR Remediation complete.'")
                lines.extend(rollback_lines)
                script_content = "\n".join(lines)
            else:
                lines = [
                    "#!/bin/bash",
                    "# ===========================================================================",
                    "# ATTACKTRACE AUTOMATED SOAR REMEDIATION PLAYBOOK",
                    "# Generated Automatically by Layer 5 Mitigation Engine (SIMULATION ONLY)",
                    "# ===========================================================================",
                    "",
                    "echo '[+] Starting ATTACKTRACE automated SOAR remediation (SIMULATION)...'",
                    "",
                ]
                rollback_lines = [
                    "",
                    "# ===========================================================================",
                    "# ROLLBACK PROCEDURES (To revert the applied mitigations)",
                    "# ===========================================================================",
                ]
                for action in actions:
                    lines.append(f"# Action Type: {action.action_type} on Target: {action.target} [Token: {action.rollback_token}]")
                    lines.append(f"echo '[+] Executing {action.action_type} mitigation on {action.target}...'")
                    lines.append(action.command_snippet)
                    lines.append("")

                    rollback_lines.append(f"# Rollback {action.action_type} for {action.target} [Token: {action.rollback_token}]:")
                    rollback_lines.append(f"# {action.rollback_snippet}")
                    rollback_lines.append("")

                lines.append("echo '[+] SOAR Remediation complete.'")
                lines.extend(rollback_lines)
                script_content = "\n".join(lines)

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(script_content)
            if hasattr(os, "chmod") and os.name != "nt":
                os.chmod(output_file, 0o755)  # nosec
        except Exception as e:
            print(f"Error exporting mitigation script to {output_file}: {e}")

        return script_content

    def export_rollback_script(
        self,
        actions: List[MitigationAction],
        output_file: str = "rollback.sh",
        platform: str = "auto",
    ) -> str:
        """
        Compiles the corresponding reverse rollback script (.sh or .ps1)
        using the atomic rollback snippets.
        """
        target_p = PlatformSOARAdapter.normalize_platform(platform)
        is_ps1 = output_file.endswith(".ps1") or target_p == "windows"

        if not actions:
            if is_ps1:
                script_content = "# No mitigation actions to roll back.\nWrite-Host 'No mitigation actions to roll back.'\n"
            else:
                script_content = "#!/bin/bash\n# No mitigation actions to roll back.\necho 'No mitigation actions to roll back.'\n"
        else:
            # Rollback in reverse order of application
            rev_actions = list(reversed(actions))
            if is_ps1:
                lines = [
                    "# ===========================================================================",
                    "# ATTACKTRACE ATOMIC SOAR ROLLBACK PLAYBOOK (WINDOWS POWERSHELL)",
                    "# Generated Automatically by Layer 5 Mitigation Engine",
                    "# ===========================================================================",
                    "",
                    "Write-Host '[+] Starting ATTACKTRACE atomic SOAR rollback...'",
                    "",
                ]
                for action in rev_actions:
                    lines.append(f"# Reverting {action.action_type} on {action.target} [Token: {action.rollback_token}]")
                    lines.append(f"Write-Host '[+] Reverting {action.action_type} on {action.target}...'")
                    lines.append(action.rollback_snippet)
                    lines.append("")

                lines.append("Write-Host '[+] Atomic SOAR Rollback complete.'")
                script_content = "\n".join(lines)
            else:
                lines = [
                    "#!/bin/bash",
                    "# ===========================================================================",
                    "# ATTACKTRACE ATOMIC SOAR ROLLBACK PLAYBOOK",
                    "# Generated Automatically by Layer 5 Mitigation Engine",
                    "# ===========================================================================",
                    "",
                    "echo '[+] Starting ATTACKTRACE atomic SOAR rollback...'",
                    "",
                ]
                for action in rev_actions:
                    lines.append(f"# Reverting {action.action_type} for {action.target} [Token: {action.rollback_token}]")
                    lines.append(f"echo '[+] Reverting {action.action_type} on {action.target}...'")
                    lines.append(action.rollback_snippet)
                    lines.append("")

                lines.append("echo '[+] Atomic SOAR Rollback complete.'")
                script_content = "\n".join(lines)

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(script_content)
            if hasattr(os, "chmod") and os.name != "nt":
                os.chmod(output_file, 0o755)  # nosec
        except Exception as e:
            print(f"Error exporting rollback script to {output_file}: {e}")

        return script_content
