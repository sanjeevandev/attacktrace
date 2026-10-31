from typing import Any, Dict, List, Set, Tuple
from src.models import UnifiedEvent


class MitreMapper:
    @staticmethod
    def map_event(event: UnifiedEvent) -> Tuple[List[str], List[Dict[str, str]], List[str]]:
        """
        Evaluates a UnifiedEvent against security signature rules.
        Returns:
            (tactics_list, techniques_list, indicators_list)
        """
        tactics: Set[str] = set()
        techniques: List[Dict[str, str]] = []  # List of dicts to preserve order and uniqueness based on ID
        indicators: Set[str] = set()

        # Helper to check pattern in resource or payload
        resource_str = (event.resource or "").lower()
        payload_str = str(event.raw_payload or "").lower()
        user_str = (event.user or "").lower()

        def contains_any(patterns: List[str]) -> bool:
            return any(p in resource_str or p in payload_str for p in patterns)

        # 1. SQL Injection (SQLi)
        # Patterns: ' OR '1'='1, UNION SELECT, SQL comment with space, information_schema, ; DROP TABLE
        sqli_patterns = [
            "' or '1'='1", "union select", "-- ",
            "information_schema", "; drop table", "; select ", " or 1=1"
        ]
        if contains_any(sqli_patterns):
            tactics.add("Initial Access")
            tech = {"id": "T1190", "name": "Exploit Public-Facing Application"}
            if tech not in techniques:
                techniques.append(tech)
            indicators.add("SQL_INJECTION_PATTERN")

        # 2. Authentication Failure & Brute Force
        attempts = 1
        if isinstance(event.raw_payload, dict):
            attempts = (
                event.raw_payload.get("attempt")
                or event.raw_payload.get("attempts")
                or event.raw_payload.get("failed_attempts")
                or event.raw_payload.get("count")
                or 1
            )

        if event.status in [401, 403] or event.event_type in ["LOGIN_FAILED", "AUTH_FAILURE", "FAILED_AUTH_BURST"]:
            tactics.add("Credential Access")
            tech = {"id": "T1110", "name": "Brute Force"}
            if tech not in techniques:
                techniques.append(tech)

            if attempts >= 2 or event.event_type == "FAILED_AUTH_BURST":
                indicators.add("FAILED_AUTH_BURST")
            else:
                indicators.add("AUTH_FAILURE")

        # Admin Credential Access (Extra context based indicator from models description)
        if user_str == "root" or user_str == "admin":
            # If they are trying auth and it's root/admin, flag ADMIN_CREDENTIAL_ACCESS
            if event.source_type == "auth" or event.event_type in ["LOGIN_FAILED", "LOGIN_SUCCESS", "AUTH_FAILURE", "FAILED_AUTH_BURST"]:
                indicators.add("ADMIN_CREDENTIAL_ACCESS")

        # 3. Privilege Escalation
        # Sudo commands, su, /etc/sudoers, chmod 777, chmod +s, setuid, whoami /priv
        priv_esc_patterns = [
            "sudo ", "su -", "/etc/sudoers", "chmod 777",
            "chmod +s", "setuid", "whoami /priv"
        ]
        if contains_any(priv_esc_patterns):
            tactics.add("Privilege Escalation")
            tactics.add("Defense Evasion")
            tech_accounts = {"id": "T1078", "name": "Valid Accounts"}
            tech_elevation = {"id": "T1548", "name": "Abuse Elevation Control Mechanism"}
            if tech_accounts not in techniques:
                techniques.append(tech_accounts)
            if tech_elevation not in techniques:
                techniques.append(tech_elevation)
            indicators.add("PRIVILEGE_ESCALATION")

        # 4. Unauthorized Exfiltration / Access
        # Sensitive targets or large-scale bulk exfiltration
        exfil_patterns = [
            "/export", "select * from credentials", "select * from users",
            "credentials", "passwords", "tokens", "pg_dump"
        ]
        large_payload = False
        if isinstance(event.raw_payload, dict):
            rows_returned = event.raw_payload.get("rows_returned")
            if isinstance(rows_returned, (int, float)) and rows_returned >= 1000:
                large_payload = True
            payload_size = event.raw_payload.get("payload_size_bytes") or event.raw_payload.get("bytes_sent")
            if isinstance(payload_size, (int, float)) and payload_size > 1_000_000:
                large_payload = True

        if contains_any(exfil_patterns) or large_payload:
            tactics.add("Collection")
            tactics.add("Exfiltration")
            tech_collection = {"id": "T1005", "name": "Data from Local System"}
            tech_exfil = {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}
            if tech_collection not in techniques:
                techniques.append(tech_collection)
            if tech_exfil not in techniques:
                techniques.append(tech_exfil)
            indicators.add("UNAUTHORIZED_EXFILTRATION")

        # 5. Suspicious Web Recon
        # Endpoints like /.env, /wp-admin, /etc/passwd, /phpmyadmin
        recon_patterns = ["/.env", "/wp-admin", "/etc/passwd", "/phpmyadmin"]
        if contains_any(recon_patterns):
            tactics.add("Reconnaissance")
            tech = {"id": "T1595", "name": "Active Scanning"}
            if tech not in techniques:
                techniques.append(tech)
            indicators.add("SUSPICIOUS_WEB_RECON")

        # 6. Command & Scripting Execution (PowerShell, AppleScript, osascript)
        script_patterns = ["powershell", "-enc ", "encodedcommand", "osascript"]
        if contains_any(script_patterns):
            tactics.add("Execution")
            tech_exec = {"id": "T1059", "name": "Command and Scripting Interpreter"}
            if tech_exec not in techniques:
                techniques.append(tech_exec)
            indicators.add("SUSPICIOUS_SCRIPT_EXECUTION")

        # 7. Persistence (LaunchAgents, LaunchDaemons, etc.)
        persistence_patterns = ["launchagents", "launchdaemons", "/systemd/system"]
        if contains_any(persistence_patterns):
            tactics.add("Persistence")
            tech_persist = {"id": "T1543", "name": "Create or Modify System Process"}
            if tech_persist not in techniques:
                techniques.append(tech_persist)
            indicators.add("PERSISTENCE_MECHANISM")

        # 8. Credential Store Access (Keychain, NTDS.dit, lsass, mimikatz)
        cred_store_patterns = ["security find-generic-password", "keychain", "ntds.dit", "lsass", "mimikatz"]
        if contains_any(cred_store_patterns):
            tactics.add("Credential Access")
            tech_cred = {"id": "T1555", "name": "Credentials from Password Stores"}
            if tech_cred not in techniques:
                techniques.append(tech_cred)
            indicators.add("CREDENTIAL_STORE_ACCESS")

        return sorted(list(tactics)), techniques, sorted(list(indicators))
