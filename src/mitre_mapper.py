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
        # Patterns: ' OR '1'='1, UNION SELECT, --, information_schema
        sqli_patterns = ["' or '1'='1", "union select", "--", "information_schema"]
        if contains_any(sqli_patterns):
            tactics.add("Initial Access")
            tech = {"id": "T1190", "name": "Exploit Public-Facing Application"}
            if tech not in techniques:
                techniques.append(tech)
            indicators.add("SQL_INJECTION_PATTERN")

        # 2. Authentication Brute Force
        # Status 401/403 or LOGIN_FAILED
        if event.status in [401, 403] or event.event_type == "LOGIN_FAILED":
            tactics.add("Credential Access")
            tech = {"id": "T1110", "name": "Brute Force"}
            if tech not in techniques:
                techniques.append(tech)
            indicators.add("FAILED_AUTH_BURST")

        # Admin Credential Access (Extra context based indicator from models description)
        if user_str == "root" or user_str == "admin":
            # If they are trying auth and it's root/admin, flag ADMIN_CREDENTIAL_ACCESS
            if event.source_type == "auth" or event.event_type in ["LOGIN_FAILED", "LOGIN_SUCCESS"]:
                indicators.add("ADMIN_CREDENTIAL_ACCESS")

        # 3. Privilege Escalation
        # Sudo commands, root user activity, /etc/sudoers, chmod 777
        priv_esc_patterns = ["sudo ", "/etc/sudoers", "chmod 777"]
        if user_str == "root" or contains_any(priv_esc_patterns):
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
        # /export, SELECT * FROM credentials/users, large payloads (e.g. database rows_returned > 10)
        exfil_patterns = ["/export", "select * from credentials", "select * from users"]
        # Large payload indicator detection based on rows_returned or similar keys
        large_payload = False
        if isinstance(event.raw_payload, dict):
            # Check rows returned or payload sizes
            rows_returned = event.raw_payload.get("rows_returned")
            if isinstance(rows_returned, (int, float)) and rows_returned >= 10:
                large_payload = True
            response_time = event.raw_payload.get("response_time_ms")
            if isinstance(response_time, (int, float)) and response_time > 500:
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

        return sorted(list(tactics)), techniques, sorted(list(indicators))
