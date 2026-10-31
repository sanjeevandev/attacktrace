from typing import Dict
from src.models import EnrichedSecurityEvent, SeverityLevel, UnifiedEvent
from src.mitre_mapper import MitreMapper

INDICATOR_WEIGHTS: Dict[str, int] = {
    "AUTH_FAILURE": 15,
    "SUSPICIOUS_WEB_RECON": 25,
    "FAILED_AUTH_BURST": 35,
    "SUSPICIOUS_SCRIPT_EXECUTION": 40,
    "ADMIN_CREDENTIAL_ACCESS": 45,
    "PERSISTENCE_MECHANISM": 50,
    "CREDENTIAL_STORE_ACCESS": 60,
    "SQL_INJECTION_PATTERN": 75,
    "UNAUTHORIZED_EXFILTRATION": 80,
    "PRIVILEGE_ESCALATION": 85,
}


class SecurityParser:
    def __init__(self) -> None:
        pass

    def parse(self, event: UnifiedEvent) -> EnrichedSecurityEvent:
        """
        Parses a UnifiedEvent, maps MITRE ATT&CK elements, computes risk score,
        and assigns a SeverityLevel.
        """
        # Map MITRE ATT&CK and indicators
        tactics, techniques, indicators = MitreMapper.map_event(event)

        # Compute risk score
        total_weight = sum(INDICATOR_WEIGHTS.get(ind, 10) for ind in indicators)
        risk_score = min(max(total_weight, 0), 100)

        # Map to SeverityLevel
        # INFO: 0-19, LOW: 20-39, MEDIUM: 40-69, HIGH: 70-89, CRITICAL: 90-100
        if risk_score <= 19:
            severity = SeverityLevel.INFO
        elif risk_score <= 39:
            severity = SeverityLevel.LOW
        elif risk_score <= 69:
            severity = SeverityLevel.MEDIUM
        elif risk_score <= 89:
            severity = SeverityLevel.HIGH
        else:
            severity = SeverityLevel.CRITICAL

        return EnrichedSecurityEvent(
            base_event=event,
            severity=severity,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            indicators=indicators,
            risk_score=risk_score,
        )
