import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


@dataclass
class UnifiedEvent:
    timestamp: str
    source_type: str
    event_type: str
    raw_payload: Dict[str, Any]
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user: Optional[str] = None
    source_ip: Optional[str] = None
    resource: Optional[str] = None
    status: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict) -> "UnifiedEvent":
        """
        Validates presence and non-emptiness of timestamp, source_type, and event_type.
        Parses dict and returns a UnifiedEvent instance.
        Raises ValueError if validation fails.
        """
        if not data:
            raise ValueError("Record is empty or None")

        # Validate required fields
        for field_name in ["timestamp", "source_type", "event_type"]:
            val = data.get(field_name)
            if val is None or (isinstance(val, str) and not val.strip()):
                raise ValueError(f"Missing or empty required field: '{field_name}'")

        # Extract values
        timestamp = data.get("timestamp")
        source_type = data.get("source_type")
        event_type = data.get("event_type")
        
        # event_id: use existing one if present and valid, otherwise generate new UUIDv4
        event_id = data.get("event_id")
        if not event_id:
            event_id = str(uuid.uuid4())

        user = data.get("user")
        source_ip = data.get("source_ip")
        resource = data.get("resource")
        status = data.get("status")
        
        # raw_payload contains everything from raw log
        raw_payload = data.get("raw_payload") if "raw_payload" in data else data

        return cls(
            event_id=event_id,
            timestamp=timestamp,
            source_type=source_type,
            event_type=event_type,
            user=user,
            source_ip=source_ip,
            resource=resource,
            status=status,
            raw_payload=raw_payload,
        )

    def to_dict(self) -> dict:
        """
        Serializes the UnifiedEvent into a dictionary.
        """
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "event_type": self.event_type,
            "user": self.user,
            "source_ip": self.source_ip,
            "resource": self.resource,
            "status": self.status,
            "raw_payload": self.raw_payload,
        }


class SeverityLevel(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class EnrichedSecurityEvent:
    base_event: UnifiedEvent
    severity: SeverityLevel
    mitre_tactics: List[str]
    mitre_techniques: List[Dict[str, str]]
    indicators: List[str]
    risk_score: int

    def to_dict(self) -> dict:
        """
        Serializes the EnrichedSecurityEvent into a dictionary.
        """
        return {
            "base_event": self.base_event.to_dict(),
            "severity": self.severity.name,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "indicators": self.indicators,
            "risk_score": self.risk_score,
        }


class KillChainStage(Enum):
    RECONNAISSANCE = "RECONNAISSANCE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    EXFILTRATION = "EXFILTRATION"
    UNKNOWN = "UNKNOWN"


@dataclass
class AttackStep:
    stage: KillChainStage
    timestamp: str
    technique: str
    description: str
    actor: str
    risk_score: int

    def to_dict(self) -> dict:
        """
        Serializes the AttackStep into a dictionary.
        """
        return {
            "stage": self.stage.name,
            "timestamp": self.timestamp,
            "technique": self.technique,
            "description": self.description,
            "actor": self.actor,
            "risk_score": self.risk_score,
        }


@dataclass
class ThreatIntelData:
    ip: str
    reputation_score: int  # 0 to 100
    threat_actor_category: str  # "Scanner", "Tor Exit Node", "Known APT", "Clean"
    country: str
    is_tor_exit_node: bool

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "reputation_score": self.reputation_score,
            "threat_actor_category": self.threat_actor_category,
            "country": self.country,
            "is_tor_exit_node": self.is_tor_exit_node
        }


@dataclass
class MitigationAction:
    action_type: str  # "FIREWALL_BLOCK", "SESSION_REVOKE", "ISOLATE_HOST"
    target: str
    command_snippet: str
    status: str = "SIMULATED"  # "PENDING", "EXECUTED", "SIMULATED"
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target": self.target,
            "command_snippet": self.command_snippet,
            "status": self.status
        }


@dataclass
class AttackIncident:
    primary_actor_ip: str
    targeted_users: List[str]
    start_time: str
    end_time: str
    overall_severity: SeverityLevel
    confidence_score: int
    stages_detected: List[KillChainStage]
    steps: List[AttackStep]
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_intel: Optional[ThreatIntelData] = None

    def to_dict(self) -> dict:
        """
        Serializes the AttackIncident into a dictionary.
        """
        return {
            "incident_id": self.incident_id,
            "primary_actor_ip": self.primary_actor_ip,
            "targeted_users": self.targeted_users,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "overall_severity": self.overall_severity.name,
            "confidence_score": self.confidence_score,
            "stages_detected": [stage.name for stage in self.stages_detected],
            "steps": [step.to_dict() for step in self.steps],
            "threat_intel": self.threat_intel.to_dict() if self.threat_intel else None,
        }
