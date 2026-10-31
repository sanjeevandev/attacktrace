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

    @classmethod
    def from_dict(cls, data: dict) -> "EnrichedSecurityEvent":
        sev = data.get("severity", "INFO")
        severity = SeverityLevel[sev] if isinstance(sev, str) and sev in SeverityLevel.__members__ else SeverityLevel.INFO
        return cls(
            base_event=UnifiedEvent.from_dict(data["base_event"]),
            severity=severity,
            mitre_tactics=data.get("mitre_tactics", []),
            mitre_techniques=data.get("mitre_techniques", []),
            indicators=data.get("indicators", []),
            risk_score=data.get("risk_score", 0),
        )


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
    step_index: int = 0
    parent_step_id: Optional[str] = None
    step_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        """
        Serializes the AttackStep into a dictionary.
        """
        return {
            "step_id": self.step_id,
            "step_index": self.step_index,
            "parent_step_id": self.parent_step_id,
            "stage": self.stage.name,
            "timestamp": self.timestamp,
            "technique": self.technique,
            "description": self.description,
            "actor": self.actor,
            "risk_score": self.risk_score,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttackStep":
        stage_val = data.get("stage", "UNKNOWN")
        stage = KillChainStage[stage_val] if isinstance(stage_val, str) and stage_val in KillChainStage.__members__ else KillChainStage.UNKNOWN
        return cls(
            stage=stage,
            timestamp=data.get("timestamp", ""),
            technique=data.get("technique", ""),
            description=data.get("description", ""),
            actor=data.get("actor", ""),
            risk_score=data.get("risk_score", 0),
            step_index=data.get("step_index", 0),
            parent_step_id=data.get("parent_step_id"),
            step_id=data.get("step_id", str(uuid.uuid4())),
        )


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

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatIntelData":
        return cls(
            ip=data.get("ip", ""),
            reputation_score=data.get("reputation_score", 0),
            threat_actor_category=data.get("threat_actor_category", "Clean"),
            country=data.get("country", "Unknown"),
            is_tor_exit_node=data.get("is_tor_exit_node", False),
        )


@dataclass
class MitigationAction:
    action_type: str  # "FIREWALL_BLOCK", "SESSION_REVOKE", "ISOLATE_HOST"
    target: str
    command_snippet: str
    status: str = "SIMULATED"  # "PENDING", "EXECUTED", "SIMULATED"
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rollback_snippet: str = ""
    rollback_token: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target": self.target,
            "command_snippet": self.command_snippet,
            "status": self.status,
            "rollback_snippet": self.rollback_snippet,
            "rollback_token": self.rollback_token,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MitigationAction":
        return cls(
            action_type=data.get("action_type", ""),
            target=data.get("target", ""),
            command_snippet=data.get("command_snippet", ""),
            status=data.get("status", "SIMULATED"),
            action_id=data.get("action_id", str(uuid.uuid4())),
            rollback_snippet=data.get("rollback_snippet", ""),
            rollback_token=data.get("rollback_token", str(uuid.uuid4())),
        )


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

    @classmethod
    def from_dict(cls, data: dict) -> "AttackIncident":
        sev_val = data.get("overall_severity", "INFO")
        severity = SeverityLevel[sev_val] if isinstance(sev_val, str) and sev_val in SeverityLevel.__members__ else SeverityLevel.INFO

        stages: List[KillChainStage] = []
        for s in data.get("stages_detected", []):
            if isinstance(s, str) and s in KillChainStage.__members__:
                stages.append(KillChainStage[s])
            elif isinstance(s, KillChainStage):
                stages.append(s)

        steps: List[AttackStep] = []
        for st in data.get("steps", []):
            if isinstance(st, dict):
                steps.append(AttackStep.from_dict(st))
            elif isinstance(st, AttackStep):
                steps.append(st)

        threat_intel = None
        ti_data = data.get("threat_intel")
        if isinstance(ti_data, dict):
            threat_intel = ThreatIntelData.from_dict(ti_data)
        elif isinstance(ti_data, ThreatIntelData):
            threat_intel = ti_data

        return cls(
            primary_actor_ip=data.get("primary_actor_ip", "Unknown"),
            targeted_users=list(data.get("targeted_users", [])),
            start_time=data.get("start_time", ""),
            end_time=data.get("end_time", ""),
            overall_severity=severity,
            confidence_score=int(data.get("confidence_score", 0)),
            stages_detected=stages,
            steps=steps,
            incident_id=data.get("incident_id", str(uuid.uuid4())),
            threat_intel=threat_intel,
        )
