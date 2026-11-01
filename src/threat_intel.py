import json
import os
import ipaddress
from pathlib import Path
from typing import Optional
from src.models import ThreatIntelData, AttackIncident

def resolve_default_intel_db_path() -> str:
    candidates = [
        Path(__file__).resolve().parent / "data" / "mock_threat_intel.json",
        Path(__file__).resolve().parent.parent / "data" / "mock_threat_intel.json",
        Path.cwd() / "data" / "mock_threat_intel.json",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return str(Path(__file__).resolve().parent / "data" / "mock_threat_intel.json")

DEFAULT_INTEL_DB_PATH = resolve_default_intel_db_path()


class ThreatIntelEngine:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is not None and os.path.exists(str(db_path)):
            self.db_path = str(db_path)
        else:
            self.db_path = resolve_default_intel_db_path()
        self.database = {}
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self.database = json.load(f)
            except Exception as e:
                print(f"Error loading mock_threat_intel database: {e}")

    def is_private_ip(self, ip: str) -> bool:
        """
        Determines whether the given IP address is private (RFC1918), loopback, or link-local.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    def lookup_ip(self, ip: str) -> ThreatIntelData:
        """
        Queries the local database for IP reputation metrics.
        Applies heuristics to categorize private/internal address blocks safely.
        """
        if not ip or ip == "N/A":
            return ThreatIntelData(
                ip=ip or "N/A",
                reputation_score=0,
                threat_actor_category="Clean",
                country="Unknown",
                is_tor_exit_node=False
            )

        if ip in self.database:
            entry = self.database[ip]
            return ThreatIntelData(
                ip=ip,
                reputation_score=entry.get("reputation_score", 0),
                threat_actor_category=entry.get("threat_actor_category", "Clean"),
                country=entry.get("country", "Unknown"),
                is_tor_exit_node=entry.get("is_tor_exit_node", False)
            )

        if self.is_private_ip(ip):
            return ThreatIntelData(
                ip=ip,
                reputation_score=0,
                threat_actor_category="Clean",
                country="Private/Internal",
                is_tor_exit_node=False
            )

        # Default for other unknown public IPs
        return ThreatIntelData(
            ip=ip,
            reputation_score=15,
            threat_actor_category="Clean",
            country="Unknown",
            is_tor_exit_node=False
        )

    def enrich_incident(self, incident: AttackIncident) -> AttackIncident:
        """
        Resolves threat intel reputation data for the incident's primary actor IP
        and binds it to the incident object.
        """
        intel = self.lookup_ip(incident.primary_actor_ip)
        incident.threat_intel = intel
        return incident
