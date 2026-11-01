import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.db import DatabaseManager
from src.models import AttackIncident
from src.pipeline import AttackTracePipeline
from src.threat_intel import ThreatIntelEngine

def resolve_default_scenarios_dir() -> Path:
    candidates = [
        Path(__file__).resolve().parent / "data" / "scenarios",
        Path(__file__).resolve().parent.parent / "data" / "scenarios",
        Path.cwd() / "data" / "scenarios",
    ]
    for c in candidates:
        if c.exists() and any(c.glob("*.json")):
            return c
    return Path(__file__).resolve().parent / "data" / "scenarios"

DEFAULT_SCENARIOS_DIR = resolve_default_scenarios_dir()

SCENARIO_METADATA: Dict[str, Dict[str, str]] = {
    "windows_ad_compromise": {
        "platform": "Windows",
        "description": "Active Directory Kerberoasting, RDP access, PowerShell execution, token elevation, and NTDS credential dump",
    },
    "linux_server_breach": {
        "platform": "Linux",
        "description": "Web reconnaissance, SQL injection vulnerability exploitation, sudoers privilege escalation, and table exfiltration",
    },
    "macos_endpoint_intrusion": {
        "platform": "macOS",
        "description": "Phishing AppleScript execution, LaunchAgents persistence mechanism, Keychain extraction, and outbound exfiltration",
    },
}


class ScenarioManager:
    """
    Manages loading, execution, and cleanup of multi-platform synthetic scenarios.
    Allows repeatable demonstrations and end-to-end testing without victim infrastructure.
    """

    def __init__(self, scenarios_dir: Optional[Union[str, Path]] = None) -> None:
        if scenarios_dir is not None and Path(scenarios_dir).exists():
            self.scenarios_dir = Path(scenarios_dir)
        else:
            self.scenarios_dir = resolve_default_scenarios_dir()
        self.threat_intel_engine = ThreatIntelEngine()

    def list_available_scenarios(self) -> List[Dict[str, Any]]:
        """
        Discovers all available scenario datasets in the scenarios directory
        and returns descriptive metadata for each.
        """
        results: List[Dict[str, Any]] = []
        if not self.scenarios_dir.exists():
            return results

        for path in sorted(self.scenarios_dir.glob("*.json")):
            base_name = path.stem
            meta = SCENARIO_METADATA.get(base_name, {})
            platform = meta.get("platform", "Cross-Platform")
            description = meta.get("description", f"Synthetic scenario: {base_name}")

            event_count = 0
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        event_count = len(data)
            except Exception:
                pass

            results.append({
                "name": base_name,
                "platform": platform,
                "description": description,
                "event_count": event_count,
                "file_path": str(path),
            })

        return results

    def load_scenario(self, scenario_name: str) -> List[Dict[str, Any]]:
        """
        Loads the specified scenario dataset by name (with or without .json extension).
        Ensures each record carries is_demo = True.
        Raises FileNotFoundError if not found.
        """
        clean_name = scenario_name[:-5] if scenario_name.endswith(".json") else scenario_name
        file_path = self.scenarios_dir / f"{clean_name}.json"

        if not file_path.exists():
            raise FileNotFoundError(f"Scenario dataset not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            records = json.load(f)

        if not isinstance(records, list):
            raise ValueError(f"Scenario dataset in {file_path} must be a JSON array of events")

        # Explicitly enforce is_demo = True for demo isolation
        for rec in records:
            if isinstance(rec, dict):
                rec["is_demo"] = True
                if "raw_payload" in rec and isinstance(rec["raw_payload"], dict):
                    rec["raw_payload"]["is_demo"] = True

        return records

    def run_scenario(
        self,
        scenario_name: str,
        db: Optional[DatabaseManager] = None,
    ) -> List[AttackIncident]:
        """
        Runs the full detection pipeline on the chosen scenario:
        1. Ingests raw logs
        2. Enriches threat indicators & MITRE ATT&CK techniques
        3. Correlates events into AttackIncidents
        4. Enriches incidents with threat intelligence
        5. Persists to database with is_demo=True if db is provided
        """
        records = self.load_scenario(scenario_name)
        pipeline = AttackTracePipeline(db=db)

        # Execute full 3-layer pipeline
        incidents = pipeline.run_pipeline_list(records, is_demo=True)

        # Layer 4: Threat Intelligence resolution
        for inc in incidents:
            self.threat_intel_engine.enrich_incident(inc)
            if db:
                db.save_incident(inc, is_demo=True)

        return incidents

    def reset_demo_state(self, db: DatabaseManager) -> Dict[str, int]:
        """
        Safely purges synthetic demo records from the database while preserving real records.
        """
        return db.clear_demo_data()
