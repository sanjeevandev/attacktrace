import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.models import (
    AttackIncident,
    AttackStep,
    EnrichedSecurityEvent,
    KillChainStage,
    MitigationAction,
    SeverityLevel,
    ThreatIntelData,
    UnifiedEvent,
)


class DatabaseManager:
    """
    Zero-configuration SQLite persistence manager for ATTACKTRACE.
    Stores events, enriched threat indicators, correlated incidents, attack graph steps,
    and atomic SOAR remediation actions.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is not None:
            self.db_path = db_path
        else:
            env_path = os.getenv("ATTACKTRACE_DB_PATH")
            if env_path:
                self.db_path = env_path
            else:
                default_dir = Path.home() / ".attacktrace"
                default_dir.mkdir(parents=True, exist_ok=True)
                self.db_path = str(default_dir / "attacktrace.db")

        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        # Configure Pragmas
        self._conn.execute("PRAGMA foreign_keys = ON;")
        if self.db_path != ":memory:":
            try:
                self._conn.execute("PRAGMA journal_mode = WAL;")
            except sqlite3.OperationalError:
                pass

        self._init_schema()

    @contextmanager
    def connection(self):
        with self._lock:
            yield self._conn

    def _init_schema(self) -> None:
        """
        Initializes schema migrations and applies pending migration versions.
        """
        with self.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                """
            )
            cursor = conn.execute("SELECT version FROM schema_migrations ORDER BY version ASC;")
            applied_versions = {row["version"] for row in cursor.fetchall()}

            # Migration Version 1: Core 6 tables and indices
            if 1 not in applied_versions:
                conn.executescript(
                    """
                    -- 1. Unified raw/canonical events
                    CREATE TABLE IF NOT EXISTS events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        user TEXT,
                        source_ip TEXT,
                        resource TEXT,
                        status INTEGER,
                        raw_payload TEXT NOT NULL,
                        is_demo INTEGER NOT NULL DEFAULT 0,
                        ingested_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_events_actor ON events(source_ip, user);
                    CREATE INDEX IF NOT EXISTS idx_events_is_demo ON events(is_demo);

                    -- 2. Enriched security event signatures
                    CREATE TABLE IF NOT EXISTS enriched_events (
                        event_id TEXT PRIMARY KEY REFERENCES events(event_id) ON DELETE CASCADE,
                        severity TEXT NOT NULL,
                        mitre_tactics TEXT NOT NULL,
                        mitre_techniques TEXT NOT NULL,
                        indicators TEXT NOT NULL,
                        risk_score INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_enriched_severity ON enriched_events(severity);
                    CREATE INDEX IF NOT EXISTS idx_enriched_risk ON enriched_events(risk_score);

                    -- 3. Correlated Attack Incidents
                    CREATE TABLE IF NOT EXISTS incidents (
                        incident_id TEXT PRIMARY KEY,
                        primary_actor_ip TEXT NOT NULL,
                        targeted_users TEXT NOT NULL,
                        start_time TEXT NOT NULL,
                        end_time TEXT NOT NULL,
                        overall_severity TEXT NOT NULL,
                        confidence_score INTEGER NOT NULL,
                        stages_detected TEXT NOT NULL,
                        threat_intel_json TEXT,
                        is_demo INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_incidents_actor ON incidents(primary_actor_ip);
                    CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(start_time, end_time);
                    CREATE INDEX IF NOT EXISTS idx_incidents_is_demo ON incidents(is_demo);

                    -- 4. Reconstructed Attack Steps (Kill-Chain Path & Root Cause)
                    CREATE TABLE IF NOT EXISTS attack_steps (
                        step_id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                        step_order INTEGER NOT NULL,
                        parent_step_id TEXT,
                        stage TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        technique TEXT NOT NULL,
                        description TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        risk_score INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_steps_incident ON attack_steps(incident_id, step_order);

                    -- 5. SOAR Mitigation Actions & Atomic Rollbacks
                    CREATE TABLE IF NOT EXISTS soar_actions (
                        action_id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                        action_type TEXT NOT NULL,
                        target TEXT NOT NULL,
                        command_snippet TEXT NOT NULL,
                        rollback_snippet TEXT NOT NULL,
                        rollback_token TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'SIMULATED',
                        created_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_soar_incident ON soar_actions(incident_id);
                    """
                )
                now_str = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?);",
                    (1, now_str),
                )
                conn.commit()

            # Migration Version 2: Inquiries table
            if 2 not in applied_versions:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS inquiries (
                        inquiry_id TEXT PRIMARY KEY,
                        full_name TEXT,
                        email TEXT,
                        organization TEXT,
                        inquiry_type TEXT,
                        log_volume TEXT,
                        message TEXT,
                        created_at TEXT
                    );
                    """
                )
                now_str = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?);",
                    (2, now_str),
                )
                conn.commit()

            # Ensure inquiries table exists
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS inquiries (
                    inquiry_id TEXT PRIMARY KEY,
                    full_name TEXT,
                    email TEXT,
                    organization TEXT,
                    inquiry_type TEXT,
                    log_volume TEXT,
                    message TEXT,
                    created_at TEXT
                );
                """
            )
            conn.commit()

    def save_events(self, events: List[UnifiedEvent], is_demo: bool = False) -> None:
        """
        Saves a batch of UnifiedEvents to the database.
        """
        if not events:
            return

        now_str = datetime.now(timezone.utc).isoformat()
        records = []
        for e in events:
            raw_payload_str = json.dumps(e.raw_payload) if isinstance(e.raw_payload, (dict, list)) else str(e.raw_payload or "")
            records.append((
                e.event_id,
                e.timestamp,
                e.source_type,
                e.event_type,
                e.user,
                e.source_ip,
                e.resource,
                e.status,
                raw_payload_str,
                1 if is_demo else 0,
                now_str,
            ))

        with self.connection() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO events (
                    event_id, timestamp, source_type, event_type, user, source_ip,
                    resource, status, raw_payload, is_demo, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                records,
            )
            conn.commit()

    def save_enriched_events(self, enriched_events: List[EnrichedSecurityEvent], is_demo: bool = False) -> None:
        """
        Saves enriched security events and their base events into the database.
        """
        if not enriched_events:
            return

        # 1. Save base events first
        base_events = [ee.base_event for ee in enriched_events]
        self.save_events(base_events, is_demo=is_demo)

        # 2. Save enrichment records
        records = []
        for ee in enriched_events:
            records.append((
                ee.base_event.event_id,
                ee.severity.name,
                json.dumps(ee.mitre_tactics),
                json.dumps(ee.mitre_techniques),
                json.dumps(ee.indicators),
                ee.risk_score,
            ))

        with self.connection() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO enriched_events (
                    event_id, severity, mitre_tactics, mitre_techniques, indicators, risk_score
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                records,
            )
            conn.commit()

    def save_incident(
        self,
        incident: AttackIncident,
        is_demo: bool = False,
        actions: Optional[List[MitigationAction]] = None,
    ) -> None:
        """
        Persists a correlated AttackIncident along with its steps and optional SOAR actions.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        threat_intel_json = json.dumps(incident.threat_intel.to_dict()) if incident.threat_intel else None

        with self.connection() as conn:
            # 1. Insert or replace incident record
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id, primary_actor_ip, targeted_users, start_time, end_time,
                    overall_severity, confidence_score, stages_detected, threat_intel_json,
                    is_demo, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    incident.incident_id,
                    incident.primary_actor_ip,
                    json.dumps(incident.targeted_users),
                    incident.start_time,
                    incident.end_time,
                    incident.overall_severity.name,
                    incident.confidence_score,
                    json.dumps([stage.name for stage in incident.stages_detected]),
                    threat_intel_json,
                    1 if is_demo else 0,
                    now_str,
                ),
            )

            # 2. Replace steps
            conn.execute("DELETE FROM attack_steps WHERE incident_id = ?;", (incident.incident_id,))
            step_records = []
            for idx, step in enumerate(incident.steps):
                step_records.append((
                    step.step_id,
                    incident.incident_id,
                    idx,
                    step.parent_step_id,
                    step.stage.name,
                    step.timestamp,
                    step.technique,
                    step.description,
                    step.actor,
                    step.risk_score,
                ))

            if step_records:
                conn.executemany(
                    """
                    INSERT INTO attack_steps (
                        step_id, incident_id, step_order, parent_step_id, stage,
                        timestamp, technique, description, actor, risk_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    step_records,
                )

            # 3. Save SOAR actions if provided
            if actions:
                conn.execute("DELETE FROM soar_actions WHERE incident_id = ?;", (incident.incident_id,))
                action_records = []
                for act in actions:
                    action_records.append((
                        act.action_id,
                        incident.incident_id,
                        act.action_type,
                        act.target,
                        act.command_snippet,
                        act.rollback_snippet,
                        act.rollback_token,
                        act.status,
                        now_str,
                    ))
                conn.executemany(
                    """
                    INSERT INTO soar_actions (
                        action_id, incident_id, action_type, target, command_snippet,
                        rollback_snippet, rollback_token, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    action_records,
                )

            conn.commit()

    def save_soar_actions(self, incident_id: str, actions: List[MitigationAction]) -> None:
        """
        Saves or updates SOAR actions for a specific incident.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        records = []
        for act in actions:
            records.append((
                act.action_id,
                incident_id,
                act.action_type,
                act.target,
                act.command_snippet,
                act.rollback_snippet,
                act.rollback_token,
                act.status,
                now_str,
            ))

        with self.connection() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO soar_actions (
                    action_id, incident_id, action_type, target, command_snippet,
                    rollback_snippet, rollback_token, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                records,
            )
            conn.commit()

    def get_soar_actions(self, incident_id: str) -> List[MitigationAction]:
        """
        Retrieves all mitigation actions recorded for an incident.
        """
        with self.connection() as conn:
            cursor = conn.execute(
                """
                SELECT action_id, action_type, target, command_snippet,
                       rollback_snippet, rollback_token, status
                FROM soar_actions
                WHERE incident_id = ?
                ORDER BY created_at ASC;
                """,
                (incident_id,),
            )
            actions = []
            for row in cursor.fetchall():
                actions.append(MitigationAction(
                    action_id=row["action_id"],
                    action_type=row["action_type"],
                    target=row["target"],
                    command_snippet=row["command_snippet"],
                    rollback_snippet=row["rollback_snippet"],
                    rollback_token=row["rollback_token"],
                    status=row["status"],
                ))
            return actions

    def get_incidents(
        self,
        limit: int = 50,
        is_demo: Optional[bool] = None,
    ) -> List[AttackIncident]:
        """
        Retrieves incidents from SQLite, optionally filtered by demo status.
        """
        query = "SELECT * FROM incidents"
        params: List[Any] = []

        if is_demo is not None:
            query += " WHERE is_demo = ?"
            params.append(1 if is_demo else 0)

        query += " ORDER BY start_time DESC LIMIT ?;"
        params.append(limit)

        incidents: List[AttackIncident] = []
        with self.connection() as conn:
            cursor = conn.execute(query, params)
            incident_rows = cursor.fetchall()

            for row in incident_rows:
                inc_id = row["incident_id"]

                # Fetch steps
                step_cursor = conn.execute(
                    """
                    SELECT step_id, step_order, parent_step_id, stage,
                           timestamp, technique, description, actor, risk_score
                    FROM attack_steps
                    WHERE incident_id = ?
                    ORDER BY step_order ASC;
                    """,
                    (inc_id,),
                )
                steps: List[AttackStep] = []
                for s_row in step_cursor.fetchall():
                    stage_name = s_row["stage"]
                    stage = KillChainStage[stage_name] if stage_name in KillChainStage.__members__ else KillChainStage.UNKNOWN
                    steps.append(AttackStep(
                        step_id=s_row["step_id"],
                        step_index=s_row["step_order"],
                        parent_step_id=s_row["parent_step_id"],
                        stage=stage,
                        timestamp=s_row["timestamp"],
                        technique=s_row["technique"],
                        description=s_row["description"],
                        actor=s_row["actor"],
                        risk_score=s_row["risk_score"],
                    ))

                # Deserialize threat intel
                threat_intel = None
                if row["threat_intel_json"]:
                    try:
                        ti_dict = json.loads(row["threat_intel_json"])
                        threat_intel = ThreatIntelData.from_dict(ti_dict)
                    except Exception:
                        pass

                # Parse stages
                stages_list = []
                try:
                    raw_stages = json.loads(row["stages_detected"])
                    for st in raw_stages:
                        if st in KillChainStage.__members__:
                            stages_list.append(KillChainStage[st])
                except Exception:
                    pass

                # Parse users
                try:
                    users = json.loads(row["targeted_users"])
                except Exception:
                    users = []

                sev_name = row["overall_severity"]
                severity = SeverityLevel[sev_name] if sev_name in SeverityLevel.__members__ else SeverityLevel.INFO

                inc = AttackIncident(
                    incident_id=inc_id,
                    primary_actor_ip=row["primary_actor_ip"],
                    targeted_users=users,
                    start_time=row["start_time"],
                    end_time=row["end_time"],
                    overall_severity=severity,
                    confidence_score=row["confidence_score"],
                    stages_detected=stages_list,
                    steps=steps,
                    threat_intel=threat_intel,
                )
                incidents.append(inc)

        return incidents

    def get_incident_by_id(self, incident_id: str) -> Optional[AttackIncident]:
        """
        Retrieves a single incident by ID. Returns None if not found.
        """
        with self.connection() as conn:
            cursor = conn.execute("SELECT * FROM incidents WHERE incident_id = ?;", (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None

            # Fetch steps
            step_cursor = conn.execute(
                """
                SELECT step_id, step_order, parent_step_id, stage,
                       timestamp, technique, description, actor, risk_score
                FROM attack_steps
                WHERE incident_id = ?
                ORDER BY step_order ASC;
                """,
                (incident_id,),
            )
            steps: List[AttackStep] = []
            for s_row in step_cursor.fetchall():
                stage_name = s_row["stage"]
                stage = KillChainStage[stage_name] if stage_name in KillChainStage.__members__ else KillChainStage.UNKNOWN
                steps.append(AttackStep(
                    step_id=s_row["step_id"],
                    step_index=s_row["step_order"],
                    parent_step_id=s_row["parent_step_id"],
                    stage=stage,
                    timestamp=s_row["timestamp"],
                    technique=s_row["technique"],
                    description=s_row["description"],
                    actor=s_row["actor"],
                    risk_score=s_row["risk_score"],
                ))

            # Deserialize threat intel
            threat_intel = None
            if row["threat_intel_json"]:
                try:
                    ti_dict = json.loads(row["threat_intel_json"])
                    threat_intel = ThreatIntelData.from_dict(ti_dict)
                except Exception:
                    pass

            stages_list = []
            try:
                raw_stages = json.loads(row["stages_detected"])
                for st in raw_stages:
                    if st in KillChainStage.__members__:
                        stages_list.append(KillChainStage[st])
            except Exception:
                pass

            try:
                users = json.loads(row["targeted_users"])
            except Exception:
                users = []

            sev_name = row["overall_severity"]
            severity = SeverityLevel[sev_name] if sev_name in SeverityLevel.__members__ else SeverityLevel.INFO

            return AttackIncident(
                incident_id=incident_id,
                primary_actor_ip=row["primary_actor_ip"],
                targeted_users=users,
                start_time=row["start_time"],
                end_time=row["end_time"],
                overall_severity=severity,
                confidence_score=row["confidence_score"],
                stages_detected=stages_list,
                steps=steps,
                threat_intel=threat_intel,
            )

    def clear_demo_data(self) -> Dict[str, int]:
        """
        Safely purges only records marked as is_demo = 1.
        Due to ON DELETE CASCADE, child steps and SOAR actions are removed automatically.
        Real forensic investigation records (is_demo = 0) are preserved intact.
        """
        with self.connection() as conn:
            cur_inc = conn.execute("DELETE FROM incidents WHERE is_demo = 1;")
            inc_deleted = cur_inc.rowcount

            cur_evt = conn.execute("DELETE FROM events WHERE is_demo = 1;")
            evt_deleted = cur_evt.rowcount

            conn.commit()
            return {
                "incidents_deleted": inc_deleted,
                "events_deleted": evt_deleted,
            }

    def get_stats(self) -> Dict[str, Any]:
        """
        Calculates aggregate security metrics directly via SQL.
        """
        with self.connection() as conn:
            cur_events = conn.execute("SELECT COUNT(*) AS cnt FROM events;")
            total_ingested = cur_events.fetchone()["cnt"]

            cur_incidents = conn.execute("SELECT COUNT(*) AS cnt FROM incidents;")
            total_incidents = cur_incidents.fetchone()["cnt"]

            cur_demo = conn.execute("SELECT COUNT(*) AS cnt FROM incidents WHERE is_demo = 1;")
            demo_incidents = cur_demo.fetchone()["cnt"]

            cur_real = conn.execute("SELECT COUNT(*) AS cnt FROM incidents WHERE is_demo = 0;")
            real_incidents = cur_real.fetchone()["cnt"]

            cur_risk = conn.execute("SELECT COALESCE(MAX(risk_score), 0) AS max_risk FROM enriched_events;")
            max_risk = cur_risk.fetchone()["max_risk"]

            cur_sev = conn.execute(
                """
                SELECT overall_severity, COUNT(*) AS count
                FROM incidents
                GROUP BY overall_severity;
                """
            )
            sev_dist: Dict[str, int] = {
                "INFO": 0,
                "LOW": 0,
                "MEDIUM": 0,
                "HIGH": 0,
                "CRITICAL": 0,
            }
            for row in cur_sev.fetchall():
                sev_dist[row["overall_severity"]] = row["count"]

            return {
                "total_ingested": total_ingested,
                "total_incidents": total_incidents,
                "demo_incidents": demo_incidents,
                "real_incidents": real_incidents,
                "max_risk": max_risk,
                "severity_distribution": sev_dist,
            }

    def save_inquiry(self, data: Dict[str, Any]) -> str:
        """
        Saves a commercial contact inquiry or demo request into the inquiries table.
        Returns the generated unique inquiry ticket ID.
        """
        inquiry_id = data.get("inquiry_id")
        if not inquiry_id:
            inquiry_id = f"INQ-{uuid.uuid4().hex[:8].upper()}"

        now_str = data.get("created_at") or datetime.now(timezone.utc).isoformat()
        full_name = data.get("full_name", "")
        email = data.get("email", "")
        organization = data.get("organization", "")
        inquiry_type = data.get("inquiry_type", "Request SOC Demo")
        log_volume = data.get("log_volume", "<1GB/day")
        message = data.get("message", "")

        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO inquiries (
                    inquiry_id, full_name, email, organization,
                    inquiry_type, log_volume, message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    inquiry_id,
                    full_name,
                    email,
                    organization,
                    inquiry_type,
                    log_volume,
                    message,
                    now_str,
                ),
            )
            conn.commit()

        return inquiry_id

    def get_inquiry(self, inquiry_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves an inquiry record by its ID.
        """
        with self.connection() as conn:
            cur = conn.execute("SELECT * FROM inquiries WHERE inquiry_id = ?;", (inquiry_id,))
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def get_inquiries(self) -> List[Dict[str, Any]]:
        """
        Retrieves all inquiries ordered by creation date descending.
        """
        with self.connection() as conn:
            cur = conn.execute("SELECT * FROM inquiries ORDER BY created_at DESC;")
            return [dict(row) for row in cur.fetchall()]

    def close(self) -> None:
        """
        Closes database connection.
        """
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
