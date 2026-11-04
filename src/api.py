import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
import re
from pydantic import BaseModel, Field, field_validator

from src.pipeline import AttackTracePipeline
from src.visualizer import GraphVisualizer
from src.websocket_manager import ConnectionManager
from src.models import UnifiedEvent
from src.threat_intel import ThreatIntelEngine
from src.playbooks import PlaybookEngine, PlatformSOARAdapter
from src.reporter import IncidentReporter

from src.db import DatabaseManager
from src.demo_manager import ScenarioManager

BASE_DIR = Path(__file__).resolve().parent.parent

# In-memory pipeline, database manager, and Layer 5 engine instances
db_manager = DatabaseManager()
pipeline = AttackTracePipeline(db=db_manager)
visualizer = GraphVisualizer()
ws_manager = ConnectionManager()
ti_engine = ThreatIntelEngine()
playbook_engine = PlaybookEngine()
reporter = IncidentReporter()
scenario_manager = ScenarioManager()

def resolve_default_scenario_path() -> str:
    candidates = [
        Path(__file__).resolve().parent / "data" / "attack_scenario.json",
        Path(__file__).resolve().parent.parent / "data" / "attack_scenario.json",
        Path.cwd() / "data" / "attack_scenario.json",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return str(Path(__file__).resolve().parent / "data" / "attack_scenario.json")

def resolve_template_path() -> Path:
    candidates = [
        Path(__file__).resolve().parent / "templates" / "dashboard.html",
        Path(__file__).resolve().parent.parent / "templates" / "dashboard.html",
        Path.cwd() / "templates" / "dashboard.html",
    ]
    for c in candidates:
        if c.exists():
            return c
    return Path(__file__).resolve().parent / "templates" / "dashboard.html"


def resolve_contact_template_path() -> Path:
    candidates = [
        Path(__file__).resolve().parent / "templates" / "contact.html",
        Path(__file__).resolve().parent.parent / "templates" / "contact.html",
        Path.cwd() / "templates" / "contact.html",
    ]
    for c in candidates:
        if c.exists():
            return c
    return Path(__file__).resolve().parent / "templates" / "contact.html"

DEFAULT_SCENARIO_PATH = resolve_default_scenario_path()


def enrich_all_incidents():
    for inc in pipeline.incidents:
        ti_engine.enrich_incident(inc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    On startup, load the default attack scenario JSON into memory and enrich it.
    """
    if os.path.exists(DEFAULT_SCENARIO_PATH):
        try:
            pipeline.run_pipeline(DEFAULT_SCENARIO_PATH)
            enrich_all_incidents()
        except Exception as e:
            print(f"Failed to ingest default scenario: {e}")
    yield


app = FastAPI(
    title="ATTACKTRACE Threat Intelligence API",
    description="REST backend for threat ingestion, mitigation mapping, and attack graph correlation.",
    version="1.0.0",
    lifespan=lifespan
)


class RawLogIngestPayload(BaseModel):
    logs: List[Dict[str, Any]]


@app.post("/api/v1/ingest")
def ingest_logs(payload: List[Dict[str, Any]]):
    """
    Ingests a batch of raw logs, enriches them with MITRE signatures, 
    correlates incidents, caches state, and returns detected campaigns.
    """
    if not payload:
        raise HTTPException(status_code=400, detail="Empty log list payload")
    
    try:
        incidents = pipeline.run_pipeline_list(payload)
        for inc in incidents:
            ti_engine.enrich_incident(inc)
        return [inc.to_dict() for inc in incidents]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log ingestion pipeline failed: {str(e)}")


@app.get("/api/v1/incidents")
def get_incidents():
    """
    Returns all currently correlated incidents.
    """
    return [inc.to_dict() for inc in pipeline.incidents]


@app.get("/api/v1/incidents/{incident_id}")
def get_incident_details(incident_id: str):
    """
    Returns detailed steps and info for a specific incident.
    """
    for inc in pipeline.incidents:
        if inc.incident_id == incident_id:
            return inc.to_dict()
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/api/v1/incidents/{incident_id}/graph")
def get_incident_graph(incident_id: str):
    """
    Returns the nodes and edges graph topology for the incident.
    """
    for inc in pipeline.incidents:
        if inc.incident_id == incident_id:
            return visualizer.export_graph_json(inc)
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/api/v1/stats")
def get_stats():
    """
    Returns aggregated security pipeline metrics.
    """
    valid_events = pipeline.collector.valid_events
    dropped_events = pipeline.collector.dropped_events
    enriched_events = pipeline.enriched_events
    incidents = pipeline.incidents

    max_risk = 0
    severity_dist = {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }
    mitre_tech_counts = {}

    for event in enriched_events:
        max_risk = max(max_risk, event.risk_score)
        severity_dist[event.severity.name] = severity_dist.get(event.severity.name, 0) + 1

        for tech in event.mitre_techniques:
            tech_label = f"{tech['id']} - {tech['name']}"
            mitre_tech_counts[tech_label] = mitre_tech_counts.get(tech_label, 0) + 1

    return {
        "total_ingested": len(valid_events),
        "total_dropped": len(dropped_events),
        "total_incidents": len(incidents),
        "max_risk": max_risk,
        "mitre_techniques": mitre_tech_counts,
        "severity_distribution": severity_dist
    }


@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    """
    Serves the interactive SOC console.
    """
    template_path = resolve_template_path()
    if not template_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard template file not found")

    with open(template_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    return HTMLResponse(content=html_content)


@app.get("/contact", response_class=HTMLResponse)
def get_contact():
    """
    Serves the commercial contact and enterprise demo page.
    """
    template_path = resolve_contact_template_path()
    if not template_path.exists():
        raise HTTPException(status_code=404, detail="Contact template file not found")

    with open(template_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    return HTMLResponse(content=html_content)


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class InquiryPayload(BaseModel):
    full_name: str = Field(..., min_length=1)
    email: str = Field(..., min_length=3)
    organization: Optional[str] = ""
    inquiry_type: Optional[str] = "Request SOC Demo"
    log_volume: Optional[str] = "<1GB/day"
    message: str = Field(..., min_length=1)

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Full name cannot be empty")
        return v.strip()

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Email cannot be empty")
        v = v.strip()
        if not EMAIL_REGEX.match(v):
            raise ValueError("Invalid email format")
        return v

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Message cannot be empty")
        return v.strip()


@app.post("/api/v1/inquiry")
def submit_inquiry(payload: InquiryPayload):
    """
    Validates input payload, saves to the database, and returns status and ticket_id.
    """
    data = payload.model_dump()
    target_db = pipeline.db if (pipeline and pipeline.db) else db_manager
    ticket_id = target_db.save_inquiry(data)
    return {
        "status": "success",
        "ticket_id": ticket_id
    }


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    Handles live WebSocket client registration and connection cycles.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep client socket connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


@app.post("/api/v1/stream/trigger")
async def trigger_stream_ingest(payload: List[Dict[str, Any]]):
    """
    Simulates real-time log ingestion stream, running Layer 1, 2, and 3 engines
    per record and broadcasting updates over WebSockets immediately.
    """
    if not payload:
        raise HTTPException(status_code=400, detail="Empty log list payload")

    new_events_count = 0
    for record in payload:
        try:
            # 1. Layer 1 Ingestion
            if not isinstance(record, dict):
                raise ValueError("Log record must be a dictionary")
            event = UnifiedEvent.from_dict(record)
            pipeline.collector.valid_events.append(event)

            # 2. Layer 2 Enrichment
            enriched = pipeline.parser.parse(event)
            pipeline.enriched_events.append(enriched)
            new_events_count += 1

            # Broadcast NEW_EVENT
            await ws_manager.broadcast_json({
                "type": "NEW_EVENT",
                "payload": enriched.to_dict()
            })

            # 3. Layer 3 Correlation
            pipeline.incidents = pipeline.correlator.correlate(
                pipeline.enriched_events,
                time_window_minutes=60
            )
            enrich_all_incidents()

            # Broadcast updated/new incidents
            for inc in pipeline.incidents:
                await ws_manager.broadcast_json({
                    "type": "NEW_INCIDENT",
                    "payload": inc.to_dict()
                })

            # 4. Broadcast METRIC_UPDATE
            stats = get_stats()
            await ws_manager.broadcast_json({
                "type": "METRIC_UPDATE",
                "payload": stats
            })

        except Exception as e:
            pipeline.collector.dropped_events.append({
                "record": record,
                "error": str(e)
            })
            # Broadcast METRIC_UPDATE to update dropped counter
            stats = get_stats()
            await ws_manager.broadcast_json({
                "type": "METRIC_UPDATE",
                "payload": stats
            })

    return {
        "status": "success",
        "processed_events": new_events_count,
        "current_incidents": len(pipeline.incidents)
    }


@app.post("/api/v1/incidents/{incident_id}/mitigate")
def mitigate_incident(incident_id: str, platform: Optional[str] = "auto"):
    """
    Generates remediation actions for the specified incident, 
    saves to SQLite database with rollback tokens, writes script, and returns actions.
    """
    target_incident = None
    for inc in pipeline.incidents:
        if inc.incident_id == incident_id:
            target_incident = inc
            break

    if not target_incident and db_manager:
        target_incident = db_manager.get_incident_by_id(incident_id)

    if not target_incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    actions = playbook_engine.generate_mitigations(target_incident, platform=platform)

    # Persist SOAR actions with atomic rollback tokens to SQLite
    if db_manager:
        db_manager.save_soar_actions(target_incident.incident_id, actions)

    norm_p = PlatformSOARAdapter.normalize_platform(platform)
    ext = "ps1" if norm_p == "windows" else "sh"
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_script = os.path.join(project_dir, f"mitigate.{ext}")
    playbook_engine.export_mitigation_script(actions, output_script, platform=platform)

    return [act.to_dict() for act in actions]


@app.get("/api/v1/incidents/{incident_id}/rollback-script", response_class=PlainTextResponse)
def get_rollback_script(incident_id: str, platform: Optional[str] = "auto"):
    """
    Generates and returns the downloadable atomic twin rollback script.
    """
    target_incident = None
    for inc in pipeline.incidents:
        if inc.incident_id == incident_id:
            target_incident = inc
            break

    if not target_incident and db_manager:
        target_incident = db_manager.get_incident_by_id(incident_id)

    if not target_incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    actions = []
    if db_manager:
        actions = db_manager.get_soar_actions(incident_id)

    if not actions:
        actions = playbook_engine.generate_mitigations(target_incident, platform=platform)

    norm_p = PlatformSOARAdapter.normalize_platform(platform)
    ext = "ps1" if norm_p == "windows" else "sh"
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_script = os.path.join(project_dir, f"rollback.{ext}")
    content = playbook_engine.export_rollback_script(actions, output_script, platform=platform)

    media_type = "text/plain" if norm_p == "windows" else "text/x-shellscript"
    return PlainTextResponse(content=content, media_type=media_type)


@app.get("/api/v1/incidents/{incident_id}/report", response_class=PlainTextResponse)
def get_incident_report(incident_id: str):
    """
    Generates and returns the markdown forensic report as plain text.
    """
    target_incident = None
    for inc in pipeline.incidents:
        if inc.incident_id == incident_id:
            target_incident = inc
            break
            
    if not target_incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    threat_data = ti_engine.lookup_ip(target_incident.primary_actor_ip)
    actions = playbook_engine.generate_mitigations(target_incident)
    
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_report = os.path.join(project_dir, "INCIDENT_REPORT.md")
    
    report_content = reporter.generate_markdown_report(
        target_incident, threat_data, actions, output_report
    )
    
    return PlainTextResponse(content=report_content, media_type="text/markdown")


@app.get("/api/v1/incidents/{incident_id}/dossier")
def get_incident_dossier(incident_id: str):
    """
    Generates and returns the structured JSON forensic evidence package.
    """
    target_incident = None
    for inc in pipeline.incidents:
        if inc.incident_id == incident_id:
            target_incident = inc
            break

    if not target_incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    threat_data = ti_engine.lookup_ip(target_incident.primary_actor_ip)
    actions = playbook_engine.generate_mitigations(target_incident)

    return reporter.generate_json_dossier(
        target_incident, threat_data, actions
    )


@app.get("/api/v1/incidents/{incident_id}/navigator")
def get_incident_navigator(incident_id: str):
    """
    Generates and returns the MITRE ATT&CK Navigator v4.5 JSON layer.
    """
    target_incident = None
    for inc in pipeline.incidents:
        if inc.incident_id == incident_id:
            target_incident = inc
            break

    if not target_incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return reporter.generate_navigator_layer(target_incident)


@app.get("/api/v1/demo/scenarios")
def list_demo_scenarios():
    """
    Returns a list of available multi-platform synthetic attack scenarios.
    """
    return scenario_manager.list_available_scenarios()


@app.post("/api/v1/demo/load/{scenario_name}")
def load_demo_scenario(scenario_name: str):
    """
    Loads and correlates the selected synthetic scenario into the database and active memory.
    """
    try:
        incidents = scenario_manager.run_scenario(scenario_name, db=db_manager)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load scenario: {e}")

    # Synchronize in-memory pipeline state
    pipeline.incidents = incidents
    enrich_all_incidents()

    return {
        "status": "success",
        "scenario": scenario_name,
        "incidents_created": len(incidents),
        "incidents": [inc.to_dict() for inc in incidents],
    }


@app.post("/api/v1/demo/reset")
def reset_demo_scenario():
    """
    Purges synthetic demo records cleanly from the database and active memory.
    """
    purged = scenario_manager.reset_demo_state(db=db_manager)
    pipeline.incidents = []
    return {
        "status": "success",
        "purged": purged,
    }
