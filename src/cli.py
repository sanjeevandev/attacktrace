#!/usr/bin/env python3
"""
ATTACKTRACE Unified Command-Line Interface.
Modular subcommand cybersecurity engine inspired by Nmap and Burp Suite.
"""
import argparse
import json
import os
import platform
import sys
from typing import Any, Dict, List, Optional

from src.collector import LogCollector
from src.db import DatabaseManager
from src.demo_manager import ScenarioManager
from src.models import AttackIncident, SeverityLevel
from src.pipeline import AttackTracePipeline
from src.playbooks import PlatformSOARAdapter, PlaybookEngine
from src.reporter import IncidentReporter
from src.threat_intel import ThreatIntelEngine
from src.timeline import AttackTimelineRenderer

# ANSI Color Codes
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[91m"
CLR_ORANGE = "\033[38;5;208m"
CLR_YELLOW = "\033[93m"
CLR_GREEN = "\033[92m"
CLR_CYAN = "\033[96m"
CLR_WHITE = "\033[97m"
CLR_GRAY = "\033[90m"
CLR_BG_RED = "\033[41;97m"

__version__ = "1.0.0"


def print_banner() -> None:
    banner = f"""
{CLR_CYAN}{CLR_BOLD}================================================================================
  ▲  A T T A C K T R A C E   |   Cybersecurity Threat Reconstruction Engine
================================================================================{CLR_RESET}"""
    print(banner)


def get_severity_styled(severity: Any) -> str:
    sev_name = severity.name if hasattr(severity, "name") else str(severity)
    if sev_name == "CRITICAL":
        return f"{CLR_BG_RED}{CLR_BOLD} CRITICAL {CLR_RESET}"
    elif sev_name == "HIGH":
        return f"{CLR_RED}{CLR_BOLD}HIGH{CLR_RESET}"
    elif sev_name == "MEDIUM":
        return f"{CLR_ORANGE}{CLR_BOLD}MEDIUM{CLR_RESET}"
    elif sev_name == "LOW":
        return f"{CLR_YELLOW}LOW{CLR_RESET}"
    else:
        return f"{CLR_GRAY}INFO{CLR_RESET}"


def cmd_version() -> int:
    """Displays version and system platform info."""
    py_ver = sys.version.split()[0]
    os_name = platform.system()
    os_release = platform.release()
    arch = platform.machine()
    print(f"{CLR_BOLD}ATTACKTRACE{CLR_RESET} v{__version__}")
    print(f"Platform: {os_name} {os_release} ({arch}) | Python: {py_ver}")
    return 0


def cmd_status(args: argparse.Namespace, db: Optional[DatabaseManager] = None) -> int:
    """Displays SQLite database location, total events, total incidents, severity breakdown, and storage metrics."""
    db_mgr = db or DatabaseManager(db_path=getattr(args, "db", None))
    print_banner()
    print(
        f"{CLR_CYAN}{CLR_BOLD}┌──────────────────────────────────────────────────────────────────────────────┐"
    )
    print(
        f"│                   D A T A B A S E   &   S Y S T E M   S T A T U S            │"
    )
    print(
        f"└──────────────────────────────────────────────────────────────────────────────┘{CLR_RESET}"
    )

    db_location = db_mgr.db_path
    storage_size_str = "In-Memory (:memory:)"
    if db_location != ":memory:" and os.path.exists(db_location):
        bytes_size = os.path.getsize(db_location)
        if bytes_size < 1024:
            storage_size_str = f"{bytes_size} bytes"
        elif bytes_size < 1024 * 1024:
            storage_size_str = f"{bytes_size / 1024:.2f} KB"
        else:
            storage_size_str = f"{bytes_size / (1024 * 1024):.2f} MB"

    stats = db_mgr.get_stats()
    print(f"  {CLR_BOLD}Database Path:{CLR_RESET}        {CLR_WHITE}{db_location}{CLR_RESET}")
    print(f"  {CLR_BOLD}Storage Size:{CLR_RESET}         {storage_size_str}")
    print(f"  {CLR_BOLD}Total Log Events:{CLR_RESET}     {stats['total_ingested']}")
    tot_inc = stats["total_incidents"]
    inc_color = CLR_RED if tot_inc > 0 else CLR_GREEN
    print(
        f"  {CLR_BOLD}Total Incidents:{CLR_RESET}      {inc_color}{tot_inc}{CLR_RESET} "
        f"({stats['real_incidents']} real, {stats['demo_incidents']} demo)"
    )
    print(f"  {CLR_BOLD}Max Risk Score:{CLR_RESET}       {stats['max_risk']}")
    print(f"  {CLR_BOLD}Severity Breakdown:{CLR_RESET}")
    for sev, count in stats["severity_distribution"].items():
        styled = (
            get_severity_styled(SeverityLevel[sev])
            if sev in SeverityLevel.__members__
            else sev
        )
        print(f"    - {styled:<20}: {count}")
    print(CLR_GRAY + "─" * 80 + CLR_RESET)
    return 0


def cmd_demo(args: argparse.Namespace, db: Optional[DatabaseManager] = None) -> int:
    """Runs built-in multi-platform cyber breach simulations through the real pipeline and saves to SQLite."""
    db_mgr = db or DatabaseManager(db_path=getattr(args, "db", None))
    scenario_mgr = ScenarioManager()
    print_banner()

    if getattr(args, "reset", False):
        purged = scenario_mgr.reset_demo_state(db_mgr)
        print(f"{CLR_GREEN}{CLR_BOLD}[SUCCESS] Synthetic demo state purged from database.{CLR_RESET}")
        print(f"  Events purged:    {purged.get('purged_events', 0)}")
        print(f"  Incidents purged: {purged.get('purged_incidents', 0)}")
        return 0

    scenario_map = {
        "windows": "windows_ad_compromise",
        "linux": "linux_server_breach",
        "macos": "macos_endpoint_intrusion",
    }
    raw_scenario = getattr(args, "scenario", "windows") or "windows"
    scenario_name = scenario_map.get(raw_scenario, raw_scenario)

    print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Loading and executing breach scenario: {CLR_CYAN}{scenario_name}{CLR_RESET}...")
    try:
        incidents = scenario_mgr.run_scenario(scenario_name, db=db_mgr)
    except FileNotFoundError as e:
        print(f"{CLR_RED}{CLR_BOLD}[ERROR]{CLR_RESET} Scenario '{scenario_name}' not found: {e}")
        return 1
    except Exception as e:
        print(f"{CLR_RED}{CLR_BOLD}[ERROR]{CLR_RESET} Demo execution failed: {e}")
        return 1

    print(
        f"{CLR_GREEN}{CLR_BOLD}[SUCCESS] Scenario completed.{CLR_RESET} "
        f"Correlated {len(incidents)} incident(s) persisted to DB.\n"
    )
    for inc in incidents:
        print(
            f"  • {CLR_BOLD}Incident ID:{CLR_RESET} {CLR_WHITE}{inc.incident_id}{CLR_RESET} | "
            f"{get_severity_styled(inc.overall_severity)} | Actor: {CLR_YELLOW}{inc.primary_actor_ip}{CLR_RESET} | "
            f"Stages: {len(inc.stages_detected)} | Steps: {len(inc.steps)} | Confidence: {inc.confidence_score}%"
        )
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Starts the FastAPI server, WebSocket hub, and Dark SOC web dashboard."""
    import uvicorn
    print_banner()
    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 8000)
    reload = getattr(args, "reload", False)
    print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Starting ATTACKTRACE SOC server on {CLR_CYAN}http://{host}:{port}{CLR_RESET}...")
    print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Interactive Dark SOC dashboard: {CLR_CYAN}http://{host}:{port}/dashboard{CLR_RESET}")
    uvicorn.run("src.api:app", host=host, port=port, reload=reload)
    return 0


def cmd_ingest(args: argparse.Namespace, db: Optional[DatabaseManager] = None) -> int:
    """Ingests a local log file (.json, .jsonl, .log, .syslog), correlates incidents, and outputs summary statistics."""
    file_path = getattr(args, "file_path", None)
    if not file_path or not os.path.exists(file_path):
        print(f"{CLR_RED}{CLR_BOLD}[ERROR]{CLR_RESET} File not found: {file_path}")
        return 1

    file_type = getattr(args, "type", "auto") or "auto"
    db_mgr = db or DatabaseManager(db_path=getattr(args, "db", None))
    pipeline = AttackTracePipeline(db=db_mgr)
    print_banner()
    print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Ingesting logs from {CLR_WHITE}{file_path}{CLR_RESET} (format: {CLR_CYAN}{file_type}{CLR_RESET})...")

    window = getattr(args, "window", 60)
    max_campaign = getattr(args, "max_campaign", 240)

    try:
        incidents = pipeline.run_pipeline(
            file_path,
            time_window_minutes=window,
            max_campaign_duration_minutes=max_campaign,
            is_demo=False,
            file_type=file_type,
        )
    except Exception as e:
        print(f"{CLR_RED}{CLR_BOLD}[CRITICAL ERROR]{CLR_RESET} Pipeline processing failed: {e}")
        return 1

    total_valid = len(pipeline.collector.valid_events)
    total_dropped = len(pipeline.collector.dropped_events)
    total_enriched = len(pipeline.enriched_events)

    if total_valid == 0 and total_dropped == 0:
        print(f"{CLR_YELLOW}[WARNING]{CLR_RESET} No log records found in {file_path}.")
        return 0

    print(f"{CLR_CYAN}{CLR_BOLD}┌──────────────────────────────────────────────────────────────────────────────┐")
    print(f"│                     I N G E S T I O N   S U M M A R Y                        │")
    print(f"└──────────────────────────────────────────────────────────────────────────────┘{CLR_RESET}")
    print(f"  {CLR_BOLD}Ingested logs (L1):{CLR_RESET}   {total_valid}")
    print(f"  {CLR_BOLD}Dropped logs (L1):{CLR_RESET}    {total_dropped}")
    print(f"  {CLR_BOLD}Enriched events (L2):{CLR_RESET} {total_enriched}")
    inc_clr = CLR_RED if len(incidents) > 0 else CLR_GREEN
    print(f"  {CLR_BOLD}Correlated Incidents:{CLR_RESET} {inc_clr}{len(incidents)}{CLR_RESET}")
    print(CLR_GRAY + "─" * 80 + CLR_RESET)

    if not incidents:
        print(f"\n{CLR_GREEN}{CLR_BOLD}✓ No threat campaigns detected or correlated.{CLR_RESET}\n")
    else:
        for idx, inc in enumerate(incidents, start=1):
            print(
                f"  [{idx}] {CLR_WHITE}{inc.incident_id}{CLR_RESET} | "
                f"{get_severity_styled(inc.overall_severity)} | Actor: {CLR_YELLOW}{inc.primary_actor_ip}{CLR_RESET} | "
                f"Stages: {len(inc.stages_detected)} | Confidence: {inc.confidence_score}%"
            )
    return 0


def cmd_incidents(args: argparse.Namespace, db: Optional[DatabaseManager] = None) -> int:
    """Lists correlated incidents in a formatted terminal table or deep-dives into a specific incident narrative."""
    db_mgr = db or DatabaseManager(db_path=getattr(args, "db", None))
    target_id = getattr(args, "id", None)
    is_json = getattr(args, "json", False)

    if target_id:
        incident = db_mgr.get_incident_by_id(target_id)
        if not incident:
            print(f"{CLR_RED}{CLR_BOLD}[ERROR]{CLR_RESET} Incident '{target_id}' not found.")
            return 1

        if is_json:
            print(json.dumps(incident.to_dict(), indent=2))
            return 0

        renderer = AttackTimelineRenderer()
        print_banner()
        print(f"\n{CLR_RED}{CLR_BOLD}┌──────────────────────────────────────────────────────────────────────────────┐")
        print(f"│               D E T E C T E D   A T T A C K   I N C I D E N T                │")
        print(f"└──────────────────────────────────────────────────────────────────────────────┘{CLR_RESET}")
        print(f"  {CLR_BOLD}Incident ID:{CLR_RESET}      {CLR_WHITE}{incident.incident_id}{CLR_RESET}")
        print(f"  {CLR_BOLD}Origin Actor IP:{CLR_RESET}  {CLR_YELLOW}{incident.primary_actor_ip}{CLR_RESET}")
        print(f"  {CLR_BOLD}Target Users:{CLR_RESET}     {', '.join(incident.targeted_users) or 'None'}")
        print(f"  {CLR_BOLD}Time Bounds:{CLR_RESET}      {incident.start_time}  -->  {incident.end_time}")
        print(f"  {CLR_BOLD}Overall Severity:{CLR_RESET}{get_severity_styled(incident.overall_severity)}")
        print(
            f"  {CLR_BOLD}Confidence Score:{CLR_RESET}"
            f"{CLR_GREEN if incident.confidence_score >= 80 else CLR_YELLOW}{incident.confidence_score}%{CLR_RESET}"
        )
        print(f"  {CLR_BOLD}Stages Traversed:{CLR_RESET} {', '.join(stage.name for stage in incident.stages_detected)}")
        print(CLR_GRAY + "─" * 80 + CLR_RESET)

        print(f"\n{CLR_CYAN}{CLR_BOLD}================================================================================")
        print(f"  A N A L Y S T   I N V E S T I G A T I O N   N A R R A T I V E")
        print(f"================================================================================{CLR_RESET}")
        print(renderer.generate_story(incident))
        print(CLR_GRAY + "─" * 80 + CLR_RESET)

        print(f"\n{CLR_CYAN}{CLR_BOLD}================================================================================")
        print(f"  C H R O N O L O G I C A L   A T T A C K   P A T H   G R A P H")
        print(f"================================================================================{CLR_RESET}")
        print(renderer.render_ascii_graph(incident))
        print(CLR_GRAY + "─" * 80 + CLR_RESET)
        return 0

    # Otherwise list incidents
    incidents = db_mgr.get_incidents(limit=100)
    if is_json:
        print(json.dumps([inc.to_dict() for inc in incidents], indent=2))
        return 0

    print_banner()
    if not incidents:
        print(f"{CLR_YELLOW}No correlated incidents found in database ({db_mgr.db_path}).{CLR_RESET}")
        return 0

    print(f"{CLR_CYAN}{CLR_BOLD}Correlated Attack Incidents ({len(incidents)}):{CLR_RESET}\n")
    header = f"{'Incident ID':<38} | {'Severity':<10} | {'Actor IP':<16} | {'Stages':<8} | {'Steps':<6} | {'Confidence':<10}"
    print(CLR_BOLD + header + CLR_RESET)
    print(CLR_GRAY + "─" * len(header) + CLR_RESET)
    for inc in incidents:
        sev_str = inc.overall_severity.name if hasattr(inc.overall_severity, "name") else str(inc.overall_severity)
        print(
            f"{inc.incident_id:<38} | {sev_str:<10} | {inc.primary_actor_ip:<16} | "
            f"{len(inc.stages_detected):<8} | {len(inc.steps):<6} | {inc.confidence_score}%"
        )
    print(CLR_GRAY + "─" * len(header) + CLR_RESET)
    return 0


def cmd_report(args: argparse.Namespace, db: Optional[DatabaseManager] = None) -> int:
    """Compiles and exports the incident report to file."""
    incident_id = getattr(args, "id", None)
    if not incident_id:
        print(f"{CLR_RED}{CLR_BOLD}[ERROR]{CLR_RESET} Missing required incident ID (--id).")
        return 1

    db_mgr = db or DatabaseManager(db_path=getattr(args, "db", None))
    incident = db_mgr.get_incident_by_id(incident_id)
    if not incident:
        print(f"{CLR_RED}{CLR_BOLD}[ERROR]{CLR_RESET} Incident '{incident_id}' not found.")
        return 1

    ti_engine = ThreatIntelEngine()
    playbook_engine = PlaybookEngine()
    reporter = IncidentReporter()

    threat_data = ti_engine.lookup_ip(incident.primary_actor_ip)
    actions = playbook_engine.generate_mitigations(incident)

    fmt = getattr(args, "format", "markdown") or "markdown"
    fmt = fmt.lower()
    custom_out = getattr(args, "output", None)

    if fmt == "json":
        out_path = custom_out or f"dossier_{incident.incident_id}.json"
        reporter.generate_json_dossier(incident, threat_data, actions, output_path=out_path)
    elif fmt == "navigator":
        out_path = custom_out or f"navigator_{incident.incident_id}.json"
        reporter.generate_navigator_layer(incident, output_path=out_path)
    else:  # markdown
        out_path = custom_out or f"INCIDENT_REPORT_{incident.incident_id}.md"
        reporter.generate_markdown_report(incident, threat_data, actions, output_path=out_path)

    print(f"{CLR_GREEN}{CLR_BOLD}[SUCCESS]{CLR_RESET} Incident report ({fmt}) written to: {CLR_WHITE}{out_path}{CLR_RESET}")
    return 0


def cmd_mitigate(args: argparse.Namespace, db: Optional[DatabaseManager] = None) -> int:
    """Compiles and exports containment script or twin rollback script."""
    incident_id = getattr(args, "id", None)
    if not incident_id:
        print(f"{CLR_RED}{CLR_BOLD}[ERROR]{CLR_RESET} Missing required incident ID (--id).")
        return 1

    db_mgr = db or DatabaseManager(db_path=getattr(args, "db", None))
    incident = db_mgr.get_incident_by_id(incident_id)
    if not incident:
        print(f"{CLR_RED}{CLR_BOLD}[ERROR]{CLR_RESET} Incident '{incident_id}' not found.")
        return 1

    playbook_engine = PlaybookEngine()
    platform_choice = getattr(args, "platform", "auto") or "auto"
    actions = playbook_engine.generate_mitigations(incident, platform=platform_choice)
    db_mgr.save_soar_actions(incident.incident_id, actions)

    norm_p = PlatformSOARAdapter.normalize_platform(platform_choice)
    ext = "ps1" if norm_p == "windows" else "sh"
    custom_out = getattr(args, "output", None)
    is_rollback = getattr(args, "rollback", False)

    if is_rollback:
        out_path = custom_out or f"rollback.{ext}"
        playbook_engine.export_rollback_script(actions, output_file=out_path, platform=platform_choice)
        print(f"{CLR_GREEN}{CLR_BOLD}[SUCCESS]{CLR_RESET} Atomic SOAR rollback script written to: {CLR_WHITE}{out_path}{CLR_RESET}")
    else:
        out_path = custom_out or f"mitigate.{ext}"
        playbook_engine.export_mitigation_script(actions, output_file=out_path, platform=platform_choice)
        print(f"{CLR_GREEN}{CLR_BOLD}[SUCCESS]{CLR_RESET} Containment playbook script written to: {CLR_WHITE}{out_path}{CLR_RESET}")

    print(f"Generated {len(actions)} action(s):")
    for act in actions:
        print(f"  • [{act.action_type}] Target: {act.target} | Token: {act.rollback_token}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Constructs the comprehensive argument parser for ATTACKTRACE."""
    parser = argparse.ArgumentParser(
        prog="attacktrace",
        description="ATTACKTRACE: Automated Threat Reconstruction and Adaptive Containment Kernel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Display version and platform information.",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Custom SQLite database file path (or :memory:).",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. status
    p_status = subparsers.add_parser("status", help="Display SQLite database and pipeline storage metrics.")
    p_status.add_argument("--db", type=str, default=None, help="Custom SQLite database path.")

    # 2. demo
    p_demo = subparsers.add_parser("demo", help="Run built-in multi-platform cyber breach simulations.")
    p_demo.add_argument(
        "--scenario",
        type=str,
        default="windows",
        choices=["windows", "linux", "macos", "windows_ad_compromise", "linux_server_breach", "macos_endpoint_intrusion"],
        help="Select synthetic scenario (default: windows).",
    )
    p_demo.add_argument(
        "--reset",
        action="store_true",
        help="Purge synthetic demo records from the database.",
    )
    p_demo.add_argument("--db", type=str, default=None, help="Custom SQLite database path.")

    # 3. serve
    p_serve = subparsers.add_parser("serve", help="Start the FastAPI server, WebSocket hub, and SOC web dashboard.")
    p_serve.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1).")
    p_serve.add_argument("--port", type=int, default=8000, help="Server port (default: 8000).")
    p_serve.add_argument("--reload", action="store_true", help="Enable auto-reload on code change.")

    # 4. ingest
    p_ingest = subparsers.add_parser("ingest", help="Ingest a local log file (.json, .jsonl, .log, .syslog) and correlate incidents.")
    p_ingest.add_argument("file_path", type=str, help="Path to raw log file (.json, .jsonl, .log, .syslog).")
    p_ingest.add_argument(
        "--type",
        type=str,
        default="auto",
        choices=["auto", "json", "jsonl", "windows", "syslog", "web"],
        help="Log format type (default: auto).",
    )
    p_ingest.add_argument("--window", type=int, default=60, help="Sliding correlation window in minutes (default: 60).")
    p_ingest.add_argument("--max-campaign", type=int, default=240, help="Max campaign duration in minutes (default: 240).")
    p_ingest.add_argument("--db", type=str, default=None, help="Custom SQLite database path.")

    # 5. incidents
    p_incidents = subparsers.add_parser("incidents", help="List correlated incidents or deep-dive into an incident.")
    p_incidents.add_argument("--list", action="store_true", help="List all correlated incidents in a formatted table.")
    p_incidents.add_argument("--id", type=str, default=None, help="Target incident ID to inspect.")
    p_incidents.add_argument("--json", action="store_true", help="Output results in JSON format.")
    p_incidents.add_argument("--db", type=str, default=None, help="Custom SQLite database path.")

    # 6. report
    p_report = subparsers.add_parser("report", help="Compile and export an incident report to file.")
    p_report.add_argument("--id", type=str, required=True, help="Incident ID to report on.")
    p_report.add_argument(
        "--format",
        type=str,
        default="markdown",
        choices=["markdown", "json", "navigator"],
        help="Report export format (default: markdown).",
    )
    p_report.add_argument("--output", type=str, default=None, help="Output destination file path.")
    p_report.add_argument("--db", type=str, default=None, help="Custom SQLite database path.")

    # 7. mitigate
    p_mitigate = subparsers.add_parser("mitigate", help="Compile and export containment or rollback scripts.")
    p_mitigate.add_argument("--id", type=str, required=True, help="Incident ID to mitigate.")
    p_mitigate.add_argument(
        "--platform",
        type=str,
        default="auto",
        choices=["auto", "windows", "linux", "macos"],
        help="Target OS platform (default: auto).",
    )
    p_mitigate.add_argument("--rollback", action="store_true", help="Generate reverse atomic rollback script.")
    p_mitigate.add_argument("--output", type=str, default=None, help="Output destination file path.")
    p_mitigate.add_argument("--db", type=str, default=None, help="Custom SQLite database path.")

    return parser


def main(argv: Optional[List[str]] = None, db: Optional[DatabaseManager] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    # Top-level --version check
    if "--version" in argv:
        return cmd_version()

    # If no arguments provided, print banner and help
    if not argv:
        print_banner()
        parser.print_help()
        return 0

    # Support legacy main.py flags gracefully
    if argv == ["--serve"]:
        return cmd_serve(argparse.Namespace(host="127.0.0.1", port=8000, reload=False))
    if argv == ["--cli"]:
        return cmd_status(argparse.Namespace(db=None), db=db)

    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1

    if args.version:
        return cmd_version()

    if not args.subcommand:
        print_banner()
        parser.print_help()
        return 0

    if args.subcommand == "status":
        return cmd_status(args, db=db)
    elif args.subcommand == "demo":
        return cmd_demo(args, db=db)
    elif args.subcommand == "serve":
        return cmd_serve(args)
    elif args.subcommand == "ingest":
        return cmd_ingest(args, db=db)
    elif args.subcommand == "incidents":
        return cmd_incidents(args, db=db)
    elif args.subcommand == "report":
        return cmd_report(args, db=db)
    elif args.subcommand == "mitigate":
        return cmd_mitigate(args, db=db)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
