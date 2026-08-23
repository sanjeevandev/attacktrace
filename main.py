#!/usr/bin/env python3
import argparse
import os
import sys
from src.pipeline import AttackTracePipeline
from src.timeline import AttackTimelineRenderer
from src.models import SeverityLevel

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


def print_banner():
    banner = f"""
{CLR_CYAN}{CLR_BOLD}================================================================================
  ▲  A T T A C K T R A C E   |   Layer 5: Mitigation Playbooks & Threat Intel
================================================================================{CLR_RESET}"""
    print(banner)


def get_severity_styled(severity: SeverityLevel) -> str:
    if severity == SeverityLevel.CRITICAL:
        return f"{CLR_BG_RED}{CLR_BOLD} CRITICAL {CLR_RESET}"
    elif severity == SeverityLevel.HIGH:
        return f"{CLR_RED}{CLR_BOLD}HIGH{CLR_RESET}"
    elif severity == SeverityLevel.MEDIUM:
        return f"{CLR_ORANGE}{CLR_BOLD}MEDIUM{CLR_RESET}"
    elif severity == SeverityLevel.LOW:
        return f"{CLR_YELLOW}LOW{CLR_RESET}"
    else:
        return f"{CLR_GRAY}INFO{CLR_RESET}"


def run_cli_analysis(scenario_path: str):
    print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Running end-to-end detection pipeline...")
    print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Scenario dataset: {CLR_WHITE}{scenario_path}{CLR_RESET}\n")

    pipeline = AttackTracePipeline()
    renderer = AttackTimelineRenderer()

    try:
        incidents = pipeline.run_pipeline(scenario_path, time_window_minutes=60)
    except FileNotFoundError:
        print(f"{CLR_RED}{CLR_BOLD}[ERROR]{CLR_RESET} Attack scenario file not found at: {scenario_path}")
        sys.exit(1)
    except Exception as e:
        print(f"{CLR_RED}{CLR_BOLD}[CRITICAL ERROR]{CLR_RESET} Pipeline execution failed: {e}")
        sys.exit(1)

    total_ingested = len(pipeline.collector.valid_events)
    total_dropped = len(pipeline.collector.dropped_events)
    total_enriched = len(pipeline.enriched_events)
    total_incidents = len(incidents)

    # 1. Pipeline Summary Dashboard
    print(f"{CLR_CYAN}{CLR_BOLD}┌──────────────────────────────────────────────────────────────────────────────┐")
    print(f"│                     P I P E L I N E   S T A T I S T I C S                    │")
    print(f"└──────────────────────────────────────────────────────────────────────────────┘{CLR_RESET}")
    print(f"  {CLR_BOLD}Ingested logs (L1):{CLR_RESET}   {total_ingested}")
    print(f"  {CLR_BOLD}Dropped logs (L1):{CLR_RESET}    {total_dropped}")
    print(f"  {CLR_BOLD}Enriched events (L2):{CLR_RESET} {total_enriched}")
    print(f"  {CLR_BOLD}Correlated Incidents:{CLR_RESET} {CLR_RED if total_incidents > 0 else CLR_GREEN}{total_incidents}{CLR_RESET}")
    print(CLR_GRAY + "─" * 80 + CLR_RESET)

    # 2. Render Incident Details (If Any)
    if not incidents:
        print(f"\n{CLR_GREEN}{CLR_BOLD}✓ No threat campaigns detected or correlated.{CLR_RESET}\n")
    else:
        for idx, incident in enumerate(incidents, start=1):
            print(f"\n{CLR_RED}{CLR_BOLD}┌──────────────────────────────────────────────────────────────────────────────┐")
            print(f"│               D E T E C T E D   A T T A C K   I N C I D E N T  #{idx:<13}│")
            print(f"└──────────────────────────────────────────────────────────────────────────────┘{CLR_RESET}")
            
            # Metadata Grid
            print(f"  {CLR_BOLD}Incident ID:{CLR_RESET}      {CLR_WHITE}{incident.incident_id}{CLR_RESET}")
            print(f"  {CLR_BOLD}Origin Actor IP:{CLR_RESET}  {CLR_YELLOW}{incident.primary_actor_ip}{CLR_RESET}")
            print(f"  {CLR_BOLD}Target Users:{CLR_RESET}     {', '.join(incident.targeted_users)}")
            print(f"  {CLR_BOLD}Time Bounds:{CLR_RESET}      {incident.start_time}  -->  {incident.end_time}")
            print(f"  {CLR_BOLD}Overall Severity:{CLR_RESET}{get_severity_styled(incident.overall_severity)}")
            print(f"  {CLR_BOLD}Confidence Score:{CLR_RESET}{CLR_GREEN if incident.confidence_score >= 80 else CLR_YELLOW}{incident.confidence_score}%{CLR_RESET}")
            print(f"  {CLR_BOLD}Stages Traversed:{CLR_RESET} {', '.join(stage.name for stage in incident.stages_detected)}")
            print(CLR_GRAY + "─" * 80 + CLR_RESET)

            # 3. Investigation Story
            print(f"\n{CLR_CYAN}{CLR_BOLD}================================================================================")
            print(f"  A N A L Y S T   I N V E S T I G A T I O N   N A R R A T I V E")
            print(f"================================================================================{CLR_RESET}")
            story_text = renderer.generate_story(incident)
            print(story_text)
            print(CLR_GRAY + "─" * 80 + CLR_RESET)

            # 4. ASCII Attack Tree Graph
            print(f"\n{CLR_CYAN}{CLR_BOLD}================================================================================")
            print(f"  C H R O N O L O G I C A L   A T T A C K   P A T H   G R A P H")
            print(f"================================================================================{CLR_RESET}")
            ascii_tree = renderer.render_ascii_graph(incident)
            print(ascii_tree)
            print(CLR_GRAY + "─" * 80 + CLR_RESET)

    print(f"\n{CLR_GREEN}{CLR_BOLD}[STATUS] ATTACKTRACE Correlation Stage: COMPLETED ✓ (Attack graphs ready){CLR_RESET}")
    print(f"{CLR_CYAN}{CLR_BOLD}================================================================================{CLR_RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="ATTACKTRACE Core System CLI")
    parser.add_argument("--cli", action="store_true", help="Run the terminal-based report (Layer 1-3 output).")
    parser.add_argument("--serve", action="store_true", help="Start the FastAPI REST backend server.")
    parser.add_argument("--report", action="store_true", help="Ingest scenario and export standalone HTML dashboard to report.html.")
    parser.add_argument("--mitigate", action="store_true", help="Runs pipeline, correlates incidents, and exports mitigate.sh")
    parser.add_argument("--full-report", action="store_true", help="Runs pipeline and outputs INCIDENT_REPORT.md and report.html")

    args = parser.parse_args()

    # Default option
    if not (args.cli or args.serve or args.report or args.mitigate or args.full_report):
        args.cli = True

    project_dir = os.path.dirname(os.path.abspath(__file__))
    scenario_path = os.path.join(project_dir, "data", "attack_scenario.json")

    if args.serve:
        import uvicorn
        print_banner()
        print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Launching FastAPI backend REST Server...")
        uvicorn.run("src.api:app", host="127.0.0.1", port=8000, reload=False)
        return

    if args.mitigate:
        from src.threat_intel import ThreatIntelEngine
        from src.playbooks import PlaybookEngine
        print_banner()
        print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Running pipeline and generating SOAR mitigations...")
        
        pipeline = AttackTracePipeline()
        ti_engine = ThreatIntelEngine()
        playbook_engine = PlaybookEngine()

        try:
            incidents = pipeline.run_pipeline(scenario_path)
            all_actions = []
            for inc in incidents:
                ti_engine.enrich_incident(inc)
                actions = playbook_engine.generate_mitigations(inc)
                all_actions.extend(actions)
            
            output_script = os.path.join(project_dir, "mitigate.sh")
            playbook_engine.export_mitigation_script(all_actions, output_script)
            print(f"{CLR_GREEN}{CLR_BOLD}[SUCCESS] Mitigation playbook script compiled at: {output_script}{CLR_RESET}")
            print(f"Total actions generated: {len(all_actions)}")
        except Exception as e:
            print(f"{CLR_RED}{CLR_BOLD}[ERROR] Mitigation script compilation failed: {e}{CLR_RESET}")
            sys.exit(1)
        return

    if args.full_report:
        from src.threat_intel import ThreatIntelEngine
        from src.playbooks import PlaybookEngine
        from src.reporter import IncidentReporter
        from src.visualizer import GraphVisualizer
        print_banner()
        print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Generating full incident report and HTML dashboard...")

        pipeline = AttackTracePipeline()
        ti_engine = ThreatIntelEngine()
        playbook_engine = PlaybookEngine()
        reporter = IncidentReporter()
        visualizer = GraphVisualizer()

        try:
            incidents = pipeline.run_pipeline(scenario_path)
            for inc in incidents:
                ti_engine.enrich_incident(inc)

            if incidents:
                primary = incidents[0]
                threat_data = ti_engine.lookup_ip(primary.primary_actor_ip)
                actions = playbook_engine.generate_mitigations(primary)
                md_path = os.path.join(project_dir, "INCIDENT_REPORT.md")
                reporter.generate_markdown_report(primary, threat_data, actions, md_path)
                print(f"{CLR_GREEN}{CLR_BOLD}[SUCCESS] Forensic Markdown Report written to: {md_path}{CLR_RESET}")
            else:
                print(f"{CLR_YELLOW}[WARNING] No incidents found to generate forensic report.{CLR_RESET}")

            html_path = os.path.join(project_dir, "report.html")
            visualizer.generate_html_report(incidents, html_path)
            print(f"{CLR_GREEN}{CLR_BOLD}[SUCCESS] Standalone HTML dashboard report written to: {html_path}{CLR_RESET}")
        except Exception as e:
            print(f"{CLR_RED}{CLR_BOLD}[ERROR] Full report generation failed: {e}{CLR_RESET}")
            sys.exit(1)
        return

    if args.report:
        from src.visualizer import GraphVisualizer
        output_report_path = os.path.join(project_dir, "report.html")

        print_banner()
        print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Constructing static HTML SOC dashboard report...")
        print(f"{CLR_GRAY}[SYSTEM]{CLR_RESET} Source: {scenario_path}")

        pipeline = AttackTracePipeline()
        visualizer = GraphVisualizer()

        try:
            incidents = pipeline.run_pipeline(scenario_path)
            visualizer.generate_html_report(incidents, output_report_path)
            print(f"{CLR_GREEN}{CLR_BOLD}[SUCCESS] HTML SOC dashboard compiled at: {output_report_path}{CLR_RESET}")
        except Exception as e:
            print(f"{CLR_RED}{CLR_BOLD}[ERROR] HTML compilation failed: {e}{CLR_RESET}")
            sys.exit(1)
        return

    if args.cli:
        print_banner()
        run_cli_analysis(scenario_path)


if __name__ == "__main__":
    main()
