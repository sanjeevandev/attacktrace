from src.models import AttackIncident


class AttackTimelineRenderer:
    def __init__(self) -> None:
        pass

    def generate_story(self, incident: AttackIncident) -> str:
        """
        Produces a human-readable investigation narrative summarizing the attacker's actions.
        """
        narrative = []
        narrative.append(
            f"Incident Analysis Alert: A multi-stage attack campaign was reconstructed, originating "
            f"from actor IP {incident.primary_actor_ip}."
        )
        narrative.append(
            f"The attack targeted system account(s): {', '.join(incident.targeted_users or ['None'])}."
        )
        
        stages_str = ", ".join(stage.name for stage in incident.stages_detected)
        narrative.append(
            f"The campaign spanned from {incident.start_time} to {incident.end_time}, "
            f"progressing through {len(incident.stages_detected)} distinct kill-chain stages: [{stages_str}]."
        )
        
        narrative.append("\nChronological Investigation Log:")
        for idx, step in enumerate(incident.steps, 1):
            narrative.append(
                f"  {idx:02d}. [{step.timestamp}] stage ({step.stage.name}) | Actor: {step.actor}\n"
                f"      Utilized Technique: {step.technique}\n"
                f"      Action: {step.description} (Risk: {step.risk_score})"
            )
            
        narrative.append(
            f"\nRisk Assessment Conclusion: This threat campaign has been classified at "
            f"{incident.overall_severity.name} severity with a detection confidence of {incident.confidence_score}%."
        )
        
        return "\n".join(narrative)

    def render_ascii_graph(self, incident: AttackIncident) -> str:
        """
        Renders an ASCII tree showing the chronological path of the attack from initial probe to final step.
        """
        lines = []
        lines.append(f"┌─ [ATTACK GRAPH] Campaign ID: {incident.incident_id}")
        lines.append(f"│  Origin Actor IP: {incident.primary_actor_ip} | Targets: {', '.join(incident.targeted_users)}")
        lines.append("│")
        
        total_steps = len(incident.steps)
        for idx, step in enumerate(incident.steps):
            is_last = (idx == total_steps - 1)
            branch = "└───►" if is_last else "├───►"
            spacer = "     " if is_last else "│    "
            
            lines.append(f"├─ {branch} [{step.timestamp}] ({step.stage.name})")
            lines.append(f"│  {spacer} Tech: {step.technique}")
            lines.append(f"│  {spacer} Desc: {step.description}")
            lines.append(f"│  {spacer} Risk: {step.risk_score}")
            if not is_last:
                lines.append("│")
                
        lines.append(f"└─ [Severity: {incident.overall_severity.name} | Confidence: {incident.confidence_score}%]")
        return "\n".join(lines)
