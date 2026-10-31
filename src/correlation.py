from datetime import datetime
from typing import Dict, List, Set, Tuple
from src.models import (
    AttackIncident,
    AttackStep,
    EnrichedSecurityEvent,
    KillChainStage,
    SeverityLevel,
)


def parse_time(ts: str) -> datetime:
    """
    Parses ISO 8601 string to a timezone-aware datetime object.
    """
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def map_tactic_to_stage(tactic: str) -> KillChainStage:
    """
    Maps MITRE ATT&CK tactics to KillChainStage enum.
    """
    t = tactic.lower()
    if "recon" in t:
        return KillChainStage.RECONNAISSANCE
    elif "initial" in t:
        return KillChainStage.INITIAL_ACCESS
    elif "credential" in t:
        return KillChainStage.CREDENTIAL_ACCESS
    elif "execution" in t:
        return KillChainStage.EXECUTION
    elif "privilege" in t or "evasion" in t or "persistence" in t:
        return KillChainStage.PRIVILEGE_ESCALATION
    elif "collection" in t or "exfiltration" in t:
        return KillChainStage.EXFILTRATION
    return KillChainStage.UNKNOWN


class ThreatCorrelator:
    def __init__(self) -> None:
        pass

    def correlate(
        self,
        events: List[EnrichedSecurityEvent],
        time_window_minutes: int = 60,
        max_campaign_duration_minutes: int = 240,
    ) -> List[AttackIncident]:
        """
        Correlates enriched security events into AttackIncidents based on actor IPs, users,
        and temporal proximity with dual-bounded sliding windows:
        1. Maximum Inter-Event Gap: time_window_minutes (default: 60 min)
        2. Maximum Campaign Duration: max_campaign_duration_minutes (default: 240 min)
        """
        if not events:
            return []

        # Sort events chronologically
        sorted_events = sorted(events, key=lambda e: parse_time(e.base_event.timestamp))

        # Groups: List of Lists of EnrichedSecurityEvent
        groups: List[List[EnrichedSecurityEvent]] = []

        for event in sorted_events:
            evt_ip = event.base_event.source_ip
            evt_user = event.base_event.user
            evt_time = parse_time(event.base_event.timestamp)

            matched_group = None
            for group in groups:
                last_evt = group[-1]
                last_time = parse_time(last_evt.base_event.timestamp)
                time_diff_mins = (evt_time - last_time).total_seconds() / 60.0

                root_evt = group[0]
                root_time = parse_time(root_evt.base_event.timestamp)
                total_duration_mins = (evt_time - root_time).total_seconds() / 60.0

                if time_diff_mins <= time_window_minutes and total_duration_mins <= max_campaign_duration_minutes:
                    # Link by IP or User
                    group_ips = {
                        e.base_event.source_ip
                        for e in group
                        if e.base_event.source_ip and e.base_event.source_ip != "127.0.0.1"
                    }
                    group_users = {
                        e.base_event.user
                        for e in group
                        if e.base_event.user
                    }

                    # IP match: public IP matches public IP in group
                    ip_match = evt_ip and evt_ip != "127.0.0.1" and evt_ip in group_ips
                    
                    # User match: username matches, but only if the event shows suspicious indicators (risk > 0)
                    # to prevent normal baseline activity of common service users (like db_webapp) from merging.
                    user_match = (
                        evt_user and
                        evt_user in group_users and
                        event.risk_score > 0
                    )

                    # Loopback IP action matching targeted user in incident (local commands executed by attacker)
                    local_actor_match = (
                        evt_ip in ["127.0.0.1", None] and
                        evt_user and
                        evt_user in group_users
                    )

                    if ip_match or user_match or local_actor_match:
                        matched_group = group
                        break

            if matched_group is not None:
                matched_group.append(event)
            else:
                groups.append([event])

        incidents: List[AttackIncident] = []

        for group in groups:
            # Check repeated auth failures within group to promote to FAILED_AUTH_BURST
            auth_fail_count = sum(
                1 for e in group
                if "AUTH_FAILURE" in e.indicators or "FAILED_AUTH_BURST" in e.indicators
            )
            if auth_fail_count >= 2:
                for e in group:
                    if "AUTH_FAILURE" in e.indicators and "FAILED_AUTH_BURST" not in e.indicators:
                        e.indicators.append("FAILED_AUTH_BURST")
                        e.risk_score = max(e.risk_score, 35)
                        if e.severity in [SeverityLevel.INFO, SeverityLevel.LOW]:
                            e.severity = SeverityLevel.MEDIUM

            # 1. Determine unique Kill Chain stages represented
            stages_set: Set[KillChainStage] = set()
            max_risk = 0
            
            for event in group:
                max_risk = max(max_risk, event.risk_score)
                # Map tactics
                for tactic in event.mitre_tactics:
                    stage = map_tactic_to_stage(tactic)
                    if stage != KillChainStage.UNKNOWN:
                        stages_set.add(stage)
                # If no tactics are present, default to UNKNOWN
                if not event.mitre_tactics:
                    stages_set.add(KillChainStage.UNKNOWN)

            # We discard UNKNOWN from the unique stage count unless it is the only one
            active_stages = stages_set - {KillChainStage.UNKNOWN}
            num_stages = len(active_stages)

            # 2. Filter: at least 2+ distinct kill chain stages OR risk score > 60
            if num_stages < 2 and max_risk <= 60:
                continue

            # 3. Build steps
            steps: List[AttackStep] = []
            targeted_users: Set[str] = set()
            primary_actor_ip = "Unknown"

            for event in group:
                # Find primary public actor IP - anchor to the first non-local IP and don't overwrite it
                if primary_actor_ip in ["Unknown", "127.0.0.1"]:
                    if event.base_event.source_ip and event.base_event.source_ip != "127.0.0.1":
                        primary_actor_ip = event.base_event.source_ip

                if event.base_event.user:
                    targeted_users.add(event.base_event.user)

                # Primary stage/technique matching
                primary_stage = KillChainStage.UNKNOWN
                if event.mitre_tactics:
                    primary_stage = map_tactic_to_stage(event.mitre_tactics[0])

                technique_str = "N/A - Legitimate Action"
                if event.mitre_techniques:
                    t_info = event.mitre_techniques[0]
                    technique_str = f"{t_info['id']} - {t_info['name']}"

                desc = f"Accessed {event.base_event.resource or 'N/A'} (Status: {event.base_event.status or 'N/A'})"
                if event.indicators:
                    desc += f" [Indicators: {', '.join(event.indicators)}]"

                actor_str = f"{event.base_event.source_ip or 'Unknown'} -> {event.base_event.user or 'None'}"

                step = AttackStep(
                    stage=primary_stage,
                    timestamp=event.base_event.timestamp,
                    technique=technique_str,
                    description=desc,
                    actor=actor_str,
                    risk_score=event.risk_score,
                    step_index=len(steps),
                    parent_step_id=steps[-1].step_id if steps else None,
                )
                steps.append(step)

            # 4. Overall severity and confidence calculation
            severity_order = {
                SeverityLevel.INFO: 1,
                SeverityLevel.LOW: 2,
                SeverityLevel.MEDIUM: 3,
                SeverityLevel.HIGH: 4,
                SeverityLevel.CRITICAL: 5,
            }
            overall_severity = max(group, key=lambda e: severity_order[e.severity]).severity

            # Confidence score: base confidence + stage count factor + risk score factor
            confidence_score = min(30 + num_stages * 12 + int(max_risk * 0.25), 100)

            # Chronological bounds
            start_time = steps[0].timestamp
            end_time = steps[-1].timestamp

            incident = AttackIncident(
                primary_actor_ip=primary_actor_ip,
                targeted_users=sorted(list(targeted_users)),
                start_time=start_time,
                end_time=end_time,
                overall_severity=overall_severity,
                confidence_score=confidence_score,
                stages_detected=sorted(list(active_stages), key=lambda s: s.name),
                steps=steps,
            )
            incidents.append(incident)

        return incidents
