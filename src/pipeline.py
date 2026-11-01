from typing import List, Optional, Tuple
from src.collector import LogCollector
from src.parser import SecurityParser
from src.correlation import ThreatCorrelator
from src.models import EnrichedSecurityEvent, AttackIncident
from src.db import DatabaseManager


class AttackTracePipeline:
    def __init__(self, db: Optional[DatabaseManager] = None) -> None:
        self.collector = LogCollector()
        self.parser = SecurityParser()
        self.correlator = ThreatCorrelator()
        self.db = db
        
        self.enriched_events: List[EnrichedSecurityEvent] = []
        self.incidents: List[AttackIncident] = []

    def run_batch(
        self, file_path: str, is_demo: bool = False, file_type: str = "auto"
    ) -> List[EnrichedSecurityEvent]:
        """
        Runs ingestion on raw logs, processes valid items, and enriches them.
        Supports multi-format auto-detection (.json, .jsonl, .log, .syslog, Windows events).
        Returns a list of EnrichedSecurityEvent instances.
        """
        self.collector.clear()
        self.collector.auto_ingest_file(file_path, file_type=file_type)

        self.enriched_events = []
        for event in self.collector.valid_events:
            enriched = self.parser.parse(event)
            self.enriched_events.append(enriched)

        if self.db:
            self.db.save_enriched_events(self.enriched_events, is_demo=is_demo)

        return self.enriched_events

    def run_pipeline(
        self,
        file_path: str,
        time_window_minutes: int = 60,
        max_campaign_duration_minutes: int = 240,
        is_demo: bool = False,
        file_type: str = "auto",
    ) -> List[AttackIncident]:
        """
        Runs the full 3-layer pipeline:
        1. Ingests raw logs across multiple formats via LogCollector (L1)
        2. Enriches with threat indicators & MITRE ATT&CK mappings (L2)
        3. Correlates events into attack incidents (L3)
        Returns the correlated AttackIncident list.
        """
        # Run Ingestion & Enrichment (Layers 1 and 2)
        self.run_batch(file_path, is_demo=is_demo, file_type=file_type)
        
        # Run Correlation (Layer 3)
        self.incidents = self.correlator.correlate(
            self.enriched_events, 
            time_window_minutes=time_window_minutes,
            max_campaign_duration_minutes=max_campaign_duration_minutes,
        )

        if self.db:
            for inc in self.incidents:
                self.db.save_incident(inc, is_demo=is_demo)
        
        return self.incidents

    def run_pipeline_list(
        self,
        log_list: List[dict],
        time_window_minutes: int = 60,
        max_campaign_duration_minutes: int = 240,
        is_demo: bool = False,
    ) -> List[AttackIncident]:
        """
        Runs the full 3-layer pipeline on a list of raw log record dictionaries.
        1. Ingests raw logs (L1)
        2. Enriches with threat indicators & MITRE ATT&CK mappings (L2)
        3. Correlates events into attack incidents (L3)
        Returns the correlated AttackIncident list.
        """
        self.collector.clear()
        self.collector.ingest_log_list(log_list)

        self.enriched_events = []
        for event in self.collector.valid_events:
            enriched = self.parser.parse(event)
            self.enriched_events.append(enriched)

        if self.db:
            self.db.save_enriched_events(self.enriched_events, is_demo=is_demo)

        self.incidents = self.correlator.correlate(
            self.enriched_events,
            time_window_minutes=time_window_minutes,
            max_campaign_duration_minutes=max_campaign_duration_minutes,
        )

        if self.db:
            for inc in self.incidents:
                self.db.save_incident(inc, is_demo=is_demo)

        return self.incidents
