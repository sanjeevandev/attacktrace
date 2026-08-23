from typing import List, Tuple
from src.collector import LogCollector
from src.parser import SecurityParser
from src.correlation import ThreatCorrelator
from src.models import EnrichedSecurityEvent, AttackIncident


class AttackTracePipeline:
    def __init__(self) -> None:
        self.collector = LogCollector()
        self.parser = SecurityParser()
        self.correlator = ThreatCorrelator()
        
        self.enriched_events: List[EnrichedSecurityEvent] = []
        self.incidents: List[AttackIncident] = []

    def run_batch(self, file_path: str) -> List[EnrichedSecurityEvent]:
        """
        Runs ingestion on raw logs, processes valid items, and enriches them.
        Returns a list of EnrichedSecurityEvent instances.
        """
        self.collector.clear()
        self.collector.ingest_json_file(file_path)

        self.enriched_events = []
        for event in self.collector.valid_events:
            enriched = self.parser.parse(event)
            self.enriched_events.append(enriched)

        return self.enriched_events

    def run_pipeline(self, file_path: str, time_window_minutes: int = 60) -> List[AttackIncident]:
        """
        Runs the full 3-layer pipeline:
        1. Ingests raw logs (L1)
        2. Enriches with threat indicators & MITRE ATT&CK mappings (L2)
        3. Correlates events into attack incidents (L3)
        Returns the correlated AttackIncident list.
        """
        # Run Ingestion & Enrichment (Layers 1 and 2)
        self.run_batch(file_path)
        
        # Run Correlation (Layer 3)
        self.incidents = self.correlator.correlate(
            self.enriched_events, 
            time_window_minutes=time_window_minutes
        )
        
        return self.incidents

    def run_pipeline_list(self, log_list: List[dict], time_window_minutes: int = 60) -> List[AttackIncident]:
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

        self.incidents = self.correlator.correlate(
            self.enriched_events,
            time_window_minutes=time_window_minutes
        )
        return self.incidents

