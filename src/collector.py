import json
import os
from typing import Any, Dict, List, Tuple

from src.models import UnifiedEvent


class LogCollector:
    def __init__(self) -> None:
        self.valid_events: List[UnifiedEvent] = []
        # dropped_events: list of dicts, e.g., [{"record": record, "error": error_reason}]
        self.dropped_events: List[Dict[str, Any]] = []

    def ingest_json_file(self, file_path: str) -> Tuple[int, int]:
        """
        Reads a JSON file containing an array of logs.
        Attempts to parse each record into a UnifiedEvent.
        Appends successfully parsed events to valid_events.
        Appends failed records (with error info) to dropped_events.
        Returns:
            (len(valid_events), len(dropped_events))
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                # If the entire file is invalid JSON, we raise the error so it can be handled
                raise ValueError(f"Failed to parse JSON file structure: {e}")

        if not isinstance(data, list):
            raise ValueError("Root of JSON log file must be a JSON array (list)")

        for record in data:
            try:
                # Ensure the record is a dictionary before parsing
                if not isinstance(record, dict):
                    raise ValueError(f"Log record must be a dictionary, got {type(record).__name__}")
                
                event = UnifiedEvent.from_dict(record)
                self.valid_events.append(event)
            except Exception as e:
                self.dropped_events.append({
                    "record": record,
                    "error": str(e)
                })

        return len(self.valid_events), len(self.dropped_events)

    def ingest_log_list(self, data: List[Dict[str, Any]]) -> Tuple[int, int]:
        """
        Ingests a list of raw log record dictionaries.
        Attempts to parse each record into a UnifiedEvent.
        Appends successfully parsed events to valid_events.
        Appends failed records to dropped_events.
        """
        if not isinstance(data, list):
            raise ValueError("Log data must be a list")

        for record in data:
            try:
                if not isinstance(record, dict):
                    raise ValueError(f"Log record must be a dictionary, got {type(record).__name__}")
                
                event = UnifiedEvent.from_dict(record)
                self.valid_events.append(event)
            except Exception as e:
                self.dropped_events.append({
                    "record": record,
                    "error": str(e)
                })

        return len(self.valid_events), len(self.dropped_events)


    def get_summary(self) -> Dict[str, int]:
        """
        Returns a dictionary mapping event_type -> count for all valid events.
        """
        summary: Dict[str, int] = {}
        for event in self.valid_events:
            summary[event.event_type] = summary.get(event.event_type, 0) + 1
        return summary

    def clear(self) -> None:
        """
        Resets both valid_events and dropped_events lists.
        """
        self.valid_events.clear()
        self.dropped_events.clear()
