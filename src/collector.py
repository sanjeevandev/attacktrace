import json
import os
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

from src.models import UnifiedEvent
from src.adapters import WindowsEventAdapter, SyslogAdapter, WebLogAdapter


def stream_jsonl_chunks(file_path: str, chunk_size: int = 1000) -> Generator[List[Tuple[int, str]], None, None]:
    """
    Memory-efficient streaming generator that yields batches of (line_number, line_str)
    from a Newline-Delimited JSON (.jsonl) file to avoid Out-Of-Memory (OOM) crashes.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        chunk: List[Tuple[int, str]] = []
        for line_num, line in enumerate(f, start=1):
            chunk.append((line_num, line))
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk


class LogCollector:
    """
    Security Telemetry Collector supporting multi-format and streaming ingestion.
    Supports standard JSON arrays, line-by-line JSONL streaming, Windows Security Event
    Logs (EVTX/JSON), RFC 3164/5424 Syslog, and Apache/Nginx Web Server Access Logs.
    """

    def __init__(self) -> None:
        self.valid_events: List[UnifiedEvent] = []
        # dropped_events: list of dicts, e.g., [{"record": record, "error": error_reason, "line_number": n}]
        self.dropped_events: List[Dict[str, Any]] = []

    def ingest_json_file(self, file_path: str, record_provenance: bool = False) -> Tuple[int, int]:
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
                raise ValueError(f"Failed to parse JSON file structure: {e}")

        if not isinstance(data, list):
            raise ValueError("Root of JSON log file must be a JSON array (list)")

        for record in data:
            try:
                if not isinstance(record, dict):
                    raise ValueError(f"Log record must be a dictionary, got {type(record).__name__}")

                # Detect Windows event structure vs canonical UnifiedEvent
                if "EventID" in record or ("Event" in record and isinstance(record["Event"], dict)):
                    event = WindowsEventAdapter.normalize(record, provenance_file=file_path if record_provenance else None)
                else:
                    event = UnifiedEvent.from_dict(record)
                    if record_provenance and isinstance(event.raw_payload, dict):
                        event.raw_payload["_provenance_file"] = os.path.abspath(file_path)
                        event.raw_payload["is_demo"] = False

                self.valid_events.append(event)
            except Exception as e:
                self.dropped_events.append({
                    "record": record,
                    "error": str(e)
                })

        return len(self.valid_events), len(self.dropped_events)

    def ingest_jsonl_file(self, file_path: str, chunk_size: int = 1000) -> Tuple[int, int]:
        """
        Reads a .jsonl file line-by-line using a streaming generator to prevent OOM errors on large files.
        Validates and parses each line into UnifiedEvent.
        Quarantines broken JSON lines into dropped_events with line numbers and reasons.
        Returns:
            (len(valid_events), len(dropped_events))
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

        for chunk in stream_jsonl_chunks(file_path, chunk_size=chunk_size):
            for line_num, line in chunk:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                    if not isinstance(record, dict):
                        raise ValueError(f"JSON line must be a JSON object, got {type(record).__name__}")

                    # Check if Windows Security Event
                    if "EventID" in record or ("Event" in record and isinstance(record["Event"], dict)):
                        event = WindowsEventAdapter.normalize(record, provenance_file=file_path)
                    else:
                        event = UnifiedEvent.from_dict(record)
                        if isinstance(event.raw_payload, dict):
                            event.raw_payload["_provenance_file"] = os.path.abspath(file_path)
                            event.raw_payload["is_demo"] = False

                    self.valid_events.append(event)
                except Exception as e:
                    self.dropped_events.append({
                        "line_number": line_num,
                        "line": stripped,
                        "record": stripped,
                        "error": str(e)
                    })

        return len(self.valid_events), len(self.dropped_events)

    def ingest_windows_events(
        self, records: List[Union[Dict[str, Any], str]], provenance_file: Optional[str] = None
    ) -> Tuple[int, int]:
        """
        Normalizes a list of Windows Security Event records into UnifiedEvent instances.
        """
        for record in records:
            try:
                event = WindowsEventAdapter.normalize(record, provenance_file=provenance_file)
                self.valid_events.append(event)
            except Exception as e:
                self.dropped_events.append({
                    "record": record,
                    "error": str(e)
                })
        return len(self.valid_events), len(self.dropped_events)

    def ingest_windows_file(self, file_path: str) -> Tuple[int, int]:
        """
        Ingests a JSON or JSONL file containing Windows Security Events.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

        # Check if first character is '[' (JSON array) or '{' (JSONL)
        with open(file_path, "r", encoding="utf-8") as f:
            first_char = f.read(1)

        if first_char == "[":
            return self.ingest_json_file(file_path)
        else:
            return self.ingest_jsonl_file(file_path)

    def ingest_syslog_file(self, file_path: str) -> Tuple[int, int]:
        """
        Ingests an RFC 3164 or RFC 5424 Syslog file line-by-line.
        Appends parsed events to valid_events and failed lines to dropped_events.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    event = SyslogAdapter.parse_line(stripped, provenance_file=file_path)
                    self.valid_events.append(event)
                except Exception as e:
                    self.dropped_events.append({
                        "line_number": line_num,
                        "line": stripped,
                        "record": stripped,
                        "error": str(e)
                    })

        return len(self.valid_events), len(self.dropped_events)

    def ingest_web_log_file(self, file_path: str) -> Tuple[int, int]:
        """
        Ingests an Apache or Nginx Web Server Access Log file (Combined or Common format).
        Appends parsed events to valid_events and failed lines to dropped_events.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    event = WebLogAdapter.parse_line(stripped, provenance_file=file_path)
                    self.valid_events.append(event)
                except Exception as e:
                    self.dropped_events.append({
                        "line_number": line_num,
                        "line": stripped,
                        "record": stripped,
                        "error": str(e)
                    })

        return len(self.valid_events), len(self.dropped_events)

    def auto_ingest_file(self, file_path: str, file_type: str = "auto") -> Tuple[int, int]:
        """
        Automatically detects log telemetry format and routes to the appropriate adapter.
        Supported explicit types: 'json', 'jsonl', 'windows', 'syslog', 'web', or 'auto'.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

        file_type = (file_type or "auto").lower()

        # Explicit routing
        if file_type == "json":
            return self.ingest_json_file(file_path, record_provenance=True)
        elif file_type == "jsonl":
            return self.ingest_jsonl_file(file_path)
        elif file_type == "windows":
            return self.ingest_windows_file(file_path)
        elif file_type == "syslog":
            return self.ingest_syslog_file(file_path)
        elif file_type in ("web", "apache", "nginx"):
            return self.ingest_web_log_file(file_path)

        # Automatic detection
        ext = os.path.splitext(file_path)[1].lower()

        if ext == ".jsonl":
            return self.ingest_jsonl_file(file_path)

        # Inspect head of file
        with open(file_path, "r", encoding="utf-8") as f:
            sample_lines = [f.readline() for _ in range(5)]
            sample = "".join(sample_lines).strip()

        if not sample:
            return 0, 0

        # Check for JSON array
        if sample.startswith("["):
            return self.ingest_json_file(file_path, record_provenance=True)

        # Check for JSON object line (JSONL or Windows event)
        if sample.startswith("{"):
            if "EventID" in sample or '"Event"' in sample:
                return self.ingest_windows_file(file_path)
            return self.ingest_jsonl_file(file_path)

        # Check for Web Access Log pattern
        first_line = sample_lines[0].strip()
        if WebLogAdapter.COMBINED_PATTERN.match(first_line):
            return self.ingest_web_log_file(file_path)

        # Check for Syslog pattern or .syslog extension
        if ext in (".syslog",) or SyslogAdapter.RFC5424_PATTERN.match(first_line) or SyslogAdapter.RFC3164_PATTERN.match(first_line):
            return self.ingest_syslog_file(file_path)

        # Default fallback for .log or text files
        if ext == ".log":
            # Test if web log or syslog
            if WebLogAdapter.COMBINED_PATTERN.match(first_line):
                return self.ingest_web_log_file(file_path)
            return self.ingest_syslog_file(file_path)

        # Final fallback: try jsonl, then syslog
        try:
            return self.ingest_jsonl_file(file_path)
        except Exception:
            return self.ingest_syslog_file(file_path)

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

                if "EventID" in record or ("Event" in record and isinstance(record["Event"], dict)):
                    event = WindowsEventAdapter.normalize(record)
                else:
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
