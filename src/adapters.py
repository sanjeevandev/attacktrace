import json
import os
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from src.models import UnifiedEvent


class WindowsEventAdapter:
    """
    Adapter for normalizing Windows Security Event Log records (EVTX exports / JSON)
    into UnifiedEvent schema.
    Supported Event IDs:
      - 4624: Successful Logon (LOGIN_SUCCESS)
      - 4625: Failed Logon (LOGIN_FAILED)
      - 4688: Process Creation (PROCESS_CREATION)
      - 4672: Special Privileges Assigned (PRIVILEGE_ASSIGNED)
    """

    @staticmethod
    def _extract_field(raw: Dict[str, Any], names: List[str]) -> Optional[Any]:
        """Looks up a field across flat keys, Event.EventData, and Event.System."""
        # 1. Flat dictionary check
        for n in names:
            if n in raw and raw[n] not in (None, "", "-"):
                return raw[n]

        # 2. Check Event wrapper
        event = raw.get("Event", raw) if isinstance(raw, dict) else raw
        if not isinstance(event, dict):
            return None

        # Check EventData
        event_data = event.get("EventData", {})
        if isinstance(event_data, dict):
            for n in names:
                if n in event_data and event_data[n] not in (None, "", "-"):
                    return event_data[n]
        elif isinstance(event_data, list):
            # List of dicts like [{"@Name": "TargetUserName", "#text": "admin"}, ...]
            for item in event_data:
                if isinstance(item, dict):
                    item_name = item.get("@Name") or item.get("Name")
                    if item_name in names:
                        val = item.get("#text") or item.get("Value") or item.get("text")
                        if val not in (None, "", "-"):
                            return val

        # Check System
        system = event.get("System", {})
        if isinstance(system, dict):
            for n in names:
                if n in system and system[n] not in (None, "", "-"):
                    return system[n]

        return None

    @classmethod
    def normalize(cls, record: Union[Dict[str, Any], str], provenance_file: Optional[str] = None) -> UnifiedEvent:
        """
        Parses a Windows Security Event record into a canonical UnifiedEvent.
        """
        if isinstance(record, str):
            record = json.loads(record)

        if not isinstance(record, dict):
            raise ValueError(f"Windows event record must be a dict, got {type(record).__name__}")

        # Extract Event ID
        raw_event_id = cls._extract_field(record, ["EventID", "EventId", "event_id", "ID", "Id"])
        if raw_event_id is None:
            raise ValueError("Missing Windows EventID in log record")

        try:
            event_id = int(raw_event_id)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid Windows EventID: {raw_event_id}")

        # Extract timestamp
        raw_ts = cls._extract_field(
            record,
            ["TimeCreated", "timestamp", "TimeGenerated", "EventTime", "@SystemTime", "Date"]
        )
        if isinstance(raw_ts, dict):
            raw_ts = raw_ts.get("@SystemTime") or raw_ts.get("#text")

        if raw_ts and isinstance(raw_ts, str) and raw_ts.strip():
            timestamp = raw_ts.strip()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        # Build raw payload copy
        raw_payload = dict(record)
        if provenance_file:
            raw_payload["_provenance_file"] = os.path.abspath(provenance_file)
        raw_payload["is_demo"] = False

        # Extract common fields
        target_user = cls._extract_field(record, ["TargetUserName", "TargetUser", "user", "UserName"])
        subject_user = cls._extract_field(record, ["SubjectUserName", "SubjectUser", "user"])
        ip_addr = cls._extract_field(record, ["IpAddress", "SourceIp", "ClientIPAddress", "source_ip", "IPAddress"])
        if ip_addr in ("-", "::1", "127.0.0.1", ""):
            # Keep if provided or set None if placeholder dash
            if ip_addr == "-":
                ip_addr = None

        computer = cls._extract_field(record, ["Computer", "ComputerName", "WorkstationName", "Workstation"])

        # Map by Event ID
        if event_id == 4624:
            # Logon Success
            logon_type = cls._extract_field(record, ["LogonType", "logon_type"])
            user = target_user or subject_user
            resource = f"LogonType:{logon_type}" if logon_type else (computer or "Windows-Logon")
            return UnifiedEvent(
                timestamp=timestamp,
                source_type="windows_event",
                event_type="LOGIN_SUCCESS",
                user=user,
                source_ip=ip_addr,
                resource=resource,
                status=200,
                raw_payload=raw_payload,
            )

        elif event_id == 4625:
            # Logon Failed
            failure_reason = cls._extract_field(
                record, ["FailureReason", "Status", "SubStatus", "StatusDescription"]
            ) or "Logon Failure"
            user = target_user or subject_user
            return UnifiedEvent(
                timestamp=timestamp,
                source_type="windows_event",
                event_type="LOGIN_FAILED",
                user=user,
                source_ip=ip_addr,
                resource=str(failure_reason),
                status=401,
                raw_payload=raw_payload,
            )

        elif event_id == 4688:
            # Process Creation
            new_process = cls._extract_field(
                record, ["NewProcessName", "NewProcess", "CommandLine", "ProcessName", "resource"]
            )
            cmd_line = cls._extract_field(record, ["CommandLine", "ProcessCommandLine"])
            user = subject_user or target_user
            if cmd_line:
                raw_payload["CommandLine"] = cmd_line
            if new_process:
                raw_payload["NewProcessName"] = new_process

            return UnifiedEvent(
                timestamp=timestamp,
                source_type="windows_event",
                event_type="PROCESS_CREATION",
                user=user,
                source_ip=ip_addr or computer,
                resource=str(new_process) if new_process else (str(cmd_line) if cmd_line else "NewProcess"),
                status=0,
                raw_payload=raw_payload,
            )

        elif event_id == 4672:
            # Special Privileges Assigned
            privileges = cls._extract_field(record, ["PrivilegeList", "Privileges", "Privilege"])
            user = subject_user or target_user
            if privileges:
                raw_payload["PrivilegeList"] = privileges

            return UnifiedEvent(
                timestamp=timestamp,
                source_type="windows_event",
                event_type="PRIVILEGE_ASSIGNED",
                user=user,
                source_ip=ip_addr or computer,
                resource=str(privileges) if privileges else "SePrivilegesAssigned",
                status=0,
                raw_payload=raw_payload,
            )

        else:
            # Generic Windows event fallback
            user = target_user or subject_user
            return UnifiedEvent(
                timestamp=timestamp,
                source_type="windows_event",
                event_type=f"WINDOWS_{event_id}",
                user=user,
                source_ip=ip_addr,
                resource=computer,
                status=0,
                raw_payload=raw_payload,
            )


class SyslogAdapter:
    """
    Adapter for parsing RFC 3164 and RFC 5424 Syslog strings into UnifiedEvent schema.
    Detects SSH authentication attempts, sudo commands, and system notifications.
    """

    # RFC 5424 regex: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
    RFC5424_PATTERN = re.compile(
        r"^(?:<(?P<pri>\d{1,3})>)?(?P<version>\d+)\s+"
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T[^\s]+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<app>\S+)\s+"
        r"(?P<procid>\S+)\s+"
        r"(?P<msgid>\S+)\s*"
        r"(?P<sd>\[.*?\]|-)?\s*"
        r"(?P<msg>.*)$"
    )

    # RFC 3164 regex: <PRI>Mmm dd hh:mm:ss hostname app[pid]: message
    RFC3164_PATTERN = re.compile(
        r"^(?:<(?P<pri>\d{1,3})>)?(?P<timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<app>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<msg>.*)$"
    )

    # SSH failed password pattern
    SSH_FAILED_PATTERN = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE
    )

    # SSH accepted password or publickey pattern
    SSH_ACCEPTED_PATTERN = re.compile(
        r"Accepted (?:password|publickey|keyboard-interactive/pam)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE
    )

    # Sudo command pattern
    SUDO_PATTERN = re.compile(
        r"(?:sudo:\s*)?(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)",
        re.IGNORECASE
    )

    @classmethod
    def _parse_timestamp(cls, raw_ts: str) -> str:
        """Normalizes RFC 3164 or ISO timestamp to standard ISO 8601 UTC string."""
        raw_ts = raw_ts.strip()
        # Check if already ISO
        if "T" in raw_ts:
            return raw_ts

        # Parse BSD date like "Oct 24 14:02:10" or "Nov  1 08:30:15"
        try:
            # Replace multiple spaces with single space for single-digit days
            cleaned = re.sub(r"\s+", " ", raw_ts)
            dt = datetime.strptime(cleaned, "%b %d %H:%M:%S")
            year = datetime.now(timezone.utc).year
            normalized_dt = dt.replace(year=year, tzinfo=timezone.utc)
            return normalized_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return datetime.now(timezone.utc).isoformat()

    @classmethod
    def parse_line(cls, line: str, provenance_file: Optional[str] = None) -> UnifiedEvent:
        """
        Parses an RFC 3164 or RFC 5424 syslog string into a UnifiedEvent.
        """
        line_clean = line.strip()
        if not line_clean:
            raise ValueError("Empty syslog line")

        pri: Optional[int] = None
        timestamp = datetime.now(timezone.utc).isoformat()
        hostname: Optional[str] = None
        app: Optional[str] = None
        msg: str = line_clean

        m5424 = cls.RFC5424_PATTERN.match(line_clean)
        if m5424:
            pri = int(m5424.group("pri")) if m5424.group("pri") else None
            timestamp = cls._parse_timestamp(m5424.group("timestamp"))
            hostname = m5424.group("hostname")
            app = m5424.group("app")
            msg = m5424.group("msg")
        else:
            m3164 = cls.RFC3164_PATTERN.match(line_clean)
            if m3164:
                pri = int(m3164.group("pri")) if m3164.group("pri") else None
                timestamp = cls._parse_timestamp(m3164.group("timestamp"))
                hostname = m3164.group("hostname")
                app = m3164.group("app")
                msg = m3164.group("msg")
            else:
                # Lenient fallback if syslog has <PRI> but non-standard header
                pri_match = re.match(r"^<(?P<pri>\d{1,3})>(?P<rest>.*)$", line_clean)
                if pri_match:
                    pri = int(pri_match.group("pri"))
                    msg = pri_match.group("rest").strip()

        # Build raw payload dictionary
        raw_payload = {
            "raw_line": line_clean,
            "message": msg,
            "pri": pri,
            "hostname": hostname,
            "app": app,
            "is_demo": False,
        }
        if provenance_file:
            raw_payload["_provenance_file"] = os.path.abspath(provenance_file)

        # 1. Check SSH Failed login
        ssh_failed = cls.SSH_FAILED_PATTERN.search(msg)
        if ssh_failed:
            user = ssh_failed.group("user")
            ip = ssh_failed.group("ip")
            return UnifiedEvent(
                timestamp=timestamp,
                source_type="syslog",
                event_type="LOGIN_FAILED",
                user=user,
                source_ip=ip,
                resource=app or "sshd",
                status=401,
                raw_payload=raw_payload,
            )

        # 2. Check SSH Accepted login
        ssh_accepted = cls.SSH_ACCEPTED_PATTERN.search(msg)
        if ssh_accepted:
            user = ssh_accepted.group("user")
            ip = ssh_accepted.group("ip")
            return UnifiedEvent(
                timestamp=timestamp,
                source_type="syslog",
                event_type="LOGIN_SUCCESS",
                user=user,
                source_ip=ip,
                resource=app or "sshd",
                status=200,
                raw_payload=raw_payload,
            )

        # 3. Check sudo / privilege escalation
        sudo_match = cls.SUDO_PATTERN.search(msg) or cls.SUDO_PATTERN.search(line_clean)
        if sudo_match:
            user = sudo_match.group("user")
            cmd = sudo_match.group("cmd").strip()
            raw_payload["command"] = cmd
            return UnifiedEvent(
                timestamp=timestamp,
                source_type="syslog",
                event_type="PRIVILEGE_ASSIGNED",
                user=user,
                source_ip=hostname,
                resource=f"sudo {cmd}",
                status=0,
                raw_payload=raw_payload,
            )

        # 4. General Syslog Event
        return UnifiedEvent(
            timestamp=timestamp,
            source_type="syslog",
            event_type="SYSTEM_LOG",
            user=None,
            source_ip=hostname,
            resource=app or "syslog",
            status=0,
            raw_payload=raw_payload,
        )


class WebLogAdapter:
    """
    Adapter for parsing Apache / Nginx Combined Log Format and Common Log Format lines.
    Normalizes access requests into UnifiedEvent (source_type="web", event_type="API_REQUEST").
    Decodes URL parameters so MITRE signatures (e.g., SQLi, LFI, Admin Probing) match accurately.
    """

    # Combined Log Format: %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
    COMBINED_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+(?P<proto>HTTP/[\d\.]+))?"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    @classmethod
    def _parse_clf_timestamp(cls, raw_time: str) -> str:
        """Parses [01/Nov/2026:10:00:00 +0000] into standard ISO 8601 UTC string."""
        raw_time = raw_time.strip()
        try:
            dt = datetime.strptime(raw_time, "%d/%b/%Y:%H:%M:%S %z")
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return datetime.now(timezone.utc).isoformat()

    @classmethod
    def parse_line(cls, line: str, provenance_file: Optional[str] = None) -> UnifiedEvent:
        """
        Parses a single Combined Log Format or Common Log Format line into a UnifiedEvent.
        """
        line_clean = line.strip()
        if not line_clean:
            raise ValueError("Empty web log line")

        match = cls.COMBINED_PATTERN.match(line_clean)
        if not match:
            raise ValueError(f"Line does not conform to Web Server Access Log format: {line_clean[:80]}...")

        source_ip = match.group("ip")
        if source_ip == "-":
            source_ip = None

        raw_user = match.group("user")
        user = raw_user if raw_user and raw_user != "-" else None

        timestamp = cls._parse_clf_timestamp(match.group("time"))
        method = match.group("method")
        raw_url = match.group("url")
        status_code = int(match.group("status"))
        
        # Decode URL query strings to expose injection payloads like ' OR 1=1
        try:
            decoded_resource = urllib.parse.unquote(raw_url)
        except Exception:
            decoded_resource = raw_url

        user_agent = match.group("user_agent") or ""
        referer = match.group("referer") or ""
        size = match.group("size")

        raw_payload = {
            "http_method": method,
            "raw_url": raw_url,
            "resource": decoded_resource,
            "status_code": status_code,
            "user_agent": user_agent,
            "referer": referer,
            "bytes_sent": size,
            "raw_log": line_clean,
            "is_demo": False,
        }
        if provenance_file:
            raw_payload["_provenance_file"] = os.path.abspath(provenance_file)

        return UnifiedEvent(
            timestamp=timestamp,
            source_type="web",
            event_type="API_REQUEST",
            user=user,
            source_ip=source_ip,
            resource=decoded_resource,
            status=status_code,
            raw_payload=raw_payload,
        )
