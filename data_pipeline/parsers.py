"""Parsers converting raw BOTS-style JSON log lines into a common RawEvent shape."""
from __future__ import annotations
import json
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple


@dataclass
class RawEvent:
    timestamp: str
    host: str
    user: Optional[str]
    event_type: str
    indicators: List[Tuple[str, str]]
    raw_line: str


def parse_suricata(line: str) -> Optional[RawEvent]:
    try:
        d = json.loads(line)
        signature = d["alert"]["signature"]
        dest_ip = d["dest_ip"]
        src_ip = d["src_ip"]
        timestamp = d["timestamp"]
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return RawEvent(
            timestamp=timestamp,
            host=dest_ip,
            user=None,
            event_type=signature,
            indicators=[("ip", src_ip), ("ip", dest_ip)],
            raw_line=line,
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


def parse_cloudtrail(line: str) -> Optional[RawEvent]:
    try:
        d = json.loads(line)
        event_name = d["eventName"]
        source_ip = d["sourceIPAddress"]
        user_name = d["userIdentity"]["userName"]
        timestamp = d["eventTime"]
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return RawEvent(
            timestamp=timestamp,
            host=source_ip,
            user=user_name,
            event_type=event_name,
            indicators=[("user", user_name), ("ip", source_ip)],
            raw_line=line,
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


def parse_dns(line: str) -> Optional[RawEvent]:
    try:
        d = json.loads(line)
        src = d["src"]
        query = d["query"]
        answer = d.get("answer")
        indicators: List[Tuple[str, str]] = [("domain", query)]
        if answer:
            indicators.append(("ip", answer))
        timestamp = d["_time"]
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return RawEvent(
            timestamp=timestamp,
            host=src,
            user=None,
            event_type="dns_query",
            indicators=indicators,
            raw_line=line,
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None
