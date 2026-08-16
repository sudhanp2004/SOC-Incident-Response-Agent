"""Ground-truth labeling and RawEvent -> SIEMAlert/NetworkHost schema mapping."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Set

from soc_env.models import (
    AlertSeverity, HostStatus, MITRETactic, NetworkHost, SIEMAlert, ThreatIndicator,
)
from .parsers import RawEvent


def load_ioc_table(path: str | Path) -> Dict[str, Set[str]]:
    with open(path) as f:
        raw = json.load(f)
    return {k: set(v) for k, v in raw.items()}


def is_malicious(event: RawEvent, ioc_table: Dict[str, Set[str]]) -> bool:
    for kind, value in event.indicators:
        if value in ioc_table.get(kind, set()):
            return True
    return False


def _host_id(raw_host: str) -> str:
    return "HOST-" + raw_host.replace(".", "-")


def _tactic_for(event: RawEvent, malicious: bool):
    if not malicious:
        return None
    et = event.event_type.lower()
    if "scan" in et:
        return MITRETactic.DISCOVERY
    if "login" in et:
        return MITRETactic.CREDENTIAL_ACCESS
    if event.event_type == "dns_query":
        return MITRETactic.EXFILTRATION
    return None


def to_siem_alert(event: RawEvent, index: int, ioc_table: Dict[str, Set[str]]) -> SIEMAlert:
    malicious = is_malicious(event, ioc_table)
    return SIEMAlert(
        alert_id=f"ALT-RW-{index:04d}",
        timestamp=event.timestamp,
        severity=AlertSeverity.HIGH if malicious else AlertSeverity.LOW,
        rule_name=event.event_type,
        description=f"Auto-converted from real log data: {event.event_type}",
        host_id=_host_id(event.host),
        user_id=event.user,
        mitre_tactic=_tactic_for(event, malicious),
        indicators=[
            ThreatIndicator(
                type=kind,
                value=value,
                reputation="malicious" if value in ioc_table.get(kind, set()) else "unknown",
            )
            for kind, value in event.indicators
            if kind in ("ip", "hash", "domain", "user")
        ],
        raw_log=event.raw_line,
        ground_truth=malicious,
    )


def to_network_host(host_id: str, compromised: bool = False) -> NetworkHost:
    ip = host_id.replace("HOST-", "").replace("-", ".")
    return NetworkHost(
        host_id=host_id,
        hostname=host_id.lower(),
        ip_address=ip,
        subnet="0.0.0.0/0",
        os="unknown",
        role="unknown",
        is_critical=False,
        status=HostStatus.SUSPICIOUS if compromised else HostStatus.CLEAN,
    )
