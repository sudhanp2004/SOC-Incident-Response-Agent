"""Groups labeled RawEvents into time-window episodes with a synthesized AttackChain."""
from __future__ import annotations
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from .mapper import _host_id, to_network_host, to_siem_alert
from .parsers import RawEvent


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def assemble_episodes(
    events: List[RawEvent], ioc_table: Dict[str, Set[str]], window_minutes: int = 45
) -> List[Dict[str, Any]]:
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: _parse_ts(e.timestamp))
    episodes: List[Dict[str, Any]] = []
    bucket: List[RawEvent] = []
    window_end = _parse_ts(sorted_events[0].timestamp) + timedelta(minutes=window_minutes)

    for event in sorted_events:
        ts = _parse_ts(event.timestamp)
        if ts > window_end:
            episode = _build_episode(bucket, ioc_table)
            if episode:
                episodes.append(episode)
            bucket = []
            window_end = ts + timedelta(minutes=window_minutes)
        bucket.append(event)

    episode = _build_episode(bucket, ioc_table)
    if episode:
        episodes.append(episode)
    return episodes


def _build_episode(bucket: List[RawEvent], ioc_table: Dict[str, Set[str]]) -> Optional[Dict[str, Any]]:
    if not bucket:
        return None

    # bucket is time-sorted by the caller, and alerts are built in the same order,
    # so alerts is also time-sorted -- preserve that ordering for chronological logic.
    alerts = [to_siem_alert(e, i, ioc_table) for i, e in enumerate(bucket)]
    malicious_alerts = [a for a in alerts if a.ground_truth]
    benign_alerts = [a for a in alerts if not a.ground_truth]
    if not malicious_alerts or not benign_alerts:
        return None

    host_ids = sorted({a.host_id for a in alerts})
    malicious_hosts = sorted({a.host_id for a in malicious_alerts})
    hosts = [to_network_host(h, compromised=h in malicious_hosts) for h in host_ids]

    # Patient zero is the host of the chronologically-earliest malicious alert,
    # not the alphabetically-first host id.
    patient_zero = malicious_alerts[0].host_id
    lateral_targets = sorted(h for h in malicious_hosts if h != patient_zero)

    # Crown jewel: prefer a host explicitly configured as a crown jewel via known_iocs,
    # else fall back to a clean (non-malicious) host so containment scoring is meaningful,
    # else (last resort, old behavior) just take the last host id.
    crown_jewel_iocs = {_host_id(v) for v in ioc_table.get("crown_jewel", set())}
    configured_crown_jewels = [h for h in host_ids if h in crown_jewel_iocs]
    clean_hosts = [h for h in host_ids if h not in malicious_hosts]
    if configured_crown_jewels:
        crown_jewel = configured_crown_jewels[0]
    elif clean_hosts:
        crown_jewel = clean_hosts[0]
    else:
        crown_jewel = host_ids[-1]

    stages = sorted({a.mitre_tactic.value for a in malicious_alerts if a.mitre_tactic})
    if not stages:
        return None

    return {
        "alerts": [a.model_dump(mode="json") for a in alerts],
        "hosts": [h.model_dump(mode="json") for h in hosts],
        "attack_chain": {
            "patient_zero_host": patient_zero,
            "stages": stages,
            "lateral_movement_targets": lateral_targets,
            "crown_jewel_host": crown_jewel,
            "exfiltration_complete": False,
            "attacker_dwell_minutes": 45,
        },
    }
