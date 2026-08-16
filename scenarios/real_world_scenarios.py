"""Real-world scenario loader — reads pre-built episodes derived from Splunk BOTS logs."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict

from soc_env.models import AttackChain, NetworkHost, Observation, SIEMAlert

_DATA_DIR = Path(__file__).resolve().parent / "data" / "real_world"


def _load_episode(seed: int) -> Dict[str, Any]:
    files = sorted(_DATA_DIR.glob("episode_*.json"))
    if not files:
        raise RuntimeError(
            "No real-world episodes found. Run tools/build_real_world_scenarios.py first."
        )
    path = files[seed % len(files)]
    with open(path) as f:
        return json.load(f)


def get_real_world_scenario(seed: int = 42) -> Dict[str, Any]:
    episode = _load_episode(seed)
    alerts = [SIEMAlert(**a) for a in episode["alerts"]]
    hosts = [NetworkHost(**h) for h in episode["hosts"]]
    chain = AttackChain(**episode["attack_chain"])

    obs = Observation(
        step=0,
        task_id="real_world_incident",
        task_description=(
            "ACTIVE INCIDENT — alerts derived from real security log data. "
            "Correlate alerts across hosts, identify the attack chain, and "
            "contain the threat before it reaches the crown jewel host."
        ),
        active_alerts=alerts,
        hosts=hosts,
        business_constraints=[],
        elapsed_minutes=0,
        max_minutes=120,
        steps_remaining=25,
    )
    return {"observation": obs, "attack_chain": chain}
