"""Scenario loader dispatcher for SOC OpenEnv tasks."""
from __future__ import annotations

from typing import Any, Dict

from .easy_scenarios import get_easy_scenario
from .medium_scenarios import get_medium_scenario
from .hard_scenarios import get_hard_scenario
from .real_world_scenarios import get_real_world_scenario


def load_scenario(task_id: str, seed: int = 42) -> Dict[str, Any]:
	"""Return the scenario payload for a given task id."""
	if task_id == "alert_triage":
		return get_easy_scenario(seed=seed)
	if task_id == "attack_chain_reconstruction":
		return get_medium_scenario(seed=seed)
	if task_id == "constrained_incident_response":
		return get_hard_scenario(seed=seed)
	if task_id == "real_world_incident":
		return get_real_world_scenario(seed=seed)
	raise ValueError(f"Unknown task_id: {task_id}")


__all__ = ["load_scenario"]
