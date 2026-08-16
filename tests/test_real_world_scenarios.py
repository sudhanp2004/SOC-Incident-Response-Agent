import shutil
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "bots_samples" / "episode_0000.json"


def test_get_real_world_scenario_returns_observation_and_chain(tmp_path, monkeypatch):
    import scenarios.real_world_scenarios as mod
    shutil.copy(FIXTURE, tmp_path / "episode_0000.json")
    monkeypatch.setattr(mod, "_DATA_DIR", tmp_path)
    result = mod.get_real_world_scenario(seed=0)
    assert result["observation"].task_id == "real_world_incident"
    assert len(result["observation"].active_alerts) == 2
    assert result["attack_chain"].patient_zero_host == "HOST-10-0-2-10"


def test_get_real_world_scenario_raises_if_no_episodes(tmp_path, monkeypatch):
    import scenarios.real_world_scenarios as mod
    monkeypatch.setattr(mod, "_DATA_DIR", tmp_path)
    with pytest.raises(RuntimeError, match="build_real_world_scenarios"):
        mod.get_real_world_scenario(seed=0)
