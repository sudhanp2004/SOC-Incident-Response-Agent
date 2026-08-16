import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "bots_samples"


def _run_build(raw_dir: Path, out_dir: Path) -> subprocess.CompletedProcess:
    env = {
        "BOTS_RAW_DIR": str(raw_dir),
        "BOTS_OUT_DIR": str(out_dir),
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "build_real_world_scenarios.py")],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
    )


def test_build_fails_cleanly_when_raw_dir_missing(tmp_path):
    missing_dir = tmp_path / "does_not_exist"
    out_dir = tmp_path / "out"
    result = _run_build(missing_dir, out_dir)
    assert result.returncode == 1
    assert "missing or empty" in result.stdout


def test_build_writes_episode_files(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    (raw_dir / "suricata_eve.json").write_text((FIXTURES / "suricata_sample.jsonl").read_text())
    (raw_dir / "cloudtrail.json").write_text((FIXTURES / "cloudtrail_sample.jsonl").read_text())
    (raw_dir / "dns_stream.json").write_text((FIXTURES / "dns_sample.jsonl").read_text())
    out_dir = tmp_path / "out"

    result = _run_build(raw_dir, out_dir)

    assert result.returncode == 0, result.stdout + result.stderr
    written = sorted(out_dir.glob("episode_*.json"))
    assert len(written) >= 1
    episode = json.loads(written[0].read_text())
    assert "alerts" in episode and "hosts" in episode and "attack_chain" in episode


def test_build_writes_episodes_with_tp_and_fp_alerts(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    (raw_dir / "suricata_eve.json").write_text((FIXTURES / "suricata_sample.jsonl").read_text())
    (raw_dir / "cloudtrail.json").write_text((FIXTURES / "cloudtrail_sample.jsonl").read_text())
    (raw_dir / "dns_stream.json").write_text((FIXTURES / "dns_sample.jsonl").read_text())
    out_dir = tmp_path / "out"

    result = _run_build(raw_dir, out_dir)

    assert result.returncode == 0, result.stdout + result.stderr
    written = sorted(out_dir.glob("episode_*.json"))
    assert len(written) >= 1
    for path in written:
        episode = json.loads(path.read_text())
        ground_truths = [a["ground_truth"] for a in episode["alerts"]]
        assert any(g is True for g in ground_truths), f"{path} has no TP alert"
        assert any(g is False for g in ground_truths), f"{path} has no FP alert"
