#!/usr/bin/env python3
"""One-time offline build script: raw BOTS logs -> scenarios/data/real_world/*.json

Usage:
    python tools/build_real_world_scenarios.py

Env vars:
    BOTS_RAW_DIR  Directory containing suricata_eve.json / cloudtrail.json / dns_stream.json
                  (default: data_pipeline/raw)
    BOTS_OUT_DIR  Directory to write episode_*.json files to
                  (default: scenarios/data/real_world)
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from data_pipeline.assembler import assemble_episodes
from data_pipeline.mapper import load_ioc_table
from data_pipeline.parsers import parse_cloudtrail, parse_dns, parse_suricata

RAW_DIR = Path(os.environ.get("BOTS_RAW_DIR", REPO_ROOT / "data_pipeline" / "raw"))
OUT_DIR = Path(os.environ.get("BOTS_OUT_DIR", REPO_ROOT / "scenarios" / "data" / "real_world"))
IOC_PATH = REPO_ROOT / "data_pipeline" / "known_iocs.json"

SOURCES = [
    ("suricata_eve.json", parse_suricata),
    ("cloudtrail.json", parse_cloudtrail),
    ("dns_stream.json", parse_dns),
]


def main() -> int:
    if not RAW_DIR.exists() or not any(RAW_DIR.iterdir()):
        print(f"ERROR: raw data directory {RAW_DIR} is missing or empty.")
        print("Download BOTS v1 and place its log files there before running this script.")
        return 1

    ioc_table = load_ioc_table(IOC_PATH)
    events = []
    skipped = 0
    for filename, parser in SOURCES:
        path = RAW_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = parser(line)
                if event is None:
                    skipped += 1
                else:
                    events.append(event)

    print(f"Parsed {len(events)} events, skipped {skipped} malformed lines.")

    episodes = assemble_episodes(events, ioc_table)
    if not episodes:
        print("ERROR: no valid episodes assembled (need windows with both real threats and noise).")
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for old in OUT_DIR.glob("episode_*.json"):
        old.unlink()
    for i, episode in enumerate(episodes):
        with open(OUT_DIR / f"episode_{i:04d}.json", "w") as f:
            json.dump(episode, f, indent=2)

    print(f"Wrote {len(episodes)} episodes to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
