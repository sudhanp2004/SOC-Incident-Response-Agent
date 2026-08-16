---
title: MetaXRL Soc-OpenEnv
emoji: 🐳
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
license: mit
---

# SOC Incident Response OpenEnv

## Problem Statement

Security Operations Center teams handle large alert volumes, multi-stage attacks, and conflicting business constraints during active incidents. This project turns that real workflow into a trainable and testable OpenEnv benchmark.

The goal is to evaluate how well an agent can:

- triage noisy SIEM alerts
- reconstruct attack chains across hosts
- contain threats without violating critical business constraints

This environment is designed for hackathon-style validation and reproducible benchmarking.

## What This Project Implements

- Real-world SOC simulation (not a toy domain)
- Full OpenEnv interface with typed models
- `reset()`, `step()`, `state()` contract
- Three tasks with difficulty progression
- Deterministic graders returning scores in `[0.0, 1.0]`
- Dense reward shaping with partial progress signals
- Baseline inference script using OpenAI client against an OpenAI-compatible endpoint
- FastAPI backend and React frontend console for local and judge demos
- Docker + Hugging Face Spaces compatible packaging

## Core Workflow (Conceptual)

This project has three separate layers:

1. Environment
   The simulator generates observations, applies actions, tracks state, and emits rewards.

2. Policy Model
   The baseline model reads observations and outputs one JSON action per step.

3. Grader
   At episode end, deterministic graders map final state to a score from `0.0` to `1.0`.

In short: `observation -> action -> step -> reward -> final grade`.

## Tasks

| ID | Difficulty | Max Steps | Objective |
|---|---|---:|---|
| `alert_triage` | Easy | 10 | Classify and contain true positives while avoiding false-positive containment |
| `attack_chain_reconstruction` | Medium | 25 | Correlate alerts across hosts, recover ATT&CK chain context, contain correctly |
| `constrained_incident_response` | Hard | 40 | Balance security, continuity, and compliance under hard business constraints |

## Real-World Task Data (`real_world_incident`)

The 4th task's alerts are converted from Splunk's public "Boss of the SOC"
(BOTS v1) dataset rather than hand-written. The raw dataset (~8GB) is not
included in this repo. To (re)build the episode bank:

1. Download BOTS v1 from Splunk's public dataset registry.
2. Place `suricata_eve.json`, `cloudtrail.json`, and `dns_stream.json` (one
   JSON object per line) into `data_pipeline/raw/`.
3. Run:
   ```bash
   python tools/build_real_world_scenarios.py
   ```
4. Commit the generated `scenarios/data/real_world/episode_*.json` files —
   these are small (converted/summarized alerts, not raw logs) and are what
   the environment actually reads at game-time.

Ground truth (real threat vs. noise) comes from `data_pipeline/known_iocs.json`
— a small, hand-curated list of indicators sourced from BOTS' own public
answer key, not from automatic detection.

## API Endpoints

- `POST /reset`
- `POST /step`
- `GET /state`
- `POST /grade`
- `GET /api/tasks`

## Local Setup

### 1) Python dependencies

```bash
pip install -r requirements.txt
pip install -e . --no-deps
```

### 2) Frontend dependencies

```bash
cd web
npm install
cd ..
```

## Run Locally (Recommended Terminal Layout)

Use two terminals.

### Terminal A: backend

```powershell
python server.py
```

Backend should be live at:

- `http://127.0.0.1:7860/docs`

### Terminal B: frontend

```powershell
cd web
$env:VITE_API_BASE_URL="http://127.0.0.1:7860"
npm run dev
```

Frontend should be live at:

- `http://localhost:5173`

## How To Test Locally (Backend-Only)

This is the fastest way to validate API behavior before UI checks.

### Step 1: reset

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:7860/reset" -ContentType "application/json" -Body '{"task_id":"alert_triage","seed":42}'
```

### Step 2: step

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:7860/step" -ContentType "application/json" -Body '{"task_id":"alert_triage","action":{"action_type":"enrich_alert","alert_id":"ALT-001","source":"threat_intel"}}'
```

### Step 3: state

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:7860/state?task_id=alert_triage"
```

### Step 4: grade

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:7860/grade?task_id=alert_triage"
```

Important: Always call `reset` first for a task before calling `step` or `grade`.

## How To Test Locally (Frontend Console)

After backend + frontend are running:

1. Open `http://localhost:5173`
2. Select a task on the left panel
3. Click `Reset episode`
4. Confirm `Current observation` and `Backend state` are populated
5. Click `Load suggested action` or edit JSON manually
6. Click `Execute draft action`
7. Optionally click `Run guided demo`
8. Click `Grade current episode`

You should see trace events, reward updates, and a final score breakdown.

## Baseline Inference Script

`inference.py` runs all three tasks by default and writes `baseline_results.json`.

Required environment variables:

- `API_BASE_URL`
- `MODEL_NAME`
- `HF_TOKEN`

Example (PowerShell):

```powershell
$env:API_BASE_URL="https://router.huggingface.co/v1"
$env:MODEL_NAME="meta-llama/Llama-3.3-70B-Instruct"
$env:HF_TOKEN="hf_your_token_here"
python inference.py
```

Single task:

```powershell
python inference.py --task alert_triage
```

## Expected Output Artifacts

- Console logs per step with action and reward
- Final scores per task
- `baseline_results.json` in repo root

## Common Errors and Fixes

### 400 on `/step` in UI

Cause:
- Episode not reset for the selected task.

Fix:
- Click `Reset episode` first, then run step.

### 401 Invalid username or password in `inference.py`

Cause:
- Invalid or missing token/model access.

Fix:
- Verify `HF_TOKEN` is set in the same terminal session.
- Verify token has access to chosen model.
- Verify endpoint and model name are valid.

### Frontend cannot reach backend

Cause:
- Wrong API base URL.

Fix:
- Start backend on `127.0.0.1:7860`.
- Start frontend with `VITE_API_BASE_URL=http://127.0.0.1:7860`.

## Tests

Run unit tests:

```powershell
pytest tests -q
```

## Docker

```bash
docker build -t soc-openenv .
docker run -p 7860:7860 \
  -e API_BASE_URL="https://router.huggingface.co/v1" \
  -e MODEL_NAME="meta-llama/Llama-3.3-70B-Instruct" \
  -e HF_TOKEN="hf_your_token_here" \
  soc-openenv
```

## Validation Before Submission

```bash
./validate.sh
./validate.sh https://YOUR_USERNAME-soc-openenv.hf.space
```

## Hugging Face Spaces

Set these Space secrets:

- `API_BASE_URL`
- `MODEL_NAME`
- `HF_TOKEN`

## Project Structure

```text
soc-openenv/
├── openenv.yaml
├── Dockerfile
├── requirements.txt
├── pyproject.toml
├── README.md
├── inference.py
├── server.py
├── validate.sh
├── soc_env/
├── scenarios/
├── tests/
└── web/
```

## Contact

ankit.k23@iiits.in
