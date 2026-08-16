"""
FastAPI server — OpenEnv HTTP interface.

Endpoints:
  POST /reset   -> Observation (JSON)
  POST /step    -> {observation, reward, done, info}
  GET  /state   -> EnvState (JSON)
  GET  /tasks   -> list of tasks
  POST /grade   -> {task_id, score, breakdown}
"""
import os
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from soc_env import SOCEnv, Action
from soc_env.graders import (
    grade_task_easy_detailed,
    grade_task_medium_detailed,
    grade_task_hard_detailed,
)

app = FastAPI(
    title="SOC Incident Response — OpenEnv",
    description="Real-world cybersecurity SOC environment for training AI agents.",
    version="1.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_envs: Dict[str, SOCEnv] = {}
TASK_METADATA = [
    {
        "id": "alert_triage",
        "difficulty": "easy",
        "max_steps": 10,
        "name": "Alert triage",
        "description": "Classify noisy SIEM alerts, enrich the useful ones, and contain the true positives.",
    },
    {
        "id": "attack_chain_reconstruction",
        "difficulty": "medium",
        "max_steps": 25,
        "name": "Attack chain reconstruction",
        "description": "Correlate alerts across hosts, identify the ATT&CK chain, and stop lateral movement.",
    },
    {
        "id": "constrained_incident_response",
        "difficulty": "hard",
        "max_steps": 40,
        "name": "Constrained incident response",
        "description": "Respond to an active breach while respecting legal hold, customer-facing, and hard-block constraints.",
    },
    {
        "id": "real_world_incident",
        "difficulty": "medium",
        "max_steps": 25,
        "name": "Real-world incident",
        "description": "Same attack-chain task, backed by real log data converted from the Splunk BOTS dataset instead of a fixed scenario.",
    },
]


def _get_env(task_id: str) -> SOCEnv:
    if task_id not in _envs:
        raise HTTPException(status_code=400, detail=f"Call POST /reset with task_id='{task_id}' first.")
    return _envs[task_id]


class ResetRequest(BaseModel):
    task_id: str = "alert_triage"
    seed: int = 42


class StepRequest(BaseModel):
    task_id: str = "alert_triage"
    action: Action


@app.get("/")
def root():
    """Serve React frontend."""
    static_dir = Path(__file__).parent / "web" / "dist"
    index_file = static_dir / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"name": "SOC Incident Response OpenEnv", "version": "1.0.0",
            "tasks": SOCEnv.TASK_IDS, "docs": "/docs"}


@app.get("/api/tasks")
def list_tasks():
    return {"tasks": TASK_METADATA}


@app.post("/reset")
def reset(req: Optional[ResetRequest] = None):
    """Reset environment for a task. Returns initial Observation."""
    if req is None:
        req = ResetRequest()
    if req.task_id not in SOCEnv.TASK_IDS:
        raise HTTPException(status_code=400, detail=f"task_id must be one of {SOCEnv.TASK_IDS}")
    env = SOCEnv(task_id=req.task_id, seed=req.seed)
    _envs[req.task_id] = env
    obs = env.reset()
    return obs.model_dump_safe()


@app.post("/step")
def step(req: StepRequest):
    """Advance environment one step."""
    env = _get_env(req.task_id)
    try:
        obs, reward, done, info = env.step(req.action)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"observation": obs.model_dump_safe(), "reward": reward.model_dump(), "done": done, "info": info}


@app.get("/state")
def state(task_id: str = "alert_triage"):
    """Full environment state including ground truth (for grading/debugging)."""
    return _get_env(task_id).state().model_dump()


@app.post("/grade")
def grade(task_id: str = "alert_triage"):
    """Grade current episode. Returns score 0.0–1.0 with breakdown."""
    env = _get_env(task_id)
    s = env.state()
    if task_id == "alert_triage":
        breakdown, score = grade_task_easy_detailed(s)
    elif task_id in ("attack_chain_reconstruction", "real_world_incident"):
        breakdown, score = grade_task_medium_detailed(s)
    else:
        breakdown, score = grade_task_hard_detailed(s)
    return {"task_id": task_id, "score": round(score, 4), "breakdown": breakdown}


# Updated catch-all route to exclude static file requests
@app.get("/{path_name:path}")
def serve_frontend(path_name: str):
    """Catch-all route to serve React app for client-side routing."""
    static_dir = Path(__file__).parent / "web" / "dist"
    index_file = static_dir / "index.html"

    # Exclude static file requests
    if (static_dir / path_name).exists():
        return FileResponse(static_dir / path_name)

    if index_file.exists():
        return FileResponse(index_file)
    return {"error": "Frontend not built. Run: cd web && npm run build"}


# Mount static assets from dist (this runs before catch-all due to FastAPI routing order)
static_dir = Path(__file__).parent / "web" / "dist"
if static_dir.exists():
    # Mount assets subdirectory
    app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
