"""
SOCEnv — main OpenEnv environment class.

Public interface (OpenEnv spec):
  reset()        -> Observation
  step(action)   -> (Observation, Reward, done: bool, info: dict)
  state()        -> EnvState
  grade()        -> float  [0.0, 1.0]
"""
from __future__ import annotations
import copy
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    Action, ActionType, AlertStatus, Observation, Reward, EnvState,
    InvestigationNote, MITRETactic, HostStatus, BusinessConstraint,
    NetworkHost, SIEMAlert,
)


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_scenario(task_id: str, seed: int) -> Dict[str, Any]:
    """Import scenarios module with robust path resolution."""
    # Add repo root to path so 'scenarios' package is always found
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    from scenarios import load_scenario
    return load_scenario(task_id, seed=seed)


class SOCEnv:
    """Security Operations Center OpenEnv environment."""

    TASK_IDS = [
        "alert_triage",
        "attack_chain_reconstruction",
        "constrained_incident_response",
        "real_world_incident",
    ]
    MAX_STEPS = {
        "alert_triage": 10,
        "attack_chain_reconstruction": 25,
        "constrained_incident_response": 40,
        "real_world_incident": 25,
    }
    MAX_MINUTES = {
        "alert_triage": 30,
        "attack_chain_reconstruction": 120,
        "constrained_incident_response": 240,
        "real_world_incident": 120,
    }
    MINUTES_PER_STEP = {
        "alert_triage": 3,
        "attack_chain_reconstruction": 5,
        "constrained_incident_response": 6,
        "real_world_incident": 5,
    }

    def __init__(self, task_id: str = "alert_triage", seed: int = 42):
        if task_id not in self.TASK_IDS:
            raise ValueError(f"task_id must be one of {self.TASK_IDS}")
        self.task_id = task_id
        self.seed = seed
        self._state: Optional[EnvState] = None

    # ------------------------------------------------------------------
    # OpenEnv public interface
    # ------------------------------------------------------------------

    def reset(self) -> Observation:
        """Initialise episode. Returns first Observation."""
        scenario = _load_scenario(self.task_id, self.seed)
        self._state = EnvState(
            task_id=self.task_id,
            step=0,
            done=False,
            cumulative_reward=0.0,
            observation=scenario["observation"],
            attack_chain=scenario.get("attack_chain"),
            agent_classifications={},
            identified_stages=[],
            isolated_hosts=[],
            disabled_accounts=[],
            forensics_collected={},
            escalated=False,
            ticket_created=False,
        )
        return copy.deepcopy(self._state.observation)

    def step(self, action: Action) -> Tuple[Observation, Reward, bool, Dict[str, Any]]:
        """Advance environment one step. Returns (obs, reward, done, info)."""
        if self._state is None:
            raise RuntimeError("Call reset() before step().")
        if self._state.done:
            raise RuntimeError("Episode done. Call reset() to start a new episode.")

        s = self._state
        s.step += 1
        s.observation.step = s.step
        s.observation.steps_remaining = self.MAX_STEPS[self.task_id] - s.step
        s.observation.elapsed_minutes = min(
            s.observation.elapsed_minutes + self.MINUTES_PER_STEP[self.task_id],
            self.MAX_MINUTES[self.task_id],
        )

        action_result, action_ok = self._apply_action(action, s)
        s.observation.last_action_result = action_result
        s.observation.last_action_success = action_ok

        s.observation.notes.append(InvestigationNote(
            step=s.step,
            action_taken=action.action_type.value,
            finding=action_result,
            timestamp=_ts(),
        ))

        reward = self._compute_reward(action, s, action_ok)
        s.cumulative_reward = round(s.cumulative_reward + reward.total, 4)
        s.done = self._check_done(s)

        # Move non-pending alerts to acknowledged list
        s.observation.acknowledged_alerts = [
            a for a in s.observation.active_alerts + s.observation.acknowledged_alerts
            if a.status != AlertStatus.PENDING
        ]
        s.observation.active_alerts = [
            a for a in s.observation.active_alerts
            if a.status == AlertStatus.PENDING
        ]

        info = {
            "cumulative_reward": s.cumulative_reward,
            "step": s.step,
            "identified_stages": [st.value for st in s.identified_stages],
            "isolated_hosts": s.isolated_hosts,
            "done": s.done,
        }
        return copy.deepcopy(s.observation), reward, s.done, info

    def state(self) -> EnvState:
        """Return full environment state including ground truth (for grading)."""
        if self._state is None:
            raise RuntimeError("Call reset() before state().")
        return copy.deepcopy(self._state)

    def grade(self) -> float:
        """Run the grader on current state. Returns float in [0.0, 1.0]."""
        if self._state is None:
            raise RuntimeError("Call reset() and run an episode before grading.")
        from .graders import grade_task_easy, grade_task_medium, grade_task_hard
        s = self._state
        if self.task_id == "alert_triage":
            return grade_task_easy(s)
        elif self.task_id in ("attack_chain_reconstruction", "real_world_incident"):
            return grade_task_medium(s)
        else:
            return grade_task_hard(s)

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _apply_action(self, action: Action, s: EnvState) -> Tuple[str, bool]:
        t = action.action_type
        if t == ActionType.ENRICH_ALERT:
            return self._do_enrich(action, s)
        elif t == ActionType.CORRELATE_ALERTS:
            return self._do_correlate(action, s)
        elif t == ActionType.ISOLATE_ENDPOINT:
            return self._do_isolate(action, s)
        elif t == ActionType.DISABLE_ACCOUNT:
            return self._do_disable_account(action, s)
        elif t == ActionType.COLLECT_FORENSICS:
            return self._do_forensics(action, s)
        elif t == ActionType.ESCALATE_TO_TIER2:
            return self._do_escalate(action, s)
        elif t == ActionType.CREATE_TICKET:
            return self._do_ticket(action, s)
        return "Unknown action type.", False

    def _do_enrich(self, action: Action, s: EnvState) -> Tuple[str, bool]:
        alert = self._find_alert(action.alert_id, s)
        if not alert:
            return f"Alert {action.alert_id} not found.", False
        alert.status = AlertStatus.INVESTIGATING
        source = action.source or "threat_intel"
        enrichment: Dict[str, Any] = {"source": source, "retrieved_at": _ts()}
        if source == "threat_intel":
            enrichment["indicators_checked"] = len(alert.indicators)
            enrichment["malicious_hits"] = sum(
                1 for i in alert.indicators if i.reputation == "malicious"
            )
            for ind in alert.indicators:
                ind.reputation = ind.reputation or "unknown"
        elif source == "user_context":
            enrichment["user_id"] = alert.user_id
            enrichment["anomalous_behaviour"] = bool(alert.ground_truth)
        elif source == "asset_db":
            host = self._find_host(alert.host_id, s)
            enrichment["host_role"] = host.role if host else "unknown"
            enrichment["is_critical"] = host.is_critical if host else False
        alert.enrichment = enrichment
        return f"Enriched alert {action.alert_id} via {source}: {json.dumps(enrichment)}", True

    def _do_correlate(self, action: Action, s: EnvState) -> Tuple[str, bool]:
        if not action.alert_ids or len(action.alert_ids) < 2:
            return "correlate_alerts requires at least 2 alert_ids.", False
        all_alerts = s.observation.active_alerts + s.observation.acknowledged_alerts
        alerts = [a for a in all_alerts if a.alert_id in action.alert_ids]
        if len(alerts) < 2:
            return "Could not find 2+ valid alerts to correlate.", False
        new_tactics: List[MITRETactic] = []
        for a in alerts:
            if a.mitre_tactic and a.mitre_tactic not in s.identified_stages:
                s.identified_stages.append(a.mitre_tactic)
                new_tactics.append(a.mitre_tactic)
        return (
            f"Correlated {len(alerts)} alerts. "
            f"Hypothesis: {action.correlation_hypothesis or '(none)'}. "
            f"New ATT&CK tactics: {[t.value for t in new_tactics] or 'none'}."
        ), True

    def _do_isolate(self, action: Action, s: EnvState) -> Tuple[str, bool]:
        host = self._find_host(action.host_id, s)
        if not host:
            return f"Host {action.host_id} not found.", False
        for bc in s.observation.business_constraints:
            if bc.host_id == action.host_id and bc.constraint_type == "cannot_isolate":
                if bc.severity == "hard_block":
                    return f"BLOCKED: Cannot isolate {host.hostname}. Reason: {bc.reason}", False
        if host.status == HostStatus.ISOLATED:
            return f"{host.hostname} is already isolated.", False
        host.status = HostStatus.ISOLATED
        if action.host_id not in s.isolated_hosts:
            s.isolated_hosts.append(action.host_id)
        return f"Endpoint {host.hostname} ({host.ip_address}) isolated from network.", True

    def _do_disable_account(self, action: Action, s: EnvState) -> Tuple[str, bool]:
        if not action.user_id:
            return "user_id is required for disable_account.", False
        if action.user_id not in s.disabled_accounts:
            s.disabled_accounts.append(action.user_id)
        return f"Account {action.user_id} disabled. Active sessions terminated.", True

    def _do_forensics(self, action: Action, s: EnvState) -> Tuple[str, bool]:
        host = self._find_host(action.host_id, s)
        if not host:
            return f"Host {action.host_id} not found.", False
        artifacts = action.artifact_types or ["memory_dump", "event_logs"]
        s.forensics_collected[action.host_id] = list(
            set(s.forensics_collected.get(action.host_id, []) + artifacts)
        )
        for bc in s.observation.business_constraints:
            if bc.host_id == action.host_id and bc.constraint_type == "legal_hold":
                return (
                    f"Forensics collected from {host.hostname}: {artifacts}. "
                    f"LEGAL HOLD applied — evidence preserved per: {bc.reason}."
                ), True
        return f"Forensics collected from {host.hostname}: {artifacts}.", True

    def _do_escalate(self, action: Action, s: EnvState) -> Tuple[str, bool]:
        if s.escalated:
            return "Already escalated to Tier 2.", False
        s.escalated = True
        return f"Escalated to Tier 2. Summary: {action.summary or '(no summary provided)'}.", True

    def _do_ticket(self, action: Action, s: EnvState) -> Tuple[str, bool]:
        s.ticket_created = True
        return (
            f"Ticket created — priority {action.priority or 'P2'}. "
            f"Summary: {action.summary or '(no summary)'}."
        ), True

    # ------------------------------------------------------------------
    # Reward computation
    # ------------------------------------------------------------------

    def _compute_reward(self, action: Action, s: EnvState, action_ok: bool) -> Reward:
        r = Reward(total=0.0)
        if not action_ok:
            r.total = -0.02
            r.info = "invalid_action"
            return r

        t = action.action_type

        if t == ActionType.ENRICH_ALERT:
            r.classification_delta = 0.05
            r.info = "enrichment"

        elif t == ActionType.CORRELATE_ALERTS:
            r.chain_coverage_delta = round(len(s.identified_stages) * 0.08, 3)
            r.info = f"correlation_stages_{len(s.identified_stages)}"

        elif t == ActionType.ISOLATE_ENDPOINT:
            host = self._find_host(action.host_id, s)
            if host:
                chain = s.attack_chain
                in_chain = chain and (
                    action.host_id == chain.patient_zero_host
                    or action.host_id in chain.lateral_movement_targets
                )
                if in_chain:
                    r.containment_delta = 0.25
                    r.info = "correct_isolation"
                else:
                    r.fp_penalty = -0.20
                    r.info = "fp_isolation"

        elif t == ActionType.DISABLE_ACCOUNT:
            all_alerts = s.observation.active_alerts + s.observation.acknowledged_alerts
            alert_users = {a.user_id for a in all_alerts if a.user_id}
            if action.user_id in alert_users:
                r.containment_delta = 0.10
                r.info = "correct_account_disable"
            else:
                r.fp_penalty = -0.05
                r.info = "fp_account_disable"

        elif t == ActionType.COLLECT_FORENSICS:
            r.classification_delta = 0.05
            r.info = "forensics_collected"

        elif t == ActionType.ESCALATE_TO_TIER2:
            if s.observation.business_constraints:
                r.compliance_delta = 0.10
                r.info = "appropriate_escalation"
            else:
                r.fp_penalty = -0.05
                r.info = "premature_escalation"

        elif t == ActionType.CREATE_TICKET:
            r.compliance_delta = 0.05
            r.info = "ticket_created"

        r.dwell_penalty = round(-0.005 * self.MINUTES_PER_STEP[self.task_id], 4)
        r.total = round(
            r.classification_delta + r.chain_coverage_delta + r.containment_delta
            + r.fp_penalty + r.compliance_delta + r.dwell_penalty,
            4,
        )
        r.total = max(-1.0, min(1.0, r.total))
        return r

    # ------------------------------------------------------------------
    # Done condition
    # ------------------------------------------------------------------

    def _check_done(self, s: EnvState) -> bool:
        if s.step >= self.MAX_STEPS[self.task_id]:
            return True
        if s.attack_chain and s.attack_chain.exfiltration_complete:
            return True
        all_alerts = s.observation.active_alerts + s.observation.acknowledged_alerts
        closed_statuses = {AlertStatus.CONTAINED, AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE}
        if all_alerts and all(a.status in closed_statuses for a in all_alerts):
            return True
        return False

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_alert(alert_id: Optional[str], s: EnvState) -> Optional[SIEMAlert]:
        if not alert_id:
            return None
        for a in s.observation.active_alerts + s.observation.acknowledged_alerts:
            if a.alert_id == alert_id:
                return a
        return None

    @staticmethod
    def _find_host(host_id: Optional[str], s: EnvState) -> Optional[NetworkHost]:
        if not host_id:
            return None
        for h in s.observation.hosts:
            if h.host_id == host_id:
                return h
        return None
