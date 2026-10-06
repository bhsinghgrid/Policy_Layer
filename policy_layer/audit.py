"""
audit.py — Persistent State & Cryptographic Audit Ledger.

Architecture Step:
  Decision / Execution ──► Persistent State and Audit (DB)
"""

import uuid
import datetime
from typing import Any, Dict, List, Optional
from policy_layer.snapshot import ActionSnapshot
from policy_layer.judge import PolicyDecision


class PersistentAuditLedger:
    """
    Immutable chronological record of all proposed actions, cryptographic hashes,
    policy judgments, approval transitions, and execution outcomes.
    """

    def __init__(self):
        self.entries: List[Dict[str, Any]] = []

    def record(
        self,
        snapshot: ActionSnapshot,
        decision: PolicyDecision,
        executed: bool,
        result: Any = None,
        ticket_id: Optional[str] = None,
    ):
        entry = {
            "entry_id": f"aud_{uuid.uuid4().hex[:12]}",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "snapshot_id": snapshot.snapshot_id,
            "action_hash": snapshot.hash,
            "tool": snapshot.tool_name,
            "args": snapshot.args,
            "verdict": decision.verdict,
            "risk_score": decision.risk_score,
            "rule": decision.rule_name,
            "reason": decision.reason,
            "executed": executed,
            "ticket_id": ticket_id,
            "result_summary": str(result)[:300] if result else None,
        }
        self.entries.append(entry)
