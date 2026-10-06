"""
approval.py — Human-in-the-Loop Approval Service & Action Revalidation.

Architecture Steps:
  Decision == ASK_USER ──► Approval Service (Queue Ticket)
  Approval Service ──► Approved ──► Revalidate Action (RV) ──► Controlled Executor
"""

import uuid
import datetime
from typing import Any, Dict, Optional, Tuple
from policy_layer.snapshot import ActionSnapshot
from policy_layer.judge import PolicyDecision
from policy_layer.context import TrustedContext


class ApprovalService:
    """
    Manages asynchronous human-in-the-loop (HITL) approval tickets.
    Holds the original cryptographic snapshot for revalidation before execution.
    """

    def __init__(self):
        self.pending_tickets: Dict[str, Dict[str, Any]] = {}
        self.resolved_tickets: Dict[str, Dict[str, Any]] = {}

    def create_ticket(
        self,
        snapshot: ActionSnapshot,
        decision: PolicyDecision,
        context: TrustedContext,
    ) -> str:
        ticket_id = f"tkt_{uuid.uuid4().hex[:8]}"
        self.pending_tickets[ticket_id] = {
            "ticket_id": ticket_id,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "snapshot_obj": snapshot,
            "snapshot": snapshot.to_dict(),
            "decision": decision.to_dict(),
            "context": context.to_dict(),
            "status": "PENDING",
            "resolution": None,
        }
        return ticket_id

    def resolve_ticket(
        self,
        ticket_id: str,
        approved: bool,
        operator_notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        if ticket_id not in self.pending_tickets:
            return None

        ticket = self.pending_tickets.pop(ticket_id)
        ticket["status"] = "APPROVED" if approved else "REJECTED"
        ticket["resolved_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        ticket["operator_notes"] = operator_notes
        self.resolved_tickets[ticket_id] = ticket
        return ticket


class ActionRevalidator:
    """
    Step 'RV' in architecture flowchart:
    Revalidates the Action Snapshot before Controlled Executor is triggered on an approved ticket.
    Protects against parameter alteration between approval and execution.
    """

    @staticmethod
    def revalidate(snapshot: ActionSnapshot) -> Tuple[bool, str]:
        if not snapshot.verify_integrity():
            return False, "Integrity check failed: Snapshot hash does not match serialized action."
        return True, "Integrity confirmed. Action matches original human-approved intent."
