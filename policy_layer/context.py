"""
context.py — Out-of-Band Trusted Context Builder.

Architecture Step:
  Validate & Snapshot Action ──► Build Trusted Context ──► Policy Judge LLM
"""

import datetime
from typing import Any, Dict, List
from tools import PurchaseManager


class TrustedContext:
    """
    Out-of-band context collected from persistent systems (not from the LLM prompt).
    Prevents prompt injection from falsifying authorization limits.
    """

    def __init__(
        self,
        daily_spent: float,
        daily_budget: float,
        trusted_domains: List[str],
        protected_asset_descriptions: List[str],
        caller_role: str = "ai_task_agent",
    ):
        self.daily_spent = daily_spent
        self.daily_budget = daily_budget
        self.remaining_budget = max(0.0, daily_budget - daily_spent)
        self.trusted_domains = trusted_domains
        self.protected_asset_descriptions = protected_asset_descriptions
        self.caller_role = caller_role
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "daily_spent": self.daily_spent,
            "daily_budget": self.daily_budget,
            "remaining_budget": self.remaining_budget,
            "trusted_domains": self.trusted_domains,
            "protected_asset_descriptions": self.protected_asset_descriptions,
            "caller_role": self.caller_role,
        }


class TrustedContextBuilder:
    """Constructs live out-of-band context for the Policy Judge LLM."""

    def __init__(self, purchase_mgr: PurchaseManager):
        self.purchase_mgr = purchase_mgr
        self.daily_budget = 5000.0
        self.trusted_domains = ["company.com", "corp.internal", "trusted-partner.org"]
        self.protected_asset_descriptions = [
            "Root secrets, API credentials, and environment configuration (.env)",
            "Private SSH keys and asymmetric authentication material (.ssh/id_rsa)",
            "Mission-critical production database files (system/production_db.sqlite)",
            "Proprietary customer credentials and system passwords",
        ]

    def build_context(self) -> TrustedContext:
        """Pulls real-time metrics directly from system state."""
        return TrustedContext(
            daily_spent=self.purchase_mgr.total_spent,
            daily_budget=self.daily_budget,
            trusted_domains=self.trusted_domains,
            protected_asset_descriptions=self.protected_asset_descriptions,
            caller_role="standard_agent_worker",
        )
