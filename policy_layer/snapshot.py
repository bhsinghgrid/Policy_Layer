"""
snapshot.py — Action Gateway & Cryptographic Snapshot.

Architecture Step:
  Task Agent ──► Action Gateway ──► Validate & Snapshot Action (SHA-256)
"""

import json
import uuid
import hashlib
import datetime
from typing import Any, Dict


class ActionSnapshot:
    """
    An immutable cryptographic snapshot of an intercepted tool action.

    Guarantees:
      - Deep-copies arguments to freeze state.
      - Produces canonical JSON serialization (sorted keys, compact separators).
      - Computes SHA-256 digest to prevent Time-of-Check to Time-of-Use (TOCTOU) tampering.
    """

    def __init__(self, tool_name: str, args: Dict[str, Any]):
        self.snapshot_id = f"snap_{uuid.uuid4().hex[:10]}"
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.tool_name = tool_name
        self.args = json.loads(json.dumps(args))  # Frozen copy
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        canonical = json.dumps(
            {"tool": self.tool_name, "args": self.args},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify the snapshot has not been mutated since creation."""
        return self._compute_hash() == self.hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "tool": self.tool_name,
            "args": self.args,
            "hash": f"{self.hash[:16]}...",
            "full_hash": self.hash,
        }
