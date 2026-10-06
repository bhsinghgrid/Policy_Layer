"""
executor.py — Controlled Executor & Adapter Boundary.

Architecture Step:
  Decision == ALLOW (or Approved + Revalidated) ──► Controlled Executor ──► Tool Adapters
"""

from typing import Any, Dict
from tools import FileManager, EmailSender, PurchaseManager


class ControlledExecutor:
    """
    Safe execution proxy that dispatches authorized actions to underlying tool adapters.
    Catches and isolates adapter errors without compromising system stability.
    """

    def __init__(
        self,
        file_mgr: FileManager,
        email_sender: EmailSender,
        purchase_mgr: PurchaseManager,
    ):
        self.file_mgr = file_mgr
        self.email_sender = email_sender
        self.purchase_mgr = purchase_mgr

    def execute(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch action to specific adapter."""
        try:
            if tool_name == "read_file":
                return self.file_mgr.read_file(args.get("path", ""))
            elif tool_name == "write_file":
                return self.file_mgr.write_file(args.get("path", ""), args.get("content", ""))
            elif tool_name == "delete_file":
                return self.file_mgr.delete_file(args.get("path", ""))
            elif tool_name == "list_files":
                return self.file_mgr.list_files(args.get("directory", ""))
            elif tool_name == "send_email":
                return self.email_sender.send_email(
                    args.get("to", ""),
                    args.get("subject", ""),
                    args.get("body", ""),
                )
            elif tool_name == "make_purchase":
                return self.purchase_mgr.make_purchase(
                    args.get("vendor", ""),
                    args.get("item", ""),
                    float(args.get("amount", 0)),
                )
            else:
                return {"success": False, "error": f"Unknown executor target: {tool_name}"}
        except Exception as err:
            return {"success": False, "error": f"Adapter execution failure: {str(err)}"}
