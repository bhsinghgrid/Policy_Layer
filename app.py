"""
app.py — FastAPI Application Server for AI Policy Layer.

Provides REST API endpoints for:
  - Direct Agent execution (Unprotected baseline)
  - Governed Agent execution (Policy Layer protected)
  - Interactive Human Approval ticket resolution with Action Revalidation
  - Sandbox file listing, inspection, and environment resets
  - Persistent Audit Ledger inspection
  - Serving the modern side-by-side comparison UI
"""

import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

load_dotenv()  # Loads GEMINI_API_KEY from .env
ENV_API_KEY = os.getenv("GEMINI_API_KEY", "")

from tools import FileManager, EmailSender, PurchaseManager, reset_sandbox
from agent import run_agent
from policy_layer import (
    TrustedContextBuilder,
    PolicyJudge,
    PersistentAuditLedger,
    ApprovalService,
    ActionRevalidator,
    ControlledExecutor,
    run_governed_agent,
)

# ── Core Adapter Instances ──
file_mgr = FileManager()
email_sender = EmailSender()
purchase_mgr = PurchaseManager()

# ── Policy Layer Components ──
context_builder = TrustedContextBuilder(purchase_mgr)
judge = PolicyJudge(context_builder)
audit_ledger = PersistentAuditLedger()
approval_service = ApprovalService()
controlled_executor = ControlledExecutor(file_mgr, email_sender, purchase_mgr)


# ── Request / Response Models ──
class ExecuteRequest(BaseModel):
    prompt: str
    api_key: str = ""  # Optional — falls back to .env GEMINI_API_KEY
    model: str = "gemini-3.8-flash"


class ResolveRequest(BaseModel):
    ticket_id: str
    approved: bool
    comment: str = ""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Seed the sandbox filesystem upon application startup."""
    reset_sandbox()
    yield


app = FastAPI(title="AI Policy Layer Governance Platform", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── API Routes ──

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "has_env_key": bool(ENV_API_KEY),
        "default_model": "gemini-3.8-flash",
    }


@app.post("/api/direct/execute")
async def execute_direct(req: ExecuteRequest):
    """Executes prompt via Direct Agent (UNPROTECTED baseline)."""
    key = req.api_key.strip() or ENV_API_KEY
    if not key:
        raise HTTPException(
            status_code=400,
            detail="Gemini API key is required. Set GEMINI_API_KEY in .env or provide it in the request.",
        )
    return run_agent(
        prompt=req.prompt,
        api_key=key,
        file_mgr=file_mgr,
        email_sender=email_sender,
        purchase_mgr=purchase_mgr,
        model_name=req.model,
    )


@app.post("/api/governed/execute")
async def execute_governed(req: ExecuteRequest):
    """Executes prompt via Governed Agent (Policy Layer Active)."""
    key = req.api_key.strip() or ENV_API_KEY
    if not key:
        raise HTTPException(
            status_code=400,
            detail="Gemini API key is required. Set GEMINI_API_KEY in .env or provide it in the request.",
        )
    return run_governed_agent(
        prompt=req.prompt,
        api_key=key,
        file_mgr=file_mgr,
        email_sender=email_sender,
        purchase_mgr=purchase_mgr,
        judge=judge,
        audit=audit_ledger,
        approval_service=approval_service,
        model_name=req.model,
    )


@app.get("/api/sandbox/files")
async def sandbox_files():
    """List current files in sandbox filesystem."""
    return file_mgr.list_files("")


@app.get("/api/sandbox/file-content")
async def sandbox_file_content(path: str = Query(..., description="Relative path of file")):
    """Read file content for inspector modal."""
    return file_mgr.read_file(path)


@app.post("/api/sandbox/reset")
async def sandbox_reset():
    """Wipe and restore sandbox files, outbox, purchases, approvals, and audit log."""
    reset_sandbox()
    email_sender.outbox.clear()
    purchase_mgr.transactions.clear()
    purchase_mgr.total_spent = 0.0
    audit_ledger.entries.clear()
    approval_service.pending_tickets.clear()
    approval_service.resolved_tickets.clear()
    return {"status": "ok", "message": "Sandbox environment, logs, and state fully reset."}


@app.get("/api/approvals")
async def list_approvals():
    """List pending tickets in Human-in-the-Loop queue."""
    pending = []
    for tid, t in approval_service.pending_tickets.items():
        pending.append({
            "ticket_id": t["ticket_id"],
            "created_at": t["created_at"],
            "snapshot": t["snapshot"],
            "decision": t["decision"],
            "context": t.get("context", {}),
            "status": t["status"],
        })
    return {
        "pending": pending,
        "resolved_count": len(approval_service.resolved_tickets),
    }


@app.post("/api/approvals/resolve")
async def resolve_approval(req: ResolveRequest):
    """
    Operator approves or rejects a pending ticket.
    If approved, performs Step RV (Action Revalidation) before Controlled Execution.
    """
    ticket = approval_service.resolve_ticket(
        ticket_id=req.ticket_id,
        approved=req.approved,
        operator_notes=req.comment,
    )
    if not ticket:
        raise HTTPException(status_code=404, detail=f"Ticket '{req.ticket_id}' not found.")

    execution_result = None
    revalidation_status = None

    if req.approved:
        snap_obj = ticket.get("snapshot_obj")
        if not snap_obj:
            execution_result = {"success": False, "error": "Missing snapshot object for ticket."}
        else:
            # ── ARCHITECTURE STEP: REVALIDATE ACTION (RV) ──
            is_valid, msg = ActionRevalidator.revalidate(snap_obj)
            revalidation_status = {"valid": is_valid, "message": msg}

            if is_valid:
                # ── ARCHITECTURE STEP: CONTROLLED EXECUTOR (EX) ──
                execution_result = controlled_executor.execute(snap_obj.tool_name, snap_obj.args)

                # Record execution in persistent audit log
                audit_ledger.record(
                    snapshot=snap_obj,
                    decision=judge.evaluate(snap_obj, api_key=ENV_API_KEY)[0],
                    executed=True,
                    result=execution_result,
                    ticket_id=req.ticket_id,
                )
            else:
                execution_result = {
                    "success": False,
                    "error": f"Revalidation failed: {msg}",
                    "blocked_by_policy": True,
                }

    return {
        "ticket_id": req.ticket_id,
        "status": ticket["status"],
        "revalidation": revalidation_status,
        "execution_result": execution_result,
    }


@app.get("/api/audit")
async def get_audit():
    """Returns the latest 50 entries from the immutable audit ledger."""
    return {"entries": list(reversed(audit_ledger.entries[-50:]))}


# ── Static UI Mounting ──
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(frontend_dir, "index.html"))
