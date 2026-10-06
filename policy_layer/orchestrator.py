"""
orchestrator.py — Governed Agent Orchestration Loop.

Orchestrates the Task Agent and the Policy Layer:
  Task Agent proposes tool action
    ──► Action Gateway (Snapshot & Hash)
    ──► Trusted Context Builder
    ──► Policy Judge LLM (Gemini 3.8 Flash)
    ──► Decision Routing:
          - ALLOW    ──► Controlled Executor ──► Result to Agent + Audit
          - DENY     ──► Blocked Notice to Agent + Audit
          - ASK_USER ──► Approval Service (Ticket) + Audit
"""

import json
from typing import Any, Dict
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from tools import FileManager, EmailSender, PurchaseManager

from policy_layer.snapshot import ActionSnapshot
from policy_layer.judge import PolicyJudgeLLM, PolicyDecision, format_message_content
from policy_layer.approval import ApprovalService
from policy_layer.executor import ControlledExecutor
from policy_layer.audit import PersistentAuditLedger


def run_governed_agent(
    prompt: str,
    api_key: str,
    file_mgr: FileManager,
    email_sender: EmailSender,
    purchase_mgr: PurchaseManager,
    judge: PolicyJudgeLLM,
    audit: PersistentAuditLedger,
    approval_service: ApprovalService,
    model_name: str = "gemini-3.8-flash",
) -> Dict[str, Any]:
    """
    Runs the Task Agent governed by the Policy Layer.

    Every proposed tool call is intercepted, snapshotted, and semantically
    evaluated by the Policy Judge LLM before any adapter execution occurs.
    """
    try:
        executor = ControlledExecutor(file_mgr, email_sender, purchase_mgr)

        llm = ChatGoogleGenerativeAI(
            model=model_name,
            google_api_key=api_key,
            temperature=0.1,
        )

        # Register tools with LangChain
        @tool
        def read_file(path: str) -> str:
            """Read file contents from the sandbox filesystem."""
            return json.dumps({"action": "read_file", "path": path})

        @tool
        def write_file(path: str, content: str) -> str:
            """Write content to a file in the sandbox."""
            return json.dumps({"action": "write_file", "path": path, "content": content})

        @tool
        def delete_file(path: str) -> str:
            """Delete a file from the sandbox filesystem."""
            return json.dumps({"action": "delete_file", "path": path})

        @tool
        def list_files(directory: str = "") -> str:
            """List all files in the sandbox directory."""
            return json.dumps({"action": "list_files", "directory": directory})

        @tool
        def send_email(to: str, subject: str, body: str) -> str:
            """Send an email to a recipient address."""
            return json.dumps({"action": "send_email", "to": to, "subject": subject, "body": body})

        @tool
        def make_purchase(vendor: str, item: str, amount: float) -> str:
            """Make a corporate purchase order."""
            return json.dumps({"action": "make_purchase", "vendor": vendor, "item": item, "amount": amount})

        tools = [read_file, write_file, delete_file, list_files, send_email, make_purchase]
        llm_with_tools = llm.bind_tools(tools)

        system_instruction = (
            "You are an enterprise AI assistant operating within a strict Zero-Trust Policy Layer. "
            "Execute the user's instructions by proposing appropriate tool actions. "
            "If an action is blocked or queued for approval, acknowledge the security response respectfully "
            "and explain the policy reason to the user."
        )

        messages = [
            HumanMessage(content=f"{system_instruction}\n\nUser Request: {prompt}")
        ]

        policy_trace = []
        max_iterations = 5

        for step_idx in range(max_iterations):
            response = llm_with_tools.invoke(messages)
            messages.append(response)

            if not response.tool_calls:
                break

            for tc in response.tool_calls:
                tool_name = tc["name"]
                tool_args = tc["args"]

                # ── STEP 1: ACTION GATEWAY (SNAPSHOT & HASH) ──
                snapshot = ActionSnapshot(tool_name, tool_args)

                # ── STEP 2 & 3: POLICY JUDGE LLM (EVALUATE ACTION) ──
                decision, context = judge.evaluate(
                    snapshot=snapshot,
                    user_intent=prompt,
                    api_key=api_key,
                    model_name=model_name,
                )

                step_record = {
                    "step": step_idx + 1,
                    "tool": tool_name,
                    "args": tool_args,
                    "snapshot": snapshot.to_dict(),
                    "policy_decision": decision.to_dict(),
                    "trusted_context": context.to_dict(),
                    "executed": False,
                    "result": None,
                    "ticket_id": None,
                }

                # ── STEP 4: DECISION ROUTING ──
                if decision.verdict == PolicyDecision.ALLOW:
                    # Execute via Controlled Executor
                    exec_result = executor.execute(tool_name, tool_args)
                    step_record["executed"] = True
                    step_record["result"] = exec_result

                    audit.record(snapshot, decision, executed=True, result=exec_result)
                    messages.append(ToolMessage(content=json.dumps(exec_result), tool_call_id=tc["id"]))

                elif decision.verdict == PolicyDecision.DENY:
                    # Blocked: Do NOT execute. Return security denial notice to agent observation.
                    blocked_response = {
                        "success": False,
                        "blocked_by_policy": True,
                        "rule": decision.rule_name,
                        "reason": decision.reason,
                        "risk_score": decision.risk_score,
                    }
                    step_record["executed"] = False
                    step_record["result"] = {"blocked": True, "reason": decision.reason}

                    audit.record(snapshot, decision, executed=False, result=blocked_response)
                    messages.append(ToolMessage(content=json.dumps(blocked_response), tool_call_id=tc["id"]))

                elif decision.verdict == PolicyDecision.ASK_USER:
                    # Gated: Issue human-in-the-loop approval ticket
                    ticket_id = approval_service.create_ticket(snapshot, decision, context)
                    step_record["ticket_id"] = ticket_id

                    pending_response = {
                        "success": False,
                        "pending_approval": True,
                        "ticket_id": ticket_id,
                        "rule": decision.rule_name,
                        "reason": decision.reason,
                    }
                    step_record["result"] = {
                        "pending_approval": True,
                        "ticket_id": ticket_id,
                        "reason": decision.reason,
                    }

                    audit.record(snapshot, decision, executed=False, result=pending_response, ticket_id=ticket_id)
                    messages.append(ToolMessage(content=json.dumps(pending_response), tool_call_id=tc["id"]))

                policy_trace.append(step_record)

        # Synthesize clear final text
        final_text = ""
        for msg in reversed(messages):
            if isinstance(msg, AIMessage) and msg.content:
                text_content = format_message_content(msg.content)
                if text_content.strip():
                    final_text = text_content.strip()
                    break

        if not final_text and policy_trace:
            last_step = policy_trace[-1]
            verdict = last_step["policy_decision"]["verdict"]
            rule = last_step["policy_decision"]["rule"]
            if verdict == PolicyDecision.DENY:
                final_text = f"Action blocked by policy [{rule}]: {last_step['policy_decision']['reason']}"
            elif verdict == PolicyDecision.ASK_USER:
                final_text = f"Action placed in approval queue [{last_step['ticket_id']}]: {last_step['policy_decision']['reason']}"
            else:
                final_text = "Action cleared policy checks and executed successfully."

        return {
            "success": True,
            "agent_response": final_text,
            "tool_calls": policy_trace,
            "policy_trace": policy_trace,
            "audit_count": len(audit.entries),
            "pending_approvals": len(approval_service.pending_tickets),
            "model": model_name,
            "governance_mode": "GOVERNED_PROTECTED",
        }

    except Exception as e:
        error_msg = str(e)
        return {
            "success": False,
            "error": error_msg,
            "agent_response": f"Governed agent execution failed: {error_msg}",
            "tool_calls": [],
            "policy_trace": [],
            "model": model_name,
            "governance_mode": "GOVERNED_PROTECTED",
        }
