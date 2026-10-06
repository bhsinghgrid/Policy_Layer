"""
judge.py — Policy Judge LLM.

Architecture Step:
  Build Trusted Context ──► Policy Judge LLM ──► Decision (ALLOW / DENY / ASK USER)
"""

import json
from typing import Any, Dict, Optional, Tuple
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage
from policy_layer.snapshot import ActionSnapshot
from policy_layer.context import TrustedContext, TrustedContextBuilder


def format_message_content(content: Any) -> str:
    """Helper to extract string content from LangChain message response."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and "text" in item:
                parts.append(item["text"])
            elif isinstance(item, str):
                parts.append(item)
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content) if content is not None else ""


class PolicyDecision:
    """Structured decision output produced by the Policy Judge LLM."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    ASK_USER = "ASK_USER"

    def __init__(
        self,
        verdict: str,
        risk_score: float,
        rule_name: str,
        reason: str,
        mitigation: str = "",
        block_reason: str = "",
    ):
        self.verdict = verdict.upper()   # ALLOW | DENY | ASK_USER
        self.risk_score = risk_score     # 0.0 (Safe) to 1.0 (Critical Threat)
        self.rule_name = rule_name       # Identifier of the policy principle
        self.reason = reason             # LLM's natural language justification
        self.mitigation = mitigation     # Recommended safe alternative
        self.block_reason = block_reason # Brief summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "risk_score": round(self.risk_score, 2),
            "rule": self.rule_name,
            "reason": self.reason,
            "mitigation": self.mitigation,
            "block_reason": self.block_reason,
        }


POLICY_JUDGE_SYSTEM_PROMPT = """You are the Enterprise Security Policy Judge LLM.
Your responsibility is to analyze a proposed tool call from an autonomous task agent and determine whether to ALLOW it, DENY it, or hold it for human operator authorization (ASK_USER).

You operate as an authoritative security layer independent of the task agent.

EVALUATION CRITERIA:
1. DATA LOSS PREVENTION (DLP) & SECRETS:
   - DENY if the action attempts to read, write, or leak sensitive system files, environment credentials (.env), private SSH keys (id_rsa), passwords, API keys, or production databases.
2. SYSTEM INTEGRITY & DESTRUCTION:
   - DENY any attempt to delete or destroy mission-critical production databases or system infrastructure.
   - ASK_USER for deleting standard non-critical files (operator must confirm deletion).
3. DATA EXFILTRATION & COMMUNICATIONS:
   - DENY sending emails containing sensitive keys, passwords, or company secrets to external or untrusted recipients.
   - ASK_USER for sending business emails to external/untrusted domains.
   - ALLOW standard internal communication to verified corporate domains.
4. FINANCIAL GOVERNANCE:
   - ALLOW micro-purchases (<= $100.00) within remaining daily budget.
   - ASK_USER for standard purchases between $100.00 and $2,500.00 (requires operator sign-off).
   - DENY excessive purchases (> $2,500.00) or purchases exceeding the remaining daily budget.
5. BENIGN & ROUTINE ACTIONS:
   - ALLOW reading public documentation, standard CSV/data analysis, directory listings, and benign operations.

RESPONSE FORMAT:
You MUST respond with ONLY a valid JSON object matching this schema:
{
  "verdict": "ALLOW" | "DENY" | "ASK_USER",
  "risk_score": <float between 0.0 and 1.0>,
  "rule_name": "<SHORT_UPPERCASE_POLICY_IDENTIFIER>",
  "reason": "<Detailed explanation of the security risk, rationale, and policy decision>",
  "mitigation": "<Actionable alternative or next step>",
  "block_reason": "<Short summary of the restriction>"
}
"""

class PolicyJudgeLLM:
    """
    LLM-powered Policy Judge.
    Uses Gemini to evaluate the proposed action snapshot semantically against
    trusted enterprise context and security guidelines.
    """

    def __init__(
        self,
        context_builder: TrustedContextBuilder,
        default_model: str = "gemini-3.8-flash",
    ):
        self.context_builder = context_builder
        self.default_model = default_model

    def evaluate(
        self,
        snapshot: ActionSnapshot,
        user_intent: str = "",
        api_key: str = "",
        model_name: Optional[str] = None,
    ) -> Tuple[PolicyDecision, TrustedContext]:
        """
        Invokes the Policy Judge LLM to evaluate the action snapshot.
        Returns (PolicyDecision, TrustedContext).
        """
        context = self.context_builder.build_context()
        active_model = model_name or self.default_model

        try:
            judge_llm = ChatGoogleGenerativeAI(
                model=active_model,
                google_api_key=api_key,
                temperature=0.0,
            )

            # Build comprehensive prompt for the Judge LLM
            evaluation_input = (
                f"=== TRUSTED ENTERPRISE CONTEXT ===\n"
                f"- Daily Budget: ${context.daily_budget:,.2f}\n"
                f"- Cumulative Spent So Far: ${context.daily_spent:,.2f}\n"
                f"- Remaining Budget: ${context.remaining_budget:,.2f}\n"
                f"- Trusted Domains: {', '.join(context.trusted_domains)}\n"
                f"- Protected Assets: {'; '.join(context.protected_asset_descriptions)}\n\n"
                f"=== USER INTENT ===\n"
                f"{user_intent if user_intent else 'Not provided'}\n\n"
                f"=== PROPOSED ACTION SNAPSHOT ===\n"
                f"Snapshot ID: {snapshot.snapshot_id}\n"
                f"Tool Name: {snapshot.tool_name}\n"
                f"Tool Arguments: {json.dumps(snapshot.args, indent=2)}\n\n"
                f"Evaluate this proposed action and output your decision JSON:"
            )

            response = judge_llm.invoke([
                SystemMessage(content=POLICY_JUDGE_SYSTEM_PROMPT),
                HumanMessage(content=evaluation_input),
            ])

            raw_text = format_message_content(response.content).strip()
            # Clean markdown JSON fences if present
            if raw_text.startswith("```"):
                raw_text = raw_text.split("```")[1]
                if raw_text.startswith("json"):
                    raw_text = raw_text[4:]
            raw_text = raw_text.strip()

            parsed = json.loads(raw_text)

            verdict = str(parsed.get("verdict", "DENY")).upper()
            if verdict not in ["ALLOW", "DENY", "ASK_USER"]:
                verdict = "DENY"

            risk_score = float(parsed.get("risk_score", 0.5))
            if risk_score > 1.0:
                risk_score = risk_score / 100.0
            risk_score = max(0.0, min(1.0, risk_score))

            rule_name = str(parsed.get("rule_name", "SECURITY_POLICY_CHECK"))
            reason = str(parsed.get("reason", "Action reviewed by Policy Judge LLM."))
            mitigation = str(parsed.get("mitigation", ""))
            block_reason = str(parsed.get("block_reason", reason[:100]))

            decision = PolicyDecision(
                verdict=verdict,
                risk_score=risk_score,
                rule_name=rule_name,
                reason=reason,
                mitigation=mitigation,
                block_reason=block_reason,
            )
            return decision, context

        except Exception as err:
            decision = PolicyDecision(
                verdict=PolicyDecision.DENY,
                risk_score=0.9,
                rule_name="POLICY_JUDGE_EVAL_ERROR",
                reason=f"Policy Judge LLM failed to evaluate action: {str(err)}",
                block_reason="Evaluation failure fallback",
            )
            return decision, context


# Alias for backward compatibility
PolicyJudge = PolicyJudgeLLM
