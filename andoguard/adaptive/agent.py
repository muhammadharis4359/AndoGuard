"""Adaptive autonomous agent engine: ReAct loop, tool execution, and deterministic fallback walker."""

import json
from typing import TYPE_CHECKING, Any

from andoguard.adaptive.tools import ToolRegistry, create_default_registry
from andoguard.ai.provider import get_ai_provider
from andoguard.models import AdaptiveRunResult, AdaptiveStep

if TYPE_CHECKING:
    from andoguard.api import AndoGuard


class AdaptiveAgent:
    """Autonomous agent coordinating static and dynamic tools to achieve reverse engineering goals."""

    def __init__(
        self,
        autonomy_level: str = "full",
        max_steps: int = 10,
        registry: ToolRegistry | None = None,
    ) -> None:
        self.autonomy_level = autonomy_level.lower().strip()
        self.max_steps = max_steps
        self.registry = registry or create_default_registry()

    def plan(
        self,
        ag: "AndoGuard",
        goal: str,
        provider: str | None = None,
    ) -> list[str]:
        """Generate high-level step plan without executing tools."""
        try:
            ai_p = get_ai_provider(provider, config=ag.session_store.config)
            if ai_p.is_available():
                system = (
                    "You are AndoGuard Autonomous Planner. Given an Android analysis goal, "
                    "outline 3 to 6 logical inspection steps using available static and dynamic tools."
                )
                prompt = f"Goal: {goal}\nTarget package: {ag.target_info.package_name}\nPlan steps:"
                resp = ai_p.generate(prompt, system=system, max_tokens=1024)
                steps = [line.strip() for line in resp.splitlines() if line.strip() and (line[0].isdigit() or line.startswith("-"))]
                if steps:
                    return steps
        except Exception:
            pass

        # Deterministic default plan
        return [
            f"1. Extract AndroidManifest security flags and exported components for '{ag.target_info.package_name}'.",
            "2. Audit OWASP MASVS vulnerabilities across manifest and application components.",
            "3. Scan bytecode and resources for hardcoded credentials and high-entropy secrets.",
            "4. Decompile core activities and inspect cross-references for sensitive symbols.",
            "5. Synthesize findings and record verified security risks in session store.",
        ]

    def run(
        self,
        ag: "AndoGuard",
        goal: str,
        provider: str | None = None,
    ) -> AdaptiveRunResult:
        """Execute autonomous assessment loop toward goal."""
        if self.autonomy_level == "assist":
            plan_steps = self.plan(ag, goal, provider=provider)
            summary = "Plan generated in ASSIST mode (no tools executed):\n" + "\n".join(plan_steps)
            return AdaptiveRunResult(
                goal=goal,
                autonomy_level=self.autonomy_level,
                steps=[],
                findings_recorded=0,
                summary=summary,
            )

        # Check if AI provider is available for ReAct loop
        ai_available = False
        try:
            ai_p = get_ai_provider(provider, config=ag.session_store.config)
            ai_available = ai_p.is_available()
        except Exception:
            ai_available = False

        if ai_available:
            try:
                return self._run_llm_loop(ag, goal, ai_p)
            except Exception:
                # If LLM encounters rate limit or network error, gracefully fall back to deterministic walker
                pass

        return self._run_deterministic_walker(ag, goal)

    def _run_llm_loop(self, ag: "AndoGuard", goal: str, ai_p: Any) -> AdaptiveRunResult:
        """Run LLM-directed Observe-Plan-Act ReAct loop."""
        steps: list[AdaptiveStep] = []
        tools_summary = "\n".join(f"- {t.name}: {t.description}" for t in self.registry.list_tools())
        system = (
            "You are AndoGuard Autonomous Agent. You achieve reverse engineering goals by invoking tools.\n"
            f"Available tools:\n{tools_summary}\n\n"
            "At each step, respond strictly in JSON format with:\n"
            "{\n"
            '  "thought": "your step reasoning",\n'
            '  "tool": "tool_name",\n'
            '  "args": { ... arguments ... },\n'
            '  "finished": false\n'
            "}\n"
            'When the goal is met or finished is true, set "tool": "finish".'
        )

        history_context = ""
        for i in range(1, self.max_steps + 1):
            prompt = (
                f"Goal: {goal}\n"
                f"Target: {ag.target_info.package_name}\n"
                f"Step: {i} of {self.max_steps}\n"
                f"Past Actions & Observations:\n{history_context}\n\n"
                "Next action JSON:"
            )

            resp_text = ai_p.generate(prompt, system=system, max_tokens=1024)
            thought = ""
            tool_name = ""
            tool_args: dict[str, Any] = {}
            is_finished = False

            try:
                # Extract JSON substring
                start = resp_text.find("{")
                end = resp_text.rfind("}")
                if start != -1 and end != -1:
                    action_json = json.loads(resp_text[start : end + 1])
                    thought = action_json.get("thought", "")
                    tool_name = action_json.get("tool", "")
                    tool_args = action_json.get("args", {})
                    is_finished = bool(action_json.get("finished", False)) or tool_name.lower() == "finish"
            except Exception:
                tool_name = "get_manifest_info"
                thought = "Extract initial manifest flags."

            if not tool_name:
                tool_name = "get_manifest_info"
                thought = thought or "Extract initial manifest flags."

            if is_finished or tool_name.lower() == "finish":
                break

            try:
                tool_output = self.registry.execute(tool_name, ag, tool_args)
                status = "success"
            except Exception as e:
                tool_output = f"Tool error: {e}"
                status = "error"

            step_record = AdaptiveStep(
                step_index=i,
                thought=thought,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_output=tool_output,
                status=status,
            )
            steps.append(step_record)

            # Append concise summary to history
            history_context += f"Step {i} ({tool_name}): {str(tool_output)[:300]}\n"

        recorded = len(ag.session_store.get_findings(ag.session_record.session_id))
        summary = f"Autonomous assessment completed in {len(steps)} steps. {recorded} findings in session."
        return AdaptiveRunResult(
            goal=goal,
            autonomy_level=self.autonomy_level,
            steps=steps,
            findings_recorded=recorded,
            summary=summary,
        )

    def _run_deterministic_walker(self, ag: "AndoGuard", goal: str) -> AdaptiveRunResult:
        """Rule-based goal walker when AI providers are unavailable."""
        steps: list[AdaptiveStep] = []
        step_idx = 1

        # Step 1: Manifest inspection
        manifest_res = self.registry.execute("get_manifest_info", ag, {})
        steps.append(
            AdaptiveStep(
                step_index=step_idx,
                thought="Inspect AndroidManifest flags, exported components, and permissions.",
                tool_name="get_manifest_info",
                tool_args={},
                tool_output=manifest_res,
                status="success",
            )
        )
        step_idx += 1

        # Step 2: Vulnerability audit
        vulns_res = self.registry.execute("audit_vulns", ag, {})
        steps.append(
            AdaptiveStep(
                step_index=step_idx,
                thought="Execute static security vulnerability audit against OWASP MASVS.",
                tool_name="audit_vulns",
                tool_args={},
                tool_output=vulns_res,
                status="success",
            )
        )
        step_idx += 1

        # Step 3: Secrets scanning
        secrets_res = self.registry.execute("scan_secrets", ag, {})
        steps.append(
            AdaptiveStep(
                step_index=step_idx,
                thought="Scan for hardcoded API keys and high-entropy credentials.",
                tool_name="scan_secrets",
                tool_args={},
                tool_output=secrets_res,
                status="success",
            )
        )
        step_idx += 1

        # Step 4: Goal-specific targeted analysis
        goal_lower = goal.lower()
        if "crypto" in goal_lower or "key" in goal_lower or "encrypt" in goal_lower:
            methods_res = self.registry.execute("find_methods", ag, {"pattern": "*crypt*"})
            steps.append(
                AdaptiveStep(
                    step_index=step_idx,
                    thought="Locate cryptographic method calls and cipher initialization.",
                    tool_name="find_methods",
                    tool_args={"pattern": "*crypt*"},
                    tool_output=methods_res,
                    status="success",
                )
            )
            step_idx += 1
        elif "native" in goal_lower or "so" in goal_lower or "jni" in goal_lower:
            native_res = self.registry.execute("inspect_native", ag, {})
            steps.append(
                AdaptiveStep(
                    step_index=step_idx,
                    thought="Inspect native shared libraries and JNI symbol exports.",
                    tool_name="inspect_native",
                    tool_args={},
                    tool_output=native_res,
                    status="success",
                )
            )
            step_idx += 1

        # Step 5: Synthesize and record finding if high risk detected
        if manifest_res.get("debuggable"):
            self.registry.execute(
                "record_finding",
                ag,
                {
                    "title": "Autonomous Finding: Application is Debuggable",
                    "severity": "CRITICAL",
                    "evidence": "android:debuggable='true' confirmed via autonomous walker.",
                    "remediation": "Remove debuggable attribute prior to production release.",
                    "masvs_id": "MASVS-CODE-2",
                },
            )

        recorded = len(ag.session_store.get_findings(ag.session_record.session_id))
        summary = f"Deterministic autonomous walker completed {len(steps)} steps for goal: '{goal}'. {recorded} total findings recorded."
        return AdaptiveRunResult(
            goal=goal,
            autonomy_level=self.autonomy_level,
            steps=steps,
            findings_recorded=recorded,
            summary=summary,
        )
