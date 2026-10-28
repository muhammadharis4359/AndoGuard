"""Specialized prompt templates for Android security auditing and reverse engineering."""

from typing import Any

SYSTEM_ANALYST = (
    "You are AndoGuard AI, an elite Android security researcher and reverse engineering expert. "
    "Analyze Android decompiled bytecode, smali instructions, manifest security flags, and static findings. "
    "Provide concise, actionable, and mathematically precise technical insights adhering to OWASP MASVS and MASTG guidelines."
)


def build_ask_prompt(question: str, context: str | None = None) -> tuple[str, str]:
    """Construct prompt for interactive Q&A over Android target."""
    user_prompt = f"Question: {question}"
    if context:
        user_prompt += f"\n\nContext:\n```\n{context}\n```"
    return SYSTEM_ANALYST, user_prompt


def build_explain_prompt(code: str, identifier: str) -> tuple[str, str]:
    """Construct prompt to explain and de-obfuscate class or method code."""
    system = (
        f"{SYSTEM_ANALYST} Your goal is to analyze decompiled Android code, identify obfuscation, "
        "reconstruct variable semantic meanings, describe cryptographic operations, and highlight sensitive data flows."
    )
    user_prompt = (
        f"Please analyze and explain the following code for '{identifier}':\n\n"
        f"```java\n{code}\n```\n\n"
        "Provide:\n"
        "1. Summary of primary responsibility and purpose\n"
        "2. Key parameters, return values, and internal logic flows\n"
        "3. Cryptographic, network, or IPC operations detected\n"
        "4. Potential vulnerabilities or anti-reverse engineering techniques\n"
    )
    return system, user_prompt


def build_triage_prompt(
    findings: list[dict[str, Any]],
    manifest_summary: str = "",
) -> tuple[str, str]:
    """Construct prompt to prioritize, evaluate, and triage security findings."""
    system = (
        f"{SYSTEM_ANALYST} Your task is to perform security triage on an Android application. "
        "Assess false positives, contextual risk, and practical exploitability based on OWASP MASVS."
    )
    findings_text = "\n".join(
        f"- [{f.get('severity', 'UNKNOWN')}] {f.get('title', 'Unknown finding')}: {f.get('evidence', '')} (MASVS: {f.get('masvs_id', 'N/A')})"
        for f in findings
    )
    user_prompt = (
        f"Android Manifest Summary:\n{manifest_summary}\n\n"
        f"Static Findings ({len(findings)} total):\n{findings_text}\n\n"
        "Please provide a structured Triage Assessment:\n"
        "1. Executive Summary & Overall Risk Posture\n"
        "2. Top Critical/High Impact Vulnerabilities with exploitation vectors\n"
        "3. Likely False Positives or Low-Risk accepted patterns\n"
        "4. Step-by-step prioritized remediation roadmap\n"
    )
    return system, user_prompt
