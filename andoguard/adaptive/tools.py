"""Typed tool registry for autonomous reverse engineering and security auditing."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from andoguard.api import AndoGuard


@dataclass
class ToolDefinition:
    """Descriptor for an autonomous agent callable tool."""

    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[..., Any] = field(repr=False)


class ToolRegistry:
    """Registry maintaining available autonomous tools and schema definitions."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        handler: Callable[..., Any],
    ) -> None:
        """Register a new callable tool."""
        self._tools[name] = ToolDefinition(
            name=name,
            description=description,
            parameters=parameters,
            handler=handler,
        )

    def get(self, name: str) -> ToolDefinition | None:
        """Lookup tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        """Return all registered tools."""
        return list(self._tools.values())

    def get_schemas(self) -> list[dict[str, Any]]:
        """Return tool schemas in standard OpenAI/Gemini function calling format."""
        schemas: list[dict[str, Any]] = []
        for t in self._tools.values():
            schemas.append(
                {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                }
            )
        return schemas

    def execute(self, tool_name: str, ag: "AndoGuard", args: dict[str, Any]) -> Any:
        """Execute tool handler with provided arguments."""
        tool = self._tools.get(tool_name)
        if not tool:
            raise ValueError(f"Unknown tool '{tool_name}'.")
        return tool.handler(ag, **args)


# Tool Implementations


def _tool_get_manifest(ag: "AndoGuard", **kwargs: Any) -> dict[str, Any]:
    flags = ag.manifest.security_flags()
    comps = ag.manifest.components()
    return {
        "package_name": ag.target_info.package_name,
        "debuggable": flags.debuggable,
        "allow_backup": flags.allow_backup,
        "uses_cleartext_traffic": flags.uses_cleartext_traffic,
        "exported_components_count": len(ag.manifest.exported_components()),
        "total_components_count": len(comps),
        "permissions": ag.manifest.permissions(),
    }


def _tool_list_classes(ag: "AndoGuard", pattern: str | None = None, limit: int = 50, **kwargs: Any) -> list[str]:
    classes = ag.classes(grep=pattern)
    return classes[:limit]


def _tool_decompile_class(ag: "AndoGuard", class_name: str, **kwargs: Any) -> str:
    res = ag.decompile_source(class_name)
    return res.source[:8000]


def _tool_find_methods(ag: "AndoGuard", pattern: str | None = None, limit: int = 50, **kwargs: Any) -> list[str]:
    if pattern and ("#" in pattern or "->" in pattern):
        cls_name = pattern.replace("->", "#").split("#")[0]
        return ag.methods(class_name=cls_name)[:limit]

    classes = ag.classes(grep=pattern)
    methods: list[str] = []
    for c in classes[:10]:
        try:
            m = ag.methods(class_name=c)
            methods.extend(m)
        except Exception:
            pass
        if len(methods) >= limit:
            break
    return methods[:limit]


def _tool_disassemble_method(ag: "AndoGuard", method_name: str, **kwargs: Any) -> str:
    res = ag.disassemble_method(method_name)
    return "\n".join(res.instructions[:200])


def _tool_find_xrefs(ag: "AndoGuard", target_symbol: str, **kwargs: Any) -> dict[str, Any]:
    res = ag.xrefs(target_symbol)
    return {
        "target": target_symbol,
        "callers": [x.caller for x in res.xrefs_to[:25]],
        "callees": [x.callee for x in res.xrefs_from[:25]],
    }


def _tool_scan_secrets(ag: "AndoGuard", **kwargs: Any) -> list[dict[str, Any]]:
    findings = ag.secrets()
    return [
        {
            "secret_type": f.secret_type,
            "value": f.value,
            "entropy": f.entropy,
            "provenance": f.provenance,
        }
        for f in findings[:25]
    ]


def _tool_audit_vulns(ag: "AndoGuard", **kwargs: Any) -> dict[str, Any]:
    report = ag.vulns()
    return {
        "summary": report.summary,
        "findings": [
            {
                "vuln_id": f.vuln_id,
                "title": f.title,
                "severity": f.severity.value,
                "masvs_id": f.masvs_id,
                "location": f.location,
            }
            for f in report.findings
        ],
    }


def _tool_search_strings(ag: "AndoGuard", query: str, limit: int = 25, **kwargs: Any) -> list[dict[str, Any]]:
    items = ag.search(query)
    return [{"type": item.item_type, "identifier": item.identifier, "snippet": item.snippet} for item in items[:limit]]


def _tool_inspect_native(ag: "AndoGuard", **kwargs: Any) -> list[dict[str, Any]]:
    libs = ag.native()
    return [
        {
            "path": lib.path,
            "arch": lib.arch,
            "jni_exports": lib.jni_exports,
        }
        for lib in libs
    ]


def _tool_generate_hook(ag: "AndoGuard", target: str, custom_return: str | None = None, **kwargs: Any) -> str:
    return ag.generate_hook(target, custom_return=custom_return)


def _tool_record_finding(
    ag: "AndoGuard",
    title: str,
    severity: str,
    evidence: str,
    remediation: str = "Review and address highlighted security risk.",
    masvs_id: str | None = None,
    **kwargs: Any,
) -> str:
    from andoguard.models import FindingConfidence, FindingSeverity

    try:
        sev = FindingSeverity(severity.upper())
    except ValueError:
        sev = FindingSeverity.MEDIUM

    return ag.session_store.record_finding(
        session_id=ag.session_record.session_id,
        title=title,
        severity=sev,
        confidence=FindingConfidence.HIGH,
        evidence=evidence,
        remediation=remediation,
        masvs_id=masvs_id,
        provenance="autonomous_agent",
    )


def create_default_registry() -> ToolRegistry:
    """Build and return fully populated default ToolRegistry."""
    registry = ToolRegistry()

    registry.register(
        name="get_manifest_info",
        description="Extract AndroidManifest summary, permissions, and security flags.",
        parameters={"type": "object", "properties": {}},
        handler=_tool_get_manifest,
    )
    registry.register(
        name="list_classes",
        description="List class names with optional regex or substring pattern filter.",
        parameters={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern or prefix filter"},
                "limit": {"type": "integer", "description": "Max classes to return (default 50)"},
            },
        },
        handler=_tool_list_classes,
    )
    registry.register(
        name="decompile_class",
        description="Decompile Java source code for a specific target class.",
        parameters={
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "Fully-qualified class name"},
            },
            "required": ["class_name"],
        },
        handler=_tool_decompile_class,
    )
    registry.register(
        name="find_methods",
        description="Search method signatures matching pattern.",
        parameters={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Method pattern or substring"},
                "limit": {"type": "integer", "description": "Max methods to return (default 50)"},
            },
        },
        handler=_tool_find_methods,
    )
    registry.register(
        name="disassemble_method",
        description="Disassemble target method to Dalvik smali bytecode.",
        parameters={
            "type": "object",
            "properties": {
                "method_name": {"type": "string", "description": "Method descriptor"},
            },
            "required": ["method_name"],
        },
        handler=_tool_disassemble_method,
    )
    registry.register(
        name="find_xrefs",
        description="Find callers and callees for a target method, class, or symbol.",
        parameters={
            "type": "object",
            "properties": {
                "target_symbol": {"type": "string", "description": "Symbol to find xrefs for"},
            },
            "required": ["target_symbol"],
        },
        handler=_tool_find_xrefs,
    )
    registry.register(
        name="scan_secrets",
        description="Scan bytecode and resources for API keys, tokens, and high-entropy secrets.",
        parameters={"type": "object", "properties": {}},
        handler=_tool_scan_secrets,
    )
    registry.register(
        name="audit_vulns",
        description="Perform comprehensive OWASP MASVS static security audit.",
        parameters={"type": "object", "properties": {}},
        handler=_tool_audit_vulns,
    )
    registry.register(
        name="search_strings",
        description="Search indexed strings and components for keywords.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search keyword or symbol"},
                "limit": {"type": "integer", "description": "Max results to return"},
            },
            "required": ["query"],
        },
        handler=_tool_search_strings,
    )
    registry.register(
        name="inspect_native",
        description="Inspect native shared libraries (.so) and JNI exported functions.",
        parameters={"type": "object", "properties": {}},
        handler=_tool_inspect_native,
    )
    registry.register(
        name="generate_hook",
        description="Generate Frida instrumentation hook script for class, method, or symbol.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Class or method to hook"},
                "custom_return": {"type": "string", "description": "Optional override return value expression"},
            },
            "required": ["target"],
        },
        handler=_tool_generate_hook,
    )
    registry.register(
        name="record_finding",
        description="Record verified security vulnerability finding into session store.",
        parameters={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Finding title"},
                "severity": {"type": "string", "description": "CRITICAL, HIGH, MEDIUM, LOW, or INFO"},
                "evidence": {"type": "string", "description": "Technical evidence or proof"},
                "remediation": {"type": "string", "description": "Remediation guidance"},
                "masvs_id": {"type": "string", "description": "OWASP MASVS ID (e.g. MASVS-STORAGE-1)"},
            },
            "required": ["title", "severity", "evidence"],
        },
        handler=_tool_record_finding,
    )

    return registry
