"""AndoGuard core domain models and data transfer structures."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalysisMode(StrEnum):
    """Analysis operational mode."""

    STATIC = "static"
    DYNAMIC = "dynamic"
    ADAPTIVE = "adaptive"


class TargetType(StrEnum):
    """Android binary or directory container type."""

    APK = "apk"
    DEX = "dex"
    ODEX = "odex"
    OAT = "oat"
    VDEX = "vdex"
    DIRECTORY = "directory"
    UNKNOWN = "unknown"


class TargetInfo(BaseModel):
    """Structured information extracted from an analyzed target."""

    target_path: str
    target_type: TargetType
    file_size: int
    md5: str
    sha1: str
    sha256: str
    package_name: str | None = None
    version_code: int | None = None
    version_name: str | None = None
    min_sdk_version: int | None = None
    target_sdk_version: int | None = None
    app_name: str | None = None
    main_activity: str | None = None
    dex_count: int = 0
    permissions_count: int = 0
    activities_count: int = 0
    services_count: int = 0
    receivers_count: int = 0
    providers_count: int = 0
    extra_metadata: dict[str, Any] = Field(default_factory=dict)


class SessionRecord(BaseModel):
    """Persistent session record metadata."""

    session_id: str
    name: str
    target_sha256: str
    target_path: str
    target_type: str
    mode: AnalysisMode
    work_dir: str
    created_at: str
    updated_at: str
    notes: str | None = None


class FindingSeverity(StrEnum):
    """Vulnerability finding severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingConfidence(StrEnum):
    """Confidence levels for security findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Finding(BaseModel):
    """Security audit finding aligned with OWASP MASVS/MASTG."""

    id: str
    session_id: str
    title: str
    severity: FindingSeverity = FindingSeverity.MEDIUM
    confidence: FindingConfidence = FindingConfidence.MEDIUM
    masvs_id: str | None = None
    evidence: str
    remediation: str
    provenance: str
    created_at: str


class AuditRecord(BaseModel):
    """Audit log entry for tracked actions in a session."""

    id: int | None = None
    session_id: str
    event_type: str
    details: str
    timestamp: str


class BackendCapabilities(BaseModel):
    """Feature capabilities exposed by a backend adapter."""

    backend_name: str
    version: str
    has_apk_support: bool = False
    has_dex_support: bool = False
    has_manifest_support: bool = False
    has_axml_support: bool = False
    has_arsc_support: bool = False
    has_disasm: bool = False
    has_decompile: bool = False
    has_xrefs: bool = False
    has_native_support: bool = False
    has_v5_features: bool = False


class ManifestComponent(BaseModel):
    """Parsed Android manifest application component."""

    name: str
    component_type: str  # "activity", "service", "receiver", "provider"
    exported: bool
    permission: str | None = None
    intent_filters: list[dict[str, list[str]]] = Field(default_factory=list)
    attributes: dict[str, str] = Field(default_factory=dict)


class ManifestSecurityFlags(BaseModel):
    """Security-relevant application manifest flags."""

    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool = False
    network_security_config: str | None = None
    test_only: bool = False


class ManifestData(BaseModel):
    """Structured AndroidManifest.xml decoded metadata."""

    package_name: str | None = None
    version_code: int | None = None
    version_name: str | None = None
    min_sdk_version: int | None = None
    target_sdk_version: int | None = None
    permissions: list[str] = Field(default_factory=list)
    declared_permissions: list[str] = Field(default_factory=list)
    components: list[ManifestComponent] = Field(default_factory=list)
    security_flags: ManifestSecurityFlags = Field(default_factory=ManifestSecurityFlags)
    raw_xml: str | None = None


class ResourceEntry(BaseModel):
    """Parsed Android resource table entry."""

    res_id: str
    res_type: str
    name: str
    value: str | None = None
    config: str | None = None


class ApkFileEntry(BaseModel):
    """File entry within an APK container."""

    path: str
    size: int
    is_so: bool = False
    is_asset: bool = False
    is_dex: bool = False
    crc: int | None = None


class CertificateInfo(BaseModel):
    """X.509 Certificate metadata extracted from APK signing blocks."""

    sha1_fingerprint: str
    sha256_fingerprint: str
    md5_fingerprint: str | None = None
    issuer: str
    subject: str
    valid_from: str
    valid_to: str
    serial_number: str | None = None
    signature_algorithm: str | None = None
    is_self_signed: bool = False


class SignatureReport(BaseModel):
    """Signature scheme report and certificate details."""

    is_signed: bool = False
    v1_signature: bool = False
    v2_signature: bool = False
    v3_signature: bool = False
    certificates: list[CertificateInfo] = Field(default_factory=list)


class StringItem(BaseModel):
    """Extracted string literal with provenance and entropy."""

    value: str
    length: int
    entropy: float = 0.0
    source: str = "dex"


class MethodInfo(BaseModel):
    """Method descriptor and metadata."""

    name: str
    descriptor: str
    access_flags: str = ""
    is_external: bool = False
    class_name: str = ""


class FieldInfo(BaseModel):
    """Field descriptor and metadata."""

    name: str
    descriptor: str
    access_flags: str = ""
    class_name: str = ""


class ClassDetail(BaseModel):
    """Detailed class information with methods, fields, and inheritance."""

    name: str
    super_class: str | None = None
    interfaces: list[str] = Field(default_factory=list)
    access_flags: str = ""
    methods: list[MethodInfo] = Field(default_factory=list)
    fields: list[FieldInfo] = Field(default_factory=list)


class BasicBlockInfo(BaseModel):
    """Control flow graph basic block."""

    name: str
    start: int = 0
    end: int = 0
    instructions: list[str] = Field(default_factory=list)
    children: list[str] = Field(default_factory=list)


class ControlFlowGraph(BaseModel):
    """Method Control Flow Graph (CFG)."""

    method: str
    blocks: list[BasicBlockInfo] = Field(default_factory=list)
    dot: str = ""


class DisasmResult(BaseModel):
    """Dalvik disassembly output with optional CFG."""

    target: str
    instructions: list[str] = Field(default_factory=list)
    cfg: ControlFlowGraph | None = None


class CodeResult(BaseModel):
    """Decompiled or disassembled source code representation."""

    target: str
    language: str = "java"  # "java" or "dalvik"
    source: str
    cfg: ControlFlowGraph | None = None

