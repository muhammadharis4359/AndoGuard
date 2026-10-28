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
