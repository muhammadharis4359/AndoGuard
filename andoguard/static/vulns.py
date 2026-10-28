"""Vulnerability and compliance scanner aligned with OWASP MASVS and MASTG."""


from andoguard.models import (
    ManifestData,
    SeverityLevel,
    VulnerabilityFinding,
    VulnerabilityReport,
)

INSECURE_CIPHER_KEYWORDS = ["DES/", "DESede/", "Blowfish/", "RC4", "AES/ECB/"]
WEAK_HASH_KEYWORDS = ["MD5", "SHA-1"]
INSECURE_SSL_KEYWORDS = [
    "TrustAllCertificates",
    "ALLOW_ALL_HOSTNAME_VERIFIER",
    "NullTrustManager",
]


def audit_target_vulnerabilities(
    target_name: str,
    manifest: ManifestData | None = None,
    strings: list[str] | None = None,
) -> VulnerabilityReport:
    """Audit target Android binary for OWASP MASVS/MASTG security weaknesses."""
    findings: list[VulnerabilityFinding] = []

    # 1. Manifest Security Audits
    if manifest:
        sec = manifest.security_flags
        if sec.debuggable:
            findings.append(
                VulnerabilityFinding(
                    vuln_id="VULN-DEBUG-001",
                    masvs_id="MASVS-CODE-2",
                    title="Application is Debuggable in Manifest",
                    severity=SeverityLevel.CRITICAL,
                    description=(
                        "android:debuggable is set to 'true'. This enables JDWP debugging, "
                        "allowing attackers to attach runtime debuggers, dump memory, and execute code."
                    ),
                    remediation="Set android:debuggable='false' in AndroidManifest.xml before production release.",
                    location="AndroidManifest.xml <application android:debuggable='true'>",
                )
            )

        if sec.uses_cleartext_traffic:
            findings.append(
                VulnerabilityFinding(
                    vuln_id="VULN-NET-001",
                    masvs_id="MASVS-NETWORK-1",
                    title="Cleartext Network Traffic Permitted",
                    severity=SeverityLevel.HIGH,
                    description=(
                        "android:usesCleartextTraffic is set to 'true'. Unencrypted HTTP traffic "
                        "is vulnerable to eavesdropping and Machine-in-the-Middle (MitM) attacks."
                    ),
                    remediation="Enforce HTTPS across all network endpoints and configure a strict res/xml/network_security_config.xml.",
                    location="AndroidManifest.xml <application android:usesCleartextTraffic='true'>",
                )
            )

        if sec.allow_backup:
            findings.append(
                VulnerabilityFinding(
                    vuln_id="VULN-STORAGE-001",
                    masvs_id="MASVS-STORAGE-2",
                    title="Application Allows ADB Backup",
                    severity=SeverityLevel.MEDIUM,
                    description=(
                        "android:allowBackup is set to 'true'. Private app data, databases, and shared "
                        "preferences can be extracted via 'adb backup' without root access."
                    ),
                    remediation="Set android:allowBackup='false' or define an explicit fullBackupContent filter.",
                    location="AndroidManifest.xml <application android:allowBackup='true'>",
                )
            )

        if sec.test_only:
            findings.append(
                VulnerabilityFinding(
                    vuln_id="VULN-CODE-002",
                    masvs_id="MASVS-CODE-2",
                    title="Test-Only Flag Set",
                    severity=SeverityLevel.LOW,
                    description="android:testOnly is enabled, which may expose testing-only features and debug APIs.",
                    remediation="Remove android:testOnly='true' for release builds.",
                    location="AndroidManifest.xml <application android:testOnly='true'>",
                )
            )

        # Audit exported components lacking permissions
        for comp in manifest.components:
            if comp.exported and not comp.permission:
                findings.append(
                    VulnerabilityFinding(
                        vuln_id=f"VULN-EXPORTED-{comp.component_type.upper()}",
                        masvs_id="MASVS-PLATFORM-1",
                        title=f"Exported {comp.component_type.capitalize()} Without Permission Guard",
                        severity=SeverityLevel.HIGH
                        if comp.component_type in ("activity", "provider")
                        else SeverityLevel.MEDIUM,
                        description=(
                            f"{comp.component_type.capitalize()} '{comp.name}' is exported to other applications "
                            "without requiring any permission guard."
                        ),
                        remediation="Set android:exported='false' or protect the component with a signature-level permission.",
                        location=f"AndroidManifest.xml <{comp.component_type} android:name='{comp.name}'>",
                    )
                )

    # 2. Bytecode / String Pattern Audits
    if strings:
        found_insecure_cipher = False
        found_weak_hash = False
        found_insecure_ssl = False

        for s in strings:
            if not found_insecure_cipher:
                for kw in INSECURE_CIPHER_KEYWORDS:
                    if kw.lower() in s.lower():
                        findings.append(
                            VulnerabilityFinding(
                                vuln_id="VULN-CRYPTO-001",
                                masvs_id="MASVS-CRYPTO-1",
                                title="Weak or Insecure Cipher Algorithm Detected",
                                severity=SeverityLevel.HIGH,
                                description=f"Bytecode references insecure cipher or mode '{s}'. Algorithms like DES, RC4, or ECB mode are cryptographically broken.",
                                remediation="Use AES/GCM/NoPadding or standard Android Keystore cipher configurations.",
                                location=f"Bytecode literal: '{s}'",
                            )
                        )
                        found_insecure_cipher = True
                        break

            if not found_weak_hash:
                for kw in WEAK_HASH_KEYWORDS:
                    if kw == s or f"/{kw}" in s:
                        findings.append(
                            VulnerabilityFinding(
                                vuln_id="VULN-CRYPTO-002",
                                masvs_id="MASVS-CRYPTO-2",
                                title="Broken or Deprecated Hash Algorithm Referenced",
                                severity=SeverityLevel.MEDIUM,
                                description=f"Bytecode references weak hash algorithm '{s}'. MD5 and SHA-1 suffer from collision vulnerabilities.",
                                remediation="Upgrade cryptographic digests to SHA-256 or SHA-512.",
                                location=f"Bytecode literal: '{s}'",
                            )
                        )
                        found_weak_hash = True
                        break

            if not found_insecure_ssl:
                for kw in INSECURE_SSL_KEYWORDS:
                    if kw.lower() in s.lower():
                        findings.append(
                            VulnerabilityFinding(
                                vuln_id="VULN-NET-002",
                                masvs_id="MASVS-NETWORK-2",
                                title="Insecure SSL/TLS Certificate Validation Pattern",
                                severity=SeverityLevel.CRITICAL,
                                description=f"Bytecode pattern '{s}' indicates potential trust-all or disabled hostname verification, completely undermining TLS security.",
                                remediation="Rely on standard system trust roots and avoid implementing custom empty TrustManager classes.",
                                location=f"Bytecode literal: '{s}'",
                            )
                        )
                        found_insecure_ssl = True
                        break

    # 3. Summary tally
    summary = {
        SeverityLevel.CRITICAL.value: 0,
        SeverityLevel.HIGH.value: 0,
        SeverityLevel.MEDIUM.value: 0,
        SeverityLevel.LOW.value: 0,
        SeverityLevel.INFO.value: 0,
    }
    for f in findings:
        summary[f.severity.value] += 1

    return VulnerabilityReport(
        target=target_name,
        findings=findings,
        summary=summary,
    )
