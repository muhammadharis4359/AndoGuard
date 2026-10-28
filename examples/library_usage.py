"""Demonstration of AndoGuard public library API covering Milestones 1 through 9."""

import json
import tempfile
import zipfile
from pathlib import Path

from andoguard import AndoGuard
from andoguard.models import TraceEvent


def create_demo_apk(path: Path) -> None:
    """Create a realistic synthetic APK fixture for end-to-end demonstration."""
    import datetime
    import hashlib
    import struct
    import zlib

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # 1. Create minimal DEX
    magic = b"dex\n035\x00"
    map_off = 112
    file_size = 140
    header_size = 0x70
    endian_tag = 0x12345678
    body = struct.pack(
        "<20I",
        file_size,
        header_size,
        endian_tag,
        0,
        0,
        map_off,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        28,
        map_off,
    )
    map_list = (
        struct.pack("<I", 2)
        + struct.pack("<HHII", 0, 0, 1, 0)
        + struct.pack("<HHII", 4096, 0, 1, map_off)
    )
    full_body = body + map_list
    sha1 = hashlib.sha1(full_body).digest()
    adler = zlib.adler32(sha1 + full_body)
    dex_bytes = magic + struct.pack("<I", adler) + sha1 + full_body

    # 2. Manifest XML with security risks for audit
    manifest = (
        b"<manifest xmlns:android='http://schemas.android.com/apk/res/android' "
        b"package='com.andoguard.showcase' android:versionCode='101' android:versionName='2.5.0'>\n"
        b"  <uses-sdk android:minSdkVersion='24' android:targetSdkVersion='34'/>\n"
        b"  <uses-permission android:name='android.permission.INTERNET'/>\n"
        b"  <uses-permission android:name='android.permission.ACCESS_FINE_LOCATION'/>\n"
        b"  <application android:name='.DemoApp' android:debuggable='true' android:allowBackup='true' android:usesCleartextTraffic='true'>\n"
        b"    <activity android:name='.MainActivity' android:exported='true'>\n"
        b"      <intent-filter>\n"
        b"        <action android:name='android.intent.action.MAIN'/>\n"
        b"        <category android:name='android.intent.category.LAUNCHER'/>\n"
        b"      </intent-filter>\n"
        b"    </activity>\n"
        b"    <service android:name='.SecurePaymentService' android:exported='false'/>\n"
        b"  </application>\n"
        b"</manifest>"
    )

    # 3. Generate self-signed certificate
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "AndoGuard Showcase App"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "AndoGuard Security Lab"),
    ])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(999988887777)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("META-INF/CERT.RSA", cert_der)
        zf.writestr("assets/api_keys.json", b'{"demo_api_token": "aB3kL9mP8xQ2vW7zY1jK5nO4tR6uI0eS"}')
        zf.writestr("res/values/strings.xml", b"<resources><string name='app_name'>Showcase</string></resources>")


def main() -> None:
    print("=" * 70)
    print("       AndoGuard End-to-End Showcase (Milestones 1 - 9)       ")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        apk_path = tmp_path / "showcase_app.apk"
        create_demo_apk(apk_path)

        # -------------------------------------------------------------
        # Milestone 1: Open Target & Initialize SQLite Session Store
        # -------------------------------------------------------------
        print("\n[*] [M1] Opening target & establishing session...")
        with AndoGuard.open(apk_path, session_name="showcase-session", work_dir=tmp_path / ".andoguard") as ag:
            target = ag.info()
            print(f"    Target: {target.package_name} v{target.version_name} (Code: {target.version_code})")
            print(f"    SHA-256: {target.sha256}")
            print(f"    Session ID: {ag.session.id} ({ag.session.name})")

            # ---------------------------------------------------------
            # Milestone 2: Manifest & Certificate Inspection
            # ---------------------------------------------------------
            print("\n[*] [M2] Auditing AndroidManifest.xml & Certificates...")
            flags = ag.manifest.security_flags()
            print(f"    Debuggable: {flags.debuggable} | AllowBackup: {flags.allow_backup} | Cleartext: {flags.uses_cleartext_traffic}")
            perms = ag.manifest.permissions()
            print(f"    Permissions ({len(perms)}): {perms}")
            certs = ag.certs()
            print(f"    Certificates ({len(certs.certificates)}): Subject = {certs.certificates[0].subject if certs.certificates else 'None'}")

            # ---------------------------------------------------------
            # Milestone 3: Classes & Decompilation
            # ---------------------------------------------------------
            print("\n[*] [M3] Inspecting Classes & Dalvik Bytecode...")
            classes = ag.classes()
            print(f"    Loaded classes ({len(classes)}): {classes[:3]}...")
            code_res = ag.decompile_source("com.andoguard.showcase.MainActivity")
            print(f"    Decompiled target: {code_res.target} (Language: {code_res.language}, Source length: {len(code_res.source)})")

            # ---------------------------------------------------------
            # Milestone 4: Secrets Scanning & OWASP MASVS Vulnerability Audit
            # ---------------------------------------------------------
            print("\n[*] [M4] Running Secrets Scanner & MASVS Vulnerability Audit...")
            secrets = ag.secrets()
            print(f"    Detected secrets ({len(secrets)}):")
            for s in secrets:
                print(f"      - [{s.secret_type}] {s.source_file}: {s.value[:20]}... (Entropy: {s.entropy:.2f})")

            vulns = ag.vulns()
            print(f"    Audited vulnerabilities ({len(vulns.findings)}):")
            for v in vulns.findings:
                print(f"      - [{v.severity.value}] {v.title} ({v.masvs_id})")

            # ---------------------------------------------------------
            # Milestone 5: Dynamic Instrumentation Hook Generation
            # ---------------------------------------------------------
            print("\n[*] [M5] Generating Frida Dynamic Hooks...")
            hook_js = ag.generate_hook("com.andoguard.showcase.MainActivity#onCreate")
            print(f"    Frida Java Hook generated ({len(hook_js)} characters).")

            # ---------------------------------------------------------
            # Milestone 6: Security Bypasses & Memory Utilities
            # ---------------------------------------------------------
            print("\n[*] [M6] Security Bypasses & Hexdump Utilities...")
            bypass_script = ag.bypass(module="all")
            print(f"    Universal Bypass Script generated ({len(bypass_script)} characters).")
            # Save trace event in session store
            ag.save_trace_event(
                TraceEvent(
                    timestamp="2026-10-29T00:00:00Z",
                    event_type="call",
                    class_name="com.andoguard.showcase.MainActivity",
                    method_name="onCreate",
                    args=["android.os.Bundle@1a2b3c"],
                    return_val=None,
                )
            )
            print("    Recorded trace event in SQLite session repository.")

            # ---------------------------------------------------------
            # Milestone 7: AI Reasoning & Security Triage (Mock/Local Mode)
            # ---------------------------------------------------------
            print("\n[*] [M7] Running AI-Assisted Security Triage & Code Explanation...")
            ai_explanation = ag.ai_explain(
                code_res.source or "public class MainActivity { void onCreate() {} }",
                provider="mock",
            )
            print(f"    AI Code Explanation preview: {ai_explanation[:90]}...")
            ai_triage = ag.ai_triage(provider="mock")
            print(f"    AI MASVS Triage preview: {ai_triage[:90]}...")

            # ---------------------------------------------------------
            # Milestone 8: Autonomous Adaptive ReAct Agent Loop
            # ---------------------------------------------------------
            print("\n[*] [M8] Triggering Adaptive Autonomous Agent...")
            agent_result = ag.adaptive_run(
                goal="Inspect exported components and verify security flags",
                max_steps=3,
                provider="mock",
            )
            print(f"    Agent finished in {len(agent_result.steps)} steps (Findings: {agent_result.findings_recorded}).")
            print(f"    Agent summary: {agent_result.summary[:80]}...")

            # ---------------------------------------------------------
            # Milestone 9: Multi-Format Reporting & Session Bundle (.agguard)
            # ---------------------------------------------------------
            print("\n[*] [M9] Generating Multi-Format Assessment Reports & Session Bundle...")
            # Markdown Report
            md_rep = ag.generate_report(format="markdown")
            print(f"    Generated Markdown Report ({len(md_rep.splitlines())} lines).")

            # HTML Report
            html_rep = ag.generate_report(format="html")
            print(f"    Generated Offline Modern HTML Report ({len(html_rep)} bytes).")

            # JSON Report
            json_rep = ag.generate_report(format="json")
            parsed_json = json.loads(json_rep)
            print(f"    JSON Report verified: {len(parsed_json['findings'])} total findings summarized.")

            # Export session bundle (.agguard)
            bundle_file = tmp_path / "showcase_session.agguard"
            exported_path = ag.export_bundle(out_path=bundle_file)
            print(f"    Exported Session Bundle: {exported_path.name} ({exported_path.stat().st_size} bytes)")

            # Import and verify integrity into new store
            imported_session = AndoGuard.import_bundle(bundle_file, work_dir=tmp_path / "imported_workspace")
            print(f"    Integrity Verified & Imported Session: {imported_session.session_id} (Name: {imported_session.name})")

    print("\n" + "=" * 70)
    print("      All Milestones 1 - 9 Verified & Executed Successfully!    ")
    print("=" * 70)


if __name__ == "__main__":
    main()
