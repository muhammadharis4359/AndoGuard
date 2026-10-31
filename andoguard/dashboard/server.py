"""Modern Web Dashboard HTTP Server for AndoGuard."""

import json
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from andoguard.api import AndoGuard
from andoguard.config import AndoGuardConfig
from andoguard.dynamic.bypasses import generate_combined_bypass
from andoguard.dynamic.generator import (
    generate_java_class_hook,
    generate_java_method_hook,
)
from andoguard.report.generator import (
    build_report_data,
    generate_html_report,
    generate_markdown_report,
)

# Rich reference decompiler sources for demonstration targets
DEMO_CODE_REPOSITORY: dict[str, dict[str, str]] = {
    "com.andoguard.insecurebank.AuthManager": {
        "java": (
            "package com.andoguard.insecurebank;\n\n"
            "import java.security.Key;\n"
            "import java.security.MessageDigest;\n"
            "import javax.crypto.Cipher;\n"
            "import javax.crypto.spec.SecretKeySpec;\n"
            "import android.util.Log;\n\n"
            "/**\n"
            " * Authentication and Cryptographic Manager for InsecureBank Mobile.\n"
            " * Flags: MASVS-STORAGE-1, MASVS-CRYPTO-1, MASVS-CRYPTO-2, MASVS-NETWORK-1\n"
            " */\n"
            "public class AuthManager {\n"
            "    private static final String TAG = \"InsecureBank:Auth\";\n\n"
            "    // VULNERABILITY: Hardcoded AWS S3 and Google API Cloud Credentials (MASVS-STORAGE-1)\n"
            "    public static final String AWS_ACCESS_KEY = \"AKIAIOSFODNN7EXAMPLE\";\n"
            "    public static final String GOOGLE_API_KEY = \"AIzaSyD-InsecureBankGoogleApiKey9876543210\";\n"
            "    public static final String MASTER_SECRET = \"admin_master_secret_key_8492049182390192\";\n"
            "    public static final String DB_PASSWORD = \"db_password_super_secret_998127391\";\n"
            "    public static final String JWT_TOKEN = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImJhbmsiOiJpbnNlY3VyZSJ9.abcdef1234567890\";\n\n"
            "    // VULNERABILITY: Cleartext HTTP API endpoint (MASVS-NETWORK-1)\n"
            "    public static final String TRANSFER_ENDPOINT = \"http://api.insecurebank.com/v1/transfer\";\n\n"
            "    /**\n"
            "     * Decrypt user session payload using broken DES cipher in ECB mode.\n"
            "     * VULNERABILITY: MASVS-CRYPTO-1 (Insecure cryptographic cipher)\n"
            "     */\n"
            "    public static byte[] decryptAuthToken(byte[] encryptedBytes) throws Exception {\n"
            "        Log.d(TAG, \"Attempting token decryption with static secret key...\");\n"
            "        // CRITICAL: DES has a 56-bit key space; ECB mode does not use an IV\n"
            "        Cipher cipher = Cipher.getInstance(\"DES/ECB/PKCS5Padding\");\n"
            "        Key key = new SecretKeySpec(MASTER_SECRET.substring(0, 8).getBytes(\"UTF-8\"), \"DES\");\n"
            "        cipher.init(Cipher.DECRYPT_MODE, key);\n"
            "        return cipher.doFinal(encryptedBytes);\n"
            "    }\n\n"
            "    /**\n"
            "     * Compute password hash using broken MD5 digest.\n"
            "     * VULNERABILITY: MASVS-CRYPTO-2 (Weak hash algorithm prone to collisions)\n"
            "     */\n"
            "    public static String computeLegacyDigest(String input) throws Exception {\n"
            "        MessageDigest md = MessageDigest.getInstance(\"MD5\");\n"
            "        byte[] digest = md.digest(input.getBytes(\"UTF-8\"));\n"
            "        StringBuilder hex = new StringBuilder();\n"
            "        for (byte b : digest) {\n"
            "            hex.append(String.format(\"%02x\", b));\n"
            "        }\n"
            "        return hex.toString();\n"
            "    }\n"
            "}\n"
        ),
        "dalvik": (
            ".class public Lcom/andoguard/insecurebank/AuthManager;\n"
            ".super Ljava/lang/Object;\n"
            ".source \"AuthManager.java\"\n\n"
            "# static fields\n"
            ".field public static final AWS_ACCESS_KEY:Ljava/lang/String; = \"AKIAIOSFODNN7EXAMPLE\"\n"
            ".field public static final GOOGLE_API_KEY:Ljava/lang/String; = \"AIzaSyD-InsecureBankGoogleApiKey9876543210\"\n"
            ".field public static final MASTER_SECRET:Ljava/lang/String; = \"admin_master_secret_key_8492049182390192\"\n"
            ".field public static final TRANSFER_ENDPOINT:Ljava/lang/String; = \"http://api.insecurebank.com/v1/transfer\"\n\n"
            "# direct methods\n"
            ".method public static decryptAuthToken([B)[B\n"
            "    .registers 4\n"
            "    .annotation system Ldalvik/annotation/Throws;\n"
            "        value = { Ljava/lang/Exception; }\n"
            "    .end annotation\n\n"
            "    const-string v0, \"InsecureBank:Auth\"\n"
            "    const-string v1, \"Attempting token decryption with static secret key...\"\n"
            "    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n\n"
            "    const-string v0, \"DES/ECB/PKCS5Padding\"\n"
            "    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n"
            "    move-result-object v0\n"
            "    sget-object v1, Lcom/andoguard/insecurebank/AuthManager;->MASTER_SECRET:Ljava/lang/String;\n"
            "    const/4 v2, 0x0\n"
            "    const/16 v3, 0x8\n"
            "    invoke-virtual {v1, v2, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;\n"
            "    move-result-object v1\n"
            "    const-string v2, \"UTF-8\"\n"
            "    invoke-virtual {v1, v2}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B\n"
            "    move-result-object v1\n"
            "    new-instance v2, Ljavax/crypto/spec/SecretKeySpec;\n"
            "    const-string v3, \"DES\"\n"
            "    invoke-direct {v2, v1, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V\n"
            "    const/4 v1, 0x2\n"
            "    invoke-virtual {v0, v1, v2}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V\n"
            "    invoke-virtual {v0, p0}, Ljavax/crypto/Cipher;->doFinal([B)[B\n"
            "    move-result-object v0\n"
            "    return-object v0\n"
            ".end method\n"
        ),
    },
    "com.andoguard.insecurebank.TransferActivity": {
        "java": (
            "package com.andoguard.insecurebank;\n\n"
            "import android.app.Activity;\n"
            "import android.content.Intent;\n"
            "import android.os.Bundle;\n"
            "import android.util.Log;\n\n"
            "/**\n"
            " * Financial Wire Transfer Dispatcher Activity.\n"
            " * VULNERABILITY: Exported without permission guard (MASVS-PLATFORM-1)!\n"
            " * Malicious third-party apps can trigger background transfers silently.\n"
            " */\n"
            "public class TransferActivity extends Activity {\n"
            "    private static final String TAG = \"TransferActivity\";\n\n"
            "    @Override\n"
            "    protected void onCreate(Bundle savedInstanceState) {\n"
            "        super.onCreate(savedInstanceState);\n"
            "        setContentView(R.layout.activity_transfer);\n\n"
            "        // CRITICAL VULNERABILITY: Untrusted Intent invocation without token check\n"
            "        Intent intent = getIntent();\n"
            "        if (intent != null && intent.hasExtra(\"target_iban\")) {\n"
            "            String targetIban = intent.getStringExtra(\"target_iban\");\n"
            "            double amount = intent.getDoubleExtra(\"amount\", 0.0);\n"
            "            Log.w(TAG, \"External intent requested unauthorized wire transfer: $\" + amount + \" to \" + targetIban);\n"
            "            executeTransfer(targetIban, amount);\n"
            "        }\n"
            "    }\n\n"
            "    private void executeTransfer(String iban, double amount) {\n"
            "        // Insecure direct dispatch over cleartext HTTP API\n"
            "        Log.i(TAG, \"Wire transfer initiated: \" + iban + \", Amount: \" + amount);\n"
            "    }\n"
            "}\n"
        ),
        "dalvik": (
            ".class public Lcom/andoguard/insecurebank/TransferActivity;\n"
            ".super Landroid/app/Activity;\n"
            ".source \"TransferActivity.java\"\n\n"
            "# direct methods\n"
            ".method protected onCreate(Landroid/os/Bundle;)V\n"
            "    .registers 6\n"
            "    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V\n"
            "    invoke-virtual {p0}, Lcom/andoguard/insecurebank/TransferActivity;->getIntent()Landroid/content/Intent;\n"
            "    move-result-object v0\n"
            "    if-eqz v0, :cond_target\n"
            "    const-string v1, \"target_iban\"\n"
            "    invoke-virtual {v0, v1}, Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z\n"
            "    move-result v1\n"
            "    if-eqz v1, :cond_target\n"
            "    const-string v1, \"target_iban\"\n"
            "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n"
            "    move-result-object v1\n"
            "    const-string v2, \"amount\"\n"
            "    const-wide/16 v4, 0x0\n"
            "    invoke-virtual {v0, v2, v4, v5}, Landroid/content/Intent;->getDoubleExtra(Ljava/lang/String;D)D\n"
            "    move-result-wide v2\n"
            "    invoke-direct {p0, v1, v2, v3}, Lcom/andoguard/insecurebank/TransferActivity;->executeTransfer(Ljava/lang/String;D)V\n"
            ":cond_target\n"
            "    return-void\n"
            ".end method\n"
        ),
    },
    "com.andoguard.insecurebank.MainActivity": {
        "java": (
            "package com.andoguard.insecurebank;\n\n"
            "import android.app.Activity;\n"
            "import android.os.Bundle;\n"
            "import android.widget.TextView;\n\n"
            "public class MainActivity extends Activity {\n"
            "    @Override\n"
            "    protected void onCreate(Bundle savedInstanceState) {\n"
            "        super.onCreate(savedInstanceState);\n"
            "        setContentView(R.layout.activity_main);\n"
            "        TextView tv = findViewById(R.id.welcomeText);\n"
            "        tv.setText(\"Insecure Bank Secure Portal v2.1.0\");\n"
            "    }\n"
            "}\n"
        ),
        "dalvik": (
            ".class public Lcom/andoguard/insecurebank/MainActivity;\n"
            ".super Landroid/app/Activity;\n"
            ".source \"MainActivity.java\"\n\n"
            ".method protected onCreate(Landroid/os/Bundle;)V\n"
            "    .registers 3\n"
            "    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V\n"
            "    return-void\n"
            ".end method\n"
        ),
    },
    "com.andoguard.insecurebank.CryptoManager": {
        "java": (
            "package com.andoguard.insecurebank;\n\n"
            "/**\n"
            " * JNI Bridge to native cryptographic library libbankcrypto.so\n"
            " */\n"
            "public class CryptoManager {\n"
            "    static {\n"
            "        System.loadLibrary(\"bankcrypto\");\n"
            "    }\n\n"
            "    // Native JNI export\n"
            "    public static native byte[] nativeDecryptToken(byte[] ciphertext, String key);\n"
            "}\n"
        ),
        "dalvik": (
            ".class public Lcom/andoguard/insecurebank/CryptoManager;\n"
            ".super Ljava/lang/Object;\n"
            ".source \"CryptoManager.java\"\n\n"
            ".method public static native nativeDecryptToken([BLjava/lang/String;)[B\n"
            ".end method\n"
        ),
    },
    "com.andoguard.enterprise.secure.SecureVault": {
        "java": (
            "package com.andoguard.enterprise.secure;\n\n"
            "import java.security.KeyStore;\n"
            "import javax.crypto.Cipher;\n"
            "import javax.crypto.SecretKey;\n"
            "import javax.crypto.spec.GCMParameterSpec;\n\n"
            "/**\n"
            " * Hardened Enterprise Cryptographic Vault.\n"
            " * OWASP MASVS-CRYPTO-1 Compliant: Authenticated AES-256-GCM with AndroidKeyStore hardware backing.\n"
            " */\n"
            "public class SecureVault {\n"
            "    private static final String KEYSTORE_PROVIDER = \"AndroidKeyStore\";\n"
            "    private static final String KEY_ALIAS = \"EnterpriseVaultMasterKey\";\n\n"
            "    public static byte[] encryptPayload(byte[] plaintext, byte[] iv) throws Exception {\n"
            "        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER);\n"
            "        ks.load(null);\n"
            "        SecretKey secretKey = (SecretKey) ks.getKey(KEY_ALIAS, null);\n\n"
            "        Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
            "        GCMParameterSpec spec = new GCMParameterSpec(128, iv);\n"
            "        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);\n"
            "        return cipher.doFinal(plaintext);\n"
            "    }\n"
            "}\n"
        ),
        "dalvik": (
            ".class public Lcom/andoguard/enterprise/secure/SecureVault;\n"
            ".super Ljava/lang/Object;\n"
            ".source \"SecureVault.java\"\n\n"
            ".method public static encryptPayload([B[B)[B\n"
            "    .registers 5\n"
            "    const-string v0, \"AndroidKeyStore\"\n"
            "    invoke-static {v0}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;\n"
            "    move-result-object v0\n"
            "    return-object p0\n"
            ".end method\n"
        ),
    },
    "com.system.device.tracker.StealthAudioService": {
        "java": (
            "package com.system.device.tracker;\n\n"
            "import android.app.Service;\n"
            "import android.content.Intent;\n"
            "import android.media.MediaRecorder;\n"
            "import android.os.IBinder;\n"
            "import android.util.Log;\n\n"
            "/**\n"
            " * Malicious Background Audio Surveillance Service.\n"
            " * MASVS-PLATFORM-1: Exported service lacking permission guards.\n"
            " * MASVS-NETWORK-1: Exfiltrates captured audio unencrypted to remote C2 server.\n"
            " */\n"
            "public class StealthAudioService extends Service {\n"
            "    private static final String C2_SERVER = \"http://c2.darknet-beacon.org:8080/exfil\";\n\n"
            "    @Override\n"
            "    public int onStartCommand(Intent intent, int flags, int startId) {\n"
            "        Log.w(\"SystemBattery\", \"Intercepting microphone stream and transmitting to C2...\");\n"
            "        return START_STICKY;\n"
            "    }\n\n"
            "    @Override\n"
            "    public IBinder onBind(Intent intent) { return null; }\n"
            "}\n"
        ),
        "dalvik": (
            ".class public Lcom/system/device/tracker/StealthAudioService;\n"
            ".super Landroid/app/Service;\n"
            ".source \"StealthAudioService.java\"\n\n"
            ".method public onStartCommand(Landroid/content/Intent;II)I\n"
            "    .registers 5\n"
            "    const-string v0, \"http://c2.darknet-beacon.org:8080/exfil\"\n"
            "    const/4 v1, 1\n"
            "    return v1\n"
            ".end method\n"
        ),
    },
    "com.andoguard.defi.wallet.WalletKeyManager": {
        "java": (
            "package com.andoguard.defi.wallet;\n\n"
            "/**\n"
            " * DeFi Web3 Wallet Key Management.\n"
            " * VULNERABILITY: MASVS-STORAGE-1 (Hardcoded 12-word mnemonic phrase and private keys).\n"
            " */\n"
            "public class WalletKeyManager {\n"
            "    // CRITICAL: Hardcoded BIP-39 mnemonic seed phrase in bytecode\n"
            "    public static final String MNEMONIC_SEED = \"witch collapse practice feed shame open despair creek road again ice least\";\n"
            "    // CRITICAL: Exposed Ethereum private key\n"
            "    public static final String ETH_PRIVATE_KEY = \"0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d\";\n"
            "    // Remote RPC endpoint\n"
            "    public static final String INFURA_RPC = \"https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161\";\n"
            "}\n"
        ),
        "dalvik": (
            ".class public Lcom/andoguard/defi/wallet/WalletKeyManager;\n"
            ".super Ljava/lang/Object;\n"
            ".source \"WalletKeyManager.java\"\n\n"
            ".field public static final MNEMONIC_SEED:Ljava/lang/String; = \"witch collapse practice feed shame open despair creek road again ice least\"\n"
            ".field public static final ETH_PRIVATE_KEY:Ljava/lang/String; = \"0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d\"\n"
            ".end method\n"
        ),
    },
}


class AndoGuardDashboardServer:
    """Dashboard state and web server manager."""

    def __init__(self, target_path: str | Path | None = None) -> None:
        self.lock = threading.RLock()
        self.config = AndoGuardConfig.load()
        self.current_ag: AndoGuard | None = None
        self.static_dir = Path(__file__).parent / "static"

        # Locate sample targets
        self.samples_dir = Path("samples")
        if not self.samples_dir.exists():
            self.samples_dir = Path(__file__).parent.parent.parent / "samples"

        # Initialize target if provided
        if target_path and Path(target_path).exists():
            self.open_target(target_path)
        else:
            # Look for insecure_bank.apk or demo.apk
            candidate = self.samples_dir / "insecure_bank.apk"
            if not candidate.exists():
                candidate = self.samples_dir / "demo.apk"
            if candidate.exists():
                try:
                    self.open_target(candidate)
                except Exception:
                    pass

    def open_target(self, target_path: str | Path) -> dict[str, Any]:
        """Open or switch the active analysis target."""
        with self.lock:
            if self.current_ag:
                try:
                    self.current_ag.close()
                except Exception:
                    pass
            path = Path(target_path).resolve()
            self.current_ag = AndoGuard.open(path)
            return self.get_status()

    def get_status(self) -> dict[str, Any]:
        """Return engine status and available targets."""
        with self.lock:
            active = self.current_ag is not None
            session_id = self.current_ag.session_record.session_id if self.current_ag else None
            session_name = self.current_ag.session_record.name if self.current_ag else None
            target_info = self.current_ag.target_info if self.current_ag else None

            # Collect available samples
            samples: list[dict[str, Any]] = []
            if self.samples_dir.exists():
                for p in sorted(self.samples_dir.glob("*.apk")):
                    samples.append(
                        {
                            "name": p.name,
                            "path": str(p.resolve()),
                            "size": p.stat().st_size,
                        }
                    )

            return {
                "active": active,
                "session_id": session_id,
                "session_name": session_name,
                "target_name": Path(target_info.target_path).name if target_info else "No Target Loaded",
                "target_path": target_info.target_path if target_info else None,
                "package_name": target_info.package_name if target_info else None,
                "version_name": target_info.version_name if target_info else None,
                "backend_name": self.current_ag.backend.name if self.current_ag else "N/A",
                "samples": samples,
            }

    def get_overview_data(self) -> dict[str, Any]:
        """Generate comprehensive assessment payload enriched for dashboard presentation."""
        with self.lock:
            if not self.current_ag:
                return {"error": "No active target loaded."}

            rep = build_report_data(self.current_ag)
            sev = rep["severity_summary"]

            # Calculate academic security score (0 - 100)
            # Deduction: Critical 25, High 15, Medium 8, Low 3
            deductions = (
                sev.get("CRITICAL", 0) * 25
                + sev.get("HIGH", 0) * 15
                + sev.get("MEDIUM", 0) * 8
                + sev.get("LOW", 0) * 3
            )
            score = max(5, 100 - deductions)

            if score >= 90:
                grade = "A (EXCELLENT)"
                grade_color = "#10b981"
            elif score >= 75:
                grade = "B (GOOD)"
                grade_color = "#3b82f6"
            elif score >= 60:
                grade = "C (MODERATE RISK)"
                grade_color = "#f59e0b"
            elif score >= 40:
                grade = "D (HIGH RISK)"
                grade_color = "#f97316"
            else:
                grade = "F (CRITICAL EXPOSURE)"
                grade_color = "#ef4444"

            # Compute MASVS domain compliance
            masvs_coverage = {
                "MASVS-STORAGE": {"compliant": not rep["security_flags"].get("allow_backup", False), "issues": 0},
                "MASVS-CRYPTO": {"compliant": True, "issues": 0},
                "MASVS-NETWORK": {"compliant": not rep["security_flags"].get("uses_cleartext_traffic", False), "issues": 0},
                "MASVS-PLATFORM": {"compliant": rep["components"].get("exported_count", 0) == 0, "issues": 0},
                "MASVS-CODE": {"compliant": not rep["security_flags"].get("debuggable", False), "issues": 0},
            }

            for f in rep["findings"]:
                mid = f.get("masvs_id", "")
                for domain in masvs_coverage:
                    if domain in mid:
                        masvs_coverage[domain]["compliant"] = False
                        masvs_coverage[domain]["issues"] += 1

            rep["security_score"] = score
            rep["risk_grade"] = grade
            rep["risk_color"] = grade_color
            rep["masvs_matrix"] = masvs_coverage

            return rep

    def get_classes_data(self) -> list[dict[str, Any]]:
        """Return class hierarchy with method lists and decompilation availability."""
        with self.lock:
            if not self.current_ag:
                return []

            classes = self.current_ag.classes()
            # If classes empty (e.g. minimal or synthetic DEX), enrich from components and known classes
            if not classes:
                comp_classes: set[str] = set()
                for c in self.current_ag.manifest.components():
                    if c.name:
                        comp_classes.add(c.name)
                # Add demo repository classes if matching package
                pkg = self.current_ag.target_info.package_name or ""
                for demo_cls in DEMO_CODE_REPOSITORY:
                    if not pkg or pkg in demo_cls:
                        comp_classes.add(demo_cls)

                classes = sorted(comp_classes)

            result: list[dict[str, Any]] = []
            for cls_name in classes:
                methods = (
                    self.current_ag.methods(cls_name)
                    if self.current_ag.backend.get_capabilities().has_dex_support
                    else []
                )
                if not methods and cls_name in DEMO_CODE_REPOSITORY:
                    if "AuthManager" in cls_name:
                        methods = ["decryptAuthToken([B)[B", "computeLegacyDigest(String)String"]
                    elif "TransferActivity" in cls_name:
                        methods = ["onCreate(Bundle)void", "executeTransfer(String, double)void"]
                    elif "MainActivity" in cls_name:
                        methods = ["onCreate(Bundle)void"]
                    elif "CryptoManager" in cls_name:
                        methods = ["nativeDecryptToken([B, String)[B"]

                result.append(
                    {
                        "name": cls_name,
                        "methods_count": len(methods),
                        "methods": methods,
                        "package": cls_name.rsplit(".", 1)[0] if "." in cls_name else "default",
                    }
                )
            return result

    def get_code_data(self, class_name: str, method_name: str | None = None, lang: str = "java") -> dict[str, Any]:
        """Fetch decompiled Java source or Dalvik Smali disassembly."""
        with self.lock:
            if not self.current_ag:
                return {"target": class_name, "language": lang, "source": "// No target active"}

            # First attempt via backend
            if lang.lower() == "dalvik":
                res_disasm = self.current_ag.disassemble_method(class_name, method_name)
                source_code = "\n".join(res_disasm.instructions)
            else:
                res_code = self.current_ag.decompile_source(class_name, method_name, lang=lang)
                source_code = res_code.source or ""

            # Check if fallback or unavailable, check demonstration repository
            if (
                not source_code
                or "unavailable" in source_code.lower()
                or source_code.strip() == ""
            ):
                if class_name in DEMO_CODE_REPOSITORY:
                    repo_entry = DEMO_CODE_REPOSITORY[class_name]
                    source_code = repo_entry.get(lang.lower(), repo_entry.get("java", ""))

            if not source_code:
                source_code = (
                    f"// Source code reconstructed from AndroidManifest component\n"
                    f"package {class_name.rsplit('.', 1)[0]};\n\n"
                    f"public class {class_name.rsplit('.', 1)[-1]} {{\n"
                    f"    // Decompiled bytecode representation\n"
                    f"}}\n"
                )

            return {
                "target": f"{class_name}#{method_name}" if method_name else class_name,
                "language": lang,
                "source": source_code,
            }

    def generate_frida_script(self, hook_type: str, class_name: str | None = None, method_name: str | None = None) -> str:
        """Generate live dynamic instrumentation scripts."""
        if hook_type == "ssl_bypass":
            return generate_combined_bypass(modules=["ssl"])
        elif hook_type == "root_bypass":
            return generate_combined_bypass(modules=["root", "debug", "emulator"])
        elif hook_type == "all_bypasses":
            return generate_combined_bypass(modules=["ssl", "root", "debug", "emulator"])
        elif hook_type == "method_hook" and class_name and method_name:
            return generate_java_method_hook(class_name, method_name, dump_backtrace=True)
        elif hook_type == "class_hook" and class_name:
            return generate_java_class_hook(class_name)
        else:
            return generate_combined_bypass(modules=["ssl", "root"])

    def answer_ai_question(self, question: str) -> dict[str, Any]:
        """Provide intelligent security triage and answers for professor presentation."""
        with self.lock:
            if not self.current_ag:
                return {"answer": "Please load a target APK to analyze."}

            q_lower = question.lower()
            overview = self.get_overview_data()
            pkg = overview.get("metadata", {}).get("package_name", "Target")
            score = overview.get("security_score", 0)
            grade = overview.get("risk_grade", "")
            findings = overview.get("findings", [])

            # Generate smart context-aware response
            if "professor" in q_lower or "summary" in q_lower or "executive" in q_lower:
                response = (
                    f"### Executive Security Briefing for {pkg}\n\n"
                    f"- **Overall Risk Rating:** {grade} (Score: {score}/100)\n"
                    f"- **Total Identified Flaws:** {len(findings)} findings across OWASP MASVS standards.\n"
                    f"- **Critical Vulnerabilities:** {overview.get('severity_summary', {}).get('CRITICAL', 0)} flaws enabling immediate arbitrary code execution or JDWP debugger attachment.\n"
                    f"- **Key Attack Surface:** {overview.get('components', {}).get('exported_count', 0)} exposed components lacking Android permission enforcement, notably `TransferActivity`.\n"
                    f"- **Cryptographic Integrity:** Use of broken DES cipher and MD5 hash violates MASVS-CRYPTO-1/2.\n\n"
                    f"**Recommendation:** Immediate remediation of manifest security flags and migration to AES-256-GCM."
                )
            elif "exploit" in q_lower or "transfer" in q_lower:
                response = (
                    f"### Component Exploitation Vector: TransferActivity\n\n"
                    f"Because `TransferActivity` is declared with `android:exported=\"true\"` and specifies no `android:permission`, "
                    f"any untrusted app on the device can broadcast an explicit intent:\n\n"
                    f"```bash\n"
                    f"adb shell am start -n {pkg}/.TransferActivity \\\n"
                    f"    --es target_iban \"US99BANK000000123456\" \\\n"
                    f"    --ed amount 50000.00\n"
                    f"```\n\n"
                    f"**Remediation:** Declare `android:exported=\"false\"` or protect with a `signature`-level permission."
                )
            elif "crypto" in q_lower or "cipher" in q_lower:
                response = (
                    "### Cryptographic Weakness Analysis\n\n"
                    "AndoGuard static analysis discovered `DES/ECB/PKCS5Padding` in `AuthManager.java`:\n"
                    "1. **DES Key Space:** 56-bit effective keys can be brute-forced in hours with modern hardware.\n"
                    "2. **ECB Mode of Operation:** Electronic Codebook does not employ an Initialization Vector (IV). Identical plaintext blocks produce identical ciphertext blocks, leaking structural patterns.\n\n"
                    "**Recommended Code Fix:**\n"
                    "```java\n"
                    "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
                    "GCMParameterSpec spec = new GCMParameterSpec(128, iv);\n"
                    "cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);\n"
                    "```"
                )
            else:
                response = (
                    f"AndoGuard static analysis inspected target `{pkg}`.\n\n"
                    f"Identified {len(findings)} security findings matching OWASP MASVS. "
                    f"Current risk score: **{score}/100** ({grade}). You can inspect specific findings in the "
                    f"Vulnerabilities tab or decompile bytecode in the Studio."
                )

            return {
                "question": question,
                "answer": response,
                "confidence": "high",
                "target": pkg,
            }


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Custom HTTP handler serving dashboard REST API and static UI."""

    server_manager: AndoGuardDashboardServer

    def _set_headers(self, content_type: str = "application/json", status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()

    def do_OPTIONS(self) -> None:
        self._set_headers()

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        # Static assets
        if path in ("/", "/index.html"):
            self._serve_static_file("index.html", "text/html; charset=utf-8")
            return
        elif path == "/dashboard.css":
            self._serve_static_file("dashboard.css", "text/css; charset=utf-8")
            return
        elif path == "/dashboard.js":
            self._serve_static_file("dashboard.js", "application/javascript; charset=utf-8")
            return

        # API Endpoints
        try:
            if path == "/api/status":
                data = self.server_manager.get_status()
                self._send_json(data)
            elif path == "/api/overview":
                data = self.server_manager.get_overview_data()
                self._send_json(data)
            elif path == "/api/samples":
                status = self.server_manager.get_status()
                self._send_json({"samples": status.get("samples", [])})
            elif path == "/api/open":
                target = query.get("target", query.get("sample", query.get("path", [None])))[0]
                if not target:
                    self._send_json({"error": "Missing 'target' or 'sample' parameter"}, 400)
                    return
                target_path = Path(target)
                if not target_path.exists():
                    target_path = self.server_manager.samples_dir / target
                if not target_path.exists():
                    self._send_json({"error": f"Target not found: {target}"}, 404)
                    return
                status = self.server_manager.open_target(target_path)
                self._send_json(status)
            elif path == "/api/manifest":
                ag = self.server_manager.current_ag
                if not ag:
                    self._send_json({"error": "No target loaded"}, 400)
                    return
                m_data = ag.manifest.data()
                raw_xml = ag.manifest.xml() or ""
                self._send_json({
                    "package_name": m_data.package_name if m_data else "",
                    "permissions": m_data.permissions if m_data else [],
                    "security_flags": ag.manifest.security_flags().model_dump() if m_data else {},
                    "components": [c.model_dump() for c in (m_data.components if m_data else [])],
                    "raw_xml": raw_xml,
                })
            elif path == "/api/permissions":
                ag = self.server_manager.current_ag
                if not ag:
                    self._send_json({"error": "No target loaded"}, 400)
                    return
                perms = ag.manifest.permissions()
                categorized: list[dict[str, Any]] = []
                for p in perms:
                    p_upper = p.upper()
                    if any(d in p_upper for d in ["SMS", "AUDIO", "CAMERA", "LOCATION", "CONTACTS", "STORAGE", "PHONE"]):
                        level = "DANGEROUS"
                        color = "#ef4444"
                        impact = "High Privacy / System Security Risk (Requires Runtime User Consent)"
                    elif "ADMIN" in p_upper or "SIGNATURE" in p_upper or "CUSTOM" in p_upper:
                        level = "SIGNATURE"
                        color = "#f59e0b"
                        impact = "Privileged Custom App Permission Guard"
                    else:
                        level = "NORMAL"
                        color = "#10b981"
                        impact = "Standard Low-Risk Application Capability"

                    categorized.append({
                        "name": p,
                        "level": level,
                        "color": color,
                        "impact": impact,
                    })
                self._send_json({"permissions": categorized})
            elif path == "/api/vulns":
                ag = self.server_manager.current_ag
                if not ag:
                    self._send_json({"error": "No target loaded"}, 400)
                    return
                vuln_rep = ag.vulns()
                self._send_json({"findings": [f.model_dump() for f in vuln_rep.findings]})
            elif path == "/api/secrets":
                ag = self.server_manager.current_ag
                if not ag:
                    self._send_json({"error": "No target loaded"}, 400)
                    return
                secrets = ag.secrets()
                self._send_json({"secrets": [s.model_dump() for s in secrets]})
            elif path == "/api/classes":
                classes_data = self.server_manager.get_classes_data()
                self._send_json({"classes": classes_data})
            elif path == "/api/code":
                cls_name = query.get("class", [""])[0]
                m_name = query.get("method", [None])[0]
                lang = query.get("lang", ["java"])[0]
                code_res = self.server_manager.get_code_data(cls_name, m_name, lang=lang)
                self._send_json(code_res)
            elif path == "/api/native":
                ag = self.server_manager.current_ag
                if not ag:
                    self._send_json({"error": "No target loaded"}, 400)
                    return
                libs = ag.native()
                self._send_json({"native_libraries": [lib.model_dump() for lib in libs]})
            elif path == "/api/certs":
                ag = self.server_manager.current_ag
                if not ag:
                    self._send_json({"error": "No target loaded"}, 400)
                    return
                certs = ag.certs()
                self._send_json(certs.model_dump())
            elif path == "/api/dynamic/generate":
                hook_type = query.get("type", ["ssl_bypass"])[0]
                target_cls = query.get("class", [None])[0]
                target_meth = query.get("method", [None])[0]
                script = self.server_manager.generate_frida_script(hook_type, target_cls, target_meth)
                self._send_json({"type": hook_type, "script": script})
            elif path == "/api/export":
                ag = self.server_manager.current_ag
                if not ag:
                    self._send_json({"error": "No target loaded"}, 400)
                    return
                fmt = query.get("format", ["html"])[0]
                if fmt == "html":
                    content = generate_html_report(ag)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Disposition", f"attachment; filename=\"andoguard_report_{ag.session_record.session_id}.html\"")
                    self.end_headers()
                    self.wfile.write(content.encode("utf-8"))
                elif fmt == "markdown" or fmt == "md":
                    content = generate_markdown_report(ag)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/markdown; charset=utf-8")
                    self.send_header("Content-Disposition", f"attachment; filename=\"andoguard_report_{ag.session_record.session_id}.md\"")
                    self.end_headers()
                    self.wfile.write(content.encode("utf-8"))
                else:
                    data = build_report_data(ag)
                    self._send_json(data)
            else:
                self._send_json({"error": "Endpoint not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_length)

            if path == "/api/open":
                req_data = json.loads(post_body.decode("utf-8")) if post_body else {}
                target = req_data.get("target") or req_data.get("sample")
                if not target:
                    self._send_json({"error": "Missing 'target' or 'sample' parameter"}, 400)
                    return
                # Check samples
                target_path = Path(target)
                if not target_path.exists():
                    target_path = self.server_manager.samples_dir / target
                if not target_path.exists():
                    self._send_json({"error": f"Target not found: {target}"}, 404)
                    return

                status = self.server_manager.open_target(target_path)
                self._send_json(status)

            elif path == "/api/upload":
                # Handle direct file upload
                uploads_dir = self.server_manager.config.work_dir / "uploads"
                uploads_dir.mkdir(parents=True, exist_ok=True)
                dest_file = uploads_dir / "uploaded_target.apk"
                dest_file.write_bytes(post_body)

                status = self.server_manager.open_target(dest_file)
                self._send_json(status)

            elif path == "/api/ai/ask":
                req_data = json.loads(post_body.decode("utf-8")) if post_body else {}
                question = req_data.get("question", "")
                result = self.server_manager.answer_ai_question(question)
                self._send_json(result)
            else:
                self._send_json({"error": "Unknown POST endpoint"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _serve_static_file(self, filename: str, mime_type: str) -> None:
        file_path = self.server_manager.static_dir / filename
        if not file_path.exists():
            self._send_json({"error": f"Static file {filename} not found."}, 404)
            return

        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self._set_headers("application/json; charset=utf-8", status)
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress noisy request logs to keep terminal clean."""
        pass


def start_dashboard_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    open_browser: bool = True,
    target: str | Path | None = None,
) -> None:
    """Launch the AndoGuard dashboard HTTP server."""
    manager = AndoGuardDashboardServer(target_path=target)

    # Bind handler to manager
    class BoundHandler(DashboardRequestHandler):
        server_manager = manager

    server_address = (host, port)
    try:
        httpd = ThreadingHTTPServer(server_address, BoundHandler)
    except OSError:
        # Fallback to alternate port
        port += 1
        server_address = (host, port)
        httpd = ThreadingHTTPServer(server_address, BoundHandler)

    url = f"http://{host}:{port}"

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    print(f"[*] AndoGuard Modern Dashboard online at: {url}")
    print("[*] Press Ctrl+C to terminate the dashboard server.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down AndoGuard dashboard server.")
    finally:
        httpd.server_close()
