/**
 * AndoGuard Modern Web Dashboard Client Controller
 * Pure Vanilla ES6+ JavaScript
 */

// Comprehensive Demo Datasets for diverse APK security scenarios
const DEMO_DATASETS = {
  "insecure_bank.apk": {
    metadata: {
      package_name: "com.andoguard.insecurebank",
      version_name: "2.1.0",
      min_sdk: 24,
      target_sdk: 33,
      target_path: "samples/insecure_bank.apk",
      file_size: 4813,
      sha256: "597f234d080dcb3b7a72354faa2e05ede384b27287b37f77651209958623b0a9",
      session_id: "c43a6aeb",
    },
    security_score: 28,
    risk_grade: "D (HIGH RISK)",
    risk_color: "#ef4444",
    severity_summary: { CRITICAL: 2, HIGH: 6, MEDIUM: 4, LOW: 0, INFO: 0 },
    security_flags: { debuggable: true, uses_cleartext_traffic: true, allow_backup: true, network_security_config: false },
    components: {
      total: 8,
      exported_count: 6,
      exported: [
        { type: "activity", name: "com.andoguard.insecurebank.MainActivity", permission: null },
        { type: "activity", name: "com.andoguard.insecurebank.TransferActivity", permission: null },
        { type: "activity", name: "com.andoguard.insecurebank.DebugConsoleActivity", permission: null },
        { type: "service", name: "com.andoguard.insecurebank.TelemetryService", permission: null },
        { type: "receiver", name: "com.andoguard.insecurebank.SmsReceiver", permission: null },
        { type: "provider", name: "com.andoguard.insecurebank.AccountContentProvider", permission: null }
      ]
    },
    findings: [
      {
        id: "VULN-DEBUG-001",
        title: "Application is Debuggable in Manifest",
        severity: "CRITICAL",
        masvs_id: "MASVS-CODE-2",
        evidence: "android:debuggable is set to 'true'. This enables JDWP debugging, allowing attackers to attach runtime debuggers, dump memory, and execute code.",
        remediation: "Set android:debuggable='false' in AndroidManifest.xml before production release.",
        location: "AndroidManifest.xml <application android:debuggable='true'>"
      },
      {
        id: "VULN-NET-002",
        title: "Insecure SSL/TLS Certificate Validation Pattern",
        severity: "CRITICAL",
        masvs_id: "MASVS-NETWORK-2",
        evidence: "Bytecode pattern 'TrustAllCertificates' indicates potential trust-all or disabled hostname verification, completely undermining TLS security.",
        remediation: "Rely on standard system trust roots and avoid implementing custom empty TrustManager classes.",
        location: "Bytecode literal: 'TrustAllCertificates'"
      },
      {
        id: "VULN-NET-001",
        title: "Cleartext Network Traffic Permitted",
        severity: "HIGH",
        masvs_id: "MASVS-NETWORK-1",
        evidence: "android:usesCleartextTraffic is set to 'true'. Unencrypted HTTP traffic is vulnerable to eavesdropping and Machine-in-the-Middle (MitM) attacks.",
        remediation: "Enforce HTTPS across all network endpoints and configure a strict res/xml/network_security_config.xml.",
        location: "AndroidManifest.xml <application android:usesCleartextTraffic='true'>"
      },
      {
        id: "VULN-CRYPTO-001",
        title: "Weak or Insecure Cipher Algorithm Detected",
        severity: "HIGH",
        masvs_id: "MASVS-CRYPTO-1",
        evidence: "Bytecode references insecure cipher or mode 'DES/ECB/PKCS5Padding'. Algorithms like DES, RC4, or ECB mode are cryptographically broken.",
        remediation: "Use AES/GCM/NoPadding or standard Android Keystore cipher configurations.",
        location: "Bytecode literal: 'DES/ECB/PKCS5Padding'"
      },
      {
        id: "VULN-EXPORTED-ACTIVITY",
        title: "Exported Activity Without Permission Guard (TransferActivity)",
        severity: "HIGH",
        masvs_id: "MASVS-PLATFORM-1",
        evidence: "Activity 'com.andoguard.insecurebank.TransferActivity' is exported to other applications without requiring any permission guard.",
        remediation: "Set android:exported='false' or protect the component with a signature-level permission.",
        location: "AndroidManifest.xml <activity android:name='com.andoguard.insecurebank.TransferActivity'>"
      },
      {
        id: "VULN-EXPORTED-PROVIDER",
        title: "Exported Content Provider Without Permission Guard",
        severity: "HIGH",
        masvs_id: "MASVS-PLATFORM-1",
        evidence: "Provider 'com.andoguard.insecurebank.AccountContentProvider' is exported, allowing third-party apps to read private SQLite databases.",
        remediation: "Protect provider with readPermission and writePermission attributes.",
        location: "AndroidManifest.xml <provider android:name='com.andoguard.insecurebank.AccountContentProvider'>"
      },
      {
        id: "VULN-STORAGE-001",
        title: "Application Allows ADB Backup",
        severity: "MEDIUM",
        masvs_id: "MASVS-STORAGE-2",
        evidence: "android:allowBackup is set to 'true'. Private app data, databases, and shared preferences can be extracted via 'adb backup' without root access.",
        remediation: "Set android:allowBackup='false' or define an explicit fullBackupContent filter.",
        location: "AndroidManifest.xml <application android:allowBackup='true'>"
      },
      {
        id: "VULN-CRYPTO-002",
        title: "Broken or Deprecated Hash Algorithm Referenced (MD5)",
        severity: "MEDIUM",
        masvs_id: "MASVS-CRYPTO-2",
        evidence: "Bytecode references weak hash algorithm 'MD5'. MD5 and SHA-1 suffer from collision vulnerabilities.",
        remediation: "Upgrade cryptographic digests to SHA-256 or SHA-512.",
        location: "Bytecode literal: 'MD5'"
      }
    ],
    secrets: [
      { type: "JWT Token", value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImJhbmsiOiJpbnNlY3VyZSJ9.abcdef1234567890", entropy: 5.01, source: "classes.dex" },
      { type: "Google API Key", value: "AIzaSyD-InsecureBankGoogleApiKey9876543210", entropy: 4.92, source: "classes.dex" },
      { type: "AWS Access Key", value: "AKIAIOSFODNN7EXAMPLE", entropy: 3.68, source: "classes.dex" },
      { type: "High-Entropy Secret", value: "admin_master_secret_key_8492049182390192", entropy: 4.15, source: "classes.dex" },
      { type: "Database Password", value: "db_password_super_secret_998127391", entropy: 4.02, source: "classes.dex" }
    ],
    permissions: [
      { name: "android.permission.INTERNET", level: "NORMAL", color: "#10b981", impact: "Network communication - Requires strict TLS verification" },
      { name: "android.permission.ACCESS_FINE_LOCATION", level: "DANGEROUS", color: "#ef4444", impact: "Precise GPS geolocation tracking access" },
      { name: "android.permission.SEND_SMS", level: "DANGEROUS", color: "#ef4444", impact: "Financial / Fraud Risk - Direct background SMS transmission" },
      { name: "android.permission.READ_SMS", level: "DANGEROUS", color: "#ef4444", impact: "Privacy / 2FA Interception - Access to received SMS messages" },
      { name: "android.permission.RECORD_AUDIO", level: "DANGEROUS", color: "#ef4444", impact: "Surveillance / Eavesdropping - Microphone recording capability" },
      { name: "android.permission.READ_CONTACTS", level: "DANGEROUS", color: "#ef4444", impact: "Data Exfiltration Risk - Access to user address book" },
      { name: "com.andoguard.insecurebank.permission.ADMIN_TRANSFER", level: "SIGNATURE", color: "#f59e0b", impact: "Privileged Custom App Permission Guard" }
    ],
    native_libraries: [
      { path: "lib/arm64-v8a/libbankcrypto.so", arch: "AArch64 (64-bit ARM)", jni_exports: ["Java_com_andoguard_insecurebank_CryptoManager_nativeDecryptToken"] },
      { path: "lib/x86_64/libbankcrypto.so", arch: "x86-64 (Intel 64-bit)", jni_exports: ["Java_com_andoguard_insecurebank_CryptoManager_nativeDecryptToken"] }
    ],
    certificates: {
      v1_signature: true,
      v2_signature: false,
      v3_signature: false,
      certificates: [{
        subject: "CN=InsecureBank Release Signer, O=Insecure Financial Corp, C=US",
        issuer: "CN=InsecureBank Release Signer, O=Insecure Financial Corp, C=US",
        serial_number: "0x7F9A1B2C3D4E5F6A",
        sha256: "E8F2B1C4D9A019E776F438D102C455619A82BE192847D8A10984BCF10239A012"
      }]
    },
    classes: [
      { name: "com.andoguard.insecurebank.AuthManager", methods_count: 2 },
      { name: "com.andoguard.insecurebank.TransferActivity", methods_count: 2 },
      { name: "com.andoguard.insecurebank.MainActivity", methods_count: 1 },
      { name: "com.andoguard.insecurebank.CryptoManager", methods_count: 1 }
    ]
  },

  "secure_enterprise.apk": {
    metadata: {
      package_name: "com.andoguard.enterprise.secure",
      version_name: "3.4.0",
      min_sdk: 28,
      target_sdk: 34,
      target_path: "samples/secure_enterprise.apk",
      file_size: 3474,
      sha256: "18a992bc440ef1a892bce90471928374a8123049102938475610293847561029",
      session_id: "e7104b28",
    },
    security_score: 95,
    risk_grade: "A (EXCELLENT)",
    risk_color: "#10b981",
    severity_summary: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 1, INFO: 1 },
    security_flags: { debuggable: false, uses_cleartext_traffic: false, allow_backup: false, network_security_config: true },
    components: {
      total: 4,
      exported_count: 1,
      exported: [
        { type: "activity", name: "com.andoguard.enterprise.secure.MainActivity", permission: null }
      ]
    },
    findings: [
      {
        id: "INFO-HARDENING-001",
        title: "Hardware-Backed Keystore Cryptography Verified",
        severity: "INFO",
        masvs_id: "MASVS-CRYPTO-1",
        evidence: "Application uses AES-256-GCM authenticated cipher with hardware-backed AndroidKeyStore master key.",
        remediation: "Continue rotating keys per enterprise lifecycle policy.",
        location: "SecureVault.java"
      },
      {
        id: "LOW-OBSC-001",
        title: "ProGuard / R8 Class Obfuscation Recommended",
        severity: "LOW",
        masvs_id: "MASVS-CODE-1",
        evidence: "Class symbols in release DEX contain readable identifiers.",
        remediation: "Enable minifyEnable and shrinkResources in release build variant.",
        location: "classes.dex"
      }
    ],
    secrets: [],
    permissions: [
      { name: "android.permission.INTERNET", level: "NORMAL", color: "#10b981", impact: "Encrypted HTTPS communication only (Certificate Pinning Enforced)" },
      { name: "android.permission.ACCESS_NETWORK_STATE", level: "NORMAL", color: "#10b981", impact: "Network connectivity status check" }
    ],
    native_libraries: [],
    certificates: {
      v1_signature: true,
      v2_signature: true,
      v3_signature: true,
      certificates: [{
        subject: "CN=Enterprise Release Authority, O=Secure Corp Global, C=US",
        issuer: "CN=Enterprise Release Authority, O=Secure Corp Global, C=US",
        serial_number: "0x4A19827361548291",
        sha256: "99A8B7C6D5E4F3A2B1C0D9E8F7A6B5C4D3E2F1A0B9C8D7E6F5A4B3C2D1E0F9A8"
      }]
    },
    classes: [
      { name: "com.andoguard.enterprise.secure.SecureVault", methods_count: 2 },
      { name: "com.andoguard.enterprise.secure.MainActivity", methods_count: 1 },
      { name: "com.andoguard.enterprise.secure.DashboardActivity", methods_count: 1 }
    ]
  },

  "spyware_tracker.apk": {
    metadata: {
      package_name: "com.system.device.tracker",
      version_name: "1.0.1",
      min_sdk: 21,
      target_sdk: 28,
      target_path: "samples/spyware_tracker.apk",
      file_size: 4730,
      sha256: "77bb320194857201984710293847561029384756102938475610293847561029",
      session_id: "8f42019a",
    },
    security_score: 12,
    risk_grade: "F (CRITICAL MALWARE RISK)",
    risk_color: "#ef4444",
    severity_summary: { CRITICAL: 4, HIGH: 7, MEDIUM: 3, LOW: 0, INFO: 0 },
    security_flags: { debuggable: true, uses_cleartext_traffic: true, allow_backup: true, network_security_config: false },
    components: {
      total: 5,
      exported_count: 4,
      exported: [
        { type: "activity", name: "com.system.device.tracker.LauncherActivity", permission: null },
        { type: "service", name: "com.system.device.tracker.StealthAudioService", permission: null },
        { type: "service", name: "com.system.device.tracker.GpsBeaconService", permission: null },
        { type: "receiver", name: "com.system.device.tracker.SmsInterceptorReceiver", permission: null }
      ]
    },
    findings: [
      {
        id: "MALWARE-C2-001",
        title: "Active Command & Control (C2) Exfiltration Endpoint",
        severity: "CRITICAL",
        masvs_id: "MASVS-NETWORK-1",
        evidence: "Discovered hardcoded C2 beacon endpoint 'http://c2.darknet-beacon.org:8080/exfil' used for background data exfiltration.",
        remediation: "Quarantine application immediately; block remote IP and domain on network firewall.",
        location: "StealthAudioService.java"
      },
      {
        id: "MALWARE-SURVEILLANCE-001",
        title: "Covert Background Audio Recording Service",
        severity: "CRITICAL",
        masvs_id: "MASVS-PLATFORM-1",
        evidence: "Service 'StealthAudioService' is exported without permissions and accesses microphone stream silently.",
        remediation: "Revoke RECORD_AUDIO permission and remove background stealth recorder.",
        location: "AndroidManifest.xml <service android:name='.StealthAudioService'>"
      },
      {
        id: "MALWARE-SMS-STEALER",
        title: "High-Priority SMS 2FA Interception Receiver",
        severity: "CRITICAL",
        masvs_id: "MASVS-PLATFORM-1",
        evidence: "BroadcastReceiver 'SmsInterceptorReceiver' binds to SMS_RECEIVED with priority 999 to harvest one-time passwords.",
        remediation: "Do not grant SMS permissions to third-party utility applications.",
        location: "AndroidManifest.xml <receiver android:name='.SmsInterceptorReceiver'>"
      },
      {
        id: "VULN-NET-002",
        title: "Insecure SSL TrustAllCertificates Implementation",
        severity: "CRITICAL",
        masvs_id: "MASVS-NETWORK-2",
        evidence: "Bytecode pattern 'TrustAllCertificates' disables certificate verification.",
        remediation: "Enforce strict X509TrustManager verification.",
        location: "Bytecode literal: 'TrustAllCertificates'"
      }
    ],
    secrets: [
      { type: "C2 Server Endpoint", value: "http://c2.darknet-beacon.org:8080/exfil", entropy: 4.82, source: "classes.dex" },
      { type: "Telegram Bot Token", value: "bot_token_5891823901:AAH8239102-telegram-token", entropy: 4.65, source: "classes.dex" },
      { type: "AWS C2 Bucket Key", value: "AKIAIOSFODNN7C2BUCKET", entropy: 3.71, source: "classes.dex" },
      { type: "Data Drop Server", value: "http://194.87.12.99/upload_sms.php", entropy: 4.25, source: "classes.dex" }
    ],
    permissions: [
      { name: "android.permission.RECORD_AUDIO", level: "DANGEROUS", color: "#ef4444", impact: "Microphone surveillance without user awareness" },
      { name: "android.permission.ACCESS_FINE_LOCATION", level: "DANGEROUS", color: "#ef4444", impact: "Continuous GPS coordinates harvesting" },
      { name: "android.permission.READ_SMS", level: "DANGEROUS", color: "#ef4444", impact: "2FA interception and sensitive message theft" },
      { name: "android.permission.SEND_SMS", level: "DANGEROUS", color: "#ef4444", impact: "Fraudulent premium SMS dispatch" },
      { name: "android.permission.READ_CONTACTS", level: "DANGEROUS", color: "#ef4444", impact: "Complete address book harvesting" },
      { name: "android.permission.CAMERA", level: "DANGEROUS", color: "#ef4444", impact: "Covert background image/video capture" },
      { name: "android.permission.READ_CALL_LOG", level: "DANGEROUS", color: "#ef4444", impact: "Harvesting inbound and outbound call metadata" },
      { name: "android.permission.WRITE_EXTERNAL_STORAGE", level: "DANGEROUS", color: "#ef4444", impact: "Tampering with public shared storage files" },
      { name: "android.permission.INTERNET", level: "NORMAL", color: "#10b981", impact: "Communication with remote C2 server" }
    ],
    native_libraries: [
      { path: "lib/arm64-v8a/libstealth.so", arch: "AArch64 (64-bit ARM)", jni_exports: ["Java_com_system_device_tracker_NativeHook_interceptAudio"] }
    ],
    certificates: {
      v1_signature: true,
      v2_signature: false,
      v3_signature: false,
      certificates: [{
        subject: "CN=Android Debug Signer, O=AOSP Debug",
        issuer: "CN=Android Debug Signer, O=AOSP Debug",
        serial_number: "0x1122334455667788",
        sha256: "112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00"
      }]
    },
    classes: [
      { name: "com.system.device.tracker.StealthAudioService", methods_count: 2 },
      { name: "com.system.device.tracker.LauncherActivity", methods_count: 1 },
      { name: "com.system.device.tracker.GpsBeaconService", methods_count: 1 }
    ]
  },

  "crypto_wallet.apk": {
    metadata: {
      package_name: "com.andoguard.defi.wallet",
      version_name: "1.8.2",
      min_sdk: 26,
      target_sdk: 33,
      target_path: "samples/crypto_wallet.apk",
      file_size: 3676,
      sha256: "44aa990182736451928374650192837465019283746501928374650192837465",
      session_id: "7b3901de",
    },
    security_score: 40,
    risk_grade: "D (HIGH RISK)",
    risk_color: "#f97316",
    severity_summary: { CRITICAL: 2, HIGH: 4, MEDIUM: 2, LOW: 0, INFO: 0 },
    security_flags: { debuggable: true, uses_cleartext_traffic: true, allow_backup: true, network_security_config: false },
    components: {
      total: 4,
      exported_count: 2,
      exported: [
        { type: "activity", name: "com.andoguard.defi.wallet.WalletMainActivity", permission: null },
        { type: "activity", name: "com.andoguard.defi.wallet.SendCryptoActivity", permission: null }
      ]
    },
    findings: [
      {
        id: "CRYPTO-KEY-EXPOSURE",
        title: "Hardcoded 12-Word BIP-39 Mnemonic Seed Phrase",
        severity: "CRITICAL",
        masvs_id: "MASVS-STORAGE-1",
        evidence: "Discovered master recovery phrase 'witch collapse practice feed shame open despair creek road again ice least' in bytecode string pool.",
        remediation: "Never hardcode mnemonic seed phrases. Derive keys dynamically and secure them using Android Keystore / StrongBox.",
        location: "WalletKeyManager.java"
      },
      {
        id: "CRYPTO-ETH-KEY",
        title: "Exposed Ethereum Private Key in Plaintext",
        severity: "CRITICAL",
        masvs_id: "MASVS-STORAGE-1",
        evidence: "Discovered private key '0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d'. Any attacker decompiling the APK gains full access to wallet funds.",
        remediation: "Migrate private keys to encrypted secure hardware storage.",
        location: "WalletKeyManager.java"
      },
      {
        id: "CRYPTO-INFURA-RPC",
        title: "Infura Web3 RPC Key Hardcoded Without Scope Restriction",
        severity: "HIGH",
        masvs_id: "MASVS-NETWORK-1",
        evidence: "API key embedded in Infura RPC URL allows unauthorized third parties to exhaust project rate limits.",
        remediation: "Proxy Web3 requests through an authenticated backend server.",
        location: "WalletKeyManager.java"
      }
    ],
    secrets: [
      { type: "BIP-39 Mnemonic Seed", value: "witch collapse practice feed shame open despair creek road again ice least", entropy: 4.88, source: "classes.dex" },
      { type: "Ethereum Private Key", value: "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d", entropy: 4.95, source: "classes.dex" },
      { type: "Infura RPC Endpoint", value: "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161", entropy: 4.41, source: "classes.dex" }
    ],
    permissions: [
      { name: "android.permission.INTERNET", level: "NORMAL", color: "#10b981", impact: "Web3 Blockchain RPC network communication" },
      { name: "android.permission.CAMERA", level: "DANGEROUS", color: "#ef4444", impact: "QR Code address scanning camera access" },
      { name: "android.permission.USE_BIOMETRIC", level: "NORMAL", color: "#10b981", impact: "Fingerprint / Face authentication prompt" }
    ],
    native_libraries: [
      { path: "lib/arm64-v8a/libsecp256k1.so", arch: "AArch64 (64-bit ARM)", jni_exports: ["Java_com_andoguard_defi_wallet_NativeSigner_signTransaction"] },
      { path: "lib/x86_64/libsecp256k1.so", arch: "x86-64 (Intel 64-bit)", jni_exports: ["Java_com_andoguard_defi_wallet_NativeSigner_signTransaction"] }
    ],
    certificates: {
      v1_signature: true,
      v2_signature: false,
      v3_signature: false,
      certificates: [{
        subject: "CN=DeFi Wallet Signer, O=Decentralized Lab Foundation",
        issuer: "CN=DeFi Wallet Signer, O=Decentralized Lab Foundation",
        serial_number: "0x33445566778899AA",
        sha256: "33445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122"
      }]
    },
    classes: [
      { name: "com.andoguard.defi.wallet.WalletKeyManager", methods_count: 2 },
      { name: "com.andoguard.defi.wallet.WalletMainActivity", methods_count: 1 },
      { name: "com.andoguard.defi.wallet.NativeSigner", methods_count: 1 }
    ]
  },

  "demo.apk": {
    metadata: {
      package_name: "com.andoguard.showcase",
      version_name: "1.0.0",
      min_sdk: 24,
      target_sdk: 33,
      target_path: "samples/demo.apk",
      file_size: 2471,
      sha256: "2976056640fd9fa2fd19a554694303b36af01f161d47b69361784b505054df0d",
      session_id: "4ca70801",
    },
    security_score: 55,
    risk_grade: "C (MODERATE RISK)",
    risk_color: "#f59e0b",
    severity_summary: { CRITICAL: 1, HIGH: 2, MEDIUM: 1, LOW: 0, INFO: 0 },
    security_flags: { debuggable: true, uses_cleartext_traffic: true, allow_backup: true, network_security_config: false },
    components: {
      total: 2,
      exported_count: 1,
      exported: [
        { type: "activity", name: "com.andoguard.showcase.MainActivity", permission: null }
      ]
    },
    findings: [
      {
        id: "VULN-DEBUG-001",
        title: "Application is Debuggable in Manifest",
        severity: "CRITICAL",
        masvs_id: "MASVS-CODE-2",
        evidence: "android:debuggable is set to 'true'. This enables JDWP debugging.",
        remediation: "Set android:debuggable='false' in AndroidManifest.xml before release.",
        location: "AndroidManifest.xml"
      }
    ],
    secrets: [],
    permissions: [
      { name: "android.permission.INTERNET", level: "NORMAL", color: "#10b981", impact: "Standard network access" },
      { name: "android.permission.ACCESS_FINE_LOCATION", level: "DANGEROUS", color: "#ef4444", impact: "Precise GPS geolocation" }
    ],
    native_libraries: [],
    certificates: {
      v1_signature: true,
      v2_signature: false,
      v3_signature: false,
      certificates: [{
        subject: "CN=AndoGuard Showcase App, O=AndoGuard Security Lab",
        issuer: "CN=AndoGuard Showcase App, O=AndoGuard Security Lab",
        serial_number: "0xe8d3fb80e1",
        sha256: "A0ADE8A6155227DEE1029CAE71462A8C63ED9F7595C8F2096A78D3E92CF1D09D"
      }]
    },
    classes: [
      { name: "com.andoguard.showcase.MainActivity", methods_count: 1 }
    ]
  }
};

class AndoGuardDashboard {
  constructor() {
    this.currentDatasetKey = "insecure_bank.apk";
    this.currentData = DEMO_DATASETS[this.currentDatasetKey];
    this.currentClass = "com.andoguard.insecurebank.AuthManager";
    this.currentLang = "java";
    this.initElements();
    this.attachEventListeners();
    this.loadData();
  }

  initElements() {
    this.navItems = document.querySelectorAll(".nav-item");
    this.tabPanes = document.querySelectorAll(".tab-pane");
    this.targetSelect = document.getElementById("targetSelect");
    this.vulnSearchInput = document.getElementById("vulnSearchInput");
    this.filterButtons = document.querySelectorAll(".filter-btn");
    this.findingsContainer = document.getElementById("findingsContainer");
    this.classListContainer = document.getElementById("classListContainer");
    this.classSearchInput = document.getElementById("classSearchInput");
    this.codeSourceDisplay = document.getElementById("codeSourceDisplay");
    this.tabBtnJava = document.getElementById("tabBtnJava");
    this.tabBtnDalvik = document.getElementById("tabBtnDalvik");
    this.uploadModal = document.getElementById("uploadModal");
    this.exportModal = document.getElementById("exportModal");
    this.chatInput = document.getElementById("chatInput");
    this.chatSendBtn = document.getElementById("chatSendBtn");
    this.chatHistory = document.getElementById("chatHistory");
  }

  attachEventListeners() {
    // Navigation tab switching
    this.navItems.forEach(item => {
      item.addEventListener("click", () => {
        const tabId = item.getAttribute("data-tab");
        this.switchTab(tabId);
      });
    });

    // Presentation Mode shortcut button
    const presBtn = document.getElementById("presentationModeBtn");
    if (presBtn) {
      presBtn.addEventListener("click", () => {
        this.switchTab("tab-presentation");
      });
    }

    // Target Switcher
    if (this.targetSelect) {
      this.targetSelect.addEventListener("change", (e) => {
        this.switchTarget(e.target.value);
      });
    }

    // Vulnerability search & filters
    if (this.vulnSearchInput) {
      this.vulnSearchInput.addEventListener("input", () => this.filterVulnerabilities());
    }
    this.filterButtons.forEach(btn => {
      btn.addEventListener("click", () => {
        const parent = btn.parentElement;
        parent.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        if (btn.hasAttribute("data-filter")) {
          this.filterVulnerabilities();
        } else if (btn.hasAttribute("data-comp-filter")) {
          this.filterComponents(btn.getAttribute("data-comp-filter"));
        }
      });
    });

    // Studio Language Tab toggling
    if (this.tabBtnJava) {
      this.tabBtnJava.addEventListener("click", () => {
        this.currentLang = "java";
        this.tabBtnJava.classList.add("active");
        this.tabBtnDalvik.classList.remove("active");
        this.fetchCode(this.currentClass, this.currentLang);
      });
    }
    if (this.tabBtnDalvik) {
      this.tabBtnDalvik.addEventListener("click", () => {
        this.currentLang = "dalvik";
        this.tabBtnDalvik.classList.add("active");
        this.tabBtnJava.classList.remove("active");
        this.fetchCode(this.currentClass, this.currentLang);
      });
    }

    // Class Search
    if (this.classSearchInput) {
      this.classSearchInput.addEventListener("input", (e) => {
        const term = e.target.value.toLowerCase();
        document.querySelectorAll(".class-item").forEach(item => {
          const text = item.textContent.toLowerCase();
          item.style.display = text.includes(term) ? "flex" : "none";
        });
      });
    }

    // Copy buttons
    document.getElementById("copyCodeBtn")?.addEventListener("click", () => {
      navigator.clipboard.writeText(this.codeSourceDisplay.textContent || "");
      alert("Code copied to clipboard!");
    });
    document.getElementById("copyXmlBtn")?.addEventListener("click", () => {
      navigator.clipboard.writeText(document.getElementById("rawXmlCodeBlock")?.textContent || "");
      alert("Manifest XML copied to clipboard!");
    });
    document.getElementById("copyFridaScriptBtn")?.addEventListener("click", () => {
      navigator.clipboard.writeText(document.getElementById("fridaScriptCode")?.textContent || "");
      alert("Frida hook script copied to clipboard!");
    });

    // Frida Generator
    const fridaSelect = document.getElementById("fridaHookSelect");
    const methodInputs = document.getElementById("methodHookInputs");
    fridaSelect?.addEventListener("change", (e) => {
      if (methodInputs) {
        methodInputs.style.display = e.target.value === "method_hook" ? "flex" : "none";
      }
    });

    document.getElementById("generateScriptBtn")?.addEventListener("click", () => {
      this.generateFridaScript();
    });

    // Modals
    document.getElementById("uploadModalOpenBtn")?.addEventListener("click", () => {
      this.uploadModal.showModal();
    });
    document.getElementById("closeUploadModalBtn")?.addEventListener("click", () => {
      this.uploadModal.close();
    });
    document.getElementById("exportBtn")?.addEventListener("click", () => {
      this.exportModal.showModal();
    });
    document.getElementById("closeExportModalBtn")?.addEventListener("click", () => {
      this.exportModal.close();
    });

    // Drop zone upload
    const dropZone = document.getElementById("dropZone");
    const fileInput = document.getElementById("fileInput");
    dropZone?.addEventListener("click", () => fileInput?.click());
    fileInput?.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        this.uploadFile(e.target.files[0]);
      }
    });

    dropZone?.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "var(--cyan-glow)";
    });
    dropZone?.addEventListener("dragleave", () => {
      dropZone.style.borderColor = "rgba(0, 242, 254, 0.4)";
    });
    dropZone?.addEventListener("drop", (e) => {
      e.preventDefault();
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        this.uploadFile(e.dataTransfer.files[0]);
      }
    });

    // AI Chat
    this.chatSendBtn?.addEventListener("click", () => this.sendChatMessage());
    this.chatInput?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") this.sendChatMessage();
    });
    document.querySelectorAll(".chip-btn").forEach(chip => {
      chip.addEventListener("click", () => {
        const text = chip.getAttribute("data-prompt");
        if (text && this.chatInput) {
          this.chatInput.value = text;
          this.sendChatMessage();
        }
      });
    });
  }

  switchTab(tabId) {
    this.navItems.forEach(item => {
      if (item.getAttribute("data-tab") === tabId) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });
    this.tabPanes.forEach(pane => {
      if (pane.id === tabId) {
        pane.classList.add("active");
      } else {
        pane.classList.remove("active");
      }
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async loadData() {
    try {
      const res = await fetch("/api/overview");
      if (res.ok) {
        const data = await res.json();
        if (!data.error) {
          this.currentData = data;
        }
      }
    } catch (e) {
      console.log("Using dataset for", this.currentDatasetKey);
      if (DEMO_DATASETS[this.currentDatasetKey]) {
        this.currentData = DEMO_DATASETS[this.currentDatasetKey];
      }
    }
    this.renderAll();
    this.loadSamplesList();
    this.loadClasses();
  }

  async loadSamplesList() {
    try {
      const res = await fetch("/api/samples");
      if (res.ok) {
        const data = await res.json();
        if (data.samples && this.targetSelect && data.samples.length > 0) {
          this.targetSelect.innerHTML = "";
          data.samples.forEach(s => {
            const opt = document.createElement("option");
            opt.value = s.name;
            let label = s.name;
            if (s.name.includes("insecure_bank")) label = "insecure_bank.apk (Vulnerable Fintech - Grade D)";
            else if (s.name.includes("secure_enterprise")) label = "secure_enterprise.apk (Hardened Enterprise - Grade A)";
            else if (s.name.includes("spyware_tracker")) label = "spyware_tracker.apk (Surveillance Malware - Grade F)";
            else if (s.name.includes("crypto_wallet")) label = "crypto_wallet.apk (DeFi Key Leakage - Grade D)";
            else if (s.name.includes("demo")) label = "demo.apk (Minimal Baseline Target)";
            opt.textContent = `${label} [${(s.size / 1024).toFixed(1)} KB]`;
            if (s.name === this.currentDatasetKey) opt.selected = true;
            this.targetSelect.appendChild(opt);
          });
          return;
        }
      }
    } catch (e) {
      // offline
    }

    // Fallback options list for standalone offline presentation
    if (this.targetSelect && this.targetSelect.options.length < 3) {
      this.targetSelect.innerHTML = `
        <option value="insecure_bank.apk">insecure_bank.apk (Vulnerable Fintech - Grade D)</option>
        <option value="secure_enterprise.apk">secure_enterprise.apk (Hardened Enterprise - Grade A)</option>
        <option value="spyware_tracker.apk">spyware_tracker.apk (Surveillance Malware - Grade F)</option>
        <option value="crypto_wallet.apk">crypto_wallet.apk (DeFi Key Leakage - Grade D)</option>
        <option value="demo.apk">demo.apk (Minimal Baseline Target)</option>
      `;
    }
  }

  async switchTarget(sampleName) {
    this.currentDatasetKey = sampleName;
    try {
      const res = await fetch("/api/open", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sample: sampleName })
      });
      if (res.ok) {
        await this.loadData();
        return;
      }
    } catch (e) {
      // offline fallback
    }

    if (DEMO_DATASETS[sampleName]) {
      this.currentData = DEMO_DATASETS[sampleName];
      this.renderAll();
      this.loadClasses();
    }
  }

  async uploadFile(file) {
    try {
      const res = await fetch("/api/upload", {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: file
      });
      if (res.ok) {
        this.uploadModal.close();
        alert(`Target ${file.name} successfully analyzed!`);
        await this.loadData();
      } else {
        alert("Upload failed. Please ensure file is a valid Android binary.");
      }
    } catch (e) {
      alert("Offline demo mode: unable to upload binary to live server.");
    }
  }

  renderAll() {
    this.renderHeader();
    this.renderScore();
    this.renderMetrics();
    this.renderManifestFlags();
    this.renderVulnerabilities();
    this.renderComponents();
    this.renderPermissions();
    this.renderSecrets();
    this.renderNative();
    this.renderCerts();
    this.renderSessions();
  }

  renderHeader() {
    const meta = this.currentData.metadata || {};
    document.getElementById("targetPackageTitle").textContent = meta.package_name || "Target App";
    document.getElementById("targetVersionTag").textContent = meta.version_name ? `v${meta.version_name}` : "v1.0.0";
    document.getElementById("metaTargetFileName").textContent = meta.target_path ? meta.target_path.split(/[\\/]/).pop() : "target.apk";
    document.getElementById("metaSdkRange").textContent = `API ${meta.min_sdk || 24} -> ${meta.target_sdk || 33}`;
    document.getElementById("metaSha256").textContent = meta.sha256 ? `${meta.sha256.substring(0, 16)}...` : "N/A";
    document.getElementById("metaFileSize").textContent = `${((meta.file_size || 4800) / 1024).toFixed(1)} KB`;
    document.getElementById("metaSessionId").textContent = meta.session_id ? meta.session_id.substring(0, 8) : "session-01";
  }

  renderScore() {
    const score = this.currentData.security_score ?? 28;
    const grade = this.currentData.risk_grade ?? "D (HIGH RISK)";
    const color = this.currentData.risk_color ?? "#ef4444";

    const scoreNumEl = document.getElementById("securityScoreNumber");
    const circleEl = document.getElementById("scoreRadialCircle");
    const gradeEl = document.getElementById("riskGradeBadge");

    if (scoreNumEl) {
      scoreNumEl.textContent = score;
      scoreNumEl.style.color = color;
    }
    if (gradeEl) {
      gradeEl.textContent = `GRADE: ${grade}`;
      gradeEl.style.color = color;
      gradeEl.style.borderColor = color;
      gradeEl.style.background = `${color}20`;
    }
    if (circleEl) {
      const offset = 377 - (377 * (score / 100));
      circleEl.style.strokeDashoffset = offset;
      circleEl.style.stroke = color;
    }
  }

  renderMetrics() {
    const sev = this.currentData.severity_summary || {};
    const comps = this.currentData.components || {};
    const secrets = this.currentData.secrets || [];
    const perms = this.currentData.permissions || [];
    const native = this.currentData.native_libraries || [];

    document.getElementById("cardCriticalCount").textContent = sev.CRITICAL || 0;
    document.getElementById("cardHighCount").textContent = sev.HIGH || 0;
    document.getElementById("cardExportedCount").textContent = comps.exported_count || (comps.exported ? comps.exported.length : 0);
    document.getElementById("cardSecretsCount").textContent = secrets.length;
    document.getElementById("cardPermissionsCount").textContent = perms.length;
    document.getElementById("cardNativeCount").textContent = native.length;

    document.getElementById("vulnsCountBadge").textContent = (this.currentData.findings || []).length;
    document.getElementById("secretsCountBadge").textContent = secrets.length;
  }

  renderManifestFlags() {
    const flags = this.currentData.security_flags || {};
    const setFlag = (id, val, dangerText, safeText) => {
      const el = document.getElementById(id);
      if (!el) return;
      if (val) {
        el.className = "status-badge danger";
        el.textContent = dangerText;
      } else {
        el.className = "status-badge safe";
        el.textContent = safeText;
      }
    };
    setFlag("flagDebuggable", flags.debuggable, "ENABLED (VULNERABLE)", "DISABLED (SECURE)");
    setFlag("flagCleartext", flags.uses_cleartext_traffic, "ALLOWED (VULNERABLE)", "BLOCKED (HTTPS ENFORCED)");
    setFlag("flagBackup", flags.allow_backup, "ALLOWED (DATA RISK)", "RESTRICTED (SECURE)");
    setFlag("flagNetConfig", !flags.network_security_config, "NOT CONFIGURED", "CONFIGURED (PINNING ACTIVE)");
  }

  renderVulnerabilities() {
    const findings = this.currentData.findings || [];
    if (!this.findingsContainer) return;
    this.findingsContainer.innerHTML = "";

    if (findings.length === 0) {
      this.findingsContainer.innerHTML = `<div class="finding-card"><p style="color: var(--success); font-weight: 600;">✓ No vulnerabilities detected in target APK. All security checks passed!</p></div>`;
      return;
    }

    findings.forEach(f => {
      const sevClass = (f.severity || "info").toLowerCase();
      const card = document.createElement("div");
      card.className = `finding-card ${sevClass}`;
      card.setAttribute("data-sev", f.severity || "INFO");
      card.setAttribute("data-search", `${f.title} ${f.masvs_id || ""} ${f.evidence || ""}`.toLowerCase());

      card.innerHTML = `
        <div class="finding-top">
          <div class="finding-title-group">
            <span class="severity-pill ${sevClass}">${f.severity}</span>
            <span class="finding-title">${f.title}</span>
          </div>
          <span class="masvs-tag">${f.masvs_id || "OWASP MASVS"}</span>
        </div>
        <div class="finding-evidence">
          <strong>Evidence:</strong> ${f.evidence}
        </div>
        <div style="font-size: 0.75rem; color: var(--text-dim); margin-bottom: 8px;">
          📍 <code>${f.location || "Bytecode / Manifest"}</code>
        </div>
        <div class="finding-remediation-box">
          <strong>Remediation:</strong> ${f.remediation}
        </div>
      `;
      this.findingsContainer.appendChild(card);
    });
  }

  filterVulnerabilities() {
    const activeFilterBtn = document.querySelector(".filter-btn.active[data-filter]");
    const filter = activeFilterBtn ? activeFilterBtn.getAttribute("data-filter") : "all";
    const searchTerm = (this.vulnSearchInput?.value || "").toLowerCase();

    document.querySelectorAll(".finding-card[data-sev]").forEach(card => {
      const cardSev = card.getAttribute("data-sev");
      const cardText = card.getAttribute("data-search") || "";
      const matchesFilter = filter === "all" || cardSev === filter;
      const matchesSearch = !searchTerm || cardText.includes(searchTerm);
      card.style.display = (matchesFilter && matchesSearch) ? "block" : "none";
    });
  }

  renderComponents() {
    const compsContainer = document.getElementById("componentsContainer");
    if (!compsContainer) return;
    compsContainer.innerHTML = "";

    const comps = this.currentData.components?.exported || [];
    if (comps.length === 0) {
      compsContainer.innerHTML = `<div class="finding-card"><p style="color: var(--success); font-weight: 600;">✓ Zero unprotected components exported. All components are strictly private.</p></div>`;
    } else {
      comps.forEach(c => {
        const card = document.createElement("div");
        card.className = "finding-card high";
        card.setAttribute("data-comp-type", (c.type || "activity").toLowerCase());
        card.innerHTML = `
          <div class="finding-top">
            <div class="finding-title-group">
              <span class="severity-pill ${c.permission ? 'low' : 'high'}">${(c.type || 'component').toUpperCase()}</span>
              <span class="finding-title">${c.name}</span>
            </div>
            <span class="status-badge ${c.permission ? 'safe' : 'danger'}">
              ${c.permission ? 'GUARDED: ' + c.permission : 'UNPROTECTED EXPORT'}
            </span>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 6px;">
            Component is declared as <code>android:exported="true"</code>, meaning any external application or ADB shell can broadcast intents to invoke this component.
          </p>
        `;
        compsContainer.appendChild(card);
      });
    }

    const rawXmlEl = document.getElementById("rawXmlCodeBlock");
    if (rawXmlEl) {
      rawXmlEl.textContent = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="${this.currentData.metadata?.package_name || 'com.example.app'}"
    android:versionCode="201"
    android:versionName="${this.currentData.metadata?.version_name || '1.0.0'}">

    <uses-sdk android:minSdkVersion="${this.currentData.metadata?.min_sdk || 24}" android:targetSdkVersion="${this.currentData.metadata?.target_sdk || 33}" />

    ${(this.currentData.permissions || []).map(p => `<uses-permission android:name="${p.name}" />`).join('\n    ')}

    <application
        android:debuggable="${this.currentData.security_flags?.debuggable ? 'true' : 'false'}"
        android:allowBackup="${this.currentData.security_flags?.allow_backup ? 'true' : 'false'}"
        android:usesCleartextTraffic="${this.currentData.security_flags?.uses_cleartext_traffic ? 'true' : 'false'}">

        ${(this.currentData.components?.exported || []).map(c => `<${c.type} android:name="${c.name}" android:exported="true" />`).join('\n        ')}
    </application>
</manifest>`;
    }
  }

  filterComponents(type) {
    const compContainer = document.getElementById("componentsContainer");
    const xmlContainer = document.getElementById("manifestXmlContainer");
    if (type === "xml") {
      compContainer.style.display = "none";
      xmlContainer.style.display = "block";
    } else {
      compContainer.style.display = "flex";
      xmlContainer.style.display = "none";
      document.querySelectorAll("#componentsContainer [data-comp-type]").forEach(card => {
        const cType = card.getAttribute("data-comp-type");
        card.style.display = (type === "all" || cType === type) ? "block" : "none";
      });
    }
  }

  renderPermissions() {
    const tbody = document.getElementById("permissionsTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";
    const perms = this.currentData.permissions || [];
    perms.forEach(p => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code style="color: var(--cyan-glow); font-family: var(--font-code);">${p.name}</code></td>
        <td><span class="status-badge" style="background: ${p.color}20; color: ${p.color}; border: 1px solid ${p.color}50;">${p.level}</span></td>
        <td>${p.impact}</td>
        <td><span class="masvs-tag">MASVS-PLATFORM-1</span></td>
      `;
      tbody.appendChild(tr);
    });
  }

  renderSecrets() {
    const tbody = document.getElementById("secretsTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";
    const secrets = this.currentData.secrets || [];
    if (secrets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--success); font-weight: 600;">✓ No exposed credentials or high-entropy tokens discovered.</td></tr>`;
      return;
    }
    secrets.forEach(s => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong style="color: #fff;">${s.type}</strong></td>
        <td><code style="color: #38bdf8; font-family: var(--font-code); word-break: break-all;">${s.value}</code></td>
        <td>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-family: var(--font-code); font-weight: 700; color: var(--warning);">${(s.entropy || 4.0).toFixed(2)}</span>
            <div style="width: 60px; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden;">
              <div style="width: ${Math.min(100, ((s.entropy || 4.0) / 6.0) * 100)}%; height: 100%; background: var(--warning);"></div>
            </div>
          </div>
        </td>
        <td><code>${s.source || 'classes.dex'}</code></td>
        <td>
          <button class="btn btn-secondary copy-secret-btn" style="padding: 2px 8px; font-size: 0.7rem;" data-val="${s.value}">Copy</button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll(".copy-secret-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const val = btn.getAttribute("data-val");
        if (val) {
          navigator.clipboard.writeText(val);
          btn.textContent = "Copied!";
          setTimeout(() => btn.textContent = "Copy", 1500);
        }
      });
    });
  }

  async loadClasses() {
    let classes = [];
    try {
      const res = await fetch("/api/classes");
      if (res.ok) {
        const data = await res.json();
        classes = data.classes || [];
      }
    } catch (e) {
      // offline fallback
    }

    if (classes.length === 0) {
      classes = this.currentData.classes || [
        { name: "com.andoguard.insecurebank.AuthManager", methods_count: 2 },
        { name: "com.andoguard.insecurebank.TransferActivity", methods_count: 2 }
      ];
    }

    if (!this.classListContainer) return;
    this.classListContainer.innerHTML = "";

    classes.forEach((c, idx) => {
      const item = document.createElement("div");
      item.className = `class-item ${idx === 0 ? 'active' : ''}`;
      item.setAttribute("data-class", c.name);
      item.innerHTML = `
        <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${c.name.split('.').pop()}</span>
        <span class="nav-tag" style="font-size: 0.65rem;">${c.methods_count || 1}m</span>
      `;
      item.addEventListener("click", () => {
        document.querySelectorAll(".class-item").forEach(i => i.classList.remove("active"));
        item.classList.add("active");
        this.currentClass = c.name;
        this.fetchCode(c.name, this.currentLang);
      });
      this.classListContainer.appendChild(item);
    });

    if (classes.length > 0) {
      this.currentClass = classes[0].name;
      this.fetchCode(this.currentClass, this.currentLang);
    }
  }

  async fetchCode(className, lang) {
    if (!this.codeSourceDisplay) return;
    this.codeSourceDisplay.textContent = `// Decompiling ${className} [${lang}]...`;

    try {
      const res = await fetch(`/api/code?class=${encodeURIComponent(className)}&lang=${lang}`);
      if (res.ok) {
        const data = await res.json();
        if (data.source && !data.source.includes("unavailable")) {
          this.codeSourceDisplay.textContent = data.source;
          return;
        }
      }
    } catch (e) {
      // offline fallback
    }

    // Offline demo fallback code
    if (className.includes("SecureVault")) {
      this.codeSourceDisplay.textContent = lang === "java" ? `package com.andoguard.enterprise.secure;

import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Hardened Enterprise Cryptographic Vault.
 * OWASP MASVS-CRYPTO-1 Compliant: Authenticated AES-256-GCM with AndroidKeyStore hardware backing.
 */
public class SecureVault {
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String KEY_ALIAS = "EnterpriseVaultMasterKey";

    public static byte[] encryptPayload(byte[] plaintext, byte[] iv) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
        ks.load(null);
        SecretKey secretKey = (SecretKey) ks.getKey(KEY_ALIAS, null);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return cipher.doFinal(plaintext);
    }
}` : `.class public Lcom/andoguard/enterprise/secure/SecureVault;
.super Ljava/lang/Object;
.source "SecureVault.java"

.method public static encryptPayload([B[B)[B
    .registers 5
    const-string v0, "AndroidKeyStore"
    invoke-static {v0}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;
    move-result-object v0
    return-object p0
.end method`;
    } else if (className.includes("StealthAudioService")) {
      this.codeSourceDisplay.textContent = lang === "java" ? `package com.system.device.tracker;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

/**
 * Malicious Background Audio Surveillance Service.
 * MASVS-PLATFORM-1: Exported service lacking permission guards.
 * MASVS-NETWORK-1: Exfiltrates captured audio unencrypted to remote C2 server.
 */
public class StealthAudioService extends Service {
    private static final String C2_SERVER = "http://c2.darknet-beacon.org:8080/exfil";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.w("SystemBattery", "Intercepting microphone stream and transmitting to C2...");
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}` : `.class public Lcom/system/device/tracker/StealthAudioService;
.super Landroid/app/Service;
.source "StealthAudioService.java"

.method public onStartCommand(Landroid/content/Intent;II)I
    .registers 5
    const-string v0, "http://c2.darknet-beacon.org:8080/exfil"
    const/4 v1, 1
    return v1
.end method`;
    } else if (className.includes("WalletKeyManager")) {
      this.codeSourceDisplay.textContent = lang === "java" ? `package com.andoguard.defi.wallet;

/**
 * DeFi Web3 Wallet Key Management.
 * VULNERABILITY: MASVS-STORAGE-1 (Hardcoded 12-word mnemonic phrase and private keys).
 */
public class WalletKeyManager {
    // CRITICAL: Hardcoded BIP-39 mnemonic seed phrase in bytecode
    public static final String MNEMONIC_SEED = "witch collapse practice feed shame open despair creek road again ice least";
    // CRITICAL: Exposed Ethereum private key
    public static final String ETH_PRIVATE_KEY = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d";
    // Remote RPC endpoint
    public static final String INFURA_RPC = "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161";
}` : `.class public Lcom/andoguard/defi/wallet/WalletKeyManager;
.super Ljava/lang/Object;
.source "WalletKeyManager.java"

.field public static final MNEMONIC_SEED:Ljava/lang/String; = "witch collapse practice feed shame open despair creek road again ice least"
.field public static final ETH_PRIVATE_KEY:Ljava/lang/String; = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
.end method`;
    } else if (className.includes("AuthManager")) {
      this.codeSourceDisplay.textContent = lang === "java" ? `package com.andoguard.insecurebank;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import android.util.Log;

/**
 * Authentication and Cryptographic Manager for InsecureBank Mobile.
 * Flags: MASVS-STORAGE-1, MASVS-CRYPTO-1, MASVS-CRYPTO-2, MASVS-NETWORK-1
 */
public class AuthManager {
    public static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    public static final String GOOGLE_API_KEY = "AIzaSyD-InsecureBankGoogleApiKey9876543210";
    public static final String MASTER_SECRET = "admin_master_secret_key_8492049182390192";
    public static final String JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImJhbmsiOiJpbnNlY3VyZSJ9.abcdef1234567890";
    public static final String TRANSFER_ENDPOINT = "http://api.insecurebank.com/v1/transfer";

    public static byte[] decryptAuthToken(byte[] encryptedBytes) throws Exception {
        Log.d("InsecureBank:Auth", "Attempting token decryption with static secret key...");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(MASTER_SECRET.substring(0, 8).getBytes("UTF-8"), "DES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedBytes);
    }
}` : `.class public Lcom/andoguard/insecurebank/AuthManager;
.super Ljava/lang/Object;
.source "AuthManager.java"

# static fields
.field public static final AWS_ACCESS_KEY:Ljava/lang/String; = "AKIAIOSFODNN7EXAMPLE"
.field public static final GOOGLE_API_KEY:Ljava/lang/String; = "AIzaSyD-InsecureBankGoogleApiKey9876543210"

# direct methods
.method public static decryptAuthToken([B)[B
    .registers 4
    const-string v0, "DES/ECB/PKCS5Padding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v0
    ...
.end method`;
    } else {
      this.codeSourceDisplay.textContent = `// Decompiled source code for ${className}\npackage ${className.substring(0, className.lastIndexOf('.'))};\n\npublic class ${className.split('.').pop()} {\n    // Bytecode analysis complete\n}`;
    }
  }

  renderNative() {
    const container = document.getElementById("nativeLibsContainer");
    if (!container) return;
    container.innerHTML = "";

    const libs = this.currentData.native_libraries || [];
    if (libs.length === 0) {
      container.innerHTML = `<div class="panel-card"><p style="color: var(--text-dim);">No native ELF shared libraries (.so) found in APK container.</p></div>`;
      return;
    }

    libs.forEach(lib => {
      const card = document.createElement("div");
      card.className = "panel-card";
      card.innerHTML = `
        <h2>
          <span>${lib.path.split('/').pop()}</span>
          <span class="nav-tag">${lib.arch || 'ELF64'}</span>
        </h2>
        <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 12px;">
          Archive Path: <code>${lib.path}</code>
        </div>
        <div style="background: rgba(15,23,42,0.85); border-radius: 6px; padding: 12px; font-family: var(--font-code); font-size: 0.775rem;">
          <div style="color: var(--cyan-glow); font-weight: 600; margin-bottom: 6px;">Exported JNI Symbols:</div>
          ${(lib.jni_exports && lib.jni_exports.length > 0) ? lib.jni_exports.map(j => `<div>⚡ <code>${j}</code></div>`).join('') : '<div>⚡ <code>Java_com_native_function</code></div>'}
        </div>
      `;
      container.appendChild(card);
    });
  }

  renderCerts() {
    const container = document.getElementById("certsContentContainer");
    if (!container) return;
    const certs = this.currentData.certificates || {};
    const certList = certs.certificates || [];
    const c = certList[0] || {};

    container.innerHTML = `
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 18px;">
        <div class="metric-card">
          <span style="font-size: 0.75rem; color: var(--text-dim);">JAR SIGNING (v1)</span>
          <div style="font-size: 1.25rem; font-weight: 700; color: ${certs.v1_signature ? 'var(--success)' : 'var(--danger)'};">
            ${certs.v1_signature ? 'VERIFIED ✓' : 'ABSENT ✗'}
          </div>
        </div>
        <div class="metric-card">
          <span style="font-size: 0.75rem; color: var(--text-dim);">APK SIGNATURE (v2)</span>
          <div style="font-size: 1.25rem; font-weight: 700; color: ${certs.v2_signature ? 'var(--success)' : 'var(--warning)'};">
            ${certs.v2_signature ? 'VERIFIED ✓' : 'NOT PRESENT ✗'}
          </div>
        </div>
        <div class="metric-card">
          <span style="font-size: 0.75rem; color: var(--text-dim);">KEY ROTATION (v3)</span>
          <div style="font-size: 1.25rem; font-weight: 700; color: ${certs.v3_signature ? 'var(--success)' : 'var(--text-dim)'};">
            ${certs.v3_signature ? 'VERIFIED ✓' : 'NOT PRESENT ✗'}
          </div>
        </div>
      </div>
      <div class="panel-card" style="background: rgba(15,23,42,0.85);">
        <h4 style="color: #fff; margin-bottom: 10px;">X.509 Certificate Metadata</h4>
        <div style="font-size: 0.825rem; display: flex; flex-direction: column; gap: 8px;">
          <div><strong>Subject:</strong> <code>${c.subject || 'CN=AndoGuard Release Signer'}</code></div>
          <div><strong>Issuer:</strong> <code>${c.issuer || 'Self-Signed Release Certificate'}</code></div>
          <div><strong>Serial Number:</strong> <code>${c.serial_number || '0x7F9A1B2C3D4E5F6A'}</code></div>
          <div><strong>SHA-256 Fingerprint:</strong> <code style="word-break: break-all; color: var(--cyan-glow);">${c.sha256 || 'E8F2B1C4D9A019E776F438D102C455619A82BE192847D8A10984BCF10239A012'}</code></div>
        </div>
      </div>
    `;
  }

  renderSessions() {
    const tbody = document.getElementById("sessionsTableBody");
    if (!tbody) return;
    tbody.innerHTML = `
      <tr>
        <td><code>${this.currentData.metadata?.session_id || 'c43a6aeb'}</code></td>
        <td><strong>${this.currentDatasetKey}-session</strong></td>
        <td><code>${(this.currentData.metadata?.sha256 || '597f234d080d').substring(0, 16)}...</code></td>
        <td><span class="nav-tag">STATIC</span></td>
        <td>Just now (Active)</td>
        <td><span class="status-badge safe">ACTIVE SESSION</span></td>
      </tr>
      <tr>
        <td><code>4ca70801</code></td>
        <td>demo-baseline</td>
        <td><code>2976056640fd...</code></td>
        <td><span class="nav-tag">STATIC</span></td>
        <td>15 mins ago</td>
        <td><span class="status-badge" style="background: rgba(255,255,255,0.05); color: var(--text-dim);">STORED WAL</span></td>
      </tr>
    `;
  }

  async generateFridaScript() {
    const select = document.getElementById("fridaHookSelect");
    const codeEl = document.getElementById("fridaScriptCode");
    const hookType = select ? select.value : "ssl_bypass";
    const clsName = document.getElementById("hookClassInput")?.value || "com.andoguard.insecurebank.AuthManager";
    const mName = document.getElementById("hookMethodInput")?.value || "decryptAuthToken";

    if (codeEl) {
      codeEl.textContent = `// Generating dynamic Frida script for ${hookType}...`;
    }

    try {
      const res = await fetch(`/api/dynamic/generate?type=${hookType}&class=${encodeURIComponent(clsName)}&method=${encodeURIComponent(mName)}`);
      if (res.ok) {
        const data = await res.json();
        if (codeEl) {
          codeEl.textContent = data.script;
          return;
        }
      }
    } catch (e) {
      // offline fallback
    }

    if (codeEl) {
      codeEl.textContent = `// AndoGuard Synthesized Frida Script: ${hookType}
// Generated for authorized dynamic security assessment

Java.perform(function() {
    console.log("[*] AndoGuard Dynamic Bridge injected into target process");

    // 1. SSL Pinning Bypass (OkHttp3 & TrustManager)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] [Bypass] verifyChain bypassed for host: " + host);
            return untrustedChain;
        };
    } catch(err) {}

    // 2. Root Detection Bypass (Build tags & SU checks)
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        console.log("[+] [Bypass] Spoofed android.os.Build.TAGS to release-keys");
    } catch(err) {}
});`;
    }
  }

  async sendChatMessage() {
    const input = this.chatInput;
    if (!input || !input.value.trim()) return;
    const question = input.value.trim();
    input.value = "";

    const userMsg = document.createElement("div");
    userMsg.className = "chat-message user";
    userMsg.innerHTML = `
      <div class="chat-avatar">ME</div>
      <div class="chat-bubble">${question}</div>
    `;
    this.chatHistory.appendChild(userMsg);
    this.chatHistory.scrollTop = this.chatHistory.scrollHeight;

    const botMsg = document.createElement("div");
    botMsg.className = "chat-message bot";
    botMsg.innerHTML = `
      <div class="chat-avatar">AI</div>
      <div class="chat-bubble">Thinking and querying target binary index...</div>
    `;
    this.chatHistory.appendChild(botMsg);
    this.chatHistory.scrollTop = this.chatHistory.scrollHeight;

    try {
      const res = await fetch("/api/ai/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question })
      });
      if (res.ok) {
        const data = await res.json();
        botMsg.querySelector(".chat-bubble").innerHTML = data.answer.replace(/\n/g, "<br>");
        this.chatHistory.scrollTop = this.chatHistory.scrollHeight;
        return;
      }
    } catch (e) {
      // offline fallback
    }

    const pkg = this.currentData.metadata?.package_name || "target";
    let answer = `AndoGuard analyzed target <code>${pkg}</code>. `;
    if (question.toLowerCase().includes("professor") || question.toLowerCase().includes("executive")) {
      answer += `<br><br><strong>Executive Briefing for Professor:</strong><br>` +
        `• <strong>Architecture:</strong> Offline-first hexagonal adapter design with single-worker <code>BackendExecutor</code> for thread safety.<br>` +
        `• <strong>Security Posture:</strong> Grade ${this.currentData.risk_grade} (${this.currentData.security_score}/100). The assessment identified ${(this.currentData.findings || []).length} findings mapped to OWASP MASVS.<br>` +
        `• <strong>Attack Surface:</strong> ${(this.currentData.components?.exported || []).length} unprotected exported components.`;
    } else {
      answer += `<br><br>Identified ${(this.currentData.findings || []).length} security findings across OWASP MASVS. You can inspect bytecode in the Decompiler Studio tab or trigger dynamic hooks in the Frida tab.`;
    }

    botMsg.querySelector(".chat-bubble").innerHTML = answer;
    this.chatHistory.scrollTop = this.chatHistory.scrollHeight;
  }
}

// Instantiate dashboard on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  window.andoguardApp = new AndoGuardDashboard();
});
