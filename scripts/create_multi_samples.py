"""Generate realistic demo APK datasets representing diverse security postures for presentations:
1. insecure_bank.apk (Vulnerable Fintech - Grade D)
2. secure_enterprise.apk (Hardened Enterprise App - Grade A)
3. spyware_tracker.apk (Aggressive Surveillance Malware - Grade F)
4. crypto_wallet.apk (DeFi Wallet with Key Exposure - Grade D)
"""

import datetime
import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def build_dex(strings: list[str]) -> bytes:
    str_data_bytes = bytearray()
    str_data_offsets = []
    for s in strings:
        str_data_offsets.append(len(str_data_bytes))
        b = s.encode("utf-8")
        str_data_bytes.append(len(b))
        str_data_bytes.extend(b)
        str_data_bytes.append(0)

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)
    string_ids_bytes = bytearray()

    data_off = string_ids_off + string_ids_size * 4
    for off in str_data_offsets:
        string_ids_bytes.extend(struct.pack("<I", data_off + off))

    map_off = data_off + len(str_data_bytes)
    map_list = (
        struct.pack("<I", 4)
        + struct.pack("<HHII", 0, 0, 1, 0)
        + struct.pack("<HHII", 1, 0, string_ids_size, string_ids_off)
        + struct.pack("<HHII", 0x2002, 0, string_ids_size, data_off)
        + struct.pack("<HHII", 0x1000, 0, 1, map_off)
    )

    total_size = map_off + len(map_list)
    body = struct.pack(
        "<20I",
        total_size,
        header_size,
        0x12345678,
        0,
        0,
        map_off,
        string_ids_size,
        string_ids_off,
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
        len(str_data_bytes) + len(map_list),
        data_off,
    )
    full_payload = body + string_ids_bytes + str_data_bytes + map_list
    sha1 = hashlib.sha1(full_payload).digest()
    adler = zlib.adler32(sha1 + full_payload)
    return b"dex\n035\x00" + struct.pack("<I", adler) + sha1 + full_payload

def generate_cert(cn: str, org: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, cn),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
    ])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(int(hashlib.sha256(cn.encode()).hexdigest()[:15], 16))
        .not_valid_before(now - datetime.timedelta(days=30))
        .not_valid_after(now + datetime.timedelta(days=1000))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)

def make_elf(arch: str = "arm64", symbol: str = "Java_native") -> bytes:
    ei_class = 2 if arch == "arm64" else 1
    magic = b"\x7fELF" + bytes([ei_class, 1, 1, 0]) + b"\x00" * 8
    machine = 0xB7 if arch == "arm64" else 0x3E
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        magic, 3, machine, 1, 0x1000, 0, 64, 0, 64, 0, 0, 64, 0, 0
    )
    return header + symbol.encode("utf-8") + b"\x00"

def create_secure_enterprise_apk(out_path: Path) -> None:
    manifest = b"""<manifest xmlns:android='http://schemas.android.com/apk/res/android'
    package='com.andoguard.enterprise.secure'
    android:versionCode='340'
    android:versionName='3.4.0'>

    <uses-sdk android:minSdkVersion='28' android:targetSdkVersion='34'/>

    <!-- Minimal, least-privilege permissions -->
    <uses-permission android:name='android.permission.INTERNET'/>
    <uses-permission android:name='android.permission.ACCESS_NETWORK_STATE'/>

    <application
        android:name='.SecureEnterpriseApp'
        android:label='Enterprise Portal'
        android:debuggable='false'
        android:allowBackup='false'
        android:usesCleartextTraffic='false'
        android:networkSecurityConfig='@xml/network_security_config'>

        <!-- Sole exported entry point: MainActivity with standard launcher -->
        <activity android:name='.MainActivity' android:exported='true'>
            <intent-filter>
                <action android:name='android.intent.action.MAIN'/>
                <category android:name='android.intent.category.LAUNCHER'/>
            </intent-filter>
        </activity>

        <!-- All internal components strictly private -->
        <activity android:name='.DashboardActivity' android:exported='false'/>
        <activity android:name='.VaultActivity' android:exported='false'/>
        <service android:name='.SyncService' android:exported='false'/>
    </application>
</manifest>"""

    strings = [
        "com.andoguard.enterprise.secure.MainActivity",
        "com.andoguard.enterprise.secure.DashboardActivity",
        "com.andoguard.enterprise.secure.SecureVault",
        "https://api.enterprise.secure-cloud.com/v2/auth",
        "AES/GCM/NoPadding",
        "SHA-256",
        "AndroidKeyStore",
        "BiometricPrompt",
        "StrictHostKeyChecking"
    ]

    cert = generate_cert("Enterprise Release Authority", "Secure Corp Global")
    dex = build_dex(strings)

    with zipfile.ZipFile(out_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        zf.writestr("res/xml/network_security_config.xml", b"<network-security-config><domain-config cleartextTrafficPermitted='false'><domain includeSubdomains='true'>enterprise.secure-cloud.com</domain><pin-set><pin digest='SHA-256'>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin></pin-set></domain-config></network-security-config>")
        zf.writestr("META-INF/CERT.RSA", cert)

def create_spyware_tracker_apk(out_path: Path) -> None:
    manifest = b"""<manifest xmlns:android='http://schemas.android.com/apk/res/android'
    package='com.system.device.tracker'
    android:versionCode='101'
    android:versionName='1.0.1'>

    <!-- Old SDK target to bypass modern runtime permission prompts -->
    <uses-sdk android:minSdkVersion='21' android:targetSdkVersion='28'/>

    <!-- Aggressive invasive surveillance permissions -->
    <uses-permission android:name='android.permission.INTERNET'/>
    <uses-permission android:name='android.permission.RECORD_AUDIO'/>
    <uses-permission android:name='android.permission.ACCESS_FINE_LOCATION'/>
    <uses-permission android:name='android.permission.ACCESS_COARSE_LOCATION'/>
    <uses-permission android:name='android.permission.READ_SMS'/>
    <uses-permission android:name='android.permission.SEND_SMS'/>
    <uses-permission android:name='android.permission.RECEIVE_SMS'/>
    <uses-permission android:name='android.permission.READ_CONTACTS'/>
    <uses-permission android:name='android.permission.CAMERA'/>
    <uses-permission android:name='android.permission.READ_CALL_LOG'/>
    <uses-permission android:name='android.permission.RECEIVE_BOOT_COMPLETED'/>
    <uses-permission android:name='android.permission.WRITE_EXTERNAL_STORAGE'/>

    <application
        android:name='.TrackerApp'
        android:label='System Battery Optimizer'
        android:debuggable='true'
        android:allowBackup='true'
        android:usesCleartextTraffic='true'>

        <activity android:name='.LauncherActivity' android:exported='true'>
            <intent-filter>
                <action android:name='android.intent.action.MAIN'/>
                <category android:name='android.intent.category.LAUNCHER'/>
            </intent-filter>
        </activity>

        <!-- Stealth background audio recording service exported without permission -->
        <service android:name='.StealthAudioService' android:exported='true'/>
        <!-- Continuous background GPS locator beacon -->
        <service android:name='.GpsBeaconService' android:exported='true'/>

        <!-- Intercept incoming 2FA SMS messages -->
        <receiver android:name='.SmsInterceptorReceiver' android:exported='true'>
            <intent-filter android:priority='999'>
                <action android:name='android.provider.Telephony.SMS_RECEIVED'/>
                <action android:name='android.intent.action.BOOT_COMPLETED'/>
            </intent-filter>
        </receiver>
    </application>
</manifest>"""

    strings = [
        "com.system.device.tracker.LauncherActivity",
        "com.system.device.tracker.StealthAudioService",
        "com.system.device.tracker.GpsBeaconService",
        "com.system.device.tracker.SmsInterceptorReceiver",
        "http://c2.darknet-beacon.org:8080/exfil",
        "http://194.87.12.99/upload_sms.php",
        "AKIAIOSFODNN7C2BUCKET",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjMnNweXdhcmUiLCJ0YXJnZXQiOiJhbGwifQ.signature12345",
        "bot_token_5891823901:AAH8239102-telegram-token",
        "TrustAllCertificates",
        "DES/ECB/PKCS5Padding",
        "MD5"
    ]

    cert = generate_cert("Android Debug Signer", "AOSP Debug")
    dex = build_dex(strings)
    elf_arm = make_elf("arm64", "Java_com_system_device_tracker_NativeHook_interceptAudio")

    with zipfile.ZipFile(out_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        zf.writestr("lib/arm64-v8a/libstealth.so", elf_arm)
        zf.writestr("assets/c2_config.json", b'{"c2_host": "http://c2.darknet-beacon.org:8080", "exfil_interval": 30}')
        zf.writestr("META-INF/CERT.RSA", cert)

def create_crypto_wallet_apk(out_path: Path) -> None:
    manifest = b"""<manifest xmlns:android='http://schemas.android.com/apk/res/android'
    package='com.andoguard.defi.wallet'
    android:versionCode='182'
    android:versionName='1.8.2'>

    <uses-sdk android:minSdkVersion='26' android:targetSdkVersion='33'/>

    <uses-permission android:name='android.permission.INTERNET'/>
    <uses-permission android:name='android.permission.CAMERA'/>
    <uses-permission android:name='android.permission.USE_BIOMETRIC'/>

    <application
        android:name='.WalletApp'
        android:label='DeFi Web3 Wallet'
        android:debuggable='true'
        android:allowBackup='true'
        android:usesCleartextTraffic='true'>

        <activity android:name='.WalletMainActivity' android:exported='true'>
            <intent-filter>
                <action android:name='android.intent.action.MAIN'/>
                <category android:name='android.intent.category.LAUNCHER'/>
            </intent-filter>
        </activity>

        <activity android:name='.SendCryptoActivity' android:exported='true'/>
        <activity android:name='.ExportKeysActivity' android:exported='false'/>

        <provider
            android:name='.WalletCacheProvider'
            android:authorities='com.andoguard.defi.wallet.cache'
            android:exported='true'/>
    </application>
</manifest>"""

    strings = [
        "com.andoguard.defi.wallet.WalletMainActivity",
        "com.andoguard.defi.wallet.SendCryptoActivity",
        "com.andoguard.defi.wallet.WalletKeyManager",
        "com.andoguard.defi.wallet.NativeSigner",
        "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d",
        "witch collapse practice feed shame open despair creek road again ice least",
        "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161",
        "AIzaSyD-CryptoWalletRpcKey897123490",
        "http://rpc.testnet.insecure-defi.org:8545",
        "DES/ECB/PKCS5Padding",
        "SHA-1"
    ]

    cert = generate_cert("DeFi Wallet Signer", "Decentralized Lab Foundation")
    dex = build_dex(strings)
    elf_arm = make_elf("arm64", "Java_com_andoguard_defi_wallet_NativeSigner_signTransaction")
    elf_x86 = make_elf("x86_64", "Java_com_andoguard_defi_wallet_NativeSigner_signTransaction")

    with zipfile.ZipFile(out_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        zf.writestr("lib/arm64-v8a/libsecp256k1.so", elf_arm)
        zf.writestr("lib/x86_64/libsecp256k1.so", elf_x86)
        zf.writestr("META-INF/CERT.RSA", cert)

def main() -> None:
    samples_dir = Path("samples")
    samples_dir.mkdir(exist_ok=True)

    f1 = samples_dir / "secure_enterprise.apk"
    f2 = samples_dir / "spyware_tracker.apk"
    f3 = samples_dir / "crypto_wallet.apk"

    create_secure_enterprise_apk(f1)
    create_spyware_tracker_apk(f2)
    create_crypto_wallet_apk(f3)

    print(f"Created {f1} ({f1.stat().st_size} bytes)")
    print(f"Created {f2} ({f2.stat().st_size} bytes)")
    print(f"Created {f3} ({f3.stat().st_size} bytes)")

if __name__ == "__main__":
    main()
